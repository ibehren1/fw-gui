"""
Legacy SQLite user migration.

Pre-3.0.0 installs kept user accounts in ``data/database/auth.db``, a SQLite
file behind Flask-SQLAlchemy. 3.0.0 keeps them in MongoDB. This module copies
the accounts across once, at startup, with no operator action required.

The migration is idempotent in two independent ways, because the file marker
alone is not trustworthy -- a restored ``data/`` volume or a curious operator
can make it disappear:

1. ``auth.db`` is renamed to ``auth.db.migrated`` once the copy succeeds, so
   the next boot has nothing to find.
2. Every write is ``$setOnInsert``. Were the migration to run again against
   already-migrated accounts, it must not overwrite them. With ``$set`` a
   re-run would restore each user's pre-cutover password hash -- including one
   that had been deliberately rotated because it leaked -- and re-enable an
   account the operator had since disabled.

The renamed file is deliberately left in place: it is the rollback path for an
operator who downgrades the image. It is a point-in-time snapshot, so accounts
created and passwords changed after the cutover are not in it.
"""

import glob
import logging
import os
import sqlite3
import sys
from datetime import datetime

from pymongo.errors import DuplicateKeyError

from package import user_store
from package.validators import is_auth_critical_username

# Pre-3.0.0 authentication database, and the name it is renamed to once its
# accounts are in MongoDB. The rename doubles as the "already migrated" marker.
LEGACY_AUTH_DB = "data/database/auth.db"
MIGRATED_AUTH_DB = "data/database/auth.db.migrated"

# SQLAlchemy's implicit table name for "class User" is "user". The old
# mongo_converter queried "FROM User" and only worked because SQLite
# identifiers are case-insensitive.
_LEGACY_USER_QUERY = "SELECT id, username, email, password FROM user"  # nosec B608

# Server-side session store. Purged at cutover so nobody carries a session
# holding a pre-3.0.0 _user_id.
_SESSIONS_COLLECTION = "sessions"
_FILESYSTEM_SESSION_DIR = "flask_session"


def _decode_hash(password, uid):
    """Normalises a stored bcrypt hash to str, or returns None if unusable.

    The legacy column holds a mix of TEXT and BLOB: generate_password_hash
    returns bytes and the pre-3.0.0 write paths stored it unconverted. bcrypt
    hashes are ASCII, so decoding is lossless.
    """
    if isinstance(password, (bytes, bytearray, memoryview)):
        try:
            return bytes(password).decode("utf-8")
        except UnicodeDecodeError:
            logging.warning(
                f" |--> Skipping legacy user id={uid}: password hash is not decodable."
            )
            return None
    if isinstance(password, str):
        return password
    logging.warning(
        f" |--> Skipping legacy user id={uid}: password hash has unexpected type "
        f"{type(password).__name__}."
    )
    return None


def _check_collection_is_not_a_config_collection(collection):
    """Aborts startup if the users collection belongs to a user instead.

    A username is also a MongoDB collection name, so an install that already
    has a user named "users" has that user's configs where the accounts need to
    go. Registration rejects the name now, but an account predating the guard
    can already exist.
    """
    if collection.count_documents({"password": {"$exists": False}}, limit=1):
        logging.critical(
            f"Collection '{collection.name}' already holds documents that are not "
            "user accounts -- most likely the firewall configs of a user with that "
            "name. Set MONGODB_USERS_COLLECTION to an unused collection name and "
            "restart."
        )
        sys.exit(1)


def _check_no_reserved_usernames(rows):
    """Aborts startup if a legacy account collides with the account/session store.

    Migrating it would hand that user the accounts or session collection as
    their config collection. Refusing to boot is the honest outcome: the
    operator has to rename the account.

    Deliberately narrower than is_reserved_username(): a legacy account named
    "instance" collides only with the telemetry id, which is not worth refusing
    to start over. That collision degrades telemetry instead (see
    package/instance_id.py). New registrations of any reserved name are still
    blocked.
    """
    reserved = [
        username for _, username, _, _ in rows if is_auth_critical_username(username)
    ]
    if reserved:
        logging.critical(
            f"Legacy account(s) {reserved} use a reserved username. A username is "
            "also a MongoDB collection name, so these would collide with the "
            "application's own collections. Rename the account(s) in "
            f"{LEGACY_AUTH_DB} and restart."
        )
        sys.exit(1)


def _purge_sessions():
    """Clears the server-side session store.

    Flask-Login session tokens changed format at 3.0.0 (see
    user_store.SESSION_ID_PREFIX), so every existing session is stale. Deleting
    them logs everyone out at the cutover rather than leaving tokens that fail
    to resolve.
    """
    try:
        deleted = (
            user_store.collection()
            .database[_SESSIONS_COLLECTION]
            .delete_many({})
            .deleted_count
        )
        logging.info(f" |--> Cleared {deleted} server-side session(s).")
    except Exception as e:
        # A failed purge leaves stale sessions that cannot resolve to a user
        # anyway, so it must not block the migration.
        logging.warning(f" |--> Could not clear MongoDB sessions: {e}")

    if os.path.isdir(_FILESYSTEM_SESSION_DIR):
        for path in glob.glob(os.path.join(_FILESYSTEM_SESSION_DIR, "*")):
            try:
                os.remove(path)
            except OSError as e:
                logging.warning(f" |--> Could not remove session file {path}: {e}")


def _retire_legacy_db():
    """Renames auth.db so the migration does not run again.

    Never overwrites an existing auth.db.migrated: that would destroy the
    rollback snapshot of an earlier migration.
    """
    target = MIGRATED_AUTH_DB
    if os.path.exists(target):
        target = f"{MIGRATED_AUTH_DB}.{datetime.now():%Y%m%d%H%M%S}"
    os.rename(LEGACY_AUTH_DB, target)
    logging.info(f" |--> Retained legacy auth database as {target}.")


def migrate_sqlite_users():
    """Copies pre-3.0.0 SQLite accounts into MongoDB. Safe to call repeatedly."""
    if not os.path.exists(LEGACY_AUTH_DB):
        return

    logging.info("*** Starting SQLite user migration ***")

    collection = user_store.collection()
    _check_collection_is_not_a_config_collection(collection)

    con = None
    try:
        # Read-only URI: no -wal/-shm sidecars are created, and a missing file
        # is an error rather than a new empty database.
        con = sqlite3.connect(f"file:{LEGACY_AUTH_DB}?mode=ro", uri=True)
        rows = con.execute(_LEGACY_USER_QUERY).fetchall()
    except sqlite3.Error as e:
        # Do not rename: leaving the file in place means the next boot retries.
        logging.error(f" |--> Could not read {LEGACY_AUTH_DB} ({e}); skipping.")
        return
    finally:
        if con is not None:
            con.close()

    _check_no_reserved_usernames(rows)

    inserted = 0
    already_present = []
    for uid, username, email, password in rows:
        if not username or not password:
            logging.warning(
                f" |--> Skipping legacy user id={uid}: missing username or password."
            )
            continue

        password = _decode_hash(password, uid)
        if password is None:
            continue

        try:
            result = collection.update_one(
                {"_id": username},
                {
                    "$setOnInsert": {
                        "email": email or "",
                        "password": password,
                        "disabled": False,
                        "legacy_id": int(uid),
                        "migrated_from_sqlite": True,
                    }
                },
                upsert=True,
            )
        except DuplicateKeyError:
            # A concurrent boot (replicaCount > 1) inserted it first.
            continue

        if result.upserted_id is not None:
            inserted += 1
            logging.info(f" |--> Migrated user <{username}>.")
        else:
            already_present.append(username)

    logging.info(
        f" |--> {len(rows)} legacy account(s) read, {inserted} newly inserted."
    )

    # On a genuine first migration nothing is skipped, so this fires only when
    # MongoDB already holds accounts of the same name -- i.e. a re-upgrade after
    # a downgrade, or a data/ volume restored from before the cutover. Nothing
    # has gone wrong (the newer MongoDB copy winning is the whole point of
    # $setOnInsert), but which copy won is not something to leave unsaid.
    if already_present:
        logging.warning(
            f" |--> {len(already_present)} legacy account(s) already existed in "
            f"MongoDB and were left untouched: {already_present}. The MongoDB "
            "copy wins, so any password change or disable held there is "
            "preserved and the SQLite values are discarded. If this is a "
            "re-upgrade after a downgrade to pre-3.0.0, changes made while "
            "downgraded are being dropped -- see 'Downgrading and re-upgrading' "
            "in docs/data-architecture.md."
        )

    _purge_sessions()
    _retire_legacy_db()
