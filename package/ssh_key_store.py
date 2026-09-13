"""
SSH Key Store

Users' SSH private keys live in MongoDB from 3.0.0 onward, in the collection
named by ``KEYS_COLLECTION``:

    {"_id":     "alice/id_rsa",      # f"{user}/{name}"
     "user":    "alice",
     "name":    "id_rsa",
     "key":     Binary(<fernet ciphertext>),
     "created": datetime}

Pre-3.0.0 they were ``data/<username>/<name>.key``. Those files are adopted at
startup by :func:`migrate_legacy_key_files` and renamed to ``.key.migrated`` --
never deleted, because that ciphertext is the user's only copy.

**What is stored is ciphertext the server cannot read.** ``process_upload()``
generates a fresh Fernet key, shows it to the user once, and does not persist it;
the user supplies it again at connect time. Moving the blob into MongoDB does not
change that, so an unauthenticated database yields no usable key -- but it does
put the ciphertext somewhere new, including in backups via ``mongo_dump()``.

``_id`` is ``f"{user}/{name}"`` so uniqueness per (user, name) comes free with no
index to build, the same reasoning as ``user_store``. The composite is
unambiguous: usernames pass a strict allowlist that excludes ``/``, and key names
have been through ``secure_filename()``. ``user`` and ``name`` are kept as their
own fields so listing is a projection rather than string surgery on ``_id``.
"""

import glob
import logging
import os
import tempfile
from datetime import datetime, timezone

from bson.binary import Binary
from cryptography.fernet import Fernet

from package import data_file_functions
from package.validators import KEYS_COLLECTION

# Pre-3.0.0 on-disk location, and the suffix the file is renamed to once its
# ciphertext is in MongoDB. As with auth.db.migrated, the rename is the "already
# migrated" marker and the retained file is the downgrade path.
LEGACY_KEY_SUFFIX = ".key"
MIGRATED_KEY_SUFFIX = ".key.migrated"


def collection():
    """Returns the MongoDB collection holding encrypted SSH keys."""
    return data_file_functions._get_mongo_db()[KEYS_COLLECTION]


def _document_id(user, name):
    return f"{user}/{name}"


def store_key(user, name, ciphertext):
    """Stores (or replaces) a user's encrypted SSH key.

    Args:
        user (str): Account name
        name (str): Key name, without the .key extension
        ciphertext (bytes): Fernet-encrypted private key

    Replaces on re-upload: a user who has lost their Fernet key uploads again and
    gets a new one, and the old ciphertext is then undecryptable by anyone,
    including them. Keeping it would serve no purpose.
    """
    collection().update_one(
        {"_id": _document_id(user, name)},
        {
            "$set": {
                "user": user,
                "name": name,
                "key": Binary(bytes(ciphertext)),
                "created": datetime.now(timezone.utc),
            }
        },
        upsert=True,
    )
    logging.info(f"Stored encrypted SSH key <{name}> for user <{user}>.")


def list_key_names(user):
    """Returns the user's key names, sorted. Scoped to that user only."""
    names = [
        doc["name"]
        for doc in collection().find({"user": user}, {"name": 1})
        if doc.get("name")
    ]
    names.sort()
    return names


def get_ciphertext(user, name):
    """Returns the stored ciphertext as bytes, or None if there is no such key."""
    doc = collection().find_one({"_id": _document_id(user, name)})
    if doc is None or not doc.get("key"):
        return None
    return bytes(doc["key"])


def decrypt_ssh_key(user, name, fernet_key):
    """
    Decrypts a stored SSH key and stages the plaintext in a temporary file.

    Args:
        user (str): Account name
        name (str): Key name, without the .key extension
        fernet_key (bytes): The Fernet key the user was shown at upload time

    Returns:
        str: Path to the temporary file holding the plaintext private key

    Raises:
        FileNotFoundError: If no key of that name is stored for that user
        cryptography.fernet.InvalidToken: If the Fernet key is wrong

    NAPALM and Paramiko both want a filesystem path (``key_file`` /
    ``key_filename``), so the plaintext has to touch disk. It is staged with
    ``tempfile.mkstemp()`` -- a cryptographically-random name at ``0o600`` -- and
    deliberately **without** ``dir=``, so it lands in the system temp directory
    rather than the mounted data volume. The caller must delete it in a
    ``finally`` block; see napalm_ssh_functions.
    """
    ciphertext = get_ciphertext(user, name)
    if ciphertext is None:
        raise FileNotFoundError(f"No stored SSH key named '{name}' for user '{user}'.")

    # Decrypt before creating the temp file: a wrong Fernet key raises here, and
    # there is then no empty file to clean up.
    decrypted = Fernet(fernet_key).decrypt(ciphertext)

    fd, tmp_file_name = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as dec_file:
        dec_file.write(decrypted)
    logging.debug(f" |--> Decrypted key temporarily staged as: {tmp_file_name}")

    return tmp_file_name


def migrate_legacy_key_files(usernames):
    """
    Adopts pre-3.0.0 data/<user>/*.key files into MongoDB.

    Args:
        usernames (list): Account names, from user_store.list_usernames()

    Returns:
        None

    Each file's ciphertext is stored under its (user, name) and the file is then
    renamed to <name>.key.migrated. Points worth keeping in mind:

    - ``$setOnInsert``, so a re-run cannot overwrite a key the user has
      re-uploaded since -- that would replace a working key with one whose Fernet
      key they no longer have.
    - The file is **renamed, never deleted**. The ciphertext is the user's only
      copy, and the retained file is the downgrade path, exactly like
      auth.db.migrated and instance.id.migrated.
    - Never raises. A failed key migration must not stop startup; the file is left
      unrenamed so the next boot retries it.

    The account list is passed in rather than looked up here, both to keep this
    module from importing user_store and to bound the work to real per-user
    directories.
    """
    logging.info("Migrating on-disk SSH keys into MongoDB...")

    migrated = 0
    for username in usernames:
        # glob.escape: usernames pass a strict allowlist today, but a name with a
        # glob metacharacter must not widen the match.
        pattern = os.path.join(
            "data", glob.escape(str(username)), f"*{LEGACY_KEY_SUFFIX}"
        )
        for path in glob.glob(pattern):
            name = os.path.basename(path)[: -len(LEGACY_KEY_SUFFIX)]
            try:
                with open(path, "rb") as f:
                    ciphertext = f.read()

                if not ciphertext:
                    logging.warning(f" |--X Skipping empty SSH key file: {path}")
                    continue

                collection().update_one(
                    {"_id": _document_id(username, name)},
                    {
                        "$setOnInsert": {
                            "user": username,
                            "name": name,
                            "key": Binary(ciphertext),
                            "created": datetime.now(timezone.utc),
                            "migrated_from_file": True,
                        }
                    },
                    upsert=True,
                )
                _retire_legacy_file(path)
                migrated += 1
                logging.info(f" |--> Migrated SSH key <{name}> for <{username}>.")
            except Exception as e:
                # Left unrenamed on purpose, so the next boot retries.
                logging.warning(f" |--X Could not migrate SSH key {path}: {e}")

    logging.info(f" |--> SSH keys migrated: {migrated}")
    return


def _retire_legacy_file(path):
    """Renames an adopted key file, never overwriting an earlier retirement."""
    target = f"{path[: -len(LEGACY_KEY_SUFFIX)]}{MIGRATED_KEY_SUFFIX}"
    if os.path.exists(target):
        target = f"{target}.{datetime.now():%Y%m%d%H%M%S}"
    os.rename(path, target)
    logging.info(f" |--> Retained legacy key file as {target}.")
