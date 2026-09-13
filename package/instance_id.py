"""
Telemetry Instance Id

The instance id is a random UUID identifying this install to the telemetry
endpoint. It lives in MongoDB from 3.0.0 onward, in the collection named by
``INSTANCE_COLLECTION``:

    {"_id": "instance_id", "value": "<uuid4>", "created": datetime}

Pre-3.0.0 it was ``data/database/instance.id``. That file is adopted on first
read so an upgraded install keeps its identity, then renamed to
``instance.id.migrated`` -- retained, like ``auth.db.migrated``, so a downgrade
still has it.

**Nothing in here may raise.** ``telemetry_commit()`` and ``telemetry_diff()``
are called from ``napalm_ssh_functions`` outside the try blocks that protect a
firewall push, so an exception escaping this module would turn a telemetry
lookup into a failed commit. Every path returns a string; an unavailable id is
the empty string and telemetry degrades.
"""

import logging
import os
import uuid
from datetime import datetime, timezone

import pymongo

from package import data_file_functions
from package.validators import INSTANCE_COLLECTION

# Upper bound on how long a telemetry id lookup may block. Tighter than the
# shared client's SERVER_SELECTION_TIMEOUT_MS on purpose: this used to be a free
# file read, and it sits in the login path (telemetry_instance) and the commit
# path (telemetry_commit). A MongoDB outage already breaks those requests for
# other reasons; telemetry must not add to the wait.
_LOOKUP_TIMEOUT_SECONDS = 2.0

# Pre-3.0.0 location, and the name it is renamed to once its value is in
# MongoDB. As with auth.db.migrated, the rename is the "already migrated" marker
# and the retained file is the downgrade path.
LEGACY_INSTANCE_FILE = "data/database/instance.id"
MIGRATED_INSTANCE_FILE = "data/database/instance.id.migrated"

# Environment override. Short-circuits everything, including any MongoDB access,
# so CI runs can tag their telemetry and an operator can pin identity across a
# blue/green replacement.
INSTANCE_ID_ENV_VAR = "FWGUI_INSTANCE_ID"

# Fixed _id of the single document in the collection.
_DOCUMENT_ID = "instance_id"

# Cached for the life of the process. get_instance_id() is called on every
# telemetry event -- login, commit, diff, rule usage -- and this used to be a
# free file read; without the cache each one becomes a MongoDB round trip.
_instance_id = None


def _collection():
    return data_file_functions._get_mongo_db()[INSTANCE_COLLECTION]


def _read_legacy_file():
    """Returns the pre-3.0.0 file's id, or None if there isn't a usable one."""
    try:
        with open(LEGACY_INSTANCE_FILE) as f:
            value = f.read().strip()
    except OSError:
        return None

    if not value:
        logging.warning(f"{LEGACY_INSTANCE_FILE} is empty; generating a new id.")
        return None

    return value


def _retire_legacy_file():
    """Renames the legacy file so it is adopted only once. Best effort.

    Never overwrites an existing ``instance.id.migrated``: that would destroy an
    earlier migration's record.

    A failure here is deliberately not fatal to the caller. The id is already in
    MongoDB by this point, and the stored value takes precedence over the file on
    every later read, so a read-only data directory costs nothing but a leftover
    file.
    """
    target = MIGRATED_INSTANCE_FILE
    if os.path.exists(target):
        target = f"{MIGRATED_INSTANCE_FILE}.{datetime.now():%Y%m%d%H%M%S}"
    try:
        os.rename(LEGACY_INSTANCE_FILE, target)
    except OSError as e:
        logging.warning(
            f"Could not rename {LEGACY_INSTANCE_FILE} to {target} ({e}); the id is "
            "stored in MongoDB and takes precedence, so the file is now ignored."
        )
        return
    logging.info(f" |--> Retained legacy instance id file as {target}.")


def _resolve_from_mongo():
    """Returns the stored id, seeding the collection on first use."""
    collection = _collection()

    existing = collection.find_one({"_id": _DOCUMENT_ID})
    if existing is not None:
        value = existing.get("value")
        if value:
            return value
        # A document with no usable value means something else owns this
        # collection -- most likely a user registered the name before it was
        # reserved, so these are their config documents.
        logging.error(
            f"Collection '{INSTANCE_COLLECTION}' holds a document that is not a "
            "telemetry id. If a user of that name exists, set a different "
            "collection name or rename the account; telemetry is degraded until "
            "then."
        )
        return ""

    # Nothing stored yet. Adopt the pre-3.0.0 file if there is one so the install
    # keeps its identity, otherwise mint a new id.
    legacy = _read_legacy_file()
    candidate = legacy or str(uuid.uuid4())

    # $setOnInsert, so two concurrent callers converge on one value instead of
    # racing to overwrite each other. Read back rather than trusting `candidate`:
    # if another process won, its value is the real one.
    collection.update_one(
        {"_id": _DOCUMENT_ID},
        {
            "$setOnInsert": {
                "value": candidate,
                "created": datetime.now(timezone.utc),
                "migrated_from_file": legacy is not None,
            }
        },
        upsert=True,
    )
    stored = collection.find_one({"_id": _DOCUMENT_ID}).get("value", "")

    if legacy is not None:
        if stored == candidate:
            logging.info(f"Adopted instance id from {LEGACY_INSTANCE_FILE}.")
        _retire_legacy_file()

    return stored


def get_or_create_instance_id():
    """Returns the telemetry instance id, or "" if it cannot be determined.

    Never raises: see the module docstring.
    """
    override = os.environ.get(INSTANCE_ID_ENV_VAR)
    if override:
        return override.strip()

    global _instance_id
    if _instance_id:
        return _instance_id

    try:
        with pymongo.timeout(_LOOKUP_TIMEOUT_SECONDS):
            value = _resolve_from_mongo()
    except Exception as e:
        # Telemetry is not worth a failed request, let alone a failed commit.
        logging.debug(f"Could not resolve the telemetry instance id: {e}")
        return ""

    # Only cache a real value, so a transient MongoDB failure does not pin the
    # empty string for the life of the process.
    if value:
        _instance_id = value

    return value
