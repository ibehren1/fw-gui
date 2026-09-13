"""
User Account Store

User accounts live in MongoDB, in the collection named by
``MONGODB_USERS_COLLECTION`` (default ``users``) inside ``MONGODB_DATABASE``.

The document ``_id`` is the username. That is deliberate: it makes the username
unique without an index to create at startup, so there is no index build to fail
and no window in which two registrations of the same name can both succeed --
the second raises ``DuplicateKeyError``. Matching is binary, which preserves the
case-sensitive uniqueness the previous SQLite ``unique`` column gave.

Accounts are disabled, never deleted. Deleting a document would free the
username, and because a username is also the MongoDB collection name and the
``data/<username>`` directory name, whoever registered that name next would
inherit the previous holder's configs, snapshots and SSH keys.

Document shape::

    {"_id": "alice",              # username
     "email": "alice@example.com",
     "password": "$2b$12$...",    # bcrypt hash, always str
     "disabled": False,           # absent means enabled
     "legacy_id": 1,              # rows migrated from SQLite only
     "created": datetime}         # new registrations only
"""

import os
from datetime import datetime, timezone

from flask_login import UserMixin

from package import data_file_functions
from package.validators import DEFAULT_USERS_COLLECTION

# Flask-Login stores get_id() in the session as "_user_id". Namespacing the
# token keeps it out of the plain-username space: usernames may be all digits,
# so a bare username would be indistinguishable from the integer primary key
# that pre-2.5.0 sessions carry, and a stale session could resolve to the
# account *named* "1".
SESSION_ID_PREFIX = "u:"


def collection():
    """Returns the MongoDB collection holding user accounts."""
    return data_file_functions._get_mongo_db()[
        os.environ.get("MONGODB_USERS_COLLECTION", DEFAULT_USERS_COLLECTION)
    ]


class User(UserMixin):
    """A user account, wrapping its MongoDB document."""

    def __init__(self, doc):
        self.username = doc["_id"]
        self.email = doc.get("email", "")
        self.password = doc.get("password", "")
        # Absent means enabled, so documents written before the field existed
        # (and hand-written ones) keep working.
        self.disabled = bool(doc.get("disabled", False))

    @property
    def is_active(self):
        # Flask-Login refuses login_user() for an inactive user, so this backs
        # up the explicit checks in auth_functions rather than replacing them.
        return not self.disabled

    def get_id(self):
        return f"{SESSION_ID_PREFIX}{self.username}"


def get_user_by_username(username):
    """Returns the ``User`` for ``username``, or None if there is no such account.

    Disabled accounts are returned; the caller decides what to do with them.
    MongoDB errors are deliberately not caught -- rendering an outage as "no
    such user" would be the worst possible diagnostic.
    """
    if not username:
        return None
    doc = collection().find_one({"_id": username})
    return User(doc) if doc is not None else None


def get_user_by_session_id(token):
    """Returns the ``User`` for a Flask-Login session token, or None.

    Used by the ``user_loader``, so it runs on every authenticated request. It
    rejects disabled accounts itself, which is what makes disabling take effect
    on the user's next request rather than at their next login.
    """
    if not isinstance(token, str) or not token.startswith(SESSION_ID_PREFIX):
        return None
    user = get_user_by_username(token[len(SESSION_ID_PREFIX) :])
    if user is None or user.disabled:
        return None
    return user


def create_user(username, email, password_hash):
    """Inserts a new account.

    Raises ``pymongo.errors.DuplicateKeyError`` if the username is taken. That
    is the uniqueness check -- do not pre-check and then insert.
    """
    collection().insert_one(
        {
            "_id": username,
            "email": email,
            "password": password_hash,
            "disabled": False,
            "created": datetime.now(timezone.utc),
        }
    )


def set_password(username, password_hash):
    """Replaces an account's password hash. Returns True if the account existed."""
    result = collection().update_one(
        {"_id": username}, {"$set": {"password": password_hash}}
    )
    return result.matched_count == 1


def list_usernames():
    """Returns every username, including disabled accounts.

    Disabled accounts are included on purpose: mongo_converter uses this to find
    per-user directories, and a disabled user's leftover JSON should still be
    imported rather than silently skipped.
    """
    return [doc["_id"] for doc in collection().find({}, {"_id": 1})]
