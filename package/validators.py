"""
Input validators for user-supplied names used in filesystem paths and MongoDB
addressing.

Config data is addressed as ``data/<username>/<config>[/<snapshot>]`` and the
data layer splits that string on ``/`` to derive the MongoDB collection
(username) and document (config). The same names are also used to build
filesystem paths (uploaded ``.key`` files). A name
containing a path separator or ``..`` could therefore either traverse the
filesystem or shift the collection/document addressing. These helpers reject
such names.
"""

import os
import re

# Tokens that would let a single name component escape its directory or shift
# the "/"-split MongoDB addressing.
_UNSAFE_CHARS = ("/", "\\", "\x00")

# Usernames become both a directory name and a MongoDB collection name, so they
# are held to a strict allowlist (applied to new registrations).
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

# Collections owned by the application, never by a user. Hardcoded on purpose --
# see is_reserved_username.
_RESERVED_USERNAMES = frozenset({"users", "sessions", "instance", "keys"})

# The subset whose collision is not survivable: these hold the credential store,
# the session store and the encrypted SSH keys, so a user owning one could read
# and delete other users' accounts, sessions or key material. A collision here
# aborts the startup migration rather than being worked around. "instance" is
# deliberately absent -- it holds only the telemetry id, and refusing to boot over
# that would be disproportionate; the collision degrades telemetry instead (see
# package/instance_id.py).
_AUTH_CRITICAL_RESERVED = frozenset({"users", "sessions", "keys"})

# Collection holding user accounts. Overridable so an install that already has a
# user named "users" has somewhere to go.
DEFAULT_USERS_COLLECTION = "users"

# Collection holding the telemetry instance id.
INSTANCE_COLLECTION = "instance"

# Collection holding users' Fernet-encrypted SSH private keys.
KEYS_COLLECTION = "keys"


def is_safe_name(name):
    """Return True if ``name`` is a safe single path/Mongo component.

    Rejects empty values, ``.``/``..``, any embedded ``..``, and path
    separators / null bytes. Deliberately permissive otherwise so existing
    config names (spaces, timestamps, etc.) keep working.
    """
    if not isinstance(name, str) or name == "":
        return False
    if name in (".", ".."):
        return False
    if ".." in name:
        return False
    if any(ch in name for ch in _UNSAFE_CHARS):
        return False
    return True


# Shell metacharacters that must never reach the vbash script that runs
# operational commands on the device (they would allow shell breakout).
_OP_METACHARACTERS = set(";&|$`()<>\n\r\\'\"")


def is_allowed_op_command(command):
    """Return True if ``command`` is a permitted read-only operational command.

    Policy: only ``show ...`` commands are allowed, and the command may not
    contain any shell metacharacter or newline. This confines the feature to
    operational-mode inspection and prevents shell/command injection into the
    vbash script that executes it.
    """
    if not isinstance(command, str):
        return False
    cmd = command.strip()
    if cmd == "":
        return False
    if any(ch in _OP_METACHARACTERS for ch in cmd):
        return False
    tokens = cmd.split()
    return bool(tokens) and tokens[0] == "show"


def is_reserved_username(name):
    """Return True if ``name`` is a collection name the application owns.

    A username is also a MongoDB collection name, so a user holding one of these
    would be handed an application collection as their "config" collection: the
    normal config routes would let them list, read and delete other users'
    accounts (``users``), session documents (``sessions``), encrypted SSH keys
    (``keys``), or the telemetry id (``instance``).

    ``MONGODB_USERS_COLLECTION`` is honoured in addition to -- never instead of
    -- the hardcoded names, because an install that renamed the collection may
    still have a ``users``-named leftover from before the rename.
    """
    if not isinstance(name, str):
        return False
    reserved = set(_RESERVED_USERNAMES)
    reserved.add(
        os.environ.get("MONGODB_USERS_COLLECTION", DEFAULT_USERS_COLLECTION).lower()
    )
    return name.strip().lower() in reserved


def is_auth_critical_username(name):
    """Return True if ``name`` collides with a store holding credentials or keys.

    Narrower than :func:`is_reserved_username`: only the collisions that cannot
    be worked around, and so are worth refusing to start over. Used by the
    startup user migration.
    """
    if not isinstance(name, str):
        return False
    reserved = set(_AUTH_CRITICAL_RESERVED)
    reserved.add(
        os.environ.get("MONGODB_USERS_COLLECTION", DEFAULT_USERS_COLLECTION).lower()
    )
    return name.strip().lower() in reserved


def is_valid_username(name):
    """Return True if ``name`` is a valid username (strict allowlist)."""
    return bool(
        isinstance(name, str)
        and name != ""
        and ".." not in name
        and _USERNAME_RE.match(name)
        and not is_reserved_username(name)
    )
