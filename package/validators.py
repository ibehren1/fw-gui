"""
Input validators for user-supplied names used in filesystem paths and MongoDB
addressing.

Config data is addressed as ``data/<username>/<config>[/<snapshot>]`` and the
data layer splits that string on ``/`` to derive the MongoDB collection
(username) and document (config). The same names are also used to build
filesystem paths (``.conf`` command files, uploaded ``.key`` files). A name
containing a path separator or ``..`` could therefore either traverse the
filesystem or shift the collection/document addressing. These helpers reject
such names.
"""

import re

# Tokens that would let a single name component escape its directory or shift
# the "/"-split MongoDB addressing.
_UNSAFE_CHARS = ("/", "\\", "\x00")

# Usernames become both a directory name and a MongoDB collection name, so they
# are held to a strict allowlist (applied to new registrations).
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


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


def is_valid_username(name):
    """Return True if ``name`` is a valid username (strict allowlist)."""
    return bool(
        isinstance(name, str)
        and name != ""
        and ".." not in name
        and _USERNAME_RE.match(name)
    )
