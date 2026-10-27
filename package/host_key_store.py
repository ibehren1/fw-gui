"""
SSH Host Key Store

Each firewall config pins the SSH host key of the device it pushes to, in the
config's own MongoDB document under ``system.host_key``:

    {"host": "192.168.1.1:22",           # f"{hostname}:{port}" it was taken from
     "type": "ssh-ed25519",
     "key":  "<base64 public key>",
     "pinned": datetime}

Before 3.1.0 neither connection path checked the host key at all: Paramiko used
``AutoAddPolicy`` on a client that never loaded or saved keys, and napalm-vyos
left netmiko on its ``ssh_strict=False`` default, which is the same policy. Any
host on the network path could impersonate the firewall and collect the SSH
password or the configuration being pushed (GHSA-64wj-4f9q-rwr7).

The model is trust-on-first-use. The first connection to a hostname/port pins
whatever key the device presents; every later connection must present that same
key or is refused before authentication, so no credential is sent to an
impostor. The fingerprint is shown on the push page so the pin can be checked
against the device, and a key that legitimately changed (reinstall,
``generate ssh server-key``) is accepted again only after the user resets it.

The pin lives in the config document rather than a known_hosts file because the
container's filesystem holds no durable state. It is public key material, so it
riding along in snapshots, JSON downloads and backups exposes nothing. The
``host`` field ties the pin to the address it was taken from: a pin whose host no
longer matches the configured one is ignored, not enforced, so changing the
hostname re-pins instead of locking the user out.
"""

import base64
import hashlib
import logging
import os
import socket
import tempfile
from datetime import datetime, timezone

import paramiko

from package import data_file_functions

PROBE_TIMEOUT = 20


class HostKeyMismatch(paramiko.SSHException):
    """The device presented a host key other than the pinned one."""


def _locate(session):
    # data_dir format:  data/<user>; the collection is the user, the document
    # _id is the firewall name -- the same addressing as read_user_data_file.
    collection_name = session["data_dir"].split("/")[1]
    return (
        data_file_functions._get_mongo_db()[collection_name],
        session["firewall_name"],
    )


def _host_id(hostname, port):
    return f"{hostname}:{port}"


def fingerprint(key):
    """Returns the OpenSSH-style SHA256 fingerprint of a paramiko key."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def get_pinned_key(session, hostname, port):
    """Returns the pinned paramiko key for this firewall and address, or None."""
    collection, firewall = _locate(session)
    doc = collection.find_one({"_id": firewall}, {"system.host_key": 1})
    pin = ((doc or {}).get("system") or {}).get("host_key")
    if not pin or pin.get("host") != _host_id(hostname, port):
        return None
    return paramiko.PKey.from_type_string(pin["type"], base64.b64decode(pin["key"]))


def pin_key(session, hostname, port, key):
    """Pins ``key`` as the host key for this firewall and address."""
    collection, firewall = _locate(session)
    collection.update_one(
        {"_id": firewall},
        {
            "$set": {
                "system.host_key": {
                    "host": _host_id(hostname, port),
                    "type": key.get_name(),
                    "key": key.get_base64(),
                    "pinned": datetime.now(timezone.utc),
                }
            }
        },
    )
    logging.info(
        f"Pinned SSH host key {fingerprint(key)} for {_host_id(hostname, port)} "
        f"on firewall <{firewall}>."
    )


def clear_pinned_key(session):
    """Removes the pin, so the next connection trusts and pins afresh."""
    collection, firewall = _locate(session)
    collection.update_one({"_id": firewall}, {"$unset": {"system.host_key": ""}})
    logging.info(f"Cleared pinned SSH host key on firewall <{firewall}>.")


def get_pinned_fingerprint(session, hostname, port):
    """Returns the pinned key's fingerprint for display, or None if unpinned."""
    key = get_pinned_key(session, hostname, port)
    return fingerprint(key) if key is not None else None


def probe_host_key(hostname, port):
    """Completes an SSH key exchange only, and returns the server's host key.

    No authentication is attempted, so nothing secret is sent.
    """
    sock = socket.create_connection((hostname, int(port)), timeout=PROBE_TIMEOUT)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=PROBE_TIMEOUT)
        return transport.get_remote_server_key()
    finally:
        transport.close()


def verify_host_key(session, hostname, port):
    """Returns the host key the connection must present, pinning it on first use.

    Raises:
        HostKeyMismatch: If a key is pinned and the device presents another.

    The probe here is a separate TCP connection from the one that authenticates,
    so the caller must still enforce the returned key on its own connection
    (RejectPolicy with this key loaded); the probe only makes the mismatch error
    readable and supplies the key to pin.
    """
    presented = probe_host_key(hostname, port)
    pinned = get_pinned_key(session, hostname, port)

    if pinned is None:
        pin_key(session, hostname, port, presented)
        return presented

    if pinned != presented:
        logging.warning(
            f"SSH host key mismatch for {_host_id(hostname, port)}: pinned "
            f"{fingerprint(pinned)}, presented {fingerprint(presented)}."
        )
        raise HostKeyMismatch(
            f"Host key for {hostname}:{port} has changed (pinned {fingerprint(pinned)}, "
            f"presented {fingerprint(presented)}). This may be a man-in-the-middle "
            "attack; no credentials were sent. If the firewall's key changed "
            "legitimately, reset the pinned host key and connect again."
        )

    return pinned


def _known_host_names(hostname, port):
    # Paramiko looks the host up as the bare name on port 22 and as
    # "[host]:port" otherwise; write both so either lookup finds the key.
    return [hostname, f"[{hostname}]:{int(port)}"]


def add_to_host_keys(host_keys, hostname, port, key):
    """Adds ``key`` for this address to a paramiko HostKeys object."""
    for name in _known_host_names(hostname, port):
        host_keys.add(name, key.get_name(), key)


def write_known_hosts(hostname, port, key):
    """Stages a known_hosts file holding only ``key``, for netmiko.

    Returns:
        str: Path to the file; the caller must delete it in a ``finally`` block.

    Like decrypted SSH keys, it goes to the system temp dir, not data/.
    """
    host_keys = paramiko.HostKeys()
    add_to_host_keys(host_keys, hostname, port, key)
    fd, path = tempfile.mkstemp(prefix="fwgui-known-hosts-")
    os.close(fd)
    host_keys.save(path)
    return path
