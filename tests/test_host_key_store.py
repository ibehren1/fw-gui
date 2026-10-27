"""
Tests for package/host_key_store.py: trust-on-first-use pinning of the
firewall's SSH host key (GHSA-64wj-4f9q-rwr7).

The probe tests run a real Paramiko SSH server on localhost, so key exchange,
the known_hosts naming and RejectPolicy are exercised for real rather than
mocked.
"""

import os
import socket
import threading

import paramiko
import pytest

from package import host_key_store
from package.host_key_store import (
    HostKeyMismatch,
    add_to_host_keys,
    clear_pinned_key,
    fingerprint,
    get_pinned_fingerprint,
    get_pinned_key,
    pin_key,
    verify_host_key,
    write_known_hosts,
)

USER = "hostkeyuser"
FIREWALL = "fw1"


@pytest.fixture(scope="module")
def rsa_keys():
    # Two distinct server identities: the genuine firewall and an impostor.
    return paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)


@pytest.fixture
def session(mongo_client):
    collection = host_key_store.data_file_functions._get_mongo_db()[USER]
    collection.delete_many({})
    collection.insert_one(
        {"_id": FIREWALL, "system": {"hostname": "127.0.0.1", "port": "22"}}
    )
    yield {"data_dir": f"data/{USER}", "firewall_name": FIREWALL}
    collection.delete_many({})


class _RejectAllAuth(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED


class _SSHServer:
    """Accepts connections on localhost and completes key exchange with ``key``."""

    def __init__(self, key):
        self.key = key
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.transports = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(self.key)
            self.transports.append(transport)
            try:
                transport.start_server(server=_RejectAllAuth())
            except (paramiko.SSHException, EOFError, OSError):
                pass

    def close(self):
        self.sock.close()
        for transport in self.transports:
            transport.close()


@pytest.fixture
def ssh_server():
    servers = []

    def start(key):
        server = _SSHServer(key)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def test_fingerprint_matches_openssh_format(rsa_keys):
    fp = fingerprint(rsa_keys[0])
    assert fp.startswith("SHA256:")
    assert not fp.endswith("=")
    assert fp != fingerprint(rsa_keys[1])


def test_pin_round_trip(session, rsa_keys):
    assert get_pinned_key(session, "127.0.0.1", 22) is None
    assert get_pinned_fingerprint(session, "127.0.0.1", 22) is None

    pin_key(session, "127.0.0.1", 22, rsa_keys[0])

    assert get_pinned_key(session, "127.0.0.1", 22) == rsa_keys[0]
    assert get_pinned_fingerprint(session, "127.0.0.1", 22) == fingerprint(
        rsa_keys[0]
    )


def test_pin_leaves_rest_of_config_alone(session, rsa_keys):
    pin_key(session, "127.0.0.1", 22, rsa_keys[0])

    doc = host_key_store.data_file_functions._get_mongo_db()[USER].find_one(
        {"_id": FIREWALL}
    )
    assert doc["system"]["hostname"] == "127.0.0.1"
    assert doc["system"]["port"] == "22"


def test_pin_for_other_address_is_ignored(session, rsa_keys):
    pin_key(session, "127.0.0.1", 22, rsa_keys[0])

    assert get_pinned_key(session, "10.0.0.1", 22) is None
    assert get_pinned_key(session, "127.0.0.1", 2222) is None


def test_clear_pinned_key(session, rsa_keys):
    pin_key(session, "127.0.0.1", 22, rsa_keys[0])
    clear_pinned_key(session)

    assert get_pinned_key(session, "127.0.0.1", 22) is None


def test_first_connection_pins_presented_key(session, rsa_keys, ssh_server):
    server = ssh_server(rsa_keys[0])

    key = verify_host_key(session, "127.0.0.1", server.port)

    assert key == rsa_keys[0]
    assert get_pinned_key(session, "127.0.0.1", server.port) == rsa_keys[0]


def test_matching_key_is_accepted(session, rsa_keys, ssh_server):
    server = ssh_server(rsa_keys[0])
    pin_key(session, "127.0.0.1", server.port, rsa_keys[0])

    assert verify_host_key(session, "127.0.0.1", server.port) == rsa_keys[0]


def test_changed_key_is_rejected_and_pin_kept(session, rsa_keys, ssh_server):
    impostor = ssh_server(rsa_keys[1])
    pin_key(session, "127.0.0.1", impostor.port, rsa_keys[0])

    with pytest.raises(HostKeyMismatch) as excinfo:
        verify_host_key(session, "127.0.0.1", impostor.port)

    assert fingerprint(rsa_keys[0]) in str(excinfo.value)
    assert fingerprint(rsa_keys[1]) in str(excinfo.value)
    # The impostor's key must not replace the pin.
    assert get_pinned_key(session, "127.0.0.1", impostor.port) == rsa_keys[0]


def test_reset_then_reconnect_repins(session, rsa_keys, ssh_server):
    server = ssh_server(rsa_keys[1])
    pin_key(session, "127.0.0.1", server.port, rsa_keys[0])

    clear_pinned_key(session)

    assert verify_host_key(session, "127.0.0.1", server.port) == rsa_keys[1]
    assert get_pinned_key(session, "127.0.0.1", server.port) == rsa_keys[1]


def _connect_strict(host_keys_loader, port):
    client = paramiko.SSHClient()
    host_keys_loader(client)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            "127.0.0.1",
            port=port,
            username="admin",
            password="wrong",
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
        )
    finally:
        client.close()


def test_strict_client_accepts_pinned_key(rsa_keys, ssh_server):
    """Host key passes, so the connection gets as far as (failed) authentication."""
    server = ssh_server(rsa_keys[0])

    with pytest.raises(paramiko.AuthenticationException):
        _connect_strict(
            lambda c: add_to_host_keys(
                c.get_host_keys(), "127.0.0.1", server.port, rsa_keys[0]
            ),
            server.port,
        )


def test_strict_client_rejects_impostor(rsa_keys, ssh_server):
    """The authenticating connection refuses a key swapped in after the probe."""
    impostor = ssh_server(rsa_keys[1])

    with pytest.raises(paramiko.BadHostKeyException):
        _connect_strict(
            lambda c: add_to_host_keys(
                c.get_host_keys(), "127.0.0.1", impostor.port, rsa_keys[0]
            ),
            impostor.port,
        )


def test_known_hosts_file_is_what_netmiko_loads(rsa_keys, ssh_server):
    """netmiko's alt_key_file path: load_host_keys(file) + RejectPolicy."""
    server = ssh_server(rsa_keys[0])
    impostor = ssh_server(rsa_keys[1])

    path = write_known_hosts("127.0.0.1", server.port, rsa_keys[0])
    try:
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
        with pytest.raises(paramiko.AuthenticationException):
            _connect_strict(lambda c: c.load_host_keys(path), server.port)

        path_impostor = write_known_hosts("127.0.0.1", impostor.port, rsa_keys[0])
        try:
            with pytest.raises(paramiko.BadHostKeyException):
                _connect_strict(
                    lambda c: c.load_host_keys(path_impostor), impostor.port
                )
        finally:
            os.remove(path_impostor)
    finally:
        os.remove(path)


def test_probe_unreachable_raises_oserror():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    with pytest.raises(OSError):
        host_key_store.probe_host_key("127.0.0.1", port)
