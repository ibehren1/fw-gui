from unittest.mock import Mock, call, patch

import paramiko
import pytest

from package.host_key_store import HostKeyMismatch
from package.napalm_ssh_functions import (
    assemble_paramiko_driver_string,
    commit_to_firewall,
    get_diffs_from_firewall,
    run_operational_command,
)
from package.napalm_ssh_functions import test_connection as _test_connection


# Uses mock_session from conftest.py; also define specialized fixtures.

# The candidate configuration handed to NAPALM. Must be non-empty: both
# commit_to_firewall and get_diffs_from_firewall return early on a falsy
# value, before the driver is assembled.
MERGE_CONFIG = "set firewall ipv4 name FOO rule 10 action accept"


@pytest.fixture
def connection_string():
    return {
        "hostname": "192.168.1.1",
        "port": 22,
        "username": "admin",
        "password": "secret",
    }


@pytest.fixture
def connection_string_with_key():
    return {
        "hostname": "192.168.1.1",
        "port": 22,
        "username": "admin",
        "password": "keypassphrase",
        "ssh_key_name": "test_key.pem",
    }


@pytest.fixture
def op_command():
    return "show interfaces"


@pytest.fixture
def session():
    return {
        "data_dir": "/tmp/test",
        "username": "testuser",
        "hostname": "192.168.1.1",
        "port": 22,
        "firewall_name": "test_fw",
    }


# Test assemble_paramiko_driver_string
def test_assemble_paramiko_driver_string_password(connection_string, session):
    with (
        patch("paramiko.SSHClient") as mock_ssh,
        patch("package.napalm_ssh_functions.verify_host_key") as mock_verify,
        patch("package.napalm_ssh_functions.add_to_host_keys") as mock_add,
    ):
        ssh_instance = Mock()
        mock_ssh.return_value = ssh_instance
        host_key = Mock()
        mock_verify.return_value = host_key

        ssh, tmp_key = assemble_paramiko_driver_string(connection_string, session)

        assert tmp_key is None
        mock_verify.assert_called_once_with(session, "192.168.1.1", 22)
        mock_add.assert_called_once_with(
            ssh_instance.get_host_keys.return_value, "192.168.1.1", 22, host_key
        )
        # Only the verified key is trusted; anything else is rejected.
        (policy,), _ = ssh_instance.set_missing_host_key_policy.call_args
        assert isinstance(policy, paramiko.RejectPolicy)
        ssh_instance.connect.assert_called_with(
            connection_string["hostname"],
            port=connection_string["port"],
            username=connection_string["username"],
            password=connection_string["password"],
        )


def test_assemble_paramiko_driver_string_with_key(connection_string_with_key, session):
    with (
        patch("paramiko.SSHClient") as mock_ssh,
        patch("package.napalm_ssh_functions.verify_host_key"),
        patch("package.napalm_ssh_functions.add_to_host_keys"),
        patch("package.napalm_ssh_functions.decrypt_ssh_key") as mock_decrypt,
    ):
        ssh_instance = Mock()
        mock_ssh.return_value = ssh_instance
        mock_decrypt.return_value = "/tmp/decrypted_key"

        ssh, tmp_key = assemble_paramiko_driver_string(
            connection_string_with_key, session
        )

        assert tmp_key == "/tmp/decrypted_key"
        ssh_instance.connect.assert_called_with(
            connection_string_with_key["hostname"],
            port=connection_string_with_key["port"],
            username=connection_string_with_key["username"],
            key_filename="/tmp/decrypted_key",
        )


def test_assemble_paramiko_host_key_mismatch_never_connects(
    connection_string, session
):
    """A changed host key aborts before credentials are sent or keys decrypted."""
    with (
        patch("paramiko.SSHClient") as mock_ssh,
        patch(
            "package.napalm_ssh_functions.verify_host_key",
            side_effect=HostKeyMismatch("changed"),
        ),
    ):
        with pytest.raises(HostKeyMismatch):
            assemble_paramiko_driver_string(connection_string, session)

        mock_ssh.return_value.connect.assert_not_called()


# Test commit_to_firewall
def test_commit_to_firewall_success(connection_string, session):
    with patch(
        "package.napalm_ssh_functions.assemble_napalm_driver_string"
    ) as mock_assemble:
        mock_driver = Mock()
        mock_assemble.return_value = (mock_driver, [])
        mock_driver.compare_config.return_value = "Config differences"
        mock_driver.commit_config.return_value = None

        result = commit_to_firewall(connection_string, session, MERGE_CONFIG)

        assert "Config differences" in result
        assert "Commit successful" in result
        mock_driver.open.assert_called_once()
        mock_driver.load_merge_candidate.assert_called_once_with(
            config=MERGE_CONFIG
        )
        mock_driver.commit_config.assert_called_once()
        mock_driver.close.assert_called_once()


def test_commit_to_firewall_no_changes(connection_string, session):
    with patch(
        "package.napalm_ssh_functions.assemble_napalm_driver_string"
    ) as mock_assemble:
        mock_driver = Mock()
        mock_assemble.return_value = (mock_driver, [])
        mock_driver.compare_config.return_value = ""

        result = commit_to_firewall(connection_string, session, MERGE_CONFIG)

        assert result == "No configuration changes to commit."
        mock_driver.discard_config.assert_called_once()


# Test get_diffs_from_firewall
def test_get_diffs_from_firewall_with_changes(connection_string, session):
    with patch(
        "package.napalm_ssh_functions.assemble_napalm_driver_string"
    ) as mock_assemble:
        mock_driver = Mock()
        mock_assemble.return_value = (mock_driver, [])
        mock_driver.compare_config.return_value = "Config differences"

        result = get_diffs_from_firewall(connection_string, session, MERGE_CONFIG)

        assert result == "Config differences"
        mock_driver.open.assert_called_once()
        mock_driver.load_merge_candidate.assert_called_once_with(
            config=MERGE_CONFIG
        )
        mock_driver.discard_config.assert_called_once()
        mock_driver.close.assert_called_once()


# Test run_operational_command
def test_run_operational_command_success(connection_string, session, op_command):
    with patch(
        "package.napalm_ssh_functions.assemble_paramiko_driver_string"
    ) as mock_assemble:
        mock_ssh = Mock()
        mock_stdout = Mock()
        mock_stderr = Mock()
        mock_stdout.read.return_value = b"Firewall usage stats"
        mock_stderr.read.return_value = b""
        mock_ssh.exec_command.return_value = (Mock(), mock_stdout, mock_stderr)
        mock_assemble.return_value = (mock_ssh, None)

        result = run_operational_command(connection_string, session, op_command)

        assert result == "Firewall usage stats"
        mock_ssh.exec_command.assert_called_once()
        mock_ssh.close.assert_called_once()


# Test cleanup of temporary key files
def test_temporary_key_cleanup(connection_string_with_key, session):
    with (
        patch(
            "package.napalm_ssh_functions.assemble_napalm_driver_string"
        ) as mock_assemble,
        patch("os.remove") as mock_remove,
    ):
        mock_driver = Mock()
        mock_assemble.return_value = (mock_driver, ["/tmp/known_hosts", "/tmp/temp_key"])
        mock_driver.compare_config.return_value = ""

        commit_to_firewall(connection_string_with_key, session, MERGE_CONFIG)

        assert mock_remove.call_args_list == [
            call("/tmp/known_hosts"),
            call("/tmp/temp_key"),
        ]


# Test assemble_napalm_driver_string
STRICT_ARGS = {
    "ssh_strict": True,
    "alt_host_keys": True,
    "alt_key_file": "/tmp/known_hosts",
}


@pytest.fixture
def pinned_host_key():
    """Stubs host key verification and the staged known_hosts file."""
    with (
        patch("package.napalm_ssh_functions.verify_host_key") as mock_verify,
        patch(
            "package.napalm_ssh_functions.write_known_hosts",
            return_value="/tmp/known_hosts",
        ) as mock_write,
    ):
        yield mock_verify, mock_write


def test_assemble_napalm_driver_string_password(
    connection_string, session, pinned_host_key
):
    mock_verify, mock_write = pinned_host_key
    with patch("package.napalm_ssh_functions.get_network_driver") as mock_get_driver:
        mock_driver_class = Mock()
        mock_get_driver.return_value = mock_driver_class

        from package.napalm_ssh_functions import assemble_napalm_driver_string

        driver, tmpfiles = assemble_napalm_driver_string(connection_string, session)

        assert tmpfiles == ["/tmp/known_hosts"]
        mock_verify.assert_called_once_with(session, "192.168.1.1", 22)
        mock_write.assert_called_once_with(
            "192.168.1.1", 22, mock_verify.return_value
        )
        mock_get_driver.assert_called_with("vyos")
        mock_driver_class.assert_called_with(
            hostname="192.168.1.1",
            username="admin",
            password="secret",
            optional_args={"port": 22, "conn_timeout": 120, **STRICT_ARGS},
        )


def test_assemble_napalm_driver_string_with_key(
    connection_string_with_key, session, pinned_host_key
):
    with (
        patch("package.napalm_ssh_functions.get_network_driver") as mock_get_driver,
        patch("package.napalm_ssh_functions.decrypt_ssh_key") as mock_decrypt,
    ):
        mock_driver_class = Mock()
        mock_get_driver.return_value = mock_driver_class
        mock_decrypt.return_value = "/tmp/decrypted_key"

        from package.napalm_ssh_functions import assemble_napalm_driver_string

        driver, tmpfiles = assemble_napalm_driver_string(
            connection_string_with_key, session
        )

        assert tmpfiles == ["/tmp/known_hosts", "/tmp/decrypted_key"]
        # Looked up by account and key name, not by a data_dir path.
        mock_decrypt.assert_called_once_with(
            "testuser", "test_key.pem", b"keypassphrase"
        )
        mock_driver_class.assert_called_with(
            hostname="192.168.1.1",
            username="admin",
            password="",
            optional_args={
                "port": 22,
                "conn_timeout": 120,
                **STRICT_ARGS,
                "key_file": "/tmp/decrypted_key",
            },
        )


def test_assemble_napalm_driver_string_cleans_up_on_decrypt_failure(
    connection_string_with_key, session, pinned_host_key
):
    """The caller never receives tmpfiles on failure, so assembly removes them."""
    with (
        patch("package.napalm_ssh_functions.get_network_driver"),
        patch(
            "package.napalm_ssh_functions.decrypt_ssh_key",
            side_effect=ValueError("bad fernet key"),
        ),
        patch("os.remove") as mock_remove,
    ):
        from package.napalm_ssh_functions import assemble_napalm_driver_string

        with pytest.raises(ValueError):
            assemble_napalm_driver_string(connection_string_with_key, session)

        mock_remove.assert_called_once_with("/tmp/known_hosts")


def test_commit_to_firewall_host_key_mismatch(app, connection_string, session):
    with app.test_request_context():
        with patch(
            "package.napalm_ssh_functions.assemble_napalm_driver_string",
            side_effect=HostKeyMismatch("Host key for 192.168.1.1:22 has changed"),
        ):
            result = commit_to_firewall(connection_string, session, MERGE_CONFIG)

            assert "Host key verification failed" in result
            assert "has changed" in result


def test_get_diffs_host_key_probe_unreachable(app, connection_string, session):
    with app.test_request_context():
        with patch(
            "package.napalm_ssh_functions.assemble_napalm_driver_string",
            side_effect=ConnectionRefusedError("refused"),
        ):
            result = get_diffs_from_firewall(connection_string, session, MERGE_CONFIG)

            assert "Could not read the firewall's SSH host key" in result


def test_run_operational_command_host_key_mismatch(app, connection_string, session):
    with app.test_request_context():
        with patch(
            "package.napalm_ssh_functions.assemble_paramiko_driver_string",
            side_effect=HostKeyMismatch("Host key for 192.168.1.1:22 has changed"),
        ):
            result = run_operational_command(
                connection_string, session, "show interfaces"
            )

            assert "Host key verification failed" in result


# Test test_connection
def test_test_connection_success(app):
    session = {"hostname": "127.0.0.1", "port": "22"}
    with app.test_request_context():
        with patch("package.napalm_ssh_functions.socket.socket") as mock_socket:
            mock_sock_instance = Mock()
            mock_socket.return_value = mock_sock_instance

            result = _test_connection(session)

            assert result is True
            mock_sock_instance.connect.assert_called_once_with(("127.0.0.1", 22))


def test_test_connection_failure(app):
    session = {"hostname": "192.168.1.1", "port": "22"}
    with app.test_request_context():
        with patch("socket.socket") as mock_socket:
            mock_sock_instance = Mock()
            mock_socket.return_value = mock_sock_instance
            mock_sock_instance.connect.side_effect = Exception("Connection refused")

            result = _test_connection(session)

            assert result is False


def test_commit_to_firewall_driver_error(app, connection_string, session):
    with app.test_request_context():
        with patch(
            "package.napalm_ssh_functions.assemble_napalm_driver_string"
        ) as mock_assemble:
            mock_assemble.side_effect = Exception("Auth failed")

            result = commit_to_firewall(connection_string, session, MERGE_CONFIG)

            assert "Authentication failure" in result


def test_get_diffs_driver_error(app, connection_string, session):
    with app.test_request_context():
        with patch(
            "package.napalm_ssh_functions.assemble_napalm_driver_string"
        ) as mock_assemble:
            mock_assemble.side_effect = Exception("Auth failed")

            result = get_diffs_from_firewall(connection_string, session, MERGE_CONFIG)

            assert "Authentication failure" in result


def test_run_operational_command_rejects_non_show(app, connection_string, session):
    """A non-show / metacharacter command is rejected before any SSH connect."""
    with app.test_request_context():
        with patch(
            "package.napalm_ssh_functions.assemble_paramiko_driver_string"
        ) as mock_assemble:
            result = run_operational_command(
                connection_string, session, "show version; reboot"
            )

            assert "Only 'show ...'" in result
            mock_assemble.assert_not_called()


def test_run_operational_command_error(app, connection_string, session):
    with app.test_request_context():
        with patch(
            "package.napalm_ssh_functions.assemble_paramiko_driver_string"
        ) as mock_assemble:
            mock_assemble.side_effect = Exception("Connection failed")

            result = run_operational_command(
                connection_string, session, "show interfaces"
            )

            assert "Connection failed" in result


def test_get_diffs_no_changes(connection_string, session):
    with patch(
        "package.napalm_ssh_functions.assemble_napalm_driver_string"
    ) as mock_assemble:
        mock_driver = Mock()
        mock_assemble.return_value = (mock_driver, [])
        mock_driver.compare_config.return_value = ""

        result = get_diffs_from_firewall(connection_string, session, MERGE_CONFIG)

        assert result == "No configuration changes to commit."
        mock_driver.discard_config.assert_called_once()


def test_commit_to_firewall_empty_merge_config(connection_string, session):
    """An empty candidate must not reach NAPALM or open a connection.

    napalm-vyos raises MergeConfigException for a falsy config, which the broad
    except would surface as a red "Error in diff" banner. Reachable whenever
    every command is commented out -- the seeded extra-items placeholder is three
    comment lines.
    """
    with patch(
        "package.napalm_ssh_functions.assemble_napalm_driver_string"
    ) as mock_assemble:
        result = commit_to_firewall(connection_string, session, "")

        assert "No configuration commands to send" in result
        mock_assemble.assert_not_called()


def test_get_diffs_from_firewall_empty_merge_config(connection_string, session):
    """Same guard on the diff path."""
    with patch(
        "package.napalm_ssh_functions.assemble_napalm_driver_string"
    ) as mock_assemble:
        result = get_diffs_from_firewall(connection_string, session, "")

        assert "No configuration commands to send" in result
        mock_assemble.assert_not_called()


def test_napalm_vyos_forwards_strict_host_key_args():
    """napalm-vyos drops optional_args it does not whitelist; these must survive."""
    from napalm import get_network_driver

    driver = get_network_driver("vyos")(
        hostname="192.168.1.1",
        username="admin",
        password="secret",
        optional_args={"port": 22, **STRICT_ARGS},
    )

    for name, value in STRICT_ARGS.items():
        assert driver.netmiko_optional_args[name] == value
