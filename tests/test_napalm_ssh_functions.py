from pathlib import Path
from unittest.mock import Mock, patch

import paramiko
import pytest

from package.config_import import MAX_IMPORT_BYTES, ConfigImportError
from package.host_key_store import HostKeyMismatch
from package.napalm_ssh_functions import (
    RUNNING_CONFIG_COMMAND,
    assemble_paramiko_driver_string,
    commit_to_firewall,
    fetch_running_config,
    get_diffs_from_firewall,
    run_operational_command,
)
from package.napalm_ssh_functions import test_connection as _test_connection


# Uses mock_session from conftest.py; also define specialized fixtures.

# The candidate configuration for a config session. Must be non-empty: both
# commit_to_firewall and get_diffs_from_firewall return early on a falsy
# value, before connecting.
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


# Test the config import's fetch
def test_assemble_paramiko_given_host_key_skips_pin_lookup(connection_string, session):
    """The import connects before its config exists: the probed key is used as is."""
    with (
        patch("paramiko.SSHClient") as mock_ssh,
        patch("package.napalm_ssh_functions.verify_host_key") as mock_verify,
        patch("package.napalm_ssh_functions.add_to_host_keys") as mock_add,
    ):
        ssh_instance = mock_ssh.return_value
        host_key = Mock()

        assemble_paramiko_driver_string(connection_string, session, host_key=host_key)

        mock_verify.assert_not_called()
        mock_add.assert_called_once_with(
            ssh_instance.get_host_keys.return_value, "192.168.1.1", 22, host_key
        )
        (policy,), _ = ssh_instance.set_missing_host_key_policy.call_args
        assert isinstance(policy, paramiko.RejectPolicy)


def _fetch_ssh(stdout=b"", stderr=b""):
    mock_ssh = Mock()
    mock_stdin, mock_stdout, mock_stderr = Mock(), Mock(), Mock()
    mock_stdout.read.return_value = stdout
    mock_stderr.read.return_value = stderr
    mock_ssh.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)
    return mock_ssh, mock_stdin


def test_fetch_running_config_runs_fixed_command_and_never_logs_output(
    connection_string, session, caplog
):
    secret_config = '{"firewall": {}, "interfaces": {"wireguard": {"private-key": "SECRET"}}}'
    mock_ssh, mock_stdin = _fetch_ssh(stdout=secret_config.encode())
    host_key = Mock()
    with patch(
        "package.napalm_ssh_functions.assemble_paramiko_driver_string",
        return_value=(mock_ssh, None),
    ) as mock_assemble:
        caplog.set_level("DEBUG")
        result = fetch_running_config(connection_string, session, host_key)

    assert result == secret_config
    mock_assemble.assert_called_once_with(connection_string, session, host_key=host_key)
    script = mock_stdin.write.call_args.args[0]
    assert f"run {RUNNING_CONFIG_COMMAND}\n" in script
    assert RUNNING_CONFIG_COMMAND == "show configuration json"
    assert "SECRET" not in caplog.text
    mock_ssh.close.assert_called_once()


def test_fetch_running_config_empty_output_reports_stderr(connection_string, session):
    mock_ssh, _ = _fetch_ssh(stderr=b"Invalid command")
    with patch(
        "package.napalm_ssh_functions.assemble_paramiko_driver_string",
        return_value=(mock_ssh, None),
    ):
        with pytest.raises(ConfigImportError, match="Invalid command"):
            fetch_running_config(connection_string, session, Mock())
    mock_ssh.close.assert_called_once()


def test_fetch_running_config_too_large(connection_string, session):
    mock_ssh, _ = _fetch_ssh(stdout=b"x" * (MAX_IMPORT_BYTES + 1))
    with patch(
        "package.napalm_ssh_functions.assemble_paramiko_driver_string",
        return_value=(mock_ssh, None),
    ):
        with pytest.raises(ConfigImportError, match="too large"):
            fetch_running_config(connection_string, session, Mock())


def test_fetch_running_config_removes_decrypted_key(connection_string_with_key, session):
    mock_ssh, _ = _fetch_ssh(stdout=b"{}")
    with (
        patch(
            "package.napalm_ssh_functions.assemble_paramiko_driver_string",
            return_value=(mock_ssh, "/tmp/decrypted_key"),
        ),
        patch("os.remove") as mock_remove,
    ):
        fetch_running_config(connection_string_with_key, session, Mock())
    mock_remove.assert_called_once_with("/tmp/decrypted_key")


# Test View Diffs / Commit config sessions
FIXTURES = Path(__file__).parent / "fixtures" / "config_session"
FIXED_MARKER = "@@FWGUI-0123456789abcdef"
SUCCESS_OUTPUT = "\n".join([
    f"{FIXED_MARKER} L 1",
    f"{FIXED_MARKER} COMPARE",
    "[firewall ipv4 name]",
    "+ FOO {",
    "+ }",
    f"{FIXED_MARKER} COMMIT",
    f"{FIXED_MARKER} SAVE",
    "Saving configuration to '/config/config.boot'...",
    "Done",
    f"{FIXED_MARKER} END",
])


def _fixture(name):
    return (FIXTURES / f"{name}.txt").read_text()


def _fixture_config(name):
    return (FIXTURES / f"{name}.lines").read_text().strip()


@pytest.fixture
def device(app):
    """A Paramiko session whose vbash prints `device.output`."""
    mock_ssh, mock_stdin, mock_stdout = Mock(), Mock(), Mock()
    mock_ssh.exec_command.return_value = (mock_stdin, mock_stdout, Mock())
    state = Mock(output="", ssh=mock_ssh, stdin=mock_stdin, tmpfile=None)
    mock_stdout.read.side_effect = lambda: state.output.encode()
    with (
        app.test_request_context(),
        patch("package.napalm_ssh_functions.new_marker", return_value=FIXED_MARKER),
        patch(
            "package.napalm_ssh_functions.assemble_paramiko_driver_string",
            side_effect=lambda *a, **k: (mock_ssh, state.tmpfile),
        ) as assemble,
        patch("os.remove") as remove,
    ):
        state.assemble, state.remove = assemble, remove
        yield state


def test_commit_success(device, connection_string, session):
    device.output = SUCCESS_OUTPUT
    result = commit_to_firewall(connection_string, session, MERGE_CONFIG)
    assert result.endswith("Commit successful.")
    assert "+ FOO {" in result
    script = device.stdin.write.call_args.args[0]
    assert MERGE_CONFIG in script
    assert "  commit >" in script
    device.ssh.exec_command.assert_called_once_with("vbash -s", timeout=600)
    device.ssh.close.assert_called_once()


def test_commit_no_changes(device, connection_string, session):
    device.output = _fixture("commit_no_changes")
    result = commit_to_firewall(connection_string, session, _fixture_config("commit_no_changes"))
    assert result == "No configuration changes to commit."


def test_commit_rejected_line_reports_it_and_commits_nothing(device, connection_string, session):
    device.output = _fixture("commit_line_error")
    result = commit_to_firewall(connection_string, session, _fixture_config("commit_line_error"))
    assert result.startswith("The firewall rejected 1 line; nothing was committed.")
    assert "Line 2: set firewall ipv4 nosuchnode foo" in result
    assert "is not valid" in result
    assert "Commit successful" not in result


def test_commit_validation_failure(device, connection_string, session):
    device.output = _fixture("commit_validation_fails")
    result = commit_to_firewall(
        connection_string, session, _fixture_config("commit_validation_fails"))
    assert "Commit failed; nothing was committed." in result
    assert "Invalid jump-target" in result


def test_diff_reports_rejected_lines_and_accepted_diff(device, connection_string, session):
    device.output = _fixture("diff_mixed")
    result = get_diffs_from_firewall(connection_string, session, _fixture_config("diff_mixed"))
    assert result.startswith("The firewall rejected 3 lines.")
    assert "Line 5: bogusverb firewall foo" in result
    assert "The accepted lines would change:\n[firewall ipv4 name]" in result
    script = device.stdin.write.call_args.args[0]
    assert "commit" not in script.split("compare", 1)[1]


def test_diff_with_changes(device, connection_string, session):
    device.output = SUCCESS_OUTPUT.split(f"{FIXED_MARKER} COMMIT")[0] + f"{FIXED_MARKER} END\n"
    result = get_diffs_from_firewall(connection_string, session, MERGE_CONFIG)
    assert result == "[firewall ipv4 name]\n+ FOO {\n+ }"


def test_diff_no_changes(device, connection_string, session):
    device.output = _fixture("commit_no_changes").replace(" NO_CHANGES", " DISCARD")
    result = get_diffs_from_firewall(connection_string, session, "delete firewall ipv4 name X")
    assert result == "No configuration changes to commit."


def test_session_cut_short(device, connection_string, session):
    device.output = f"{FIXED_MARKER} L 1\n"
    result = commit_to_firewall(connection_string, session, MERGE_CONFIG)
    assert "ended the session before it finished" in result


def test_unsafe_line_is_never_sent(device, connection_string, session):
    result = commit_to_firewall(
        connection_string, session, "set firewall ipv4 name A description 'x'\nset x foo; reboot")
    assert result.startswith("Nothing was sent: line 2 contains the shell operator ';'")
    device.assemble.assert_not_called()


def test_session_removes_decrypted_key(device, connection_string_with_key, session):
    device.output = SUCCESS_OUTPUT
    device.tmpfile = "/tmp/decrypted_key"
    commit_to_firewall(connection_string_with_key, session, MERGE_CONFIG)
    device.remove.assert_called_once_with("/tmp/decrypted_key")


@pytest.mark.parametrize("error, message", [
    (HostKeyMismatch("Host key for 192.168.1.1:22 has changed"), "Host key verification failed"),
    (paramiko.AuthenticationException("no"), "Authentication failure"),
    (ConnectionRefusedError("refused"), "Could not connect to the firewall"),
    (KeyError("missing key"), "Authentication failure"),
])
@pytest.mark.parametrize("action", [commit_to_firewall, get_diffs_from_firewall])
def test_connection_errors(app, connection_string, session, error, message, action):
    with app.test_request_context(), patch(
        "package.napalm_ssh_functions.assemble_paramiko_driver_string", side_effect=error
    ):
        assert message in action(connection_string, session, MERGE_CONFIG)


def test_connection_drop_during_session(device, connection_string, session):
    device.ssh.exec_command.side_effect = paramiko.SSHException("channel closed")
    result = commit_to_firewall(connection_string, session, MERGE_CONFIG)
    assert "connection failed during the session" in result
    device.ssh.close.assert_called_once()


@pytest.mark.parametrize("action", [commit_to_firewall, get_diffs_from_firewall])
def test_empty_merge_config_never_connects(connection_string, session, action):
    """Every command commented out (the seeded extra-items placeholder is three
    comment lines) leaves nothing to send: no connection, no red banner."""
    with patch(
        "package.napalm_ssh_functions.assemble_paramiko_driver_string"
    ) as mock_assemble:
        result = action(connection_string, session, "")
    assert "No configuration commands to send" in result
    mock_assemble.assert_not_called()
