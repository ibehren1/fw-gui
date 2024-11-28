from napalm import get_network_driver
from package.napalm_ssh_functions import (
    assemble_napalm_driver_string,
    assemble_paramiko_driver_string,
    commit_to_firewall,
    get_diffs_from_firewall,
    show_firewall_usage,
)
from unittest.mock import Mock, patch, MagicMock
import os
import paramiko
import pytest


# Test fixtures
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
def session():
    return {
        "data_dir": "/tmp/test",
        "hostname": "192.168.1.1",
        "port": 22,
        "firewall_name": "test_fw",
    }


# TODO
# Test assemble_napalm_driver_string
# def test_assemble_napalm_driver_string_password(connection_string, session):
#     with patch("napalm.get_network_driver") as mock_driver:
#         mock_driver_instance = Mock()
#         mock_driver.return_value = mock_driver_instance

#         driver, tmp_key = assemble_napalm_driver_string(connection_string, session)

#         assert tmp_key is None
#         # mock_driver.assert_called_with("vyos")
#         mock_driver_instance.assert_called_with(
#             hostname=connection_string["hostname"],
#             username=connection_string["username"],
#             password=connection_string["password"],
#             optional_args={"port": connection_string["port"], "conn_timeout": 120},
#         )


# TODO
# def test_assemble_napalm_driver_string_with_key(connection_string_with_key, session):
#     with patch("napalm.get_network_driver") as mock_driver, patch(
#         "package.napalm_ssh_functions.decrypt_file"
#     ) as mock_decrypt:
#         mock_driver_instance = Mock()
#         mock_driver.return_value = mock_driver_instance
#         mock_decrypt.return_value = "/tmp/decrypted_key"

#         assert tmp_key == "/tmp/decrypted_key"
#         mock_decrypt.assert_called_once()
#         mock_driver_instance.assert_called_with(
#             hostname=connection_string_with_key["hostname"],
#             username=connection_string_with_key["username"],
#             password="",
#             optional_args={
#                 "port": connection_string_with_key["port"],
#                 "conn_timeout": 120,
#                 "key_file": "/tmp/decrypted_key",
#             },
#         )


# Test assemble_paramiko_driver_string
def test_assemble_paramiko_driver_string_password(connection_string, session):
    with patch("paramiko.SSHClient") as mock_ssh:
        ssh_instance = Mock()
        mock_ssh.return_value = ssh_instance

        ssh, tmp_key = assemble_paramiko_driver_string(connection_string, session)

        assert tmp_key is None
        ssh_instance.set_missing_host_key_policy.assert_called_once()
        ssh_instance.connect.assert_called_with(
            connection_string["hostname"],
            port=connection_string["port"],
            username=connection_string["username"],
            password=connection_string["password"],
        )


def test_assemble_paramiko_driver_string_with_key(connection_string_with_key, session):
    with patch("paramiko.SSHClient") as mock_ssh, patch(
        "package.napalm_ssh_functions.decrypt_file"
    ) as mock_decrypt:
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


# Test commit_to_firewall
def test_commit_to_firewall_success(connection_string, session):
    with patch(
        "package.napalm_ssh_functions.assemble_napalm_driver_string"
    ) as mock_assemble:
        mock_driver = Mock()
        mock_assemble.return_value = (mock_driver, None)
        mock_driver.compare_config.return_value = "Config differences"
        mock_driver.commit_config.return_value = None

        result = commit_to_firewall(connection_string, session)

        assert "Config differences" in result
        assert "Commit successful" in result
        mock_driver.open.assert_called_once()
        mock_driver.load_merge_candidate.assert_called_once()
        mock_driver.commit_config.assert_called_once()
        mock_driver.close.assert_called_once()


def test_commit_to_firewall_no_changes(connection_string, session):
    with patch(
        "package.napalm_ssh_functions.assemble_napalm_driver_string"
    ) as mock_assemble:
        mock_driver = Mock()
        mock_assemble.return_value = (mock_driver, None)
        mock_driver.compare_config.return_value = ""

        result = commit_to_firewall(connection_string, session)

        assert result == "No configuration changes to commit."
        mock_driver.discard_config.assert_called_once()


# Test get_diffs_from_firewall
def test_get_diffs_from_firewall_with_changes(connection_string, session):
    with patch(
        "package.napalm_ssh_functions.assemble_napalm_driver_string"
    ) as mock_assemble:
        mock_driver = Mock()
        mock_assemble.return_value = (mock_driver, None)
        mock_driver.compare_config.return_value = "Config differences"

        result = get_diffs_from_firewall(connection_string, session)

        assert result == "Config differences"
        mock_driver.open.assert_called_once()
        mock_driver.load_merge_candidate.assert_called_once()
        mock_driver.discard_config.assert_called_once()
        mock_driver.close.assert_called_once()


# Test show_firewall_usage
def test_show_firewall_usage_success(connection_string, session):
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

        result = show_firewall_usage(connection_string, session)

        assert result == "Firewall usage stats"
        mock_ssh.exec_command.assert_called_once()
        mock_ssh.close.assert_called_once()


# TODO
# def test_show_firewall_usage_error(connection_string, session):
#     with patch(
#         "package.napalm_ssh_functions.assemble_paramiko_driver_string"
#     ) as mock_assemble:
#         mock_assemble.side_effect = Exception("Connection failed")

#         result = show_firewall_usage(connection_string, session)

#         assert isinstance(result, Exception)
#         assert str(result) == "Connection failed"


# Test cleanup of temporary key files
def test_temporary_key_cleanup(connection_string_with_key, session):
    with patch(
        "package.napalm_ssh_functions.assemble_napalm_driver_string"
    ) as mock_assemble, patch("os.remove") as mock_remove:
        mock_driver = Mock()
        mock_assemble.return_value = (mock_driver, "/tmp/temp_key")
        mock_driver.compare_config.return_value = ""

        commit_to_firewall(connection_string_with_key, session)

        mock_remove.assert_called_once_with("/tmp/temp_key")
