"""
Napalm & Paramiko Functions to connect with VyOS Firewall

This module provides functions for connecting to and managing VyOS firewalls using both
the NAPALM and Paramiko libraries. It handles SSH key and password authentication,
configuration management, and connection testing.
"""

import logging
import os
import socket

import paramiko
from flask import flash
from napalm import get_network_driver

from package.data_file_functions import decrypt_file
from package.telemetry_functions import (
    telemetry_commit,
    telemetry_diff,
    telemetry_rule_usage,
)


def assemble_napalm_driver_string(connection_string, session):
    """
    Creates a NAPALM driver instance for connecting to a VyOS device.

    Args:
        connection_string (dict): Connection parameters including hostname, port, credentials
        session (dict): Session data including data directory path

    Returns:
        tuple: (NAPALM driver instance, temporary key file path if using SSH key auth)
    """
    driver = get_network_driver("vyos")
    optional_args = {"port": connection_string["port"], "conn_timeout": 120}

    if "ssh_key_name" in connection_string:
        key = connection_string["password"].encode("utf-8")
        key_name = f'{session["data_dir"]}/{connection_string["ssh_key_name"]}'
        tmp_key_name = decrypt_file(key_name, key)
        optional_args["key_file"] = tmp_key_name

        return (
            # B106 -- Not a hardcoded password.
            driver(
                hostname=connection_string["hostname"],
                username=connection_string["username"],
                password="",
                optional_args=optional_args,
            ),  # nosec
            tmp_key_name,
        )

    else:
        return (
            driver(
                hostname=connection_string["hostname"],
                username=connection_string["username"],
                password=connection_string["password"],
                optional_args=optional_args,
            ),
            None,
        )


def assemble_paramiko_driver_string(connection_string, session):
    """
    Creates a Paramiko SSH client instance for connecting to a VyOS device.

    Args:
        connection_string (dict): Connection parameters including hostname, port, credentials
        session (dict): Session data including data directory path

    Returns:
        tuple: (Paramiko SSH client instance, temporary key file path if using SSH key auth)
    """
    # B507 -- Purposely allowing trust of the unknown host key
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec

    hostname = connection_string["hostname"]
    port = connection_string["port"]
    username = connection_string["username"]
    password = connection_string["password"]

    logging.debug(connection_string)

    if "ssh_key_name" in connection_string:
        logging.info("key")
        key = connection_string["password"].encode("utf-8")
        key_name = f'{session["data_dir"]}/{connection_string["ssh_key_name"]}'
        tmp_key_name = decrypt_file(key_name, key)
        ssh.connect(hostname, port=port, username=username, key_filename=tmp_key_name)
    else:
        logging.info("no_key")
        tmp_key_name = None
        ssh.connect(hostname, port=port, username=username, password=password)

    return ssh, tmp_key_name


def commit_to_firewall(connection_string, session):
    """
    Commits configuration changes to the VyOS firewall.

    Args:
        connection_string (dict): Connection parameters
        session (dict): Session data including firewall configuration file path

    Returns:
        str: Result message indicating success or failure
    """
    logging.debug(" |------------------------------------------")
    telemetry_commit()

    try:
        driver, tmpfile = assemble_napalm_driver_string(connection_string, session)
    except Exception:
        tmpfile = None
        flash("Authentication error. Cannot unencrypt your SSH key.", "danger")
        return "Authentication failure!\nCannot unencrypt your SSH key.\n\nSuggest uploading again and saving your encryption key."

    logging.debug(f' |--> Connecting to: {session["hostname"]}:{session["port"]}')
    logging.debug(" |--> Configuring driver")

    vyos_router = driver

    logging.debug(" |--> Opening connection")

    try:
        vyos_router.open()
        vyos_router.load_merge_candidate(
            filename=f'{session["data_dir"]}/{session["firewall_name"]}.conf'
        )

        logging.debug(" |--> Comparing configuration")
        diffs = vyos_router.compare_config()

        if bool(diffs) is True:
            logging.debug(" |--> Committing configuration")
            commit = vyos_router.commit_config()

            logging.debug(" |--> Connection closed.\n |")
            vyos_router.close()

            if commit is None:
                return str(diffs + "Commit successful.")
            else:
                return str(diffs + commit)

        else:
            logging.debug(" |--> No configuration changes to commit")
            vyos_router.discard_config()

            logging.debug(" |--> Connection closed.")
            vyos_router.close()
            return "No configuration changes to commit."

    except Exception as e:
        logging.info(f" |--X Error: {e}")
        flash("Error in diff.  Inspect output and correct errors.", "danger")
        return e

    finally:
        # Delete key
        if tmpfile is not None:
            os.remove(tmpfile)
            logging.debug(f" |--> Deleted temporary key: {tmpfile}")
            logging.debug(" |-----------------------------------------")


def get_diffs_from_firewall(connection_string, session):
    """
    Gets configuration differences between local and remote firewall configurations.

    Args:
        connection_string (dict): Connection parameters
        session (dict): Session data including firewall configuration file path

    Returns:
        str: Configuration differences or status message
    """
    logging.debug(" |------------------------------------------")
    telemetry_diff()

    try:
        driver, tmpfile = assemble_napalm_driver_string(connection_string, session)
    except Exception:
        tmpfile = None
        flash("Authentication error. Cannot unencrypt your SSH key.", "danger")
        return "Authentication failure!\nCannot unencrypt your SSH key.\n\nSuggest uploading again and saving your encryption key."

    logging.debug(f' |--> Connecting to: {session["hostname"]}:{session["port"]}')
    logging.debug(" |--> Configuring driver")

    vyos_router = driver

    logging.debug(" |--> Opening connection")

    try:
        vyos_router.open()
        vyos_router.load_merge_candidate(
            filename=f'{session["data_dir"]}/{session["firewall_name"]}.conf'
        )

        logging.debug(" |--> Comparing configuration")
        diffs = vyos_router.compare_config()

        vyos_router.discard_config()
        vyos_router.close()
        logging.debug(" |--> Connection closed.")

        if bool(diffs) is True:
            return diffs
        else:
            return "No configuration changes to commit."

    except Exception as e:
        logging.info(f" |--X Error: {e}")
        flash("Error in diff.  Inspect output and correct errors.", "danger")
        return e

    finally:
        # Delete key
        if tmpfile is not None:
            os.remove(tmpfile)
            logging.debug(f" |--> Deleted temporary key: {tmpfile}")
            logging.debug(" |------------------------------------------")


# Uses Paramiko rather than Napalm
def run_operational_command(connection_string, session, op_command):
    """
    Shows current firewall usage statistics using Paramiko SSH client.

    Args:
        connection_string (dict): Connection parameters
        session (dict): Session data

    Returns:
        str: Firewall usage output or error message
    """
    logging.debug(" |------------------------------------------")
    telemetry_rule_usage()

    tmpfile = None
    try:
        ssh, tmpfile = assemble_paramiko_driver_string(connection_string, session)

        logging.info(f"Op Command: '{op_command}'")
        commands = [
            "source /opt/vyatta/etc/functions/script-template",
            f"run {op_command}",
            "exit",
        ]

        command_string = "\n".join(commands) + "\n"

        # B601 -- no shell injection
        stdin, stdout, stderr = ssh.exec_command(f"vbash -s {command_string}")  # nosec
        stdin.write(command_string)
        stdin.flush()
        stdin.channel.shutdown_write()

        # Read the output
        output = stdout.read().decode()
        # error = stderr.read().decode()

        logging.info(output)

        ssh.close()

        return output

    except Exception as e:
        logging.info(f" |--X Error: {e}")
        flash("Error connecting to host.  Inspect output and correct errors.", "danger")
        return e

    finally:
        # Delete key
        if tmpfile is not None:
            os.remove(tmpfile)
            logging.debug(f" |--> Deleted temporary key: {tmpfile}")
            logging.debug(" |------------------------------------------")


def test_connection(session):
    """
    Tests TCP connection to the firewall.

    Args:
        session (dict): Session data including hostname and port

    Returns:
        bool: True if connection successful, False otherwise
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(20)
        s.connect((session["hostname"], int(session["port"])))
        s.shutdown(2)
        flash(
            f'Connection to {session["hostname"]} on port {session["port"]} validated!',
            "success",
        )
        return True
    except Exception:
        flash(
            f'Cannot connect to {session["hostname"]} on port {session["port"]}!',
            "danger",
        )
        return False
