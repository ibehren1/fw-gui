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

from package.ssh_key_store import decrypt_ssh_key
from package.telemetry_functions import (
    telemetry_commit,
    telemetry_diff,
    telemetry_rule_usage,
)
from package.validators import is_allowed_op_command


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
        # The "password" field carries the user's Fernet key on this path, not a
        # login password.
        key = connection_string["password"].encode("utf-8")
        tmp_key_name = decrypt_ssh_key(
            session["username"], connection_string["ssh_key_name"], key
        )
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

    # Never log the password / Fernet key.
    logging.debug(
        {k: v for k, v in connection_string.items() if k != "password"}
    )

    if "ssh_key_name" in connection_string:
        logging.info("key")
        # The "password" field carries the user's Fernet key on this path, not a
        # login password.
        key = connection_string["password"].encode("utf-8")
        tmp_key_name = decrypt_ssh_key(
            session["username"], connection_string["ssh_key_name"], key
        )
        # If connect fails the caller never receives tmp_key_name, so remove
        # the decrypted key here rather than leaving it staged on disk.
        try:
            ssh.connect(
                hostname, port=port, username=username, key_filename=tmp_key_name
            )
        except Exception:
            os.remove(tmp_key_name)
            raise
    else:
        logging.info("no_key")
        tmp_key_name = None
        ssh.connect(hostname, port=port, username=username, password=password)

    return ssh, tmp_key_name


def commit_to_firewall(connection_string, session, merge_config):
    """
    Commits configuration changes to the VyOS firewall.

    Args:
        connection_string (dict): Connection parameters
        session (dict): Session data including hostname, port and data_dir (the
            latter for the SSH key, not for any configuration file)
        merge_config (str): Set commands to merge, from build_merge_config()

    Returns:
        str: Result message indicating success or failure
    """
    logging.debug(" |------------------------------------------")
    telemetry_commit()

    # Guard before the driver is assembled: an empty candidate means no SSH
    # connection, no key decryption and nothing staged in data/tmp to clean up.
    # napalm-vyos treats a falsy config as a caller error and raises
    # MergeConfigException, which the broad except below would surface as a red
    # "Error in diff" banner -- misleading for a config that simply has nothing
    # to send (every rule commented out, say). Deliberately after the telemetry
    # call so commit counts stay comparable to previous releases.
    if not merge_config:
        logging.info(" |--X No configuration commands to send; skipping connection.")
        return "No configuration commands to send.  Add rules or extra configuration items first."

    try:
        driver, tmpfile = assemble_napalm_driver_string(connection_string, session)
    except Exception as e:
        tmpfile = None
        logging.info(f" |--X Error assembling NAPALM driver: {e}")
        flash(f"Error: {e}", "danger")
        return f"Authentication failure!\n{e}\n\nIf using SSH key, suggest uploading again and saving your encryption key."

    logging.debug(f" |--> Connecting to: {session['hostname']}:{session['port']}")
    logging.debug(" |--> Configuring driver")

    vyos_router = driver

    logging.debug(" |--> Opening connection")

    try:
        vyos_router.open()
        vyos_router.load_merge_candidate(config=merge_config)

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
        return str(e)

    finally:
        # Delete key
        if tmpfile is not None:
            os.remove(tmpfile)
            logging.debug(f" |--> Deleted temporary key: {tmpfile}")
            logging.debug(" |-----------------------------------------")


def get_diffs_from_firewall(connection_string, session, merge_config):
    """
    Gets configuration differences between local and remote firewall configurations.

    Args:
        connection_string (dict): Connection parameters
        session (dict): Session data including hostname, port and data_dir (the
            latter for the SSH key, not for any configuration file)
        merge_config (str): Set commands to compare, from build_merge_config()

    Returns:
        str: Configuration differences or status message
    """
    logging.debug(" |------------------------------------------")
    telemetry_diff()

    # See commit_to_firewall for why this guard runs here, before the driver is
    # assembled and after the telemetry call.
    if not merge_config:
        logging.info(" |--X No configuration commands to send; skipping connection.")
        return "No configuration commands to send.  Add rules or extra configuration items first."

    try:
        driver, tmpfile = assemble_napalm_driver_string(connection_string, session)
    except Exception as e:
        tmpfile = None
        logging.info(f" |--X Error assembling NAPALM driver: {e}")
        flash(f"Error: {e}", "danger")
        return f"Authentication failure!\n{e}\n\nIf using SSH key, suggest uploading again and saving your encryption key."

    logging.debug(f" |--> Connecting to: {session['hostname']}:{session['port']}")
    logging.debug(" |--> Configuring driver")

    vyos_router = driver

    logging.debug(" |--> Opening connection")

    try:
        vyos_router.open()
        vyos_router.load_merge_candidate(config=merge_config)

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
        return str(e)

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

    # Only permit read-only "show ..." commands with no shell metacharacters.
    # This confines the feature to operational-mode inspection and prevents
    # shell/command injection into the vbash script below.
    if not is_allowed_op_command(op_command):
        logging.warning(f"Rejected operational command: {op_command!r}")
        flash("Only 'show ...' operational commands are permitted.", "danger")
        return "Only 'show ...' operational commands are permitted."

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

        # `vbash -s` reads the script from stdin; the command is validated
        # (show-only, no metacharacters) above. Do not pass the script as
        # command-line args.
        # B601 -- input validated; script fed via stdin only.
        stdin, stdout, stderr = ssh.exec_command("vbash -s")  # nosec
        stdin.write(command_string)
        stdin.flush()
        stdin.channel.shutdown_write()

        # Read the output
        output = stdout.read().decode()
        # error = stderr.read().decode()

        logging.debug(output)

        ssh.close()

        return output

    except Exception as e:
        logging.info(f" |--X Error: {e}")
        flash("Error connecting to host.  Inspect output and correct errors.", "danger")
        return str(e)

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
            f"Connection to {session['hostname']} on port {session['port']} validated!",
            "success",
        )
        return True
    except Exception:
        flash(
            f"Cannot connect to {session['hostname']} on port {session['port']}!",
            "danger",
        )
        return False
    finally:
        s.close()
