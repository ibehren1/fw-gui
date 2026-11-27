"""
SSH functions to connect with VyOS firewalls

Every device connection uses Paramiko with the pinned host key enforced
(host_key_store): View Diffs and Commit (a vbash configure session, see
config_session), operational commands, and the config import's fetch. It
handles SSH key and password authentication and connection testing.

The module keeps its historical name; NAPALM was removed in 4.2.6.
"""

import logging
import os
import socket

import paramiko
from flask import flash
from cryptography.fernet import InvalidToken

from package.config_import import MAX_IMPORT_BYTES, ConfigImportError
from package.config_session import (
    build_script,
    command_lines,
    describe_errors,
    new_marker,
    parse_output,
    unsafe_reason,
)
from package.host_key_store import (
    HostKeyMismatch,
    add_to_host_keys,
    verify_host_key,
)
from package.ssh_key_store import decrypt_ssh_key
from package.telemetry_functions import (
    telemetry_commit,
    telemetry_diff,
    telemetry_rule_usage,
)
from package.validators import is_allowed_op_command


def assemble_paramiko_driver_string(connection_string, session, host_key=None):
    """
    Creates a Paramiko SSH client instance for connecting to a VyOS device.

    Args:
        connection_string (dict): Connection parameters including hostname, port, credentials
        session (dict): Session data including data directory path
        host_key (paramiko.PKey): Key the device must present. When given, the
            pinned key of the session's config is not consulted (or set): the
            config import connects before its config exists and pins the key
            itself. Either way RejectPolicy refuses any other key.

    Returns:
        tuple: (Paramiko SSH client instance, temporary key file path if using SSH key auth)

    Raises:
        HostKeyMismatch: If the device's host key differs from the pinned one.
    """
    hostname = connection_string["hostname"]
    port = connection_string["port"]
    username = connection_string["username"]
    password = connection_string["password"]

    # Only the verified (or just-pinned) key is loaded, and RejectPolicy refuses
    # anything else, so the authenticating connection cannot be swapped for an
    # impostor after the probe.
    if host_key is None:
        host_key = verify_host_key(session, hostname, port)
    ssh = paramiko.SSHClient()
    add_to_host_keys(ssh.get_host_keys(), hostname, port, host_key)
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

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
                hostname, port=int(port), username=username, key_filename=tmp_key_name
            )
        except Exception:
            os.remove(tmp_key_name)
            raise
    else:
        logging.info("no_key")
        tmp_key_name = None
        ssh.connect(hostname, port=int(port), username=username, password=password)

    return ssh, tmp_key_name


# A commit of a large rule set can take minutes; give up on a silent device.
CONFIG_SESSION_TIMEOUT = 600


class _SessionError(Exception):
    """A config session could not run; the message is shown as the result."""


def _run_config_session(connection_string, session, merge_config, commit):
    """
    Runs a View Diffs (commit=False) or Commit session on the firewall.

    Returns:
        dict: config_session.parse_output's result.

    Raises:
        _SessionError: A line cannot be sent safely, or the connection failed.
            The danger flash is already raised.
    """
    lines = command_lines(merge_config)
    for number, line in enumerate(lines, start=1):
        reason = unsafe_reason(line)
        if reason:
            flash("A configuration line cannot be sent.  Correct it and try again.", "danger")
            raise _SessionError(
                f"Nothing was sent: line {number} {reason}.\n\n    {line}"
            )

    try:
        ssh, tmpfile = assemble_paramiko_driver_string(connection_string, session)
    except HostKeyMismatch as e:
        logging.info(f" |--X {e}")
        flash(str(e), "danger")
        raise _SessionError(f"Host key verification failed!\n{e}") from None
    except (paramiko.AuthenticationException, InvalidToken) as e:
        logging.info(f" |--X Authentication failed: {type(e).__name__}")
        flash("Authentication failure.", "danger")
        raise _SessionError(
            "Authentication failure!\n\nIf using SSH key, suggest uploading again "
            "and saving your encryption key."
        ) from None
    except (OSError, paramiko.SSHException) as e:
        # Unreachable host, no SSH key exchange (the host key probe), ...
        logging.info(f" |--X Error connecting: {e}")
        flash(f"Error: {e}", "danger")
        raise _SessionError(f"Could not connect to the firewall.\n{e}") from None
    except Exception as e:
        # A missing stored key, a bad key file, ...
        logging.info(f" |--X Error connecting: {type(e).__name__}: {e}")
        flash(f"Error: {e}", "danger")
        raise _SessionError(
            f"Authentication failure!\n{e}\n\nIf using SSH key, suggest uploading "
            "again and saving your encryption key."
        ) from None

    marker = new_marker()
    try:
        logging.info(
            f"Config session ({'commit' if commit else 'diff'}): {len(lines)} lines "
            f"to {connection_string['hostname']}."
        )
        # B601 -- the script is built by config_session from checked lines and
        # fed via stdin only.
        stdin, stdout, _ = ssh.exec_command(  # nosec
            "vbash -s", timeout=CONFIG_SESSION_TIMEOUT
        )
        stdin.write(build_script(lines, marker, commit))
        stdin.flush()
        stdin.channel.shutdown_write()
        output = stdout.read().decode("utf-8", errors="replace")
    except (OSError, paramiko.SSHException) as e:
        logging.info(f" |--X Session error: {e}")
        flash("The connection to the firewall failed during the session.", "danger")
        raise _SessionError(
            f"The connection failed during the session; check the firewall.\n{e}"
        ) from None
    finally:
        ssh.close()
        if tmpfile is not None:
            os.remove(tmpfile)
            logging.debug(f" |--> Deleted temporary key: {tmpfile}")

    logging.debug(output)
    result = parse_output(output, marker, lines)
    if not result["complete"]:
        flash("The firewall ended the session early.  Inspect output.", "danger")
        raise _SessionError(
            "The firewall ended the session before it finished; check the firewall."
            f"\n\n{output.strip()}"
        )
    return result


def _rejected(result, committing):
    flash("Error in diff.  Inspect output and correct errors.", "danger")
    count = len(result["errors"])
    head = f"The firewall rejected {count} line{'s' if count != 1 else ''}"
    head += "; nothing was committed." if committing else "."
    text = f"{head}\n\n{describe_errors(result['errors'])}"
    if result["diff"]:
        text += f"\n\nThe accepted lines would change:\n{result['diff']}"
    return text


def commit_to_firewall(connection_string, session, merge_config):
    """
    Commits configuration changes to the VyOS firewall.

    The lines are applied in one configure session; it is committed and saved
    only if the firewall accepted every line and there are changes, and a
    failed commit is discarded (see config_session).

    Args:
        connection_string (dict): Connection parameters
        session (dict): Session data including hostname, port and data_dir (the
            latter for the SSH key, not for any configuration file)
        merge_config (str): Set commands to merge, from build_merge_config()

    Returns:
        str: Result message indicating success or failure
    """
    telemetry_commit()

    # Guard before connecting: an empty candidate means no SSH connection and
    # no key decryption. Deliberately after the telemetry call so commit counts
    # stay comparable to previous releases.
    if not merge_config:
        logging.info(" |--X No configuration commands to send; skipping connection.")
        return "No configuration commands to send.  Add rules or extra configuration items first."

    try:
        result = _run_config_session(connection_string, session, merge_config, commit=True)
    except _SessionError as e:
        return str(e)

    if result["errors"]:
        return _rejected(result, committing=True)
    if result["commit_error"]:
        flash("Commit failed.  Inspect output and correct errors.", "danger")
        return (
            f"{result['diff']}\n\nCommit failed; nothing was committed.\n\n"
            f"{result['commit_error']}"
        )
    if not result["diff"]:
        return "No configuration changes to commit."
    if result["committed"]:
        return f"{result['diff']}\n\nCommit successful."
    flash("The commit result is unknown.  Inspect the firewall.", "danger")
    return f"{result['diff']}\n\nThe commit result is unknown; check the firewall."


def get_diffs_from_firewall(connection_string, session, merge_config):
    """
    Gets configuration differences between local and remote firewall configurations.

    The lines are applied in a configure session that is always discarded.

    Args:
        connection_string (dict): Connection parameters
        session (dict): Session data including hostname, port and data_dir (the
            latter for the SSH key, not for any configuration file)
        merge_config (str): Set commands to compare, from build_merge_config()

    Returns:
        str: Configuration differences or status message
    """
    telemetry_diff()

    # See commit_to_firewall for why this guard runs here.
    if not merge_config:
        logging.info(" |--X No configuration commands to send; skipping connection.")
        return "No configuration commands to send.  Add rules or extra configuration items first."

    try:
        result = _run_config_session(connection_string, session, merge_config, commit=False)
    except _SessionError as e:
        return str(e)

    if result["errors"]:
        return _rejected(result, committing=False)
    return result["diff"] or "No configuration changes to commit."


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

    except HostKeyMismatch as e:
        logging.info(f" |--X {e}")
        flash(str(e), "danger")
        return f"Host key verification failed!\n{e}"

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


# The whole configuration, as JSON. A fixed command: nothing user-supplied
# reaches the vbash script.
RUNNING_CONFIG_COMMAND = "show configuration json"


def fetch_running_config(connection_string, session, host_key):
    """
    Fetches the device's running configuration for the config import.

    Args:
        connection_string (dict): Connection parameters, as for the push page
        session (dict): Session data; username for a stored SSH key
        host_key (paramiko.PKey): Key the device must present (probed by the
            caller, pinned on the new config after a successful import)

    Returns:
        str: `show configuration json` output.

    Raises:
        ConfigImportError: No output, or more than MAX_IMPORT_BYTES.
        Exception: Connection and authentication errors, unchanged.

    The output is the whole configuration, secrets included (WireGuard private
    keys, password hashes), so unlike run_operational_command it is never
    logged; config_import keeps only the firewall and interface parts.
    """
    ssh, tmpfile = assemble_paramiko_driver_string(
        connection_string, session, host_key=host_key
    )
    try:
        logging.info(f"Fetching running config from {connection_string['hostname']}.")
        script = "\n".join([
            "source /opt/vyatta/etc/functions/script-template",
            f"run {RUNNING_CONFIG_COMMAND}",
            "exit",
        ]) + "\n"
        # B601 -- fixed script, fed via stdin only.
        stdin, stdout, stderr = ssh.exec_command("vbash -s")  # nosec
        stdin.write(script)
        stdin.flush()
        stdin.channel.shutdown_write()

        output = stdout.read(MAX_IMPORT_BYTES + 1).decode("utf-8", errors="replace")
        if len(output) > MAX_IMPORT_BYTES:
            raise ConfigImportError("The device configuration is too large to import.")
        if not output.strip():
            error = stderr.read(4096).decode("utf-8", errors="replace").strip()
            raise ConfigImportError(
                f"The device returned no configuration{': ' + error if error else '.'}"
            )
        return output
    finally:
        ssh.close()
        if tmpfile is not None:
            os.remove(tmpfile)
            logging.debug(f" |--> Deleted temporary key: {tmpfile}")


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
