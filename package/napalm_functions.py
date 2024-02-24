"""
    Napalm Functions to connect with VyOS Firewall
"""

from flask import flash
from napalm import get_network_driver
from package.data_file_functions import decrypt_file
import socket
import os


def assemble_driver_string(connection_string, session):

    driver = get_network_driver("vyos")
    optional_args = {"port": connection_string["port"], "conn_timeout": 120}

    if "ssh_key_name" in connection_string:
        key = connection_string["password"].encode("utf-8")
        key_name = f'{session["data_dir"]}/{connection_string["ssh_key_name"]}'
        tmp_key_name = decrypt_file(key_name, key)
        optional_args["key_file"] = tmp_key_name

        return (
            driver(
                hostname=connection_string["hostname"],
                username=connection_string["username"],
                password="",
                optional_args=optional_args,
            ),
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


def get_diffs_from_firewall(connection_string, session):

    try:
        driver, tmpfile = assemble_driver_string(connection_string, session)
    except Exception as e:
        tmpfile = None
        flash("Authentication error. Cannot unencrypt your SSH key.", "danger")
        return "Authentication failure!\nCannot unencrypt your SSH key.\n\nSuggest uploading again and saving your encryption key."

    print(f' |\n |--> Connecting to: {session["hostname"]}:{session["port"]}')
    print(" |--> Configuring driver")

    vyos_router = driver

    print(" |--> Opening connection")

    try:
        vyos_router.open()
        vyos_router.load_merge_candidate(
            filename=f'{session["data_dir"]}/{session["firewall_name"]}.conf'
        )

        print(" |--> Comparing configuration")
        diffs = vyos_router.compare_config()

        vyos_router.discard_config()
        vyos_router.close()
        print(" |--> Connection closed.\n |")

        if bool(diffs) is True:
            return diffs
        else:
            return "No configuration changes to commit."

    except Exception as e:
        print(f" |--X Error: {e}")
        flash("Error in diff.  Inspect output and correct errors.", "danger")
        print(" |")
        return e

    finally:
        # Delete key
        if tmpfile is None:
            os.remove(tmpfile)


def commit_to_firewall(connection_string, session):
    driver, tmpfile = assemble_driver_string(connection_string, session)

    print(f' |\n |--> Connecting to: {session["hostname"]}:{session["port"]}')
    print(" |--> Configuring driver")

    vyos_router = driver

    print(" |--> Opening connection")

    try:
        vyos_router.open()
        vyos_router.load_merge_candidate(
            filename=f'{session["data_dir"]}/{session["firewall_name"]}.conf'
        )

        print(" |--> Comparing configuration")
        diffs = vyos_router.compare_config()

        if bool(diffs) is True:
            print(" |--> Committing configuration")
            commit = vyos_router.commit_config()

            print(" |--> Connection closed.\n |")
            vyos_router.close()

            if commit is None:
                return str(diffs + "Commit successful.")
            else:
                return str(diffs + commit)

        else:
            print(" |--> No configuration changes to commit")
            vyos_router.discard_config()

            print(" |--> Connection closed.\n |")
            vyos_router.close()
            return "No configuration changes to commit."

    except Exception as e:
        print(f" |--X Error: {e}")
        flash("Error in diff.  Inspect output and correct errors.", "danger")
        print(" |")
        return e

    finally:
        # Delete key
        if tmpfile != None:
            os.remove(tmpfile)


def test_connection(session):
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
    except:
        flash(
            f'Cannot connect to {session["hostname"]} on port {session["port"]}!',
            "danger",
        )
        return False
