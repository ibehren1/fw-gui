"""
    Napalm Functions
"""

from flask import flash
from napalm import get_network_driver
import socket


def get_diffs_from_firewall(connection_string, session):
    driver = get_network_driver("vyos")

    print("Configuring driver")

    vyos_router = driver(
        hostname=connection_string["hostname"],
        username=connection_string["username"],
        password=connection_string["password"],
        optional_args={"port": connection_string["port"]},
    )

    print("Opening connection")

    vyos_router.open()
    vyos_router.load_merge_candidate(
        filename=f'{session["data_dir"]}/{session["firewall_name"]}.conf'
    )

    print("Comparing configuration")
    diffs = vyos_router.compare_config()

    vyos_router.discard_config()
    vyos_router.close()

    if bool(diffs) == True:
        print(diffs)

        return diffs

    else:

        return "No configuration changes to commit."


def commit_to_firewall(connection_string, session):
    driver = get_network_driver("vyos")

    print("Configuring driver")

    vyos_router = driver(
        hostname=connection_string["hostname"],
        username=connection_string["username"],
        password=connection_string["password"],
        optional_args={"port": connection_string["port"]},
    )

    print("Opening connection")

    vyos_router.open()
    vyos_router.load_merge_candidate(
        filename=f'{session["data_dir"]}/{session["firewall_name"]}.conf'
    )

    print("Comparing configuration")
    diffs = vyos_router.compare_config()

    if bool(diffs) == True:
        print(diffs)
        print("Committing configuration")
        commit = vyos_router.commit_config()
    else:
        print("No configuration changes to commit")
        vyos_router.discard_config()

    print("Closing connection")
    vyos_router.close()

    return commit


def test_connection(session):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
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
