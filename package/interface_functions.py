"""
    Interface Support Functions

    This module provides functions for managing network interface data in a firewall configuration system.
    It handles adding, deleting and listing interface configurations using a JSON-based data store.
"""

from flask import flash
from package.data_file_functions import read_user_data_file, write_user_data_file
import logging


def add_interface_to_data(session, request):
    """
    Adds a new interface configuration to the user's data file.

    Args:
        session: Flask session object containing data directory and firewall name
        request: Flask request object containing form data with interface name and description

    Returns:
        None. Updates data file and displays success message.
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    logging.debug(user_data["interfaces"])

    # Set local vars from posted form data
    interface_name = request.form["interface_name"].replace(" ", "")
    interface_desc = request.form["interface_desc"]

    # Capture list of interfaces and remove from user_data
    interface_list = user_data["interfaces"]
    del user_data["interfaces"]

    # Create higher level data structure if it does not exist
    if "interfaces" not in user_data:
        user_data["interfaces"] = []

    for interface in interface_list:
        if interface["name"] != interface_name:
            user_data["interfaces"].append(interface)

    # Assign values into data structure
    new_interface = {}
    new_interface["name"] = interface_name
    new_interface["description"] = interface_desc
    user_data["interfaces"].append(new_interface)

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"Interface {interface_name} added.", "success")

    return


def delete_interface_from_data(session, request):
    """
    Deletes an interface configuration from the user's data file.

    Args:
        session: Flask session object containing data directory and firewall name
        request: Flask request object containing form data with interface name to delete

    Returns:
        None. Updates data file and displays success message.
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    interface_name = request.form["interface"]

    interface_list = user_data["interfaces"]
    logging.debug(f"Interface list: {interface_list}")

    new_interface_list = []

    for interface in interface_list:
        if interface["name"] != interface_name:
            new_interface_list.append(interface)

    logging.debug(f"New Interface list: {new_interface_list}")

    user_data["interfaces"] = new_interface_list

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"Interface {interface_name} deleted.", "success")

    return


def list_interfaces(session):
    """
    Retrieves sorted list of interface configurations from user's data file.

    Args:
        session: Flask session object containing data directory and firewall name

    Returns:
        list: Sorted list of interface dictionaries, each containing name and description.
              Returns empty list if no interfaces exist.
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    if "interfaces" not in user_data:
        interface_list = []
    else:
        interface_list = user_data["interfaces"]

    interface_list.sort(key=lambda x: x["name"])

    logging.debug(f"Interface list: {interface_list}")

    return interface_list
