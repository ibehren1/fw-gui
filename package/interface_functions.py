"""
Interface Support Functions

This module provides functions for managing network interface data in a firewall configuration system.
It handles adding, deleting and listing interface configurations using a JSON-based data store.
"""

import logging

from flask import flash

from package.data_file_functions import read_user_data_file, write_user_data_file


# Interface types, shown colour-coded wherever an interface appears. Display
# only: the type is never written to the generated VyOS configuration.
INTERFACE_TYPES = {
    "public_wan": "Public WAN",
    "private_wan": "Private WAN",
    "lan": "LAN",
    "dmz": "DMZ",
    "custom": "Custom",
}
# Colours a custom type may use. Chosen to stay clear of the built-in types
# (red, orange, green, yellow) and the IPv4/IPv6 colours (teal, violet).
CUSTOM_TYPE_COLORS = ("blue", "pink", "brown", "gray")
CUSTOM_LABEL_MAX = 24


def interface_type_fields(form):
    """
    Returns the validated type fields from a posted interface form.

    Args:
        form: request.form with interface_type, and for custom types
              type_label and type_color

    Returns:
        dict: {} for no type, {"type": ...} for a built-in type, or
              {"type": "custom", "type_label": ..., "type_color": ...}.
              Unknown values are dropped rather than stored.
    """
    interface_type = form.get("interface_type", "")
    if interface_type not in INTERFACE_TYPES:
        return {}
    if interface_type != "custom":
        return {"type": interface_type}
    label = " ".join(form.get("type_label", "").split())[:CUSTOM_LABEL_MAX] or "Custom"
    color = form.get("type_color", "")
    if color not in CUSTOM_TYPE_COLORS:
        color = CUSTOM_TYPE_COLORS[0]
    return {"type": "custom", "type_label": label, "type_color": color}


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
    user_data = read_user_data_file(f"{session['data_dir']}/{session['firewall_name']}")

    # Set local vars from posted form data
    interface_name = request.form["interface_name"].replace(" ", "")
    interface_desc = request.form["interface_desc"]

    # Capture list of interfaces and remove from user_data
    if "interfaces" in user_data:
        interface_list = user_data["interfaces"]
        del user_data["interfaces"]
    else:
        interface_list = []

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
    new_interface.update(interface_type_fields(request.form))
    user_data["interfaces"].append(new_interface)

    # Write user_data to file
    write_user_data_file(f"{session['data_dir']}/{session['firewall_name']}", user_data)

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
    user_data = read_user_data_file(f"{session['data_dir']}/{session['firewall_name']}")

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
    write_user_data_file(f"{session['data_dir']}/{session['firewall_name']}", user_data)

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
    user_data = read_user_data_file(f"{session['data_dir']}/{session['firewall_name']}")

    if "interfaces" not in user_data:
        interface_list = []
    else:
        interface_list = user_data["interfaces"]

    interface_list.sort(key=lambda x: x["name"])

    logging.debug(f"Interface list: {interface_list}")

    return interface_list
