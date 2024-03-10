"""
    Interface Support Functions
"""

from flask import flash
from package.data_file_functions import read_user_data_file, write_user_data_file
import logging


def add_interface_to_data(session, request):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    interface_name = request.form["interface_name"].replace(" ", "")
    interface_desc = request.form["interface_desc"]

    # Check and create higher level data structure if it does not exist
    if "interfaces" not in user_data:
        user_data["interfaces"] = []

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
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    if "interfaces" not in user_data:
        interface_list = []
    else:
        interface_list = user_data["interfaces"]

    interface_list.sort(key=lambda x: x["name"])

    logging.debug(f"Interface list: {interface_list}")

    return interface_list
