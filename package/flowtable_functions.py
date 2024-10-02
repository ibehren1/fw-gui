"""
    Flowtable Functions
"""

from flask import flash
from package.data_file_functions import read_user_data_file, write_user_data_file
import logging


def add_flowtable_to_data(session, request):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    interface_list = []
    # Set local vars from posted form data
    for key, value in request.form.items():
        if key == "flowtable_name":
            flowtable_name = value.replace(" ", "")
        if key == "flowtable_desc":
            flowtable_desc = value
        if "interface_" in key:
            interface_list.append(value)

    # Check and create higher level data structure if it does not exist
    if "flowtables" not in user_data:
        user_data["flowtables"] = []

    # Assign values into data structure
    new_flowtable = {}
    new_flowtable["name"] = flowtable_name
    new_flowtable["description"] = flowtable_desc
    new_flowtable["interfaces"] = interface_list

    user_data["flowtables"].append(new_flowtable)

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"Flowtable {flowtable_name} added.", "success")

    return


def delete_flowtable_from_data(session, request):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    flowtable_name = request.form["flowtable"]

    flowtable_list = user_data["flowtables"]
    logging.debug(f"Flowtable list: {flowtable_list}")

    new_flowtable_list = []

    for flowtable in flowtable_list:
        if flowtable["name"] != flowtable_name:
            new_flowtable_list.append(flowtable)

    logging.debug(f"New Flowtable list: {new_flowtable_list}")

    user_data["flowtables"] = new_flowtable_list

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"Flowtable {flowtable_name} deleted.", "success")

    return


def list_flowtables(session):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    if "flowtables" not in user_data:
        flowtable_list = []
    else:
        flowtable_list = user_data["flowtables"]

    flowtable_list.sort(key=lambda x: x["name"])

    logging.debug(f"Flowtable list: {flowtable_list}")

    return flowtable_list
