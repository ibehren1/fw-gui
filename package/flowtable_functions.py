"""
    Flowtable Functions - Module for managing flowtables in a firewall configuration

    This module provides functions to add, delete and list flowtables. A flowtable is a 
    data structure that contains a name, description and list of interfaces.

    Functions:
        add_flowtable_to_data: Adds a new flowtable entry to the user's data file
        delete_flowtable_from_data: Removes a flowtable entry from the user's data file 
        list_flowtables: Returns a sorted list of all flowtables for a user

    Data Structure:
        Flowtables are stored as a list of dictionaries in the user's data file:
        {
            "flowtables": [
                {
                    "name": "flowtable1",
                    "description": "Description text", 
                    "interfaces": ["interface1", "interface2"]
                }
            ]
        }
"""

from flask import flash
from package.data_file_functions import read_user_data_file, write_user_data_file
import logging


def add_flowtable_to_data(session, request):
    """
    Add a new flowtable to the user's data

    Args:
        session: Flask session object containing data_dir and firewall_name
        request: Flask request object containing form data with flowtable details

    Form fields expected:
        flowtable_name: Name of the flowtable (spaces will be removed)
        flowtable_desc: Description of the flowtable
        interface_*: One or more interface names to add to the flowtable

    Returns:
        None

    Side effects:
        - Creates flowtables list in user data if it doesn't exist
        - Adds new flowtable entry to user's data file
        - Displays success message via Flask flash
    """
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
    """
    Delete a flowtable from the user's data

    Args:
        session: Flask session object containing data_dir and firewall_name
        request: Flask request object containing form data with flowtable name

    Form fields expected:
        flowtable: Name of the flowtable to delete

    Returns:
        None

    Side effects:
        - Removes specified flowtable from user's data file
        - Displays success message via Flask flash
        - Logs debug messages about flowtable list changes
    """
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
    """
    Get a sorted list of all flowtables in the user's data

    Args:
        session: Flask session object containing data_dir and firewall_name

    Returns:
        list: List of flowtable dictionaries, sorted alphabetically by name.
             Returns empty list if no flowtables exist.

    Side effects:
        - Logs debug message with returned flowtable list

    Example return value:
        [
            {
                "name": "flowtable1",
                "description": "First flowtable",
                "interfaces": ["eth0", "eth1"]
            },
            {
                "name": "flowtable2",
                "description": "Second flowtable",
                "interfaces": ["eth2"]
            }
        ]
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    if "flowtables" not in user_data:
        flowtable_list = []
    else:
        flowtable_list = user_data["flowtables"]

    flowtable_list.sort(key=lambda x: x["name"])

    logging.debug(f"Flowtable list: {flowtable_list}")

    return flowtable_list
