"""
    Group Support functions.
    
    This module provides functions for managing firewall groups in a user's data.
    It includes functionality for adding, listing, and deleting groups.
"""

import logging

from flask import flash

from package.data_file_functions import read_user_data_file, write_user_data_file


def add_group_to_data(session, request):
    """
    Add a new group to the user's data.

    Args:
        session: Flask session object containing data directory and firewall name
        request: Flask request object containing form data for the new group

    The function:
    - Reads existing user data
    - Extracts group details from form (type, IP version, description, name, values)
    - Creates necessary data structures if they don't exist
    - Adds the new group data
    - Writes updated data back to file
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    group_type = request.form["group_type"]
    if group_type == "address-group" or group_type == "network-group":
        ip_version = request.form["ip_version"]
    else:
        ip_version = "ipv4"
    group_desc = request.form["group_desc"]
    group_name = request.form["group_name"].replace(" ", "")
    group_type = request.form["group_type"]
    group_value = request.form["group_value"]

    # Convert group values to list and trim any whitespace
    group_value_list = []
    for value in group_value.split(","):
        group_value_list.append(value.strip())

    # Check and create higher level data structure if it does not exist
    if ip_version not in user_data:
        user_data[ip_version] = {}
    if "groups" not in user_data[ip_version]:
        user_data[ip_version]["groups"] = {}
    if group_name not in user_data[ip_version]["groups"]:
        user_data[ip_version]["groups"][group_name] = {}

    # Assign values into data structure
    user_data[ip_version]["groups"][group_name]["group_desc"] = group_desc
    user_data[ip_version]["groups"][group_name]["group_type"] = group_type
    user_data[ip_version]["groups"][group_name]["group_value"] = group_value_list

    # logging.info(json.dumps(user_data, indent=4))

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"Group {group_name} added.", "success")

    return


def assemble_detail_list_of_groups(session):
    """
    Get a detailed list of all groups in the user's data.

    Args:
        session: Flask session object containing data directory and firewall name

    Returns:
        list: List of dictionaries containing detailed information about each group
              including IP version, name, description, type and values
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Create dict of defined groups
    group_list_detail = []
    try:
        for ip_version in ["ipv4", "ipv6"]:
            if ip_version in user_data:
                if "groups" in user_data[ip_version]:
                    for group_name in user_data[ip_version]["groups"]:
                        item = user_data[ip_version]["groups"][group_name]
                        group_list_detail.append(
                            {
                                "ip_version": ip_version,
                                "group_name": group_name,
                                "group_desc": item["group_desc"],
                                "group_type": item["group_type"],
                                "group_value": item["group_value"],
                            }
                        )
    except Exception as e:
        logging.info(e)

    # If there are no groups, flash message
    if group_list_detail == []:
        flash("There are no groups defined.", "danger")

    return group_list_detail


def assemble_list_of_groups(session):
    """
    Get a simple list of all groups in the user's data.

    Args:
        session: Flask session object containing data directory and firewall name

    Returns:
        list: List of [ip_version, group_name] pairs for each group
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Create list of defined groups
    group_list = []
    try:
        for ip_version in ["ipv4", "ipv6"]:
            if ip_version in user_data:
                if "groups" in user_data[ip_version]:
                    for group in user_data[ip_version]["groups"]:
                        group_list.append([ip_version, group])
    except Exception as e:
        logging.info(e)

    # If there are no groups, flash message
    if group_list == []:
        flash("There are no groups defined.", "danger")

    return group_list


def delete_group_from_data(session, request):
    """
    Delete a group from the user's data.

    Args:
        session: Flask session object containing data directory and firewall name
        request: Flask request object containing form data with group to delete

    The function:
    - Extracts group details from form
    - Removes the group from the data structure
    - Cleans up empty data structures
    - Writes updated data back to file
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    group = request.form["group"].split(",")
    ip_version = group[0]
    group_name = group[1]

    # Delete group from data
    try:
        del user_data[ip_version]["groups"][group_name]
        flash(f"Deleted group {group_name} from {ip_version}.", "warning")
    except Exception:
        flash(f"Failed to delete group {group_name} from {ip_version}.", "danger")
        pass

    # Clean-up data
    try:
        if not user_data[ip_version]["groups"]:
            del user_data[ip_version]["groups"]
        if not user_data[ip_version]:
            del user_data[ip_version]
    except Exception as e:
        logging.info(e)

    # Write user's data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    return
