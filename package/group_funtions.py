"""
    Group Support functions.
"""
from package.data_file_functions import read_user_data_file, write_user_data_file
from flask import flash


def add_group_to_data(session, request):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    ip_version = request.form["ip_version"]
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
    if "group-name" not in user_data[ip_version]["groups"]:
        user_data[ip_version]["groups"][group_name] = {}

    # Assign values into data structure
    user_data[ip_version]["groups"][group_name]["group_desc"] = group_desc
    user_data[ip_version]["groups"][group_name]["group_type"] = group_type
    user_data[ip_version]["groups"][group_name]["group_value"] = group_value_list

    # print(json.dumps(user_data, indent=4))

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"Group {group_name} added.", "success")

    return


def assemble_list_of_groups(session):
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
    except:
        pass

    # If there are no groups, flash message
    if group_list == []:
        flash(f"There are no groups defined.", "danger")

    return group_list


def delete_group_from_data(session, request):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    group = request.form["group"].split(",")
    ip_version = group[0]
    group_name = group[1]

    # Delete group from data
    try:
        del user_data[ip_version]["groups"][group_name]
        flash(f"Deleted group {group_name} from table {ip_version}.", "warning")
    except:
        flash(f"Failed to delete group {group_name} from table {ip_version}.", "danger")
        pass

    # Clean-up data
    try:
        if len(user_data[ip_version]["groups"]) == 0:
            del user_data[ip_version]["groups"]
        if len(user_data[ip_version]) == 0:
            del user_data[ip_version]
    except:
        pass

    # Write user's data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    return
