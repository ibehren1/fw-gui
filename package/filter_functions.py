"""
    Filter Support Functions
"""
from package.data_file_functions import read_user_data_file, write_user_data_file
from flask import flash


def add_filter_rule_to_data(session, request):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Set local vars from posted form data
    rule = request.form["rule"]
    rule_dict = {}
    filter = request.form["filter"].split(",")
    ip_version = filter[0]
    rule_dict["ip_version"] = filter[0]
    rule_dict["filter"] = filter[1]
    filter = filter[1]
    jump_target = request.form["jump_target"].split(",")
    rule_dict["fw_table"] = jump_target[1]
    rule_dict["description"] = request.form["description"]
    if "rule_disable" in request.form:
        rule_dict["rule_disable"] = True
    if "logging" in request.form:
        rule_dict["log"] = True
    rule_dict["action"] = request.form["action"]
    rule_dict["interface"] = request.form["interface"]
    rule_dict["direction"] = request.form["direction"]

    # Check and create higher level data structure if it does not exist
    user_data[ip_version]["filters"][filter]["rules"] = {}

    # Add rule to data structure
    user_data[ip_version]["filters"][filter]["rules"][rule] = rule_dict

    # Add rule to rule-order in user data
    if rule not in user_data[ip_version]["filters"][filter]["rule-order"]:
        user_data[ip_version]["filters"][filter]["rule-order"].append(rule)

    # Sort rule-order in user data
    user_data[ip_version]["filters"][filter]["rule-order"] = sorted(
        user_data[ip_version]["filters"][filter]["rule-order"]
    )

    # print(json.dumps(user_data, indent=4))

    # Write user_data to file
    write_user_data_file(session["firewall_name"], user_data)

    flash(f"Rule {rule} added to table {ip_version}/{filter}.", "success")

    return


def add_filter_to_data(session, request):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    print(request.form)
    # Set local vars from posted form data
    ip_version = request.form["ip_version"]
    type = request.form["type"]
    description = request.form["description"]
    default_action = request.form["default_action"]
    if "logging" in request.form:
        log = request.form["logging"]
    else:
        log = False

    # Check and create higher level data structure if it does not exist
    if ip_version not in user_data:
        user_data[ip_version] = {}
    if "filters" not in user_data[ip_version]:
        user_data[ip_version]["filters"] = {}
    if type not in user_data[ip_version]["filters"]:
        user_data[ip_version]["filters"][type] = {}
        user_data[ip_version]["filters"][type]["rule-order"] = []

    # Add filter to data structure
    user_data[ip_version]["filters"][type]["description"] = description
    user_data[ip_version]["filters"][type]["default-action"] = default_action
    user_data[ip_version]["filters"][type]["log"] = log

    # Write user_data to file
    write_user_data_file(session["firewall_name"], user_data)

    flash(f"Filter {ip_version}/{type} added.", "success")

    return


def assemble_list_of_filters(session):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Create list of defined tables
    filter_list = []
    try:
        for ip_version in ["ipv4", "ipv6"]:
            if ip_version in user_data:
                for type in user_data[ip_version]["filters"]:
                    filter_list.append([ip_version, type])
    except:
        pass

    # If there are no tables, flash message
    if filter_list == []:
        flash(f"There are no filters defined.", "danger")

    return filter_list


def assemble_list_of_filter_rules(session):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Create list of defined rules
    rule_list = []
    try:
        for ip_version in ["ipv4", "ipv6"]:
            if ip_version in user_data:
                for filter in user_data[ip_version]["filters"]:
                    for rule in user_data[ip_version]["filters"][filter]["rule-order"]:
                        rule_list.append(
                            [
                                ip_version,
                                filter,
                                rule,
                                user_data[ip_version]["filters"][filter]["rules"][rule][
                                    "description"
                                ],
                            ]
                        )
    except:
        pass

    # If there are no rules, flash message
    if rule_list == []:
        flash(f"There are no filter rules defined.", "danger")

    return rule_list


def delete_filter_rule_from_data(session, request):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Set local vars from posted form data
    rule = request.form["rule"].split(",")
    ip_version = rule[0]
    filter = rule[1]
    rule = rule[2]

    # Delete rule from data
    try:
        del user_data[ip_version]["filters"][filter]["rules"][rule]
        user_data[ip_version]["filters"][filter]["rule-order"].remove(rule)
        flash(f"Deleted rule {rule} from filter {ip_version}/{filter}.", "warning")
    except:
        flash(
            f"Failed to delete rule {rule} from filter {ip_version}/{filter}.",
            "danger",
        )
        pass

    # Clean-up data
    try:
        if len(user_data[ip_version]["filters"][filter]["rule-order"]) == 0:
            del user_data[ip_version]["filters"][filter]
        if len(user_data[ip_version]["filters"]) == 0:
            del user_data[ip_version]["filters"]
        if len(user_data[ip_version]) == 0:
            del user_data[ip_version]
    except:
        pass

    # Write user's data to file
    write_user_data_file(session["firewall_name"], user_data)

    return
