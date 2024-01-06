"""
    Table Support functions.
"""
from package.data_file_functions import read_user_data_file, write_user_data_file
from flask import flash


# def add_default_rule(session, request):
#     # Get user's data
#     user_data = read_user_data_file(session["firewall_name"])

#     # Set local vars from posted form data
#     table = request.form["fw_table"].split(",")
#     ip_version = table[0]
#     fw_table = table[1]
#     description = request.form["description"]
#     default_action = request.form["default_action"]

#     # Check and create higher level data structure if it does not exist
#     if ip_version not in user_data:
#         user_data[ip_version] = {}
#         user_data[ip_version]["tables"] = {}
#     if fw_table not in user_data[ip_version]["tables"]:
#         user_data[ip_version]["tables"][fw_table] = {}
#     if "default" not in user_data[ip_version]["tables"][fw_table]:
#         user_data[ip_version]["tables"][fw_table]["default"] = {}

#     # Assign values into data structure
#     user_data[ip_version]["tables"][fw_table]["default"]["description"] = description
#     user_data[ip_version]["tables"][fw_table]["default"][
#         "default_action"
#     ] = default_action

#     # Write user_data to file
#     write_user_data_file(session["firewall_name"], user_data)

#     flash(f"Default action created for table {ip_version}/{fw_table}.", "success")

#     return


def add_rule_to_data(session, request):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Set local vars from posted form data
    table = request.form["fw_table"].split(",")
    ip_version = table[0]
    fw_table = table[1]

    # Check and create higher level data structure if it does not exist
    if ip_version not in user_data:
        user_data[ip_version] = {}
        user_data[ip_version]["tables"] = {}
    if fw_table not in user_data[ip_version]["tables"]:
        user_data[ip_version]["tables"][fw_table] = {}
    if "rule-order" not in user_data[ip_version]["tables"][fw_table]:
        user_data[ip_version]["tables"][fw_table]["rule-order"] = []

    # Assemble rule dict
    rule = request.form["rule"]
    rule_dict = {}
    rule_dict["description"] = request.form["description"]
    if "rule_disable" in request.form:
        rule_dict["rule_disable"] = True
    if "logging" in request.form:
        rule_dict["logging"] = True
    rule_dict["action"] = request.form["action"]
    rule_dict["dest_address"] = request.form["dest_address"]
    rule_dict["dest_address_type"] = request.form["dest_address_type"]
    rule_dict["dest_port"] = request.form["dest_port"]
    rule_dict["dest_port_type"] = request.form["dest_port_type"]
    rule_dict["source_address"] = request.form["source_address"]
    rule_dict["source_address_type"] = request.form["source_address_type"]
    rule_dict["source_port"] = request.form["source_port"]
    rule_dict["source_port_type"] = request.form["source_port_type"]
    rule_dict["protocol"] = (
        request.form["protocol"] if "protocol" in request.form else ""
    )
    if "state_est" in request.form:
        rule_dict["state_est"] = True
    if "state_inv" in request.form:
        rule_dict["state_inv"] = True
    if "state_new" in request.form:
        rule_dict["state_new"] = True
    if "state_rel" in request.form:
        rule_dict["state_rel"] = True

    # Assign value to data structure
    user_data[ip_version]["tables"][fw_table][rule] = rule_dict

    # Add rule to rule-order in user data
    if rule not in user_data[ip_version]["tables"][fw_table]["rule-order"]:
        user_data[ip_version]["tables"][fw_table]["rule-order"].append(rule)

    # Sort rule-order in user data
    user_data[ip_version]["tables"][fw_table]["rule-order"] = sorted(
        user_data[ip_version]["tables"][fw_table]["rule-order"]
    )

    # print(json.dumps(user_data, indent=4))

    # Write user_data to file
    write_user_data_file(session["firewall_name"], user_data)

    flash(f"Rule {rule} added to table {ip_version}/{fw_table}.", "success")

    return


def add_table_to_data(session, request):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Set local vars from posted form data
    ip_version = request.form["ip_version"]
    fw_table = request.form["fw_table"]
    description = request.form["description"]
    default_action = request.form["default_action"]

    # Check and create higher level data structure if it does not exist
    if ip_version not in user_data:
        user_data[ip_version] = {}
        user_data[ip_version]["tables"] = {}
    if fw_table not in user_data[ip_version]["tables"]:
        user_data[ip_version]["tables"][fw_table] = {}
        user_data[ip_version]["tables"][fw_table]["rule-order"] = []
    if "default" not in user_data[ip_version]["tables"][fw_table]:
        user_data[ip_version]["tables"][fw_table]["default"] = {}
    user_data[ip_version]["tables"][fw_table]["default"]["description"] = description
    user_data[ip_version]["tables"][fw_table]["default"][
        "default_action"
    ] = default_action

    # Write user_data to file
    write_user_data_file(session["firewall_name"], user_data)

    flash(f"Table {ip_version}/{fw_table} added.", "success")

    return


def assemble_list_of_rules(session):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Create list of defined rules
    rule_list = []
    try:
        for ip_version in ["ipv4", "ipv6"]:
            if ip_version in user_data:
                for fw_table in user_data[ip_version]["tables"]:
                    for rule in user_data[ip_version]["tables"][fw_table]["rule-order"]:
                        rule_list.append(
                            [
                                ip_version,
                                fw_table,
                                rule,
                                user_data[ip_version]["tables"][fw_table][rule][
                                    "description"
                                ],
                            ]
                        )
    except:
        pass

    # If there are no rules, flash message
    if rule_list == []:
        flash(f"There are no rules defined.", "danger")

    return rule_list


def assemble_list_of_tables(session):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Create list of defined tables
    table_list = []
    try:
        for ip_version in ["ipv4", "ipv6"]:
            if ip_version in user_data:
                for fw_table in user_data[ip_version]["tables"]:
                    table_list.append([ip_version, fw_table])
    except:
        pass

    # If there are no tables, flash message
    if table_list == []:
        flash(f"There are no tables defined.", "danger")

    return table_list


def delete_rule_from_data(session, request):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Set local vars from posted form data
    rule = request.form["rule"].split(",")
    ip_version = rule[0]
    fw_table = rule[1]
    rule = rule[2]

    # Delete rule from data
    try:
        del user_data[ip_version]["tables"][fw_table][rule]
        user_data[ip_version]["tables"][fw_table]["rule-order"].remove(rule)
        flash(f"Deleted rule {rule} from table {ip_version}/{fw_table}.", "warning")
    except:
        flash(
            f"Failed to delete rule {rule} from table {ip_version}/{fw_table}.",
            "danger",
        )
        pass

    # Clean-up data
    try:
        if len(user_data[ip_version]["tables"][fw_table]["rule-order"]) == 0:
            del user_data[ip_version]["tables"][fw_table]
        if len(user_data[ip_version]) == 0:
            del user_data[ip_version]
    except:
        pass

    # Write user's data to file
    write_user_data_file(session["firewall_name"], user_data)

    return
