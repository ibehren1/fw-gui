"""
    Chain Support functions.
"""
from package.data_file_functions import read_user_data_file, write_user_data_file
from flask import flash


def add_rule_to_data(session, request):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    chain = request.form["fw_chain"].split(",")
    ip_version = chain[0]
    fw_chain = chain[1]

    # Check and create higher level data structure if it does not exist
    if ip_version not in user_data:
        user_data[ip_version] = {}
        user_data[ip_version]["chains"] = {}
    if fw_chain not in user_data[ip_version]["chains"]:
        user_data[ip_version]["chains"][fw_chain] = {}
    if "rule-order" not in user_data[ip_version]["chains"][fw_chain]:
        user_data[ip_version]["chains"][fw_chain]["rule-order"] = []

    # Assemble rule dict
    rule = request.form["rule"]
    rule_dict = {}
    rule_dict["description"] = request.form["description"]
    if "rule_disable" in request.form:
        rule_dict["rule_disable"] = True
    if "logging" in request.form:
        rule_dict["logging"] = True
    rule_dict["action"] = request.form["action"]
    rule_dict["dest_address"] = request.form["dest_address"].strip()
    rule_dict["dest_address_type"] = request.form["dest_address_type"]
    rule_dict["dest_port"] = request.form["dest_port"].strip()
    rule_dict["dest_port_type"] = request.form["dest_port_type"]
    rule_dict["source_address"] = request.form["source_address"].strip()
    rule_dict["source_address_type"] = request.form["source_address_type"]
    rule_dict["source_port"] = request.form["source_port"].strip()
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
    user_data[ip_version]["chains"][fw_chain][rule] = rule_dict

    # Add rule to rule-order in user data
    if rule not in user_data[ip_version]["chains"][fw_chain]["rule-order"]:
        user_data[ip_version]["chains"][fw_chain]["rule-order"].append(rule)

    # Sort rule-order in user data
    user_data[ip_version]["chains"][fw_chain]["rule-order"] = sorted(
        user_data[ip_version]["chains"][fw_chain]["rule-order"]
    )

    # print(json.dumps(user_data, indent=4))

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"Rule {rule} added to chain {ip_version}/{fw_chain}.", "success")

    return


def add_chain_to_data(session, request):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    ip_version = request.form["ip_version"]
    fw_chain = request.form["fw_chain"]
    description = request.form["description"]
    default_action = request.form["default_action"]

    # Check and create higher level data structure if it does not exist
    if ip_version not in user_data:
        user_data[ip_version] = {}
    if "chains" not in user_data[ip_version]:
        user_data[ip_version]["chains"] = {}
    if fw_chain not in user_data[ip_version]["chains"]:
        user_data[ip_version]["chains"][fw_chain] = {}
        user_data[ip_version]["chains"][fw_chain]["rule-order"] = []
    if "default" not in user_data[ip_version]["chains"][fw_chain]:
        user_data[ip_version]["chains"][fw_chain]["default"] = {}
    user_data[ip_version]["chains"][fw_chain]["default"]["description"] = description
    user_data[ip_version]["chains"][fw_chain]["default"][
        "default_action"
    ] = default_action

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"chain {ip_version}/{fw_chain} added.", "success")

    return


def assemble_list_of_rules(session):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Create list of defined rules
    rule_list = []
    try:
        for ip_version in ["ipv4", "ipv6"]:
            if ip_version in user_data:
                for fw_chain in user_data[ip_version]["chains"]:
                    for rule in user_data[ip_version]["chains"][fw_chain]["rule-order"]:
                        rule_list.append(
                            [
                                ip_version,
                                fw_chain,
                                rule,
                                user_data[ip_version]["chains"][fw_chain][rule][
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


def assemble_list_of_chains(session):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Create list of defined chains
    chain_list = []
    try:
        for ip_version in ["ipv4", "ipv6"]:
            if ip_version in user_data:
                for fw_chain in user_data[ip_version]["chains"]:
                    chain_list.append([ip_version, fw_chain])
    except:
        pass

    # If there are no chains, flash message
    if chain_list == []:
        flash(f"There are no chains defined.", "danger")

    return chain_list


def delete_rule_from_data(session, request):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    rule = request.form["rule"].split(",")
    ip_version = rule[0]
    fw_chain = rule[1]
    rule = rule[2]

    # Delete rule from data
    try:
        del user_data[ip_version]["chains"][fw_chain][rule]
        user_data[ip_version]["chains"][fw_chain]["rule-order"].remove(rule)
        flash(f"Deleted rule {rule} from chain {ip_version}/{fw_chain}.", "warning")
    except:
        flash(
            f"Failed to delete rule {rule} from chain {ip_version}/{fw_chain}.",
            "danger",
        )
        pass

    # Clean-up data
    try:
        if len(user_data[ip_version]["chains"][fw_chain]["rule-order"]) == 0:
            del user_data[ip_version]["chains"][fw_chain]
        if len(user_data[ip_version]) == 0:
            del user_data[ip_version]
    except:
        pass

    # Write user's data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    return
