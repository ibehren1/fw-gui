"""
    Support functions.
"""
from flask import flash
import json


def add_default_rule(session, request):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Set local vars from posted form data
    ip_version = request.form["ip_version"]
    fw_table = request.form["fw_table"]
    description = request.form["description"]
    default_action = request.form["default_action"]

    if ip_version not in user_data:
        user_data[ip_version] = {}
    if fw_table not in user_data[ip_version]:
        user_data[ip_version][fw_table] = {}
    if "default" not in user_data[ip_version][fw_table]:
        user_data[ip_version][fw_table]["default"] = {}
    user_data[ip_version][fw_table]["default"]["description"] = description
    user_data[ip_version][fw_table]["default"]["default_action"] = default_action

    write_user_data_file(session["firewall_name"], user_data)

    flash(f"Default action created for table {ip_version}/{fw_table}.", "success")

    return


def add_group_to_data(session, request):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Set local vars from posted form data
    ip_version = request.form["ip_version"]
    group_name = request.form["group_name"].replace(" ", "")
    group_type = request.form["group_type"]
    group_value = request.form["group_value"]

    group_value_list = group_value.split(",")

    if ip_version not in user_data:
        user_data[ip_version] = {}
    if "groups" not in user_data[ip_version]:
        user_data[ip_version]["groups"] = {}
    if "group-name" not in user_data[ip_version]["groups"]:
        user_data[ip_version]["groups"][group_name] = {}
    user_data[ip_version]["groups"][group_name]["group_type"] = group_type
    user_data[ip_version]["groups"][group_name]["group_value"] = group_value_list

    print(json.dumps(user_data, indent=4))

    # Write user_data to file
    write_user_data_file(session["firewall_name"], user_data)

    flash(f"Group {group_name} added.", "success")

    return


def add_rule_to_data(session, request):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Set local vars from posted form data
    ip_version = request.form["ip_version"]
    fw_table = request.form["fw_table"]

    if ip_version not in user_data:
        user_data[ip_version] = {}
    if fw_table not in user_data[ip_version]:
        user_data[ip_version][fw_table] = {}
    if "rule-order" not in user_data[ip_version][fw_table]:
        user_data[ip_version][fw_table]["rule-order"] = []

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

    # Add rule to user_data
    user_data[ip_version][fw_table][rule] = rule_dict

    # Add rule to rule-order in user data
    if rule not in user_data[ip_version]["tables"][fw_table]["rule-order"]:
        user_data[ip_version]["tables"][fw_table]["rule-order"].append(rule)

    # Sort rule-order in user data
    user_data[ip_version]["tables"][fw_table]["rule-order"] = sorted(
        user_data[ip_version]["tables"][fw_table]["rule-order"]
    )

    print(json.dumps(user_data, indent=4))

    # Write user_data to file
    write_user_data_file(session["firewall_name"], user_data)

    flash(f"Rule {rule} added to table {ip_version}/{fw_table}.", "success")

    return


def delete_rule_from_data(session, request):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Set local vars from posted form data
    ip_version = request.form["ip_version"]
    fw_table = request.form["fw_table"]
    rule = request.form["rule"]

    # Delete rule from data
    try:
        del user_data[ip_version]["tables"][fw_table][rule]
        user_data[ip_version]["tables"][fw_table]["rule-order"].remove(rule)
    except:
        pass

    # Clean-up data
    try:
        if len(user_data[ip_version]["tables"][fw_table]["rule-order"]) == 0:
            del user_data[ip_version][fw_table]
        if len(user_data[ip_version]) == 0:
            del user_data[ip_version]
    except:
        pass

    # Write user's data to file
    write_user_data_file(session["firewall_name"], user_data)

    flash(f"Deleted rule {rule} from table {ip_version}/{fw_table}.", "warning")

    return


def generate_config(session):
    # Get user data
    user_data = read_user_data_file(session["firewall_name"])

    # Create firewall configuration
    config = []

    if user_data == {}:
        config.append("Empty rule set.  Use buttons on the right to add some rules.")

    # Work through each IP Version, Table and Rule adding to config
    for ip_version in user_data:
        config.append(f"#\n# {ip_version}\n#\n")

        config.append(f"#\n# Groups\n#")
        if "groups" in user_data[ip_version]:
            for group_name in user_data[ip_version]["groups"]:
                group_type = user_data[ip_version]["groups"][group_name]["group_type"]
                group_value = user_data[ip_version]["groups"][group_name]["group_value"]

                if group_type == "address-group":
                    value_type = "address"
                if group_type == "network-group":
                    value_type = "network"
                if group_type == "port-group":
                    value_type = "port"

                if ip_version == "ipv4":
                    for value in group_value:
                        config.append(
                            f"set firewall group {group_type} {group_name} {value_type} '{value}'"
                        )

                if ip_version == "ipv6":
                    for value in group_value:
                        config.append(
                            f"set firewall group {ip_version}-{group_type} {group_name} {value_type} '{value}'"
                        )

            config.append("")

        if "tables" in user_data[ip_version]:
            for fw_table in user_data[ip_version]["tables"]:
                config.append(f"#\n# Table: {fw_table}\n#")

                if "default" in user_data[ip_version]["tables"][fw_table]:
                    description = user_data[ip_version]["tables"][fw_table]["default"][
                        "description"
                    ]
                    default_action = user_data[ip_version]["tables"][fw_table][
                        "default"
                    ]["default_action"]
                    config.append(
                        f"set firewall {ip_version} name {fw_table} default-action '{default_action}'"
                    )
                    config.append(
                        f"set firewall {ip_version} name {fw_table} description '{description}'"
                    )
                    config.append("\n")

                for rule in user_data[ip_version]["tables"][fw_table]["rule-order"]:
                    for key in user_data[ip_version]["tables"][fw_table][rule]:
                        description = user_data[ip_version]["tables"][fw_table][rule][
                            "description"
                        ]
                        rule_disable = (
                            True
                            if "rule_disable"
                            in user_data[ip_version]["tables"][fw_table][rule]
                            else False
                        )
                        logging = (
                            True
                            if "logging"
                            in user_data[ip_version]["tables"][fw_table][rule]
                            else False
                        )
                        action = user_data[ip_version]["tables"][fw_table][rule][
                            "action"
                        ]
                        dest_address = user_data[ip_version]["tables"][fw_table][rule][
                            "dest_address"
                        ]
                        dest_address_type = user_data[ip_version]["tables"][fw_table][
                            rule
                        ]["dest_address_type"]
                        dest_port = user_data[ip_version]["tables"][fw_table][rule][
                            "dest_port"
                        ]
                        dest_port_type = user_data[ip_version]["tables"][fw_table][
                            rule
                        ]["dest_port_type"]
                        source_address = user_data[ip_version]["tables"][fw_table][
                            rule
                        ]["source_address"]
                        source_address_type = user_data[ip_version]["tables"][fw_table][
                            rule
                        ]["source_address_type"]
                        source_port = user_data[ip_version]["tables"][fw_table][rule][
                            "source_port"
                        ]
                        source_port_type = user_data[ip_version]["tables"][fw_table][
                            rule
                        ]["source_port_type"]
                        protocol = user_data[ip_version]["tables"][fw_table][rule][
                            "protocol"
                        ]
                        state_est = (
                            True
                            if "state_est"
                            in user_data[ip_version]["tables"][fw_table][rule]
                            else False
                        )
                        state_inv = (
                            True
                            if "state_inv"
                            in user_data[ip_version]["tables"][fw_table][rule]
                            else False
                        )
                        state_new = (
                            True
                            if "state_new"
                            in user_data[ip_version]["tables"][fw_table][rule]
                            else False
                        )
                        state_rel = (
                            True
                            if "state_rel"
                            in user_data[ip_version]["tables"][fw_table][rule]
                            else False
                        )

                    config.append(f"# Rule {rule}")

                    # Disable
                    if rule_disable:
                        config.append(
                            f"set firewall {ip_version} name {fw_table} rule {rule} disable"
                        )

                    # Description
                    config.append(
                        f"set firewall {ip_version} name {fw_table} rule {rule} description '{description}'"
                    )

                    # Action
                    config.append(
                        f"set firewall {ip_version} name {fw_table} rule {rule} action '{action}'"
                    )

                    # Destination
                    if dest_address != "":
                        if dest_address_type == "address":
                            config.append(
                                f"set firewall {ip_version} name {fw_table} rule {rule} destination address '{dest_address}'"
                            )
                        elif dest_address_type == "address_group":
                            config.append(
                                f"set firewall {ip_version} name {fw_table} rule {rule} destination group address-group '{dest_address}'"
                            )
                        elif dest_address_type == "network_group":
                            config.append(
                                f"set firewall {ip_version} name {fw_table} rule {rule} destination group network-group '{dest_address}'"
                            )
                    if dest_port != "":
                        if dest_port_type == "port":
                            config.append(
                                f"set firewall {ip_version} name {fw_table} rule {rule} destination port '{dest_port}'"
                            )
                        elif dest_port_type == "port_group":
                            config.append(
                                f"set firewall {ip_version} name {fw_table} rule {rule} destination group port-group {dest_port}"
                            )

                    # Source
                    if source_address != "":
                        if source_address_type == "address":
                            config.append(
                                f"set firewall {ip_version} name {fw_table} rule {rule} source address '{source_address}'"
                            )
                        elif source_address_type == "address_group":
                            config.append(
                                f"set firewall {ip_version} name {fw_table} rule {rule} source group address-group '{source_address}'"
                            )
                        elif source_address_type == "network_group":
                            config.append(
                                f"set firewall {ip_version} name {fw_table} rule {rule} source group network-group '{source_address}'"
                            )
                    if source_port != "":
                        if source_port_type == "port":
                            config.append(
                                f"set firewall {ip_version} name {fw_table} rule {rule} source port '{source_port}'"
                            )
                        elif source_port_type == "port_group":
                            config.append(
                                f"set firewall {ip_version} name {fw_table} rule {rule} source group port-group '{source_port}'"
                            )

                    # Protocol
                    if protocol != "":
                        if ip_version == "ipv6" and protocol == "icmp":
                            protocol = "ipv6-icmp"
                        config.append(
                            f"set firewall {ip_version} name {fw_table} rule {rule} protocol '{protocol}'"
                        )

                    # Logging
                    if logging:
                        config.append(
                            f"set firewall {ip_version} name {fw_table} rule {rule} log"
                        )

                    # States
                    if state_est:
                        config.append(
                            f"set firewall {ip_version} name {fw_table} rule {rule} state 'established'"
                        )
                    if state_inv:
                        config.append(
                            f"set firewall {ip_version} name {fw_table} rule {rule} state 'invalid'"
                        )
                    if state_new:
                        config.append(
                            f"set firewall {ip_version} name {fw_table} rule {rule} state 'new'"
                        )
                    if state_rel:
                        config.append(
                            f"set firewall {ip_version} name {fw_table} rule {rule} state 'related'"
                        )
                    config.append("")

    # Convert list of lines to single string
    message = ""
    for line in config:
        message = message + line.replace("\n", "<br>") + "<br>"

    # Return message of config commands
    return message


def read_user_data_file(filename):
    try:
        with open(f"data/{filename}.json", "r") as f:
            data = f.read()
            user_data = json.loads(data)
            return user_data
    except:
        return {}


def write_user_data_file(filename, data):
    with open(f"data/{filename}.json", "w") as f:
        f.write(json.dumps(data, indent=4))
    return
