"""
    Support functions.
"""
import json


def delete_rule_from_data(session, request):
    # Get user's data
    user_data = read_user_data_file(session["firewall_name"])

    # Set local vars from posted form data
    ip_version = request.form["ip_version"]
    fw_table = request.form["fw_table"]
    rule = request.form["rule"]

    # Delete rule from data
    try:
        del user_data[ip_version][fw_table][rule]
    except:
        pass

    # Clean-up data
    try:
        if len(user_data[ip_version][fw_table]) == 0:
            del user_data[ip_version][fw_table]
        if len(user_data[ip_version]) == 0:
            del user_data[ip_version]
    except:
        pass

    # Write user's data to file
    write_user_data_file(session["firewall_name"], user_data)

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

    print(json.dumps(user_data, indent=4))

    # Write user_data to file
    write_user_data_file(session["firewall_name"], user_data)

    return


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


def generate_config(session):
    # Get user data
    user_data = read_user_data_file(session["firewall_name"])

    # Create firewall configuration
    config = []

    # Work through each IP Version, Table and Rule adding to config
    for ip_version in user_data:
        config.append(f"#\n# {ip_version}\n#\n")

        for fw_table in user_data[ip_version]:
            config.append(f"#\n# Table: {fw_table}\n#\n")

            for rule in user_data[ip_version][fw_table]:
                for key in user_data[ip_version][fw_table][rule]:
                    description = user_data[ip_version][fw_table][rule]["description"]
                    rule_disable = (
                        True
                        if "rule_disable" in user_data[ip_version][fw_table][rule]
                        else False
                    )
                    logging = (
                        True
                        if "logging" in user_data[ip_version][fw_table][rule]
                        else False
                    )
                    action = user_data[ip_version][fw_table][rule]["action"]
                    dest_address = user_data[ip_version][fw_table][rule]["dest_address"]
                    dest_address_type = user_data[ip_version][fw_table][rule][
                        "dest_address_type"
                    ]
                    dest_port = user_data[ip_version][fw_table][rule]["dest_port"]
                    dest_port_type = user_data[ip_version][fw_table][rule][
                        "dest_port_type"
                    ]
                    source_address = user_data[ip_version][fw_table][rule][
                        "source_address"
                    ]
                    source_address_type = user_data[ip_version][fw_table][rule][
                        "source_address_type"
                    ]
                    source_port = user_data[ip_version][fw_table][rule]["source_port"]
                    source_port_type = user_data[ip_version][fw_table][rule][
                        "source_port_type"
                    ]
                    protocol = user_data[ip_version][fw_table][rule]["protocol"]
                    state_est = (
                        True
                        if "state_est" in user_data[ip_version][fw_table][rule]
                        else False
                    )
                    state_inv = (
                        True
                        if "state_inv" in user_data[ip_version][fw_table][rule]
                        else False
                    )
                    state_new = (
                        True
                        if "state_new" in user_data[ip_version][fw_table][rule]
                        else False
                    )
                    state_rel = (
                        True
                        if "state_rel" in user_data[ip_version][fw_table][rule]
                        else False
                    )

                config.append("# Rule {0}".format(rule))

                # Disable
                if rule_disable:
                    config.append(
                        "set firewall {0} name {1} rule {2} disable".format(
                            ip_version, fw_table, rule
                        )
                    )

                # Description
                config.append(
                    "set firewall {0} name {1} rule {2} description '{3}'".format(
                        ip_version, fw_table, rule, description
                    )
                )

                # Action
                config.append(
                    "set firewall {0} name {1} rule {2} action {3}".format(
                        ip_version, fw_table, rule, action
                    )
                )

                # Destination
                if dest_address != "":
                    if dest_address_type == "address":
                        config.append(
                            "set firewall {0} name {1} rule {2} destination address {3}".format(
                                ip_version, fw_table, rule, dest_address
                            )
                        )
                    elif dest_address_type == "address_group":
                        config.append(
                            "set firewall {0} name {1} rule {2} destination group address-group {3}".format(
                                ip_version, fw_table, rule, dest_address
                            )
                        )
                    elif dest_address_type == "network_group":
                        config.append(
                            "set firewall {0} name {1} rule {2} destination group network-group {3}".format(
                                ip_version, fw_table, rule, dest_address
                            )
                        )
                if dest_port != "":
                    if dest_port_type == "port":
                        config.append(
                            "set firewall {0} name {1} rule {2} destination port {3}".format(
                                ip_version, fw_table, rule, dest_port
                            )
                        )
                    elif dest_port_type == "port_group":
                        config.append(
                            "set firewall {0} name {1} rule {2} destination group port-group {3}".format(
                                ip_version, fw_table, rule, dest_port
                            )
                        )

                # Source
                if source_address != "":
                    if source_address_type == "address":
                        config.append(
                            "set firewall {0} name {1} rule {2} source address {3}".format(
                                ip_version, fw_table, rule, source_address
                            )
                        )
                    elif source_address_type == "address_group":
                        config.append(
                            "set firewall {0} name {1} rule {2} source group address-group {3}".format(
                                ip_version, fw_table, rule, source_address
                            )
                        )
                    elif source_address_type == "network_group":
                        config.append(
                            "set firewall {0} name {1} rule {2} source group network-group {3}".format(
                                ip_version, fw_table, rule, source_address
                            )
                        )
                if source_port != "":
                    if source_port_type == "port":
                        config.append(
                            "set firewall {0} name {1} rule {2} source port {3}".format(
                                ip_version, fw_table, rule, source_port
                            )
                        )
                    elif source_port_type == "port_group":
                        config.append(
                            "set firewall {0} name {1} rule {2} source group port-group {3}".format(
                                ip_version, fw_table, rule, source_address
                            )
                        )

                # Protocol
                if protocol != "":
                    if ip_version == "ipv6" and protocol == "icmp":
                        protocol = "ipv6-icmp"
                    config.append(
                        "set firewall {0} name {1} rule {2} protocol {3}".format(
                            ip_version, fw_table, rule, protocol
                        )
                    )

                # Logging
                if logging:
                    config.append(
                        "set firewall {0} name {1} rule {2} log".format(
                            ip_version, fw_table, rule
                        )
                    )

                # States
                if state_est:
                    config.append(
                        "set firewall {0} name {1} rule {2} state 'established'".format(
                            ip_version, fw_table, rule
                        )
                    )
                if state_inv:
                    config.append(
                        "set firewall {0} name {1} rule {2} state 'invalid'".format(
                            ip_version, fw_table, rule
                        )
                    )
                if state_new:
                    config.append(
                        "set firewall {0} name {1} rule {2} state 'new'".format(
                            ip_version, fw_table, rule
                        )
                    )
                if state_rel:
                    config.append(
                        "set firewall {0} name {1} rule {2} state 'related'".format(
                            ip_version, fw_table, rule
                        )
                    )
                config.append("")

    # Convert list of lines to single string
    message = ""
    for line in config:
        message = message + line.replace("\n", "<br>") + "<br>"

    # Return message of config commands
    return message
