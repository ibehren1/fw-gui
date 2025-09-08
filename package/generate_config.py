"""
    Generate Configuration

    This module handles firewall configuration generation and JSON data management.

    Key functions:
    - download_json_data: Retrieves and formats user data as JSON
    - generate_config: Generates firewall configuration from user data

    The configuration generation handles:
    - Extra configuration items
    - Flow tables configuration 
    - IPv4 and IPv6 configurations including:
    - Groups (address, domain, interface, MAC, network, port)
    - Filters with rules and actions
    - Rule descriptions, logging, and actions (jump, offload)
"""

import json

from package.data_file_functions import read_user_data_file


def download_json_data(session):
    """
    Retrieves user data and converts it to formatted JSON

    Args:
        session: Dictionary containing data_dir and firewall_name

    Returns:
        str: Formatted JSON string of user data
    """
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')
    json_data = json.dumps(user_data, indent=4)

    return json_data


def generate_config(session, snapshot="current", diff=False):
    """
    Generates firewall configuration from user data

    Args:
        session: Dictionary containing data_dir and firewall_name
        snapshot: Snapshot name to use, defaults to "current"
        diff: Whether to generate diff configuration, defaults to "False"

    Returns:
        list: Configuration commands
    """

    if not diff:
        # Get user data
        user_data = read_user_data_file(
            f'{session["data_dir"]}/{session["firewall_name"]}'
        )
    else:
        # Get user data for specific snapshot
        user_data = read_user_data_file(
            f'{session["data_dir"]}/{session["firewall_name"]}',
            snapshot=snapshot,
            diff=diff,
        )

    # Create firewall configuration
    config = []

    if (
        "ipv4" not in user_data
        and "ipv6" not in user_data
        and "extra-items" not in user_data
    ):
        config.append(
            "Empty rule set.  Start by adding a Chain using the button on the right."
        )

    # Add Extra Items
    if "extra-items" in user_data:
        config.append("#\n#\n# Extra Configuration Items\n#\n#")
        for item in user_data["extra-items"]:
            config.append(f"{item}")
        config.append("")

    # Work through each IP Version, Chain and Rule adding to config
    if "flowtables" in user_data:
        config.append("#\n#\n# FLOW TABLES\n#\n#\n")

        for flowtable in user_data["flowtables"]:
            config.append(f"# Flowtable: {flowtable["name"]}")
            for interface in flowtable["interfaces"]:
                config.append(
                    f"set firewall flowtable {flowtable["name"]} interface '{interface}'"
                )
            config.append(
                f"set firewall flowtable {flowtable["name"]} description '{flowtable["description"]}'"
            )
            config.append(
                f"set firewall flowtable {flowtable["name"]} offload software"
            )
            config.append("")

    for ip_version in user_data:
        if (
            ip_version != "extra-items"
            and ip_version != "_id"
            and ip_version != "firewall"
            and ip_version != "flowtables"
            and ip_version != "snapshot"
            and ip_version != "interfaces"
            and ip_version != "system"
            and ip_version != "version"
        ):
            if ip_version == "ipv4":
                config.append("#\n#\n# IPv4\n#\n#\n")
            if ip_version == "ipv6":
                config.append("#\n#\n# IPv6\n#\n#\n")

            if "groups" in user_data[ip_version]:
                config.append("#\n# Groups\n#")
                for group_name in user_data[ip_version]["groups"]:
                    # Get Values
                    group_desc = user_data[ip_version]["groups"][group_name][
                        "group_desc"
                    ]
                    group_type = user_data[ip_version]["groups"][group_name][
                        "group_type"
                    ]
                    group_value = user_data[ip_version]["groups"][group_name][
                        "group_value"
                    ]

                    if group_type == "address-group":
                        value_type = "address"
                    if group_type == "domain-group":
                        value_type = "address"
                    if group_type == "interface-group":
                        value_type = "interface"
                    if group_type == "mac-group":
                        value_type = "mac-address"
                    if group_type == "network-group":
                        value_type = "network"
                    if group_type == "port-group":
                        value_type = "port"

                    config.append(f"\n# Group: {group_name}")

                    # Write Config Statements
                    if ip_version == "ipv4":
                        if group_desc != "":
                            config.append(
                                f"set firewall group {group_type} {group_name} description '{group_desc}'"
                            )
                        for value in group_value:
                            if value != "":
                                config.append(
                                    f"set firewall group {group_type} {group_name} {value_type} '{value}'"
                                )

                    if ip_version == "ipv6":
                        config.append(
                            f"set firewall group {ip_version}-{group_type} {group_name} description '{group_desc}'"
                        )
                        for value in group_value:
                            config.append(
                                f"set firewall group {ip_version}-{group_type} {group_name} {value_type} '{value}'"
                            )

                config.append("")

            if "filters" in user_data[ip_version]:
                for filter_name in user_data[ip_version]["filters"]:
                    # Get Values
                    filter_desc = user_data[ip_version]["filters"][filter_name][
                        "description"
                    ]
                    filter_action = user_data[ip_version]["filters"][filter_name][
                        "default-action"
                    ]
                    filter_log = user_data[ip_version]["filters"][filter_name]["log"]

                    # Write Config Statements
                    config.append(f"#\n# Filter: {filter_name}\n#")
                    config.append(
                        f"set firewall {ip_version} {filter_name} filter description '{filter_desc}'"
                    )
                    config.append(
                        f"set firewall {ip_version} {filter_name} filter default-action {filter_action}"
                    )
                    if filter_log:
                        config.append(
                            f"set firewall {ip_version} {filter_name} filter enable-default-log"
                        )
                    config.append("\n")

                    for rule in user_data[ip_version]["filters"][filter_name][
                        "rule-order"
                    ]:
                        for key in user_data[ip_version]["filters"][filter_name][
                            "rules"
                        ][rule]:
                            # Get Values
                            description = user_data[ip_version]["filters"][filter_name][
                                "rules"
                            ][rule]["description"]
                            log = (
                                True
                                if "log"
                                in user_data[ip_version]["filters"][filter_name][
                                    "rules"
                                ][rule]
                                else False
                            )
                            rule_disable = (
                                True
                                if "rule_disable"
                                in user_data[ip_version]["filters"][filter_name][
                                    "rules"
                                ][rule]
                                else False
                            )
                            action = user_data[ip_version]["filters"][filter_name][
                                "rules"
                            ][rule]["action"]
                            if action == "jump":
                                interface = user_data[ip_version]["filters"][
                                    filter_name
                                ]["rules"][rule]["interface"]
                                direction = user_data[ip_version]["filters"][
                                    filter_name
                                ]["rules"][rule]["direction"]
                                jump_target = user_data[ip_version]["filters"][
                                    filter_name
                                ]["rules"][rule]["fw_chain"]
                            if action == "offload":
                                offload_target = user_data[ip_version]["filters"][
                                    filter_name
                                ]["rules"][rule]["fw_chain"]
                                # set firewall [ipv4 | ipv6] forward filter rule <1-999999> action offload
                                # set firewall [ipv4 | ipv6] forward filter rule <1-999999> offload-target <flowtable>

                        # Write Config Statements
                        config.append(f"# Rule {rule}")

                        # Description
                        if description != "":
                            config.append(
                                f"set firewall {ip_version} {filter_name} filter rule {rule} description '{description}'"
                            )

                        # Action
                        config.append(
                            f"set firewall {ip_version} {filter_name} filter rule {rule} action '{action}'"
                        )
                        if action == "offload":
                            config.append(
                                f"set firewall {ip_version} {filter_name} filter rule {rule} offload-target '{offload_target}'"
                            )

                        # Interface / Directions
                        if action == "jump":
                            if direction == "inbound":
                                config.append(
                                    f"set firewall {ip_version} {filter_name} filter rule {rule} inbound-interface name '{interface}'"
                                )
                            if direction == "outbound":
                                config.append(
                                    f"set firewall {ip_version} {filter_name} filter rule {rule} outbound-interface name '{interface}'"
                                )
                            config.append(
                                f"set firewall {ip_version} {filter_name} filter rule {rule} jump-target '{jump_target}'"
                            )

                        # Disable
                        if rule_disable:
                            config.append(
                                f"set firewall {ip_version} {filter_name} filter rule {rule} disable"
                            )

                        # Log
                        if log:
                            config.append(
                                f"set firewall {ip_version} {filter_name} filter rule {rule} log"
                            )
                        config.append("\n")

            if "chains" in user_data[ip_version]:
                for fw_chain in user_data[ip_version]["chains"]:
                    config.append(f"#\n# Chain: {fw_chain}\n#")

                    if "default" in user_data[ip_version]["chains"][fw_chain]:
                        description = user_data[ip_version]["chains"][fw_chain][
                            "default"
                        ]["description"]
                        if (
                            "default_logging"
                            in user_data[ip_version]["chains"][fw_chain]["default"]
                        ):
                            default_logging = user_data[ip_version]["chains"][fw_chain][
                                "default"
                            ]["default_logging"]
                        else:
                            default_logging = False
                        default_action = user_data[ip_version]["chains"][fw_chain][
                            "default"
                        ]["default_action"]
                        config.append(
                            f"set firewall {ip_version} name {fw_chain} description '{description}'"
                        )
                        config.append(
                            f"set firewall {ip_version} name {fw_chain} default-action '{default_action}'"
                        )
                        if default_logging:
                            config.append(
                                f"set firewall {ip_version} name {fw_chain} default-log"
                            )
                        config.append("\n")

                    for rule in user_data[ip_version]["chains"][fw_chain]["rule-order"]:
                        for key in user_data[ip_version]["chains"][fw_chain][rule]:
                            # Get Values
                            description = user_data[ip_version]["chains"][fw_chain][
                                rule
                            ]["description"]
                            rule_disable = (
                                True
                                if "rule_disable"
                                in user_data[ip_version]["chains"][fw_chain][rule]
                                else False
                            )
                            logging = (
                                True
                                if "logging"
                                in user_data[ip_version]["chains"][fw_chain][rule]
                                else False
                            )
                            action = user_data[ip_version]["chains"][fw_chain][rule][
                                "action"
                            ]
                            dest_address = user_data[ip_version]["chains"][fw_chain][
                                rule
                            ]["dest_address"]
                            dest_address_type = user_data[ip_version]["chains"][
                                fw_chain
                            ][rule]["dest_address_type"]
                            dest_port = user_data[ip_version]["chains"][fw_chain][rule][
                                "dest_port"
                            ]
                            dest_port_type = user_data[ip_version]["chains"][fw_chain][
                                rule
                            ]["dest_port_type"]
                            source_address = user_data[ip_version]["chains"][fw_chain][
                                rule
                            ]["source_address"]
                            source_address_type = user_data[ip_version]["chains"][
                                fw_chain
                            ][rule]["source_address_type"]
                            source_port = user_data[ip_version]["chains"][fw_chain][
                                rule
                            ]["source_port"]
                            source_port_type = user_data[ip_version]["chains"][
                                fw_chain
                            ][rule]["source_port_type"]
                            protocol = user_data[ip_version]["chains"][fw_chain][rule][
                                "protocol"
                            ]
                            state_est = (
                                True
                                if "state_est"
                                in user_data[ip_version]["chains"][fw_chain][rule]
                                else False
                            )
                            state_inv = (
                                True
                                if "state_inv"
                                in user_data[ip_version]["chains"][fw_chain][rule]
                                else False
                            )
                            state_new = (
                                True
                                if "state_new"
                                in user_data[ip_version]["chains"][fw_chain][rule]
                                else False
                            )
                            state_rel = (
                                True
                                if "state_rel"
                                in user_data[ip_version]["chains"][fw_chain][rule]
                                else False
                            )

                        # Write Config Statements
                        config.append(f"# Rule {rule}")

                        # Disable
                        if rule_disable:
                            config.append(
                                f"set firewall {ip_version} name {fw_chain} rule {rule} disable"
                            )

                        # Description
                        if description != "":
                            config.append(
                                f"set firewall {ip_version} name {fw_chain} rule {rule} description '{description}'"
                            )

                        # Action
                        config.append(
                            f"set firewall {ip_version} name {fw_chain} rule {rule} action '{action}'"
                        )

                        # Destination
                        if dest_address != "":
                            if dest_address_type == "address":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} destination address '{dest_address}'"
                                )
                            elif dest_address_type == "address_group":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} destination group address-group '{dest_address}'"
                                )
                            elif dest_address_type == "domain_group":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} destination group domain-group '{dest_address}'"
                                )
                            elif dest_address_type == "mac_group":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} destination group mac-group '{dest_address}'"
                                )
                            elif dest_address_type == "network_group":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} destination group network-group '{dest_address}'"
                                )
                        if dest_port != "":
                            if dest_port_type == "port":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} destination port '{dest_port}'"
                                )
                            elif dest_port_type == "port_group":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} destination group port-group '{dest_port}'"
                                )

                        # Source
                        if source_address != "":
                            if source_address_type == "address":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} source address '{source_address}'"
                                )
                            elif source_address_type == "address_group":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} source group address-group '{source_address}'"
                                )
                            elif source_address_type == "domain_group":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} source group domain-group '{source_address}'"
                                )
                            elif source_address_type == "mac_group":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} source group mac-group '{source_address}'"
                                )
                            elif source_address_type == "network_group":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} source group network-group '{source_address}'"
                                )
                        if source_port != "":
                            if source_port_type == "port":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} source port '{source_port}'"
                                )
                            elif source_port_type == "port_group":
                                config.append(
                                    f"set firewall {ip_version} name {fw_chain} rule {rule} source group port-group '{source_port}'"
                                )

                        # Protocol
                        if protocol != "":
                            if ip_version == "ipv6" and protocol == "icmp":
                                protocol = "ipv6-icmp"
                            config.append(
                                f"set firewall {ip_version} name {fw_chain} rule {rule} protocol '{protocol}'"
                            )

                        # Logging
                        if logging:
                            config.append(
                                f"set firewall {ip_version} name {fw_chain} rule {rule} log"
                            )

                        # States
                        if state_est:
                            config.append(
                                f"set firewall {ip_version} name {fw_chain} rule {rule} state 'established'"
                            )
                        if state_inv:
                            config.append(
                                f"set firewall {ip_version} name {fw_chain} rule {rule} state 'invalid'"
                            )
                        if state_new:
                            config.append(
                                f"set firewall {ip_version} name {fw_chain} rule {rule} state 'new'"
                            )
                        if state_rel:
                            config.append(
                                f"set firewall {ip_version} name {fw_chain} rule {rule} state 'related'"
                            )
                        config.append("")

    # If this is a Diff, just return the config
    if diff:
        return config

    # Convert list of lines to single string
    message = ""
    for line in config:
        message = message + line.replace("\n", "<br>") + "<br>"

    # Return message of config commands
    return message, config
