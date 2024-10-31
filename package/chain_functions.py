"""
    Chain Support functions.

    This module provides functions for managing firewall chains and rules in a user's data structure.
    It includes functions for:
    - Adding new firewall rules to chains
    - Adding new firewall chains
    - Reading and writing user data files
    - Processing form data for rules and chains
    - Validating IP versions and configurations

    Dependencies:
    - package.data_file_functions: For reading/writing user data files
    - flask: For flash messaging
    - logging: For logging functionality
"""

from package.data_file_functions import read_user_data_file, write_user_data_file
from flask import flash
import logging


def add_rule_to_data(session, request):
    """
    Adds a new firewall rule to a chain in the user's data structure and saves it to file.

    Args:
        session: Session object containing data_dir and firewall_name
        request: Request object containing form data with rule details

    Form data expected:
        fw_chain: Combined string of IP version and chain name (e.g. "ipv4,INPUT")
        rule: Rule number/ID
        description: Description of the rule
        rule_disable: Optional, disables rule if present
        logging: Optional, enables logging if present
        action: Action to take (e.g. ACCEPT, DROP)
        dest_address_type: Type of destination address (address, address_group, domain_group, etc)
        dest_address: Destination address value
        dest_port_type: Type of destination port (port or port_group)
        dest_port: Destination port value
        source_address_type: Type of source address (address, address_group, domain_group, etc)
        source_address: Source address value
        source_port_type: Type of source port (port or port_group)
        source_port: Source port value
        protocol: Protocol (optional)
        state_est: Optional, enables established state matching
        state_inv: Optional, enables invalid state matching
        state_new: Optional, enables new state matching
        state_rel: Optional, enables related state matching

    The function:
    1. Reads the existing user data file
    2. Extracts rule details from the form
    3. Creates necessary data structures if they don't exist
    4. Processes destination and source address/port configurations
    5. Adds the rule to the specified chain
    6. Updates the rule order list
    7. Saves updated data back to file
    8. Displays success message

    Returns:
        None
    """
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

    # Process destination
    if request.form["dest_address_type"] == "address":
        rule_dict["dest_address_type"] = "address"
        rule_dict["dest_address"] = request.form["dest_address"].strip()
    if request.form["dest_address_type"] == "address_group":
        rule_dict["dest_address_type"] = "address_group"
        if request.form["dest_address_group"].split(",")[0] == ip_version:
            rule_dict["dest_address"] = request.form["dest_address_group"].split(",")[1]
        else:
            flash_ip_version_mismatch()
            return
    if request.form["dest_address_type"] == "domain_group":
        rule_dict["dest_address_type"] = "domain_group"
        rule_dict["dest_address"] = request.form["dest_domain_group"].split(",")[1]
    if request.form["dest_address_type"] == "mac_group":
        rule_dict["dest_address_type"] = "mac_group"
        rule_dict["dest_address"] = request.form["dest_mac_group"].split(",")[1]
    if request.form["dest_address_type"] == "network_group":
        rule_dict["dest_address_type"] = "network_group"
        if request.form["dest_network_group"].split(",")[0] == ip_version:
            rule_dict["dest_address"] = request.form["dest_network_group"].split(",")[1]
        else:
            flash_ip_version_mismatch()
            return
    if request.form["dest_port_type"] == "port":
        rule_dict["dest_port_type"] = "port"
        rule_dict["dest_port"] = request.form["dest_port"].strip()
    if request.form["dest_port_type"] == "port_group":
        rule_dict["dest_port_type"] = "port_group"
        rule_dict["dest_port"] = request.form["dest_port_group"].split(",")[1]

    # Process source
    if request.form["source_address_type"] == "address":
        rule_dict["source_address_type"] = "address"
        rule_dict["source_address"] = request.form["source_address"].strip()
    if request.form["source_address_type"] == "address_group":
        rule_dict["source_address_type"] = "address_group"
        if request.form["source_address_group"].split(",")[0] == ip_version:
            rule_dict["source_address"] = request.form["source_address_group"].split(
                ","
            )[1]
        else:
            flash_ip_version_mismatch()
            return
    if request.form["source_address_type"] == "domain_group":
        rule_dict["source_address_type"] = "domain_group"
        rule_dict["source_address"] = request.form["source_domain_group"].split(",")[1]
    if request.form["source_address_type"] == "mac_group":
        rule_dict["source_address_type"] = "mac_group"
        rule_dict["source_address"] = request.form["source_mac_group"].split(",")[1]
    if request.form["source_address_type"] == "network_group":
        rule_dict["source_address_type"] = "network_group"
        if request.form["source_network_group"].split(",")[0] == ip_version:
            rule_dict["source_address"] = request.form["source_network_group"].split(
                ","
            )[1]
        else:
            flash_ip_version_mismatch()
            return
    if request.form["source_port_type"] == "port":
        rule_dict["source_port_type"] = "port"
        rule_dict["source_port"] = request.form["source_port"].strip()
    if request.form["source_port_type"] == "port_group":
        rule_dict["source_port_type"] = "port_group"
        rule_dict["source_port"] = request.form["source_port_group"].split(",")[1]

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
        user_data[ip_version]["chains"][fw_chain]["rule-order"], key=int
    )

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"Rule {rule} added to chain {ip_version}/{fw_chain}.", "success")

    return


def add_chain_to_data(session, request):
    """
    Adds a new firewall chain to the user's data structure and saves it to file.

    Args:
        session: Session object containing data_dir and firewall_name
        request: Request object containing form data with chain details

    Form data expected:
        ip_version: IP version for the chain (ipv4/ipv6)
        fw_chain: Name of the firewall chain
        description: Description of the chain
        default_action: Default action for the chain
        logging: Optional, enables logging if present

    The function:
    1. Reads the existing user data file
    2. Extracts chain details from the form
    3. Creates necessary data structure if it doesn't exist
    4. Adds the new chain with its configuration
    5. Saves updated data back to file
    6. Displays success message

    Returns:
        None
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    ip_version = request.form["ip_version"]
    fw_chain = request.form["fw_chain"]
    description = request.form["description"]
    default_action = request.form["default_action"]
    if "logging" in request.form:
        default_logging = True
    else:
        default_logging = False

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
        "default_logging"
    ] = default_logging
    user_data[ip_version]["chains"][fw_chain]["default"][
        "default_action"
    ] = default_action

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"Chain {ip_version}/{fw_chain} added.", "success")

    return


def assemble_detail_list_of_chains(session):
    """
    Assembles a detailed dictionary of all firewall chains and their rules from the user's data.

    Args:
        session: The current session containing data directory and firewall name

    Returns:
        dict: A nested dictionary structure containing chain and rule details:
            {
                'ipv4': {
                    'chain_name': [
                        {rule_details_dict1},
                        {rule_details_dict2},
                        ...
                    ]
                },
                'ipv6': {
                    'chain_name': [
                        {rule_details_dict1},
                        {rule_details_dict2},
                        ...
                    ]
                }
            }
            Returns empty dict if no chains are defined.

    The function:
    1. Reads the user's data file
    2. Creates a nested dictionary structure for IPv4 and IPv6 chains
    3. For each chain, gets all rules and their details
    4. Adds rule number to each rule's details
    5. Flashes a warning message if no chains are found
    6. Returns the assembled dictionary structure
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Create dict of defined groups
    chain_dict = {}
    try:
        for ip_version in ["ipv4", "ipv6"]:
            if ip_version in user_data:
                chain_dict[ip_version] = {}
                if "chains" in user_data[ip_version]:
                    for chain_name in user_data[ip_version]["chains"]:
                        chain_dict[ip_version][chain_name] = []
                        for rule in user_data[ip_version]["chains"][chain_name][
                            "rule-order"
                        ]:
                            rule_detail = user_data[ip_version]["chains"][chain_name][
                                rule
                            ]
                            rule_detail["number"] = rule
                            chain_dict[ip_version][chain_name].append(rule_detail)
    except:
        logging.info("Error in assemble_detail_list_of_rules")
        pass

    # If there are no groups, flash message
    if chain_dict == {}:
        flash(f"There are no chains defined.", "danger")

    return chain_dict


def assemble_list_of_rules(session):
    """
    Assembles a list of all firewall rules defined in the user's data.

    Args:
        session: The current session containing data directory and firewall name

    Returns:
        list: A list of [ip_version, chain_name, rule_number, description] for each rule.
              Returns empty list if no rules are defined.

    The function:
    1. Reads the user's data file
    2. Iterates through IPv4 and IPv6 sections
    3. For each IP version, gets all chains and their rules
    4. Creates a list entry with rule details for each rule found
    5. Flashes a warning message if no rules are found
    6. Returns the assembled list

    Example return value:
        [
            ["ipv4", "INPUT", "1", "Allow SSH"],
            ["ipv4", "OUTPUT", "10", "Allow HTTP"],
            ["ipv6", "INPUT", "5", "Block telnet"]
        ]
    """
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
    except Exception as e:
        logging.info(e)

    # If there are no rules, flash message
    if rule_list == []:
        flash(f"There are no rules defined.", "danger")

    return rule_list


def assemble_list_of_chains(session):
    """
    Assembles a list of all firewall chains defined in the user's data.

    Args:
        session: The current session containing data directory and firewall name

    Returns:
        list: A list of [ip_version, chain_name] pairs for each defined chain.
              Returns empty list if no chains are defined.

    The function:
    1. Reads the user's data file
    2. Iterates through IPv4 and IPv6 sections
    3. For each IP version, gets all defined chain names
    4. Creates a list of [ip_version, chain_name] pairs
    5. Flashes a warning message if no chains are found
    6. Returns the assembled list

    Example return value:
        [
            ["ipv4", "INPUT"],
            ["ipv4", "OUTPUT"],
            ["ipv6", "INPUT"]
        ]
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Create list of defined chains
    chain_list = []
    try:
        for ip_version in ["ipv4", "ipv6"]:
            if ip_version in user_data:
                for fw_chain in user_data[ip_version]["chains"]:
                    chain_list.append([ip_version, fw_chain])
    except Exception as e:
        logging.info(e)

    # If there are no chains, flash message
    if chain_list == []:
        flash(f"There are no chains defined.", "danger")

    return chain_list


def delete_rule_from_data(session, request):
    """
    Deletes a firewall rule from the user's data and updates the data file.

    Args:
        session: The current session containing data directory and firewall name
        request: The HTTP request containing form data with the rule to delete

    Form Parameters:
        rule: Comma-separated string containing "ip_version,chain,rule_number"

    Returns:
        None

    The function:
    1. Reads the user's data file
    2. Extracts ip_version, chain and rule number from the form data
    3. Deletes the rule from the chain and removes it from the rule order list
    4. Cleans up by removing empty chains and ip versions
    5. Writes the updated data back to file
    6. Flashes success/failure messages to the user

    Example:
        For rule="ipv4,INPUT,10":
        - Deletes rule 10 from the INPUT chain in the IPv4 firewall
        - If INPUT chain becomes empty, removes the chain
        - If IPv4 has no more chains, removes the IPv4 section
    """
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
        if not user_data[ip_version]["chains"][fw_chain]["rule-order"]:
            del user_data[ip_version]["chains"][fw_chain]
        if not user_data[ip_version]:
            del user_data[ip_version]
    except Exception as e:
        logging.info(e)

    # Write user's data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    return


def flash_ip_version_mismatch():
    """
    Displays an error message when there is a mismatch between IP versions.

    This function flashes a danger-level message to notify the user that the IP version
    of a rule does not match the IP version of the associated group object.

    Returns:
        None
    """
    flash(f"IP version of rule must match IP version of group object.", "danger")
    return


def reorder_chain_rule_in_data(session, request):
    """
    Reorders a rule within a firewall chain by assigning it a new rule number.

    Args:
        session: The current session containing data directory and firewall name
        request: The HTTP request containing form data with the rule to reorder

    Form Parameters:
        reorder_rule: Comma-separated string containing "ip_version,chain,old_rule_number"
        new_rule_number: The desired new rule number to assign

    Returns:
        str: Concatenated ip_version and chain name on success
        None: If validation fails

    Validation:
    - Rule must have 3 components (ip_version, chain, old rule number)
    - New rule number must be different from old rule number
    - New rule number must be a valid integer
    - New rule number must not already exist in the chain
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    rule = request.form["reorder_rule"].split(",")

    if len(rule) != 3:
        return None
    else:
        ip_version = rule[0]
        fw_chain = rule[1]
        old_rule_number = rule[2]
        new_rule_number = request.form["new_rule_number"].strip()

    # Get list of existing rules in chain
    existing_rule_list = user_data[ip_version]["chains"][fw_chain]["rule-order"]

    # Validate new rule number
    if old_rule_number == new_rule_number:
        flash(f"Old and new rule numbers must be different.", "danger")
        return None

    try:
        int(new_rule_number)
    except:
        flash(f"New rule number musht be an integer.", "danger")
        return None

    if new_rule_number in existing_rule_list:
        flash(f"New rule number must not already exist in the chain.", "danger")
        return None

    # Add new rule to chain in user data
    user_data[ip_version]["chains"][fw_chain][new_rule_number] = user_data[ip_version][
        "chains"
    ][fw_chain][old_rule_number]

    # Add new rule to rule-order in user data
    user_data[ip_version]["chains"][fw_chain]["rule-order"].append(new_rule_number)

    # Remove Old Rule from user data
    del user_data[ip_version]["chains"][fw_chain][old_rule_number]

    # Remove Old Rule from rule-order in user data
    user_data[ip_version]["chains"][fw_chain]["rule-order"].remove(old_rule_number)

    # Sort rule-order in user data
    user_data[ip_version]["chains"][fw_chain]["rule-order"] = sorted(
        user_data[ip_version]["chains"][fw_chain]["rule-order"], key=int
    )

    # Write user's data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    return f"{ip_version}{fw_chain}"
