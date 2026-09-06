"""
    Filter Support Functions

    This module provides functions for managing firewall filters and rules.
    Contains functions for:
    - Adding filter rules to data
    - Adding new filters
    - Assembling lists of filters and rules
    - Deleting filter rules
    - Reordering filter rules

    The functions interact with user data files that store firewall configurations.
"""

import logging

from flask import flash

from package.data_file_functions import read_user_data_file, write_user_data_file
from package.rule_order_functions import (
    apply_renumber_map,
    build_renumber_map,
    build_resequence_map,
    build_swap_map,
    RESEQUENCE_STEP,
)


def add_filter_rule_to_data(session, request):
    """
    Adds a new filter rule to the user's firewall configuration.

    Args:
        session: Flask session object containing data directory and firewall name
        request: Flask request object containing form data for the new rule

    The function:
    - Extracts rule details from the request form
    - Creates a rule dictionary with the configuration
    - Adds the rule to the user's data structure
    - Updates the rule ordering
    - Writes changes back to the data file
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    rule = request.form["rule"]
    rule_dict = {}
    filter_info = request.form["filter"].split(",")
    ip_version = filter_info[0]
    filter = filter_info[1]
    rule_dict["ip_version"] = ip_version
    rule_dict["filter"] = filter
    # rule_dict["fw_chain"] = jump_target[1]
    rule_dict["description"] = request.form["description"]
    if "rule_disable" in request.form:
        rule_dict["rule_disable"] = True
    if "logging" in request.form:
        rule_dict["log"] = True
    rule_dict["action"] = request.form["action"]
    if request.form["action"] == "jump":
        jump_target = request.form["jump_target"].split(",")
        rule_dict["fw_chain"] = jump_target[1]
        rule_dict["interface"] = request.form["interface"]
        rule_dict["direction"] = request.form["direction"]
    if request.form["action"] == "offload":
        rule_dict["fw_chain"] = request.form["offload_target"]

    # Check and create higher level data structure if it does not exist
    # (mirror the chain path so adding a rule to a missing filter cannot KeyError)
    if ip_version not in user_data:
        user_data[ip_version] = {}
    if "filters" not in user_data[ip_version]:
        user_data[ip_version]["filters"] = {}
    if filter not in user_data[ip_version]["filters"]:
        user_data[ip_version]["filters"][filter] = {}
    if "rule-order" not in user_data[ip_version]["filters"][filter]:
        user_data[ip_version]["filters"][filter]["rule-order"] = []
    if "rules" not in user_data[ip_version]["filters"][filter]:
        user_data[ip_version]["filters"][filter]["rules"] = {}

    # Add rule to data structure
    user_data[ip_version]["filters"][filter]["rules"][rule] = rule_dict

    # Add rule to rule-order in user data
    if rule not in user_data[ip_version]["filters"][filter]["rule-order"]:
        user_data[ip_version]["filters"][filter]["rule-order"].append(rule)

    # Sort rule-order in user data
    user_data[ip_version]["filters"][filter]["rule-order"] = sorted(
        user_data[ip_version]["filters"][filter]["rule-order"], key=int
    )

    # logging.info(json.dumps(user_data, indent=4))

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"Rule {rule} added to filter {ip_version}/{filter}.", "success")

    return


def add_filter_to_data(session, request):
    """
    Adds a new filter to the user's firewall configuration.

    Args:
        session: Flask session object containing data directory and firewall name
        request: Flask request object containing form data for the new filter

    The function:
    - Extracts filter details from the request form
    - Creates necessary data structures if they don't exist
    - Adds the filter configuration
    - Writes changes back to the data file
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

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
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(f"Filter {ip_version}/{type} added.", "success")

    return


def assemble_detail_list_of_filters(session):
    """
    Creates a detailed dictionary of all filters and their rules.

    Args:
        session: Flask session object containing data directory and firewall name

    Returns:
        Dictionary containing filter details organized by IP version and filter name
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Create list of defined filters
    filter_dict = {}
    for ip_version in ["ipv4", "ipv6"]:
        try:
            if ip_version in user_data:
                filter_dict[ip_version] = {}
                if "filters" in user_data[ip_version]:
                    for filter_name in user_data[ip_version]["filters"]:
                        filter_dict[ip_version][filter_name] = []
                        for rule in user_data[ip_version]["filters"][filter_name][
                            "rule-order"
                        ]:
                            rule_detail = user_data[ip_version]["filters"][filter_name][
                                "rules"
                            ][rule]
                            rule_detail["number"] = rule
                            filter_dict[ip_version][filter_name].append(rule_detail)
        except Exception:
            logging.info("Error in assemble_detail_list_of_rules")
            pass

    # If there are no filters, flash message
    if filter_dict == {}:
        flash("There are no filters defined.", "danger")

    return filter_dict


def assemble_list_of_filters(session):
    """
    Creates a simple list of all defined filters.

    Args:
        session: Flask session object containing data directory and firewall name

    Returns:
        List of [ip_version, filter_type] pairs for each defined filter
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Create list of defined filters
    filter_list = []
    for ip_version in ["ipv4", "ipv6"]:
        try:
            if ip_version in user_data:
                for type in user_data[ip_version]["filters"]:
                    filter_list.append([ip_version, type])
        except Exception as e:
            logging.info(e)

    # If there are no filters, flash message
    if filter_list == []:
        flash("There are no filters defined.", "danger")

    return filter_list


def assemble_list_of_filter_rules(session):
    """
    Creates a list of all filter rules.

    Args:
        session: Flask session object containing data directory and firewall name

    Returns:
        List of [ip_version, filter, rule_number, description] for each rule
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

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
    except Exception as e:
        logging.info(e)

    # If there are no rules, flash message
    if rule_list == []:
        flash("There are no filter rules defined.", "danger")

    return rule_list


def delete_filter_rule_from_data(session, request):
    """
    Deletes a filter rule from the configuration.

    Args:
        session: Flask session object containing data directory and firewall name
        request: Flask request object containing the rule to delete

    The function:
    - Removes the rule from the data structure
    - Cleans up empty data structures
    - Writes changes back to the data file
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

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
    except Exception:
        flash(
            f"Failed to delete rule {rule} from filter {ip_version}/{filter}.",
            "danger",
        )
        pass

    # Clean-up data — intentionally removes the entire filter (including defaults)
    # when the last rule is deleted, as empty filters are not desired.
    try:
        if not user_data[ip_version]["filters"][filter]["rule-order"]:
            del user_data[ip_version]["filters"][filter]
        if not user_data[ip_version]["filters"]:
            del user_data[ip_version]["filters"]
        if not user_data[ip_version]:
            del user_data[ip_version]
    except Exception as e:
        logging.info(e)

    # Write user's data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    return


def reorder_filter_rule_in_data(session, request):
    """
    Changes the order number of a filter rule.

    Args:
        session: Flask session object containing data directory and firewall name
        request: Flask request object containing the rule to reorder and new position

    The function:
    - Validates the new rule number
    - Updates the rule ordering
    - Writes changes back to the data file

    If the new rule number is already in use, that rule — and any rules directly
    following it with no gap in between — are each shifted up by one to make room.
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    rule = request.form["reorder_rule"].split(",")

    if len(rule) != 3:
        return None
    else:
        ip_version = rule[0]
        filter = rule[1]
        old_rule_number = rule[2]
        new_rule_number = request.form["new_rule_number"].strip()

    fw_filter = _get_filter(user_data, ip_version, filter)
    if fw_filter is None:
        return None

    # Build the map of rule number changes, shifting rules that are in the way
    try:
        renumber_map = build_renumber_map(
            fw_filter["rule-order"], old_rule_number, new_rule_number
        )
    except ValueError as e:
        flash(str(e), "danger")
        return None

    # Apply the renumbering to the filter in user data
    apply_renumber_map(fw_filter["rules"], fw_filter, renumber_map)

    # Write user's data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(
        f"Renumbered rule {old_rule_number} to {new_rule_number} "
        f"in filter {ip_version}/{filter}.",
        "success",
    )

    return f"{ip_version}{filter}"


def move_filter_rule_in_data(session, request):
    """
    Moves a rule up or down within a filter by swapping rule numbers.

    Args:
        session: Flask session object containing data directory and firewall name
        request: Flask request object containing the rule to move and the direction

    Form Parameters:
        move_rule: Comma-separated string containing "ip_version,filter,rule_number"
        direction: Either "up" (towards a lower rule number) or "down"

    Returns:
        str: Concatenated ip_version and filter name on success
        None: If validation fails

    The moved rule and its neighbour exchange rule numbers, so no other rule in
    the filter is affected.  Moving the first rule up, or the last rule down, does
    nothing.
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    rule = request.form["move_rule"].split(",")

    if len(rule) != 3:
        return None
    else:
        ip_version = rule[0]
        filter = rule[1]
        rule_number = rule[2]
        direction = request.form["direction"].strip()

    fw_filter = _get_filter(user_data, ip_version, filter)
    if fw_filter is None:
        return None

    # Build the map that swaps this rule with its neighbour
    try:
        renumber_map = build_swap_map(fw_filter["rule-order"], rule_number, direction)
    except ValueError as e:
        flash(str(e), "danger")
        return None

    # Rule is already at the top or bottom of the filter
    if not renumber_map:
        return f"{ip_version}{filter}"

    # Apply the renumbering to the filter in user data
    apply_renumber_map(fw_filter["rules"], fw_filter, renumber_map)

    # Write user's data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(
        f"Moved rule {rule_number} {direction} in filter {ip_version}/{filter}.",
        "success",
    )

    return f"{ip_version}{filter}"


def resequence_filter_rules_in_data(session, request):
    """
    Resequences every rule in a filter to 10, 20, 30, ...

    Args:
        session: Flask session object containing data directory and firewall name
        request: Flask request object containing the filter to resequence

    Form Parameters:
        filter: Comma-separated string containing "ip_version,filter"

    Returns:
        str: Concatenated ip_version and filter name on success
        None: If validation fails

    Relative rule order is preserved; only the rule numbers change.  This is used
    to restore gaps in a filter whose rule numbers have been used up.
    """
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Set local vars from posted form data
    filter_parts = request.form["filter"].split(",")

    if len(filter_parts) != 2:
        return None
    else:
        ip_version = filter_parts[0]
        filter = filter_parts[1]

    fw_filter = _get_filter(user_data, ip_version, filter)
    if fw_filter is None:
        return None

    # Build the map of rule number changes
    try:
        renumber_map = build_resequence_map(fw_filter["rule-order"], RESEQUENCE_STEP)
    except ValueError as e:
        flash(str(e), "danger")
        return None

    # Rules are already sequenced
    if not renumber_map:
        flash(
            f"Rules in filter {ip_version}/{filter} are already sequenced by "
            f"{RESEQUENCE_STEP}.",
            "warning",
        )
        return f"{ip_version}{filter}"

    # Apply the renumbering to the filter in user data
    apply_renumber_map(fw_filter["rules"], fw_filter, renumber_map)

    # Write user's data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)

    flash(
        f"Resequenced rules in filter {ip_version}/{filter} by {RESEQUENCE_STEP}.",
        "success",
    )

    return f"{ip_version}{filter}"


def _get_filter(user_data, ip_version, filter):
    """
    Returns the filter dict for the given ip version and filter name.

    Args:
        user_data: The user's firewall data
        ip_version: Either "ipv4" or "ipv6"
        filter: Name of the filter

    Returns:
        dict: The filter, including its rule-order list and rules
        None: If the filter does not exist or is missing rule-order or rules
    """
    try:
        fw_filter = user_data[ip_version]["filters"][filter]
        fw_filter["rule-order"]
        fw_filter["rules"]
    except (KeyError, TypeError):
        flash(f"Filter {ip_version}/{filter} does not exist.", "danger")
        return None

    return fw_filter
