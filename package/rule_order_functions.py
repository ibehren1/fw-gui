"""
    Rule ordering support functions.

    This module provides the shared logic used to renumber firewall rules within
    a chain or a filter.  VyOS evaluates rules in numerical order, so changing a
    rule's number is what changes its precedence.

    Three operations are supported:
    - Swapping a rule with its neighbour (move up / move down)
    - Assigning a rule an explicit new number, shifting any rules in the way
    - Resequencing every rule in a chain/filter to 10, 20, 30, ...

    The functions here are deliberately session-free and operate on two dicts so
    that both the flat chain layout and the nested filter layout can reuse them:
    - rules: the dict whose keys are rule numbers
    - owner: the dict that holds the "rule-order" list

    For chains both arguments are the chain dict itself; for filters rules is
    filter_dict["rules"] and owner is filter_dict.

    Dependencies:
    - logging: For logging functionality
"""

import logging

# Upper bound on a rule number, matching the limit enforced by the rule add form.
MAX_RULE_NUMBER = 999999

# Default gap used when resequencing all rules in a chain or filter.
RESEQUENCE_STEP = 10


def sorted_rule_order(rule_order):
    """
    Returns the rule order list sorted numerically.

    Args:
        rule_order: List of rule numbers as strings

    Returns:
        list: The rule numbers sorted by integer value
    """
    return sorted(rule_order, key=int)


def build_swap_map(rule_order, rule_number, direction):
    """
    Builds the renumber map that swaps a rule with its adjacent neighbour.

    Args:
        rule_order: List of rule numbers as strings
        rule_number: The rule number to move
        direction: Either "up" (towards a lower number) or "down"

    Returns:
        dict: Mapping of old rule number to new rule number
        None: If the rule cannot move any further, or the inputs are invalid

    Raises:
        ValueError: If the rule number is not present or direction is unknown
    """
    order = sorted_rule_order(rule_order)

    if rule_number not in order:
        raise ValueError(f"Rule {rule_number} does not exist.")

    if direction not in ("up", "down"):
        raise ValueError("Direction must be either up or down.")

    index = order.index(rule_number)
    neighbor_index = index - 1 if direction == "up" else index + 1

    # Already at the top or the bottom of the chain; nothing to do.
    if neighbor_index < 0 or neighbor_index >= len(order):
        return None

    neighbor = order[neighbor_index]

    return {rule_number: neighbor, neighbor: rule_number}


def build_renumber_map(rule_order, old_rule_number, new_rule_number):
    """
    Builds the renumber map that moves a rule to an explicit new number.

    When the requested number is already taken, that rule — and any rules
    immediately following it with no gap between them — are each shifted up by
    one to make room.  Rules beyond the first gap are left alone.

    Args:
        rule_order: List of rule numbers as strings
        old_rule_number: The rule number being moved
        new_rule_number: The requested new rule number

    Returns:
        dict: Mapping of old rule number to new rule number

    Raises:
        ValueError: If the rule does not exist, the new number is not a valid
            rule number, the number is unchanged, or the shift would push a rule
            past MAX_RULE_NUMBER
    """
    order = sorted_rule_order(rule_order)

    if old_rule_number not in order:
        raise ValueError(f"Rule {old_rule_number} does not exist.")

    if old_rule_number == new_rule_number:
        raise ValueError("Old and new rule numbers must be different.")

    try:
        target = int(new_rule_number)
    except (TypeError, ValueError):
        raise ValueError("New rule number must be an integer.")

    if target < 1 or target > MAX_RULE_NUMBER:
        raise ValueError(f"New rule number must be between 1 and {MAX_RULE_NUMBER}.")

    # Normalize so that "010" and "10" are treated as the same number.
    renumber_map = {old_rule_number: str(target)}

    # Walk the remaining rules from the target upwards, shifting each rule that
    # sits exactly where the previous rule landed.  The first gap ends the cascade.
    occupied = sorted(
        (int(rule) for rule in order if rule != old_rule_number),
    )
    current = target
    for rule in occupied:
        if rule < target:
            continue
        if rule != current:
            break
        current = rule + 1
        if current > MAX_RULE_NUMBER:
            raise ValueError(
                f"Renumbering would push a rule past {MAX_RULE_NUMBER}. "
                "Resequence the rules first."
            )
        renumber_map[str(rule)] = str(current)

    return renumber_map


def build_resequence_map(rule_order, step=RESEQUENCE_STEP):
    """
    Builds the renumber map that rewrites every rule number to step, 2*step, ...

    Relative order is preserved.

    Args:
        rule_order: List of rule numbers as strings
        step: Gap between consecutive rule numbers

    Returns:
        dict: Mapping of old rule number to new rule number, containing only the
            rules whose number actually changes

    Raises:
        ValueError: If resequencing would push a rule past MAX_RULE_NUMBER
    """
    order = sorted_rule_order(rule_order)

    if len(order) * step > MAX_RULE_NUMBER:
        raise ValueError(
            f"Too many rules to resequence with a gap of {step}.",
        )

    renumber_map = {}
    for index, rule in enumerate(order):
        new_rule_number = str((index + 1) * step)
        if new_rule_number != rule:
            renumber_map[rule] = new_rule_number

    return renumber_map


def apply_renumber_map(rules, owner, renumber_map):
    """
    Applies a renumber map to a chain or filter in place.

    All rules being moved are removed before any are re-inserted so that swaps
    and cascading shifts cannot overwrite one another.

    Args:
        rules: Dict whose keys are rule numbers
        owner: Dict holding the "rule-order" list
        renumber_map: Mapping of old rule number to new rule number

    Returns:
        None
    """
    if not renumber_map:
        return

    # Remove every rule being moved before re-inserting any of them.
    moved = {}
    for old_rule_number, new_rule_number in renumber_map.items():
        moved[new_rule_number] = rules.pop(old_rule_number)

    rules.update(moved)

    rule_order = [
        renumber_map.get(rule, rule) for rule in owner.get("rule-order", [])
    ]
    owner["rule-order"] = sorted_rule_order(rule_order)

    logging.debug(f"Applied rule renumber map: {renumber_map}")

    return
