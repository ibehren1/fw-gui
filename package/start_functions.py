"""
    Getting started support functions.

    Summarises how far a firewall configuration has been built, for the
    Getting started page's build-order steps.
"""

from package.data_file_functions import read_user_data_file


def config_progress(session):
    """
    Counts what the selected configuration already contains.

    Args:
        session: Flask session with data_dir and firewall_name

    Returns:
        dict: interfaces, groups, chains, chain_rules, filters, filter_rules
              and extra_items as counts (both IP versions together), and
              hostname_set, True once a firewall hostname has been entered.
    """
    # read_user_data_file returns None when the config document is missing.
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}') or {}

    progress = {
        "interfaces": len(user_data.get("interfaces", [])),
        "groups": 0,
        "chains": 0,
        "chain_rules": 0,
        "filters": 0,
        "filter_rules": 0,
        "extra_items": len(user_data.get("extra-items", [])),
    }
    for ip_version in ("ipv4", "ipv6"):
        version = user_data.get(ip_version, {})
        progress["groups"] += len(version.get("groups", {}))
        for chain in version.get("chains", {}).values():
            progress["chains"] += 1
            progress["chain_rules"] += len(chain.get("rule-order", []))
        for filt in version.get("filters", {}).values():
            progress["filters"] += 1
            progress["filter_rules"] += len(filt.get("rule-order", []))

    hostname = user_data.get("system", {}).get("hostname")
    progress["hostname_set"] = bool(hostname) and hostname != "None"
    return progress
