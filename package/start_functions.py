"""
    Getting started support functions.

    Summarises how far a firewall configuration has been built, for the
    Getting started page's build-order steps, and builds the quick-start
    starter configuration.
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


def _rule(description, action, protocol="", **extra):
    """A chain rule in the stored format, every match field empty by default."""
    rule = {
        "description": description,
        "action": action,
        "dest_address": "",
        "dest_address_type": "address",
        "dest_port": "",
        "dest_port_type": "port",
        "source_address": "",
        "source_address_type": "address",
        "source_port": "",
        "source_port_type": "port",
        "protocol": protocol,
    }
    rule.update(extra)
    return rule


def _chain(description, default_action, rules):
    """A chain with its rules numbered 10, 20, 30... in the given order."""
    chain = {
        "rule-order": [],
        "default": {
            "description": description,
            "default_action": default_action,
            "default_logging": False,
        },
    }
    for i, rule in enumerate(rules, start=1):
        number = str(i * 10)
        chain["rule-order"].append(number)
        chain[number] = rule
    return chain


def _filter(ip_version, name, description, jumps):
    """A base filter (input/forward) that jumps to a chain per interface."""
    filt = {
        "rule-order": [],
        "description": description,
        "default-action": "accept",
        "log": False,
        "rules": {},
    }
    for i, (chain, interface, direction) in enumerate(jumps, start=1):
        number = str(i * 10)
        filt["rule-order"].append(number)
        filt["rules"][number] = {
            "ip_version": ip_version,
            "filter": name,
            "fw_chain": chain,
            "description": f"{chain} ({direction} {interface})",
            "action": "jump",
            "interface": interface,
            "direction": direction,
        }
    return filt


def build_quick_start(wan, lan, allow_wan_ping=False):
    """
    Builds a two-interface starter configuration, IPv4 and IPv6.

    Outbound is allowed and inbound blocked:
      WAN_IN     forward, in on WAN  - return traffic only, default drop
      WAN_LOCAL  input, in on WAN    - return traffic only, default drop
      LAN_IN     forward, in on LAN  - allow all
      LAN_OUT    forward, out on LAN - return traffic only (already passed
                                       WAN_IN), default accept
      LAN_LOCAL  input, in on LAN    - allow all, so DNS, DHCP and SSH to the
                                       firewall keep working from the LAN

    IPv6 cannot work without ICMPv6 (neighbour discovery, router
    advertisements) and DHCPv6 replies, so the IPv6 WAN_LOCAL also accepts
    ICMPv6 and UDP to port 546. Accepting all ICMPv6 also answers IPv6 ping;
    allow_wan_ping adds the matching IPv4 rule.

    Args:
        wan (str): WAN interface name, e.g. "eth0"
        lan (str): LAN interface name, e.g. "eth1"
        allow_wan_ping (bool): accept ICMP echo to the firewall from the WAN

    Returns:
        dict: a complete configuration document
    """
    def established():
        return _rule("Allow established/related", "accept", state_est=True, state_rel=True)

    def invalid():
        return _rule("Drop invalid", "drop", state_inv=True)

    data = {
        "version": "1",
        # Marks the config as quick-start generated; anonymous telemetry reports
        # only whether any such config exists (see telemetry_collect).
        "origin": "quick_start",
        "system": {"hostname": "None", "port": "None"},
        "interfaces": [
            {"name": wan, "description": "WAN", "type": "public_wan"},
            {"name": lan, "description": "LAN", "type": "lan"},
        ],
    }
    for ip_version in ("ipv4", "ipv6"):
        wan_local = [established(), invalid()]
        if ip_version == "ipv6":
            wan_local += [
                _rule("Allow ICMPv6 (needed for IPv6)", "accept", "icmp"),
                _rule("Allow DHCPv6 replies", "accept", "udp", dest_port="546"),
            ]
        elif allow_wan_ping:
            wan_local.append(_rule("Allow ping", "accept", "icmp"))

        data[ip_version] = {
            "chains": {
                "WAN_IN": _chain("WAN inbound to LAN", "drop", [established(), invalid()]),
                "WAN_LOCAL": _chain("WAN inbound to the firewall", "drop", wan_local),
                "LAN_IN": _chain("LAN outbound", "accept", [_rule("Allow all from LAN", "accept")]),
                "LAN_OUT": _chain("Traffic out to the LAN", "accept", [established(), invalid()]),
                "LAN_LOCAL": _chain("LAN to the firewall", "accept", [_rule("Allow all from LAN", "accept")]),
            },
            "filters": {
                "input": _filter(ip_version, "input", "Input Filter", [
                    ("WAN_LOCAL", wan, "inbound"),
                    ("LAN_LOCAL", lan, "inbound"),
                ]),
                "forward": _filter(ip_version, "forward", "Forward Filter", [
                    ("WAN_IN", wan, "inbound"),
                    ("LAN_IN", lan, "inbound"),
                    ("LAN_OUT", lan, "outbound"),
                ]),
            },
        }
    return data
