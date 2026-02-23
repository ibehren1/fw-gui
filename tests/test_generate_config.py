"""
Tests for package/generate_config.py

Covers download_json_data, generate_config with empty data, extra items,
flowtables, IPv4/IPv6 groups, filters (jump/offload/disable/log),
chains (addresses, ports, protocol, states, logging, disable),
IPv6 icmp conversion, diff mode, and full example data.
"""

import copy
import json

import pytest

from package.generate_config import download_json_data, generate_config


# ---------------------------------------------------------------------------
# Helper: minimal chain rule with all required fields
# ---------------------------------------------------------------------------
def _make_chain_rule(
    description="",
    action="accept",
    dest_address="",
    dest_address_type="address",
    dest_port="",
    dest_port_type="port",
    source_address="",
    source_address_type="address",
    source_port="",
    source_port_type="port",
    protocol="",
    **extra,
):
    rule = {
        "description": description,
        "action": action,
        "dest_address": dest_address,
        "dest_address_type": dest_address_type,
        "dest_port": dest_port,
        "dest_port_type": dest_port_type,
        "source_address": source_address,
        "source_address_type": source_address_type,
        "source_port": source_port,
        "source_port_type": source_port_type,
        "protocol": protocol,
    }
    rule.update(extra)
    return rule


# ---------------------------------------------------------------------------
# Fixture: patch only read_user_data_file (generate_config has no write)
# ---------------------------------------------------------------------------
@pytest.fixture
def patch_read(monkeypatch):
    """Patches read_user_data_file in package.generate_config to return data.

    Usage:
        patch_read(data)
    """

    def _factory(data):
        monkeypatch.setattr(
            "package.generate_config.read_user_data_file",
            lambda *args, **kwargs: copy.deepcopy(data),
        )

    return _factory


# ===========================================================================
# download_json_data
# ===========================================================================
def test_download_json_data(mock_session, patch_read):
    """download_json_data returns a valid JSON string of the user data."""
    data = {"ipv4": {"chains": {}}, "some_key": [1, 2, 3]}
    patch_read(data)

    result = download_json_data(mock_session)

    parsed = json.loads(result)
    assert parsed["some_key"] == [1, 2, 3]
    assert "ipv4" in parsed


# ===========================================================================
# generate_config -- empty data
# ===========================================================================
def test_generate_config_empty(mock_session, patch_read):
    """Empty user data returns 'Empty rule set...' message."""
    patch_read({})

    message, config = generate_config(mock_session)

    assert len(config) == 1
    assert "Empty rule set" in config[0]
    assert "Empty rule set" in message


# ===========================================================================
# generate_config -- extra items
# ===========================================================================
def test_generate_config_extra_items(mock_session, patch_read):
    """Extra configuration items appear in the output."""
    data = {
        "extra-items": [
            "set system host-name router1",
            "set service ssh port 22",
        ]
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "#\n#\n# Extra Configuration Items\n#\n#" in config
    assert "set system host-name router1" in config
    assert "set service ssh port 22" in config


# ===========================================================================
# generate_config -- flowtables
# ===========================================================================
def test_generate_config_flowtables(mock_session, patch_read):
    """Flowtable commands include interface, description, and offload."""
    data = {
        "flowtables": [
            {
                "name": "ft1",
                "description": "Test flowtable",
                "interfaces": ["eth0", "eth1"],
            }
        ]
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "# Flowtable: ft1" in config
    assert "set firewall flowtable ft1 interface 'eth0'" in config
    assert "set firewall flowtable ft1 interface 'eth1'" in config
    assert "set firewall flowtable ft1 description 'Test flowtable'" in config
    assert "set firewall flowtable ft1 offload software" in config


# ===========================================================================
# generate_config -- IPv4 groups
# ===========================================================================
def test_generate_config_ipv4_address_group(mock_session, patch_read):
    """IPv4 address-group generates description and address entries."""
    data = {
        "ipv4": {
            "groups": {
                "SERVERS": {
                    "group_desc": "Server addresses",
                    "group_type": "address-group",
                    "group_value": ["10.0.0.1", "10.0.0.2"],
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall group address-group SERVERS description 'Server addresses'" in config
    assert "set firewall group address-group SERVERS address '10.0.0.1'" in config
    assert "set firewall group address-group SERVERS address '10.0.0.2'" in config


def test_generate_config_ipv4_port_group(mock_session, patch_read):
    """IPv4 port-group generates port entries."""
    data = {
        "ipv4": {
            "groups": {
                "WEB_PORTS": {
                    "group_desc": "Web ports",
                    "group_type": "port-group",
                    "group_value": ["80", "443"],
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall group port-group WEB_PORTS description 'Web ports'" in config
    assert "set firewall group port-group WEB_PORTS port '80'" in config
    assert "set firewall group port-group WEB_PORTS port '443'" in config


def test_generate_config_ipv4_network_group(mock_session, patch_read):
    """IPv4 network-group generates network entries."""
    data = {
        "ipv4": {
            "groups": {
                "LAN_NETS": {
                    "group_desc": "LAN networks",
                    "group_type": "network-group",
                    "group_value": ["10.0.0.0/24", "192.168.1.0/24"],
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall group network-group LAN_NETS description 'LAN networks'" in config
    assert "set firewall group network-group LAN_NETS network '10.0.0.0/24'" in config
    assert "set firewall group network-group LAN_NETS network '192.168.1.0/24'" in config


def test_generate_config_ipv4_domain_group(mock_session, patch_read):
    """IPv4 domain-group generates address entries (value_type is 'address')."""
    data = {
        "ipv4": {
            "groups": {
                "BLOCKED_DOMAINS": {
                    "group_desc": "Blocked domains",
                    "group_type": "domain-group",
                    "group_value": ["example.com", "bad.org"],
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall group domain-group BLOCKED_DOMAINS description 'Blocked domains'" in config
    assert "set firewall group domain-group BLOCKED_DOMAINS address 'example.com'" in config
    assert "set firewall group domain-group BLOCKED_DOMAINS address 'bad.org'" in config


# ===========================================================================
# generate_config -- IPv6 groups
# ===========================================================================
def test_generate_config_ipv6_group(mock_session, patch_read):
    """IPv6 groups use ipv6-{type} prefix in the command."""
    data = {
        "ipv6": {
            "groups": {
                "V6_SERVERS": {
                    "group_desc": "IPv6 servers",
                    "group_type": "address-group",
                    "group_value": ["fc00::1", "fc00::2"],
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall group ipv6-address-group V6_SERVERS description 'IPv6 servers'" in config
    assert "set firewall group ipv6-address-group V6_SERVERS address 'fc00::1'" in config
    assert "set firewall group ipv6-address-group V6_SERVERS address 'fc00::2'" in config


# ===========================================================================
# generate_config -- filters
# ===========================================================================
def test_generate_config_filter_jump(mock_session, patch_read):
    """Filter rule with jump action generates interface direction and jump-target."""
    data = {
        "ipv4": {
            "filters": {
                "input": {
                    "rule-order": ["10"],
                    "description": "Input filter",
                    "default-action": "accept",
                    "log": False,
                    "rules": {
                        "10": {
                            "description": "Jump to WAN_LOCAL",
                            "action": "jump",
                            "interface": "eth0",
                            "direction": "inbound",
                            "fw_chain": "WAN_LOCAL",
                        }
                    },
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall ipv4 input filter rule 10 action 'jump'" in config
    assert "set firewall ipv4 input filter rule 10 inbound-interface name 'eth0'" in config
    assert "set firewall ipv4 input filter rule 10 jump-target 'WAN_LOCAL'" in config
    assert "set firewall ipv4 input filter rule 10 description 'Jump to WAN_LOCAL'" in config


def test_generate_config_filter_outbound_jump(mock_session, patch_read):
    """Filter rule with outbound direction generates outbound-interface."""
    data = {
        "ipv4": {
            "filters": {
                "output": {
                    "rule-order": ["5"],
                    "description": "Output filter",
                    "default-action": "drop",
                    "log": False,
                    "rules": {
                        "5": {
                            "description": "Outbound jump",
                            "action": "jump",
                            "interface": "eth1",
                            "direction": "outbound",
                            "fw_chain": "LAN_OUT",
                        }
                    },
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall ipv4 output filter rule 5 outbound-interface name 'eth1'" in config
    assert "set firewall ipv4 output filter rule 5 jump-target 'LAN_OUT'" in config


def test_generate_config_filter_offload(mock_session, patch_read):
    """Filter rule with offload action generates offload-target."""
    data = {
        "ipv4": {
            "filters": {
                "forward": {
                    "rule-order": ["20"],
                    "description": "Forward filter",
                    "default-action": "accept",
                    "log": False,
                    "rules": {
                        "20": {
                            "description": "Offload to ft1",
                            "action": "offload",
                            "fw_chain": "ft1",
                        }
                    },
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall ipv4 forward filter rule 20 action 'offload'" in config
    assert "set firewall ipv4 forward filter rule 20 offload-target 'ft1'" in config


def test_generate_config_filter_disable_and_log(mock_session, patch_read):
    """Filter rule with disable and log flags generates both commands."""
    data = {
        "ipv4": {
            "filters": {
                "forward": {
                    "rule-order": ["10"],
                    "description": "Forward filter",
                    "default-action": "drop",
                    "log": True,
                    "rules": {
                        "10": {
                            "description": "Disabled logged rule",
                            "action": "jump",
                            "interface": "eth0",
                            "direction": "inbound",
                            "fw_chain": "TEST",
                            "rule_disable": True,
                            "log": True,
                        }
                    },
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall ipv4 forward filter rule 10 disable" in config
    assert "set firewall ipv4 forward filter rule 10 log" in config
    # The filter-level default-log should also be present
    assert "set firewall ipv4 forward filter enable-default-log" in config


# ===========================================================================
# generate_config -- chains
# ===========================================================================
def test_generate_config_chain_basic(mock_session, patch_read):
    """Chain with default action and description is generated correctly."""
    data = {
        "ipv4": {
            "chains": {
                "WAN_LOCAL": {
                    "rule-order": [],
                    "default": {
                        "description": "WAN to local",
                        "default_action": "drop",
                    },
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall ipv4 name WAN_LOCAL description 'WAN to local'" in config
    assert "set firewall ipv4 name WAN_LOCAL default-action 'drop'" in config


def test_generate_config_chain_default_logging(mock_session, patch_read):
    """Chain with default_logging=True generates default-log command."""
    data = {
        "ipv4": {
            "chains": {
                "WAN_LOCAL": {
                    "rule-order": [],
                    "default": {
                        "description": "WAN to local",
                        "default_action": "drop",
                        "default_logging": True,
                    },
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall ipv4 name WAN_LOCAL default-log" in config


def test_generate_config_chain_rule_addresses(mock_session, patch_read):
    """Chain rule with various destination/source address types."""
    data = {
        "ipv4": {
            "chains": {
                "TEST_CHAIN": {
                    "rule-order": ["10", "20", "30", "40", "50"],
                    "default": {
                        "description": "Test",
                        "default_action": "drop",
                    },
                    "10": _make_chain_rule(
                        description="Plain address dest",
                        dest_address="10.0.0.1",
                        dest_address_type="address",
                    ),
                    "20": _make_chain_rule(
                        description="Address group dest",
                        dest_address="SERVERS",
                        dest_address_type="address_group",
                    ),
                    "30": _make_chain_rule(
                        description="Domain group source",
                        source_address="BLOCKED",
                        source_address_type="domain_group",
                    ),
                    "40": _make_chain_rule(
                        description="Mac group source",
                        source_address="TRUSTED_MACS",
                        source_address_type="mac_group",
                    ),
                    "50": _make_chain_rule(
                        description="Network group dest",
                        dest_address="LAN_NETS",
                        dest_address_type="network_group",
                    ),
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    # Rule 10: plain dest address
    assert "set firewall ipv4 name TEST_CHAIN rule 10 destination address '10.0.0.1'" in config

    # Rule 20: dest address-group
    assert "set firewall ipv4 name TEST_CHAIN rule 20 destination group address-group 'SERVERS'" in config

    # Rule 30: source domain-group
    assert "set firewall ipv4 name TEST_CHAIN rule 30 source group domain-group 'BLOCKED'" in config

    # Rule 40: source mac-group
    assert "set firewall ipv4 name TEST_CHAIN rule 40 source group mac-group 'TRUSTED_MACS'" in config

    # Rule 50: dest network-group
    assert "set firewall ipv4 name TEST_CHAIN rule 50 destination group network-group 'LAN_NETS'" in config


def test_generate_config_chain_rule_ports(mock_session, patch_read):
    """Chain rule with destination/source port and port-group types."""
    data = {
        "ipv4": {
            "chains": {
                "PORT_CHAIN": {
                    "rule-order": ["10", "20"],
                    "default": {
                        "description": "Test",
                        "default_action": "drop",
                    },
                    "10": _make_chain_rule(
                        description="Plain ports",
                        dest_port="443",
                        dest_port_type="port",
                        source_port="1024",
                        source_port_type="port",
                    ),
                    "20": _make_chain_rule(
                        description="Port groups",
                        dest_port="WEB_PORTS",
                        dest_port_type="port_group",
                        source_port="HIGH_PORTS",
                        source_port_type="port_group",
                    ),
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    # Rule 10: plain ports
    assert "set firewall ipv4 name PORT_CHAIN rule 10 destination port '443'" in config
    assert "set firewall ipv4 name PORT_CHAIN rule 10 source port '1024'" in config

    # Rule 20: port groups
    assert "set firewall ipv4 name PORT_CHAIN rule 20 destination group port-group 'WEB_PORTS'" in config
    assert "set firewall ipv4 name PORT_CHAIN rule 20 source group port-group 'HIGH_PORTS'" in config


def test_generate_config_chain_rule_protocol(mock_session, patch_read):
    """Chain rule with protocol generates protocol command."""
    data = {
        "ipv4": {
            "chains": {
                "PROTO_CHAIN": {
                    "rule-order": ["10"],
                    "default": {
                        "description": "Test",
                        "default_action": "drop",
                    },
                    "10": _make_chain_rule(
                        description="TCP rule",
                        protocol="tcp",
                    ),
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall ipv4 name PROTO_CHAIN rule 10 protocol 'tcp'" in config


def test_generate_config_chain_rule_states(mock_session, patch_read):
    """Chain rule with state flags generates state commands."""
    data = {
        "ipv4": {
            "chains": {
                "STATE_CHAIN": {
                    "rule-order": ["10"],
                    "default": {
                        "description": "Test",
                        "default_action": "drop",
                    },
                    "10": _make_chain_rule(
                        description="Stateful rule",
                        state_est=True,
                        state_inv=True,
                        state_new=True,
                        state_rel=True,
                    ),
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall ipv4 name STATE_CHAIN rule 10 state 'established'" in config
    assert "set firewall ipv4 name STATE_CHAIN rule 10 state 'invalid'" in config
    assert "set firewall ipv4 name STATE_CHAIN rule 10 state 'new'" in config
    assert "set firewall ipv4 name STATE_CHAIN rule 10 state 'related'" in config


def test_generate_config_chain_rule_logging_and_disable(mock_session, patch_read):
    """Chain rule with logging and disable flags."""
    data = {
        "ipv4": {
            "chains": {
                "LOG_CHAIN": {
                    "rule-order": ["10"],
                    "default": {
                        "description": "Test",
                        "default_action": "drop",
                    },
                    "10": _make_chain_rule(
                        description="Logged disabled rule",
                        action="drop",
                        logging=True,
                        rule_disable=True,
                    ),
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall ipv4 name LOG_CHAIN rule 10 log" in config
    assert "set firewall ipv4 name LOG_CHAIN rule 10 disable" in config


# ===========================================================================
# generate_config -- IPv6 icmp conversion
# ===========================================================================
def test_generate_config_ipv6_icmp_conversion(mock_session, patch_read):
    """IPv6 chain rule with protocol 'icmp' is converted to 'ipv6-icmp'."""
    data = {
        "ipv6": {
            "chains": {
                "V6_CHAIN": {
                    "rule-order": ["10"],
                    "default": {
                        "description": "IPv6 chain",
                        "default_action": "drop",
                    },
                    "10": _make_chain_rule(
                        description="Allow ICMPv6",
                        protocol="icmp",
                    ),
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session)

    assert "set firewall ipv6 name V6_CHAIN rule 10 protocol 'ipv6-icmp'" in config
    # Ensure raw 'icmp' does NOT appear in the ipv6 protocol line
    assert "set firewall ipv6 name V6_CHAIN rule 10 protocol 'icmp'" not in config


# ===========================================================================
# generate_config -- diff mode
# ===========================================================================
def test_generate_config_diff_mode(mock_session, patch_read):
    """diff=True returns (message, config) with same format as normal mode."""
    data = {
        "ipv4": {
            "chains": {
                "DIFF_CHAIN": {
                    "rule-order": ["10"],
                    "default": {
                        "description": "Diff test",
                        "default_action": "accept",
                    },
                    "10": _make_chain_rule(
                        description="Diff rule",
                        action="accept",
                    ),
                }
            }
        }
    }
    patch_read(data)

    message, config = generate_config(mock_session, snapshot="snap1", diff=True)

    assert isinstance(message, str)
    assert isinstance(config, list)
    assert "set firewall ipv4 name DIFF_CHAIN rule 10 action 'accept'" in config
    assert "set firewall ipv4 name DIFF_CHAIN description 'Diff test'" in config
    # Message should contain HTML <br> tags
    assert "<br>" in message


# ===========================================================================
# generate_config -- full example data
# ===========================================================================
def test_generate_config_full_example(mock_session, patch_read, example_user_data):
    """Full example.json produces expected key config lines for both IPv4 and IPv6."""
    patch_read(example_user_data)

    message, config = generate_config(mock_session)

    # Verify message and config are non-empty
    assert len(config) > 0
    assert len(message) > 0

    # IPv4 section header
    assert "#\n#\n# IPv4\n#\n#\n" in config

    # IPv6 section header
    assert "#\n#\n# IPv6\n#\n#\n" in config

    # IPv4 groups
    assert "set firewall group address-group DNS_Servers description 'DNS_Servers'" in config
    assert "set firewall group address-group DNS_Servers address '10.53.53.53'" in config
    assert "set firewall group port-group DNS_Port port '53'" in config
    assert "set firewall group port-group Web_Ports port '80'" in config
    assert "set firewall group port-group Web_Ports port '443'" in config

    # IPv4 chains
    assert "set firewall ipv4 name WAN_LOCAL description 'WAN inbound to localhost.'" in config
    assert "set firewall ipv4 name WAN_LOCAL default-action 'drop'" in config
    assert "set firewall ipv4 name WAN_IN description 'WAN inbound to LAN.'" in config
    assert "set firewall ipv4 name WAN_IN default-action 'drop'" in config

    # IPv4 chain rules -- states
    assert "set firewall ipv4 name WAN_LOCAL rule 10 state 'established'" in config
    assert "set firewall ipv4 name WAN_LOCAL rule 10 state 'related'" in config
    assert "set firewall ipv4 name WAN_LOCAL rule 20 state 'invalid'" in config

    # IPv4 chain rule logging
    assert "set firewall ipv4 name WAN_LOCAL rule 20 log" in config

    # IPv4 filters
    assert "set firewall ipv4 input filter description 'Input Filter'" in config
    assert "set firewall ipv4 input filter default-action accept" in config
    assert "set firewall ipv4 input filter rule 10 action 'jump'" in config
    assert "set firewall ipv4 input filter rule 10 inbound-interface name 'eth0'" in config
    assert "set firewall ipv4 input filter rule 10 jump-target 'WAN_LOCAL'" in config

    # IPv6 groups (ipv6- prefix)
    assert "set firewall group ipv6-address-group DNS_Servers description 'DNS_Servers'" in config
    assert "set firewall group ipv6-address-group DNS_Servers address 'fc00::53'" in config

    # IPv6 chains
    assert "set firewall ipv6 name WAN_LOCAL description 'WAN inbound to localhost.'" in config
    assert "set firewall ipv6 name WAN_LOCAL default-action 'drop'" in config

    # IPv6 icmp -> ipv6-icmp conversion
    assert "set firewall ipv6 name WAN_LOCAL rule 30 protocol 'ipv6-icmp'" in config
    assert "set firewall ipv6 name WAN_IN rule 30 protocol 'ipv6-icmp'" in config

    # IPv6 filters
    assert "set firewall ipv6 input filter description 'Input Filter'" in config
    assert "set firewall ipv6 input filter rule 10 action 'jump'" in config
    assert "set firewall ipv6 input filter rule 10 jump-target 'WAN_LOCAL'" in config
