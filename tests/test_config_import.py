"""
Tests for package/config_import.py: VyOS `show configuration json` -> document.

The fixtures under tests/fixtures/import are an anonymized real firewall:
firewall.json is `show configuration json | jq .firewall`, and
firewall_commands.txt is `show configuration commands | grep firewall` from the
same device, so the commands file is an independent ground truth for what a
push of the imported document must send.
"""

import json
import shlex
from pathlib import Path

import pytest

from package.config_import import (
    ConfigImportError,
    extract_trees,
    flatten,
    import_config,
    set_line,
)
from package.generate_config import render_config

FIXTURES = Path(__file__).parent / "fixtures" / "import"


def _load(name):
    return json.loads((FIXTURES / name).read_text())


def _commands(lines):
    """Set commands as token tuples, comments, banners and blanks dropped."""
    out = set()
    for line in "\n".join(lines).split("\n"):
        line = line.strip()
        if line.startswith("set "):
            out.add(tuple(shlex.split(line)))
    return out


def _import(firewall, interfaces=None):
    tree = {"firewall": firewall}
    if interfaces is not None:
        tree["interfaces"] = interfaces
    return import_config(json.dumps(tree))


def _rule(**fields):
    return {"rule": {"10": {"action": "accept", **fields}}}


@pytest.fixture
def full_config():
    return json.dumps({
        "firewall": _load("firewall.json"),
        "interfaces": _load("interfaces.json"),
        "system": {"login": {"user": {"vyos": {"authentication": {
            "encrypted-password": "$6$secret"}}}}},
    })


class TestRoundTrip:
    def test_push_matches_device_commands(self, full_config):
        doc, report = import_config(full_config)
        device = _commands((FIXTURES / "firewall_commands.txt").read_text().splitlines())
        assert _commands(render_config(doc)) == device
        assert report["divergence"] == {"not_on_device": [], "missing": []}

    def test_counts_and_extra_items(self, full_config):
        doc, report = import_config(full_config)
        assert report["counts"] == {
            "groups": 63, "chains": 28, "chain_rules": 175, "filters": 4,
            "filter_rules": 36, "flowtables": 0, "interfaces": 21, "extra_items": 3,
        }
        assert report["extra_items"] == [
            "set firewall global-options all-ping 'enable'",
            "set firewall global-options log-martians 'disable'",
            "set firewall ipv6 name name_064 rule 10 icmpv6 type '134'",
        ]
        assert doc["extra-items"] == report["extra_items"]
        assert report["warnings"] == []

    def test_secrets_are_not_kept(self, full_config):
        doc, report = import_config(full_config)
        blob = json.dumps([doc, report])
        assert "secret" not in blob
        assert "login" not in blob

    def test_last_used_targets_rolling(self, full_config):
        doc, report = import_config(full_config)
        assert doc["system"]["vyos_release"] == {
            "rolling": True, "milestone": "2026-08", "last_used_all": False,
        }
        assert report["rolling_release"] is True
        assert doc["system"]["hostname"] == "None"
        assert doc["origin"] == "import"
        assert doc["version"] == "1"


class TestExtractTrees:
    def test_full_config(self):
        fw, ifs = extract_trees('{"firewall": {"group": {}}, "interfaces": {"ethernet": {}}}')
        assert fw == {"group": {}}
        assert ifs == {"ethernet": {}}

    def test_firewall_subtree(self):
        fw, ifs = extract_trees('{"ipv4": {"name": {}}}')
        assert fw == {"ipv4": {"name": {}}}
        assert ifs is None

    def test_leading_text_is_skipped(self):
        fw, _ = extract_trees('Welcome to VyOS\n{"firewall": {"ipv4": {}}}\n')
        assert fw == {"ipv4": {}}

    @pytest.mark.parametrize("text", [
        "", "no json here", "{not json", "[1, 2]", '{"system": {}}',
        '{"firewall": {}}', '{"firewall": "x"}',
    ])
    def test_unusable_input(self, text):
        with pytest.raises(ConfigImportError):
            extract_trees(text)


class TestFlatten:
    def test_leaves(self):
        tree = {"a": {"b": ["1", "2"], "flag": {}, "c": "x y"}}
        assert flatten(tree) == [
            (("firewall", "a", "b"), "1"),
            (("firewall", "a", "b"), "2"),
            (("firewall", "a", "flag"), None),
            (("firewall", "a", "c"), "x y"),
        ]

    def test_set_line_quotes(self):
        assert set_line(("firewall", "x"), None) == "set firewall x"
        assert set_line(("firewall", "x"), "it's") == "set firewall x 'it'\\''s'"


class TestGroups:
    def test_types_and_ip_versions(self):
        doc, _ = _import({"group": {
            "address-group": {"a": {"address": ["10.0.0.1"], "description": "A"}},
            "ipv6-network-group": {"n6": {"network": ["fd00::/64"]}},
            "port-group": {"p": {"port": ["22", "80-81"]}},
            "domain-group": {"d": {"address": ["example.com"]}},
            "mac-group": {"m": {"mac-address": ["00:11:22:33:44:55"]}},
            "interface-group": {"i": {"interface": ["eth0"]}},
        }})
        assert doc["ipv4"]["groups"]["a"] == {
            "group_desc": "A", "group_type": "address-group", "group_value": ["10.0.0.1"]}
        assert doc["ipv6"]["groups"]["n6"] == {
            "group_desc": "", "group_type": "network-group", "group_value": ["fd00::/64"]}
        assert doc["ipv4"]["groups"]["p"]["group_value"] == ["22", "80-81"]
        assert doc["ipv4"]["groups"]["d"]["group_type"] == "domain-group"
        assert doc["ipv4"]["groups"]["m"]["group_value"] == ["00:11:22:33:44:55"]
        assert doc["ipv4"]["groups"]["i"]["group_value"] == ["eth0"]
        assert "extra-items" not in doc

    def test_include_and_unknown_types_go_to_extra_items(self):
        doc, report = _import({"group": {
            "address-group": {"a": {"address": ["10.0.0.1"], "include": "b"}},
            "dynamic-group": {"address-group": {"dyn": {"description": "D"}}},
        }})
        assert doc["extra-items"] == [
            "set firewall group address-group a include 'b'",
            "set firewall group dynamic-group address-group dyn description 'D'",
        ]
        assert report["divergence"] == {"not_on_device": [], "missing": []}

    def test_same_name_across_types_keeps_second_in_extra_items(self):
        doc, report = _import({"group": {
            "address-group": {"x": {"address": ["10.0.0.1"]}},
            "network-group": {"x": {"network": ["10.0.0.0/24"]}},
        }})
        assert doc["ipv4"]["groups"]["x"]["group_type"] == "address-group"
        assert doc["extra-items"] == ["set firewall group network-group x network '10.0.0.0/24'"]
        assert len(report["warnings"]) == 1


class TestChains:
    def test_rule_fields(self):
        doc, report = _import({"ipv4": {"name": {"c": {
            "default-action": "drop", "default-log": {}, "description": "C",
            "rule": {
                "20": {"action": "drop", "log": {}, "disable": {}, "state": ["invalid"]},
                "5": {
                    "action": "accept", "description": "web", "protocol": "tcp",
                    "state": ["established", "new", "related"],
                    "source": {"address": "10.0.0.0/8", "port": "1024-65535"},
                    "destination": {"group": {"address-group": "srv", "port-group": "web"}},
                },
            },
        }}}})
        chain = doc["ipv4"]["chains"]["c"]
        assert chain["rule-order"] == ["5", "20"]
        assert chain["default"] == {
            "description": "C", "default_action": "drop", "default_logging": True}
        assert chain["5"] == {
            "description": "web", "action": "accept",
            "dest_address": "srv", "dest_address_type": "address_group",
            "dest_port": "web", "dest_port_type": "port_group",
            "source_address": "10.0.0.0/8", "source_address_type": "address",
            "source_port": "1024-65535", "source_port_type": "port",
            "protocol": "tcp", "state_est": True, "state_new": True, "state_rel": True,
        }
        assert chain["20"]["rule_disable"] is True
        assert chain["20"]["logging"] is True
        assert chain["20"]["state_inv"] is True
        assert report["divergence"] == {"not_on_device": [], "missing": []}

    def test_unmodelled_match_fields_go_to_extra_items(self):
        doc, report = _import({"ipv4": {"name": {"c": {
            "default-action": "accept", "description": "C",
            **_rule(
                protocol="tcp",
                tcp={"flags": {"syn": {}}},
                source={"address": "10.0.0.1", "group": {"network-group": "n"}},
            ),
        }}}})
        assert doc["ipv4"]["chains"]["c"]["10"]["source_address"] == "10.0.0.1"
        assert doc["extra-items"] == [
            "set firewall ipv4 name c rule 10 tcp flags syn",
            "set firewall ipv4 name c rule 10 source group network-group 'n'",
        ]
        assert report["divergence"] == {"not_on_device": [], "missing": []}

    def test_jump_action_warns_and_keeps_target(self):
        doc, report = _import({"ipv4": {"name": {"c": {
            "default-action": "accept", "description": "C",
            "rule": {"10": {"action": "jump", "jump-target": "other"}},
        }}}})
        assert doc["ipv4"]["chains"]["c"]["10"]["action"] == "jump"
        assert doc["extra-items"] == ["set firewall ipv4 name c rule 10 jump-target 'other'"]
        assert "cannot edit" in report["warnings"][0]
        assert report["divergence"] == {"not_on_device": [], "missing": []}

    def test_ipv6_icmp_protocol_stays_verbatim(self):
        doc, report = _import({"ipv6": {"name": {"c": {
            "default-action": "accept", "description": "C", **_rule(protocol="icmp"),
        }}}})
        assert doc["ipv6"]["chains"]["c"]["10"]["protocol"] == ""
        assert doc["extra-items"] == ["set firewall ipv6 name c rule 10 protocol 'icmp'"]
        assert report["divergence"] == {"not_on_device": [], "missing": []}

    def test_missing_default_action_is_explicit_drop(self):
        doc, report = _import({"ipv4": {"name": {"c": {"description": "C"}}}})
        assert doc["ipv4"]["chains"]["c"]["default"]["default_action"] == "drop"
        assert report["divergence"]["not_on_device"] == [
            "set firewall ipv4 name c default-action drop"]
        assert report["warnings"]

    def test_quoted_description_round_trips(self):
        _, report = _import({"ipv4": {"name": {"c": {
            "default-action": "drop", "description": "it's A & B",
            **_rule(description="say \"hi\""),
        }}}})
        assert report["divergence"] == {"not_on_device": [], "missing": []}


class TestFilters:
    def test_jump_and_offload(self):
        doc, report = _import({
            "flowtable": {"ft": {"description": "FT", "interface": ["eth0", "eth1"],
                                 "offload": "software"}},
            "ipv4": {"forward": {"filter": {
                "default-action": "accept", "description": "Fwd",
                "rule": {
                    "10": {"action": "offload", "offload-target": "ft"},
                    "20": {"action": "jump", "jump-target": "c", "description": "J",
                           "outbound-interface": {"name": "eth1"}, "last-used": {},
                           "log": {}},
                },
            }}},
        })
        filt = doc["ipv4"]["filters"]["forward"]
        assert filt["rule-order"] == ["10", "20"]
        assert filt["log"] is False
        assert filt["rules"]["10"]["fw_chain"] == "ft"
        assert filt["rules"]["20"] == {
            "ip_version": "ipv4", "filter": "forward", "description": "J",
            "action": "jump", "fw_chain": "c", "interface": "eth1",
            "direction": "outbound", "last_used": True, "log": True,
        }
        assert doc["flowtables"] == [
            {"name": "ft", "description": "FT", "interfaces": ["eth0", "eth1"]}]
        assert report["divergence"] == {"not_on_device": [], "missing": []}

    def test_both_interfaces_keeps_outbound_in_extra_items(self):
        doc, report = _import({"ipv4": {"input": {"filter": {
            "default-action": "accept", "description": "In",
            "rule": {"10": {"action": "jump", "jump-target": "c",
                            "inbound-interface": {"name": "eth0"},
                            "outbound-interface": {"name": "eth1"}}},
        }}}})
        assert doc["ipv4"]["filters"]["input"]["rules"]["10"]["direction"] == "inbound"
        assert doc["extra-items"] == [
            "set firewall ipv4 input filter rule 10 outbound-interface name 'eth1'"]
        assert report["divergence"] == {"not_on_device": [], "missing": []}

    def test_accept_rule_with_conditions(self):
        doc, report = _import({"ipv4": {"input": {"filter": {
            "default-action": "drop", "description": "In",
            "rule": {"10": {"action": "accept", "state": ["established"]}},
        }}}})
        assert doc["ipv4"]["filters"]["input"]["rules"]["10"]["action"] == "accept"
        assert doc["extra-items"] == [
            "set firewall ipv4 input filter rule 10 state 'established'"]
        assert "only edits jump and offload" in report["warnings"][0]
        assert report["divergence"] == {"not_on_device": [], "missing": []}

    def test_default_log_spellings(self):
        doc, report = _import({"ipv4": {
            "input": {"filter": {"default-action": "drop", "description": "In",
                                 "default-log": {}}},
            "forward": {"filter": {"default-action": "drop", "description": "Fwd",
                                   "enable-default-log": {}}},
        }})
        assert doc["ipv4"]["filters"]["input"]["log"] is False
        assert doc["ipv4"]["filters"]["forward"]["log"] == "True"
        assert doc["extra-items"] == ["set firewall ipv4 input filter default-log"]
        assert report["divergence"] == {"not_on_device": [], "missing": []}

    def test_other_hooks_go_to_extra_items(self):
        doc, _ = _import({"ipv4": {"prerouting": {"raw": {"default-action": "accept"}}}})
        assert doc["extra-items"] == [
            "set firewall ipv4 prerouting raw default-action 'accept'"]


class TestFlowtables:
    def test_hardware_offload_kept_verbatim(self):
        doc, report = _import({"flowtable": {"ft": {
            "description": "FT", "interface": ["eth0"], "offload": "hardware"}}})
        assert "flowtables" not in doc
        assert len(doc["extra-items"]) == 3
        assert report["warnings"]
        assert report["divergence"] == {"not_on_device": [], "missing": []}


class TestInterfaces:
    def test_device_tree_with_vlans(self):
        doc, report = _import({"group": {}, "global-options": {"all-ping": "enable"}}, {
            "ethernet": {"eth0": {"description": "WAN", "vif": {"10": {"description": "V10"}},
                                  "vif-s": {"100": {"vif-c": {"20": {}}}}}},
            "loopback": {"lo": {}},
            "wireguard": {"wg0": {"private-key": "SECRET", "description": "VPN"}},
        })
        assert doc["interfaces"] == [
            {"name": "eth0", "description": "WAN"},
            {"name": "eth0.10", "description": "V10"},
            {"name": "eth0.100", "description": ""},
            {"name": "eth0.100.20", "description": ""},
            {"name": "wg0", "description": "VPN"},
        ]
        assert report["interfaces_from"] == "device"
        assert "SECRET" not in json.dumps(doc)

    def test_fallback_to_rule_references(self):
        doc, report = _import({"ipv4": {"input": {"filter": {
            "default-action": "accept", "description": "In",
            "rule": {"10": {"action": "jump", "jump-target": "c",
                            "inbound-interface": {"name": "eth3"}}},
        }}}})
        assert doc["interfaces"] == [{"name": "eth3", "description": ""}]
        assert report["interfaces_from"] == "rules"

    def test_subtree_input_without_last_used_stays_stable(self):
        doc, report = import_config('{"group": {"port-group": {"p": {"port": ["22"]}}}}')
        assert "vyos_release" not in doc["system"]
        assert report["rolling_release"] is False
