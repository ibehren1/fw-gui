"""Tests for package.op_firewall: the show firewall view."""

from pathlib import Path

import pytest

from package.op_firewall import (
    condition_parts,
    enrich,
    human_bytes,
    human_count,
    parse_firewall,
    stats,
)
from package.op_output import build_op_view
from package.op_tables import parse_segments

FIXTURES = Path(__file__).parent / "fixtures" / "op_output"


@pytest.fixture
def chains():
    text = (FIXTURES / "show_firewall.txt").read_text()
    return parse_firewall(parse_segments(text))


def by_label(chains, family, label):
    return next(c for c in chains if c["family"] == family and c["label"] == label)


class TestHumanFormats:
    @pytest.mark.parametrize(
        "n, expected",
        [(0, "0"), (9999, "9,999"), (12345, "12.3k"), (1066207523, "1.07G"), (988642, "988.6k"), (1234567, "1.23M")],
    )
    def test_count(self, n, expected):
        assert human_count(n) == expected

    @pytest.mark.parametrize(
        "n, expected",
        [(0, "0 B"), (460, "460 B"), (1536, "1.50 KiB"), (24742474, "23.6 MiB"), (1672987500, "1.56 GiB")],
    )
    def test_bytes(self, n, expected):
        assert human_bytes(n) == expected


class TestConditionParts:
    def test_states_and_verdict(self):
        parts, log, jump = condition_parts("ct state { established, related }  accept")
        assert parts == [{"t": "state", "v": "EST"}, {"t": "state", "v": "REL"}]
        assert (log, jump) == (False, None)

    def test_groups_by_set_prefix(self):
        parts, _, _ = condition_parts(
            "ct state new ip6 daddr @A6_dns_servers th dport @P_dns_ports  accept"
        )
        assert parts == [
            {"t": "state", "v": "NEW"},
            {"t": "text", "v": "ip6 daddr"},
            {"t": "group", "type": "address-group", "name": "dns_servers", "ip_version": "ipv6"},
            {"t": "text", "v": "th dport"},
            {"t": "group", "type": "port-group", "name": "dns_ports", "ip_version": "ipv4"},
        ]

    def test_group_names_with_hyphens(self):
        parts, _, _ = condition_parts("ct state new tcp dport @P_git-ssh  accept")
        assert parts[-1]["name"] == "git-ssh"

    def test_log_prefix_is_a_flag(self):
        parts, log, _ = condition_parts(
            'ct state invalid  prefix "[ipv4-NAM-wan_local-20-D]"'
        )
        assert log is True
        assert parts == [{"t": "state", "v": "INV"}]

    def test_jump_target(self):
        parts, log, jump = condition_parts('oifname "bond0.12"  jump NAME6_client_lans_out')
        assert jump == "client_lans_out"
        assert parts == [{"t": "text", "v": 'oifname "bond0.12"'}]

    def test_default_action_comment_leaves_nothing(self):
        assert condition_parts('accept comment "FWD-filter default-action accept"') == ([], False, None)
        parts, log, _ = condition_parts(
            'prefix "[ipv4-NAM-wan_in-default-D]"  comment "NAM-wan_in default-action "'
        )
        assert (parts, log) == ([], True)

    def test_unknown_text_kept(self):
        parts, _, _ = condition_parts("icmpv6 type nd-router-advert")
        assert parts == [{"t": "text", "v": "icmpv6 type nd-router-advert"}]


class TestParseFirewall:
    def test_every_ruleset_with_family_kind_name(self, chains):
        assert [(c["family"], c["kind"], c["name"]) for c in chains] == [
            ("ipv4", "filter", "forward"),
            ("ipv4", "filter", "input"),
            ("ipv4", "name", "aws_vpnpeer1_vpn_in"),
            ("ipv4", "name", "example_home_local"),
            ("ipv4", "name", "example_iot_in"),
            ("ipv4", "name", "data_center_out"),
            ("ipv4", "name", "wan_out"),
            ("ipv6", "filter", "forward"),
            ("ipv6", "name", "data_center_out"),
            ("ipv6", "name", "wan_out"),
        ]

    def test_rule_counters_and_default(self, chains):
        forward = by_label(chains, "ipv4", "forward filter")
        assert forward["rules"][2]["number"] == "10"
        assert forward["rules"][2]["packets"] == 988642
        assert forward["rules"][2]["jump"] == "mgmt_out"
        assert forward["rules"][-1]["is_default"] is True
        assert forward["default_action"] == "accept"
        assert forward["packets"] == sum(r["packets"] for r in forward["rules"])

    def test_other_tables_are_ignored(self):
        text = "Interface    MTU\n-----------  ---\neth0         1500\n"
        assert parse_firewall(parse_segments(text)) == []

    def test_table_without_title_is_ignored(self):
        text = (FIXTURES / "show_firewall.txt").read_text()
        body = text.split('ipv4 Firewall "forward filter"\n\n', 1)[1].split("\n\n")[0]
        assert parse_firewall(parse_segments(body)) == []


class TestEnrich:
    def test_descriptions_from_chains_and_filters(self, chains):
        user_data = {
            "ipv4": {
                "chains": {
                    "wan_out": {
                        "default": {"description": "WAN egress hygiene"},
                        "rule-order": ["10"],
                        "10": {"description": "Drop mDNS leak"},
                    }
                },
                "filters": {
                    "forward": {
                        "description": "IPv4 Forward Filter",
                        "rules": {"1": {"description": "WAN In"}},
                    }
                },
            }
        }
        enrich(chains, user_data)
        wan_out = by_label(chains, "ipv4", "wan_out")
        assert wan_out["in_config"] is True
        assert wan_out["description"] == "WAN egress hygiene"
        assert wan_out["rules"][0]["description"] == "Drop mDNS leak"
        # In the device output, not in this config.
        assert wan_out["rules"][1]["description"] is None
        forward = by_label(chains, "ipv4", "forward filter")
        assert forward["description"] == "IPv4 Forward Filter"
        assert forward["rules"][0]["description"] == "WAN In"
        # Same names, other IP version: not matched.
        assert by_label(chains, "ipv6", "wan_out")["in_config"] is False

    def test_without_config(self, chains):
        enrich(chains, None)
        assert all(not c["in_config"] for c in chains)
        assert all(r["description"] is None for c in chains for r in c["rules"])

    def test_share_bar_and_zero(self, chains):
        enrich(chains, {})
        data = by_label(chains, "ipv4", "data_center_out")
        top = data["rules"][0]
        assert (top["bar"], top["share"]) == (100.0, "97%")
        assert data["rules"][1]["share"] == "<1%"
        assert data["rules"][2]["zero"] is True
        assert data["rules"][2]["share"] == "0%"
        silent = by_label(chains, "ipv4", "example_iot_in")
        assert all(r["share"] == "0%" for r in silent["rules"])


def test_stats(chains):
    s = stats(chains)
    assert s["chains"] == 10
    assert s["rules"] == sum(len(c["rules"]) - 1 for c in chains)
    assert s["never_hit"] == sum(
        1 for c in chains for r in c["rules"] if not r["is_default"] and r["packets"] == 0
    )
    assert s["dropped"] == 59 + 58 + 3 + 21 + 0


def test_build_op_view_prefers_firewall_view():
    text = (FIXTURES / "show_firewall.txt").read_text()
    view = build_op_view(text, {})
    assert view["kind"] == "firewall"
    assert view["table_count"] == 10
    assert len(view["chains"]) == 10
    assert build_op_view((FIXTURES / "show_interfaces.txt").read_text())["kind"] == "tables"


class TestDeltas:
    def test_first_run_has_no_deltas(self, chains):
        from package.op_firewall import apply_deltas

        apply_deltas(chains, None)
        assert all(r["delta"] is None for c in chains for r in c["rules"])

    def test_deltas_against_previous_counters(self, chains):
        from package.op_firewall import apply_deltas, counter_key, counter_snapshot

        previous = counter_snapshot(chains)
        forward = by_label(chains, "ipv4", "forward filter")
        previous[counter_key(forward, forward["rules"][0])] -= 399
        # A counter that went down (reset) shows no delta, not a negative one.
        previous[counter_key(forward, forward["rules"][1])] += 5
        del previous[counter_key(forward, forward["rules"][2])]
        apply_deltas(chains, previous)
        assert forward["rules"][0]["delta"] == 399
        assert forward["rules"][0]["delta_h"] == "399"
        assert forward["rules"][1]["delta"] is None
        assert forward["rules"][2]["delta"] is None
        assert forward["rules"][3]["delta"] == 0

    def test_same_rule_number_in_other_family_is_separate(self, chains):
        from package.op_firewall import counter_snapshot

        keys = counter_snapshot(chains)
        assert "ipv4|name|wan_out|10" in keys
        assert "ipv6|name|wan_out|10" in keys
