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


# ---------------------------------------------------------------------------
# show firewall ... detail (vertical blocks with Last Used)
# ---------------------------------------------------------------------------
from package.op_firewall import (  # noqa: E402
    has_last_used,
    last_used_age_ms,
    parse_firewall_detail,
)


def _detail_text():
    return (FIXTURES / "show_firewall_detail.txt").read_text()


class TestParseFirewallDetail:
    def test_ruleset_and_rules(self):
        chains = parse_firewall_detail(_detail_text())
        assert len(chains) == 1
        chain = chains[0]
        assert (chain["family"], chain["kind"], chain["name"]) == ("ipv4", "name", "WAN_LOCAL")
        assert [r["number"] for r in chain["rules"]] == ["10", "20", "30", "default"]
        assert chain["default_action"] == "drop"
        assert chain["packets"] == 1520 + 7 + 99

    def test_last_used_values(self):
        rules = parse_firewall_detail(_detail_text())[0]["rules"]
        assert [r["last_used"] for r in rules] == ["1s174ms", "never", "N/A", "N/A"]

    def test_wrapped_conditions_joined(self):
        rule = parse_firewall_detail(_detail_text())[0]["rules"][0]
        assert rule["conditions"].endswith("ip saddr @A_TRUSTED")
        assert {"t": "group", "type": "address-group", "name": "TRUSTED",
                "ip_version": "ipv4"} in rule["parts"]
        assert {"t": "state", "v": "EST"} in rule["parts"]

    def test_filter_title(self):
        text = _detail_text().replace('"name WAN_LOCAL"', '"forward filter"')
        chain = parse_firewall_detail(text)[0]
        assert (chain["kind"], chain["name"], chain["label"]) == ("filter", "forward", "forward filter")

    def test_plain_show_firewall_is_not_detail(self):
        assert parse_firewall_detail((FIXTURES / "show_firewall.txt").read_text()) == []

    def test_blocks_without_title_ignored(self):
        assert parse_firewall_detail(" Rule | 10\n Action | accept\n") == []

    def test_has_last_used(self):
        assert has_last_used(parse_firewall_detail(_detail_text()))
        text = (FIXTURES / "show_firewall.txt").read_text()
        assert not has_last_used(parse_firewall(parse_segments(text)))


class TestLastUsedAge:
    @pytest.mark.parametrize("value, expected", [
        ("174ms", 174),
        ("1s174ms", 1174),
        ("2h3m4s", 2 * 3_600_000 + 3 * 60_000 + 4_000),
        ("1d", 86_400_000),
        ("never", 10**15),
        ("N/A", -1),
        ("", -1),
        (None, -1),
        ("soon", -1),
    ])
    def test_values(self, value, expected):
        assert last_used_age_ms(value) == expected


def test_build_op_view_detail():
    view = build_op_view(_detail_text(), {
        "ipv4": {"chains": {"WAN_LOCAL": {"default": {"description": "Local"},
                                          "10": {"description": "SSH in"}}}}
    })
    assert view["kind"] == "firewall"
    assert view["has_last_used"] is True
    assert view["table_count"] == 1
    rule = view["chains"][0]["rules"][0]
    assert rule["description"] == "SSH in"
    assert rule["last_used_ms"] == 1174


def test_build_op_view_plain_has_no_last_used():
    view = build_op_view((FIXTURES / "show_firewall.txt").read_text(), {})
    assert view["has_last_used"] is False


class TestLastUsedColumnRender:
    def _render(self, app, text):
        from flask import render_template_string
        with app.test_request_context():
            return render_template_string(
                '{% import "_op_output.html" as op %}{{ op.firewall_view(v) }}',
                v=build_op_view(text, {}),
            )

    def test_detail_shows_column(self):
        from app import app
        html = self._render(app, _detail_text())
        assert ">Last used</th>" in html
        assert "1s174ms ago" in html
        assert 'data-v="1174"' in html
        assert "pill-warn\">never" in html

    def test_plain_has_no_column(self):
        from app import app
        html = self._render(app, (FIXTURES / "show_firewall.txt").read_text())
        assert "Last used" not in html
