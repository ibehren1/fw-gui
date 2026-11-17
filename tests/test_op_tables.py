"""Tests for package.op_tables: VyOS tabulate output into text/table segments."""

from pathlib import Path

import pytest

from package.op_tables import has_tables, parse_segments

FIXTURES = Path(__file__).parent / "fixtures" / "op_output"


def fixture(name):
    return (FIXTURES / name).read_text()


def tables(segments):
    return [s for s in segments if s["kind"] == "table"]


class TestParseSegments:
    @pytest.mark.parametrize("value", [None, "", "   \n\n", 42])
    def test_empty_or_non_string_is_no_segments(self, value):
        assert parse_segments(value) == []

    def test_plain_text_is_one_text_segment(self):
        text = "Version:          VyOS 1.5\nRelease train:    circinus"
        assert parse_segments(text) == [{"kind": "text", "text": text}]
        assert not has_tables(parse_segments(text))

    def test_single_dash_run_is_not_a_table(self):
        # show firewall separates rulesets with one long dash line.
        text = "Title\n---------------------------------\nmore"
        assert not has_tables(parse_segments(text))

    def test_crlf_line_endings(self):
        text = "A    B\r\n---  ---\r\n1    2\r\n"
        [table] = tables(parse_segments(text))
        assert table["rows"] == [["1", "2"]]


class TestShowFirewall:
    def test_every_ruleset_is_a_table_with_its_title_before_it(self):
        segments = parse_segments(fixture("show_firewall.txt"))
        assert len(tables(segments)) == 10
        for i, segment in enumerate(segments):
            if segment["kind"] == "table":
                assert segments[i - 1]["kind"] == "text"
                assert "Firewall" in segments[i - 1]["text"]

    def test_columns_and_numeric_detection(self):
        [first, *_] = tables(parse_segments(fixture("show_firewall.txt")))
        assert first["columns"] == [
            "Rule", "Action", "Protocol", "Packets", "Bytes", "Conditions",
        ]
        assert first["numeric"] == [False, False, False, True, True, False]

    def test_row_cells_and_free_text_last_column(self):
        [first, *_] = tables(parse_segments(fixture("show_firewall.txt")))
        assert first["rows"][2] == [
            "10", "jump", "all", "988642", "1066207523",
            'oifname "bond0"  jump NAME_mgmt_out',
        ]
        assert first["rows"][-1][0] == "default"
        assert first["rows"][-1][5] == (
            'accept comment "FWD-filter default-action accept"'
        )

    def test_condition_wider_than_header_is_kept_whole(self):
        segment = next(
            t for t in tables(parse_segments(fixture("show_firewall.txt")))
            if any("@A_tvs" in r[5] for r in t["rows"])
        )
        assert segment["rows"][0][5] == (
            "ct state { invalid, established, related, new } ip saddr @A_tvs"
            '  prefix "[ipv4-NAM-example_iot_in-10-D]"'
        )


class TestContinuationRows:
    def test_interface_addresses_join_into_one_cell(self):
        [table] = tables(parse_segments(fixture("show_interfaces.txt")))
        rows = {r[0]: r for r in table["rows"]}
        assert rows["bond0.10"][1] == (
            "10.1.1.1/24\n2001:0db8:855:cd0a::1/64\nfc00:0:0:5::1/64"
        )
        assert rows["lo"][1] == "127.0.0.1/8\n192.168.255.1/32\n::1/128"
        assert rows["eth3"][6] == ""
        assert rows["eth3"][5] == "u/D"

    def test_codes_line_stays_as_text(self):
        segments = parse_segments(fixture("show_interfaces.txt"))
        assert segments[0]["kind"] == "text"
        assert segments[0]["text"].startswith("Codes:")

    def test_multiline_column_is_not_numeric(self):
        [table] = tables(parse_segments(fixture("show_interfaces.txt")))
        numeric = dict(zip(table["columns"], table["numeric"]))
        assert numeric["MTU"] is True
        assert numeric["IP Address"] is False

    def test_nat_sport_dport_line_joins_source_and_destination(self):
        [table] = tables(parse_segments(fixture("show_nat_source_rules.txt")))
        assert len(table["rows"]) == 4
        assert table["rows"][0] == [
            "10", "0.0.0.0/0\nsport any", "10.0.0.0/8\ndport any",
            "any", "any", "exclude",
        ]

    def test_text_after_a_table_is_kept(self):
        text = "A    B\n---  ---\n1    2\n\nTotal: 1"
        segments = parse_segments(text)
        assert [s["kind"] for s in segments] == ["table", "text"]
        assert segments[1]["text"].strip() == "Total: 1"
