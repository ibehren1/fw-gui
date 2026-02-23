"""
Tests for package.filter_functions module.

Covers: add_filter_to_data, add_filter_rule_to_data, assemble_detail_list_of_filters,
        assemble_list_of_filters, assemble_list_of_filter_rules,
        delete_filter_rule_from_data, reorder_filter_rule_in_data
"""

import pytest

from tests.conftest import make_request

from package.filter_functions import (
    add_filter_rule_to_data,
    add_filter_to_data,
    assemble_detail_list_of_filters,
    assemble_list_of_filter_rules,
    assemble_list_of_filters,
    delete_filter_rule_from_data,
    reorder_filter_rule_in_data,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_data():
    """Minimal starting data for add operations."""
    return {"version": "1"}


def _data_with_filter():
    """Data with an existing ipv4 input filter containing one rule."""
    return {
        "version": "1",
        "ipv4": {
            "filters": {
                "input": {
                    "rule-order": ["10"],
                    "description": "Input filter",
                    "default-action": "drop",
                    "log": False,
                    "rules": {
                        "10": {
                            "ip_version": "ipv4",
                            "filter": "input",
                            "description": "Allow established",
                            "action": "accept",
                        }
                    },
                }
            }
        },
    }


def _data_with_two_filter_rules():
    """Data with an existing ipv4 input filter containing two rules."""
    data = _data_with_filter()
    data["ipv4"]["filters"]["input"]["rule-order"] = ["10", "20"]
    data["ipv4"]["filters"]["input"]["rules"]["20"] = {
        "ip_version": "ipv4",
        "filter": "input",
        "description": "Jump to chain",
        "action": "jump",
        "fw_chain": "OUTSIDE-IN",
        "interface": "eth0",
        "direction": "in",
    }
    return data


def _data_with_empty_filter():
    """Data with a filter structure but no rules (for testing add_filter_rule from scratch)."""
    return {
        "version": "1",
        "ipv4": {
            "filters": {
                "input": {
                    "rule-order": [],
                    "description": "Input filter",
                    "default-action": "drop",
                    "log": False,
                }
            }
        },
    }


# ===================================================================
# add_filter_to_data
# ===================================================================


class TestAddFilterToData:
    def test_add_input_filter(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "ip_version": "ipv4",
            "type": "input",
            "description": "Input filter",
            "default_action": "drop",
        })
        with app.test_request_context():
            add_filter_to_data(mock_session, req)

        filt = capture.written_data["ipv4"]["filters"]["input"]
        assert filt["description"] == "Input filter"
        assert filt["default-action"] == "drop"
        assert filt["log"] is False
        assert filt["rule-order"] == []

    def test_add_forward_filter(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "ip_version": "ipv4",
            "type": "forward",
            "description": "Forward filter",
            "default_action": "accept",
        })
        with app.test_request_context():
            add_filter_to_data(mock_session, req)

        filt = capture.written_data["ipv4"]["filters"]["forward"]
        assert filt["description"] == "Forward filter"
        assert filt["default-action"] == "accept"

    def test_add_filter_with_logging(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "ip_version": "ipv4",
            "type": "output",
            "description": "Output filter",
            "default_action": "drop",
            "logging": "on",
        })
        with app.test_request_context():
            add_filter_to_data(mock_session, req)

        assert capture.written_data["ipv4"]["filters"]["output"]["log"] == "on"

    def test_add_ipv6_filter(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "ip_version": "ipv6",
            "type": "input",
            "description": "IPv6 input",
            "default_action": "drop",
        })
        with app.test_request_context():
            add_filter_to_data(mock_session, req)

        assert "ipv6" in capture.written_data
        assert "input" in capture.written_data["ipv6"]["filters"]

    def test_add_filter_creates_ip_version_from_scratch(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "ip_version": "ipv4",
            "type": "input",
            "description": "New filter",
            "default_action": "accept",
        })
        with app.test_request_context():
            add_filter_to_data(mock_session, req)

        assert "ipv4" in capture.written_data
        assert "filters" in capture.written_data["ipv4"]


# ===================================================================
# add_filter_rule_to_data
# ===================================================================


class TestAddFilterRuleToData:
    def test_jump_action(self, app, mock_session, mock_read_write):
        data = _data_with_empty_filter()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "filter": "ipv4,input",
            "rule": "10",
            "description": "Jump to outside",
            "action": "jump",
            "jump_target": "ipv4,OUTSIDE-IN",
            "interface": "eth0",
            "direction": "in",
        })
        with app.test_request_context():
            add_filter_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["filters"]["input"]["rules"]["10"]
        assert rule["action"] == "jump"
        assert rule["fw_chain"] == "OUTSIDE-IN"
        assert rule["interface"] == "eth0"
        assert rule["direction"] == "in"
        assert "10" in capture.written_data["ipv4"]["filters"]["input"]["rule-order"]

    def test_offload_action(self, app, mock_session, mock_read_write):
        data = _data_with_empty_filter()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "filter": "ipv4,input",
            "rule": "10",
            "description": "Offload to flowtable",
            "action": "offload",
            "offload_target": "MyFlowtable",
        })
        with app.test_request_context():
            add_filter_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["filters"]["input"]["rules"]["10"]
        assert rule["action"] == "offload"
        assert rule["fw_chain"] == "MyFlowtable"

    def test_accept_action(self, app, mock_session, mock_read_write):
        data = _data_with_empty_filter()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "filter": "ipv4,input",
            "rule": "10",
            "description": "Accept all",
            "action": "accept",
        })
        with app.test_request_context():
            add_filter_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["filters"]["input"]["rules"]["10"]
        assert rule["action"] == "accept"
        assert "fw_chain" not in rule

    def test_drop_action(self, app, mock_session, mock_read_write):
        data = _data_with_empty_filter()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "filter": "ipv4,input",
            "rule": "10",
            "description": "Drop all",
            "action": "drop",
        })
        with app.test_request_context():
            add_filter_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["filters"]["input"]["rules"]["10"]
        assert rule["action"] == "drop"

    def test_rule_with_disable_and_logging(self, app, mock_session, mock_read_write):
        data = _data_with_empty_filter()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "filter": "ipv4,input",
            "rule": "10",
            "description": "Disabled rule",
            "action": "accept",
            "rule_disable": "on",
            "logging": "on",
        })
        with app.test_request_context():
            add_filter_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["filters"]["input"]["rules"]["10"]
        assert rule["rule_disable"] is True
        assert rule["log"] is True

    def test_rule_order_sorted(self, app, mock_session, mock_read_write):
        data = _data_with_filter()  # Has rule 10 already
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "filter": "ipv4,input",
            "rule": "5",
            "description": "Earlier rule",
            "action": "accept",
        })
        with app.test_request_context():
            add_filter_rule_to_data(mock_session, req)

        order = capture.written_data["ipv4"]["filters"]["input"]["rule-order"]
        assert order == ["5", "10"]

    def test_creates_rules_dict_if_missing(self, app, mock_session, mock_read_write):
        # Filter with no "rules" key
        data = {
            "version": "1",
            "ipv4": {
                "filters": {
                    "input": {
                        "rule-order": [],
                        "description": "Input",
                        "default-action": "drop",
                        "log": False,
                    }
                }
            },
        }
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "filter": "ipv4,input",
            "rule": "10",
            "description": "First rule",
            "action": "accept",
        })
        with app.test_request_context():
            add_filter_rule_to_data(mock_session, req)

        assert "rules" in capture.written_data["ipv4"]["filters"]["input"]
        assert "10" in capture.written_data["ipv4"]["filters"]["input"]["rules"]


# ===================================================================
# assemble_detail_list_of_filters
# ===================================================================


class TestAssembleDetailListOfFilters:
    def test_with_data(self, app, mock_session, mock_read_write):
        data = _data_with_filter()
        mock_read_write("package.filter_functions", data)
        with app.test_request_context():
            result = assemble_detail_list_of_filters(mock_session)

        assert "ipv4" in result
        assert "input" in result["ipv4"]
        rules = result["ipv4"]["input"]
        assert len(rules) == 1
        assert rules[0]["number"] == "10"
        assert rules[0]["description"] == "Allow established"

    def test_empty_data(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        mock_read_write("package.filter_functions", data)
        with app.test_request_context():
            result = assemble_detail_list_of_filters(mock_session)

        assert result == {}


# ===================================================================
# assemble_list_of_filters
# ===================================================================


class TestAssembleListOfFilters:
    def test_with_data(self, app, mock_session, mock_read_write):
        data = _data_with_filter()
        mock_read_write("package.filter_functions", data)
        with app.test_request_context():
            result = assemble_list_of_filters(mock_session)

        assert result == [["ipv4", "input"]]

    def test_empty_data(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        mock_read_write("package.filter_functions", data)
        with app.test_request_context():
            result = assemble_list_of_filters(mock_session)

        assert result == []


# ===================================================================
# assemble_list_of_filter_rules
# ===================================================================


class TestAssembleListOfFilterRules:
    def test_with_data(self, app, mock_session, mock_read_write):
        data = _data_with_filter()
        mock_read_write("package.filter_functions", data)
        with app.test_request_context():
            result = assemble_list_of_filter_rules(mock_session)

        assert len(result) == 1
        assert result[0] == ["ipv4", "input", "10", "Allow established"]

    def test_empty_data(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        mock_read_write("package.filter_functions", data)
        with app.test_request_context():
            result = assemble_list_of_filter_rules(mock_session)

        assert result == []


# ===================================================================
# delete_filter_rule_from_data
# ===================================================================


class TestDeleteFilterRuleFromData:
    def test_basic_delete(self, app, mock_session, mock_read_write):
        data = _data_with_two_filter_rules()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({"rule": "ipv4,input,10"})
        with app.test_request_context():
            delete_filter_rule_from_data(mock_session, req)

        filt = capture.written_data["ipv4"]["filters"]["input"]
        assert "10" not in filt["rules"]
        assert "10" not in filt["rule-order"]
        assert "20" in filt["rule-order"]

    def test_delete_last_rule_removes_filter(self, app, mock_session, mock_read_write):
        data = _data_with_filter()  # Only rule 10
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({"rule": "ipv4,input,10"})
        with app.test_request_context():
            delete_filter_rule_from_data(mock_session, req)

        # Filter and ip_version should be cleaned up
        assert "ipv4" not in capture.written_data

    def test_delete_last_rule_removes_ip_version(self, app, mock_session, mock_read_write):
        data = _data_with_filter()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({"rule": "ipv4,input,10"})
        with app.test_request_context():
            delete_filter_rule_from_data(mock_session, req)

        assert "ipv4" not in capture.written_data

    def test_delete_nonexistent_rule(self, app, mock_session, mock_read_write):
        data = _data_with_filter()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({"rule": "ipv4,input,99"})
        with app.test_request_context():
            delete_filter_rule_from_data(mock_session, req)

        # Should not crash; original rule 10 remains
        assert capture.written_data is not None


# ===================================================================
# reorder_filter_rule_in_data
# ===================================================================


class TestReorderFilterRuleInData:
    def test_valid_reorder(self, app, mock_session, mock_read_write):
        data = _data_with_filter()
        capture = mock_read_write("package.filter_functions", data)
        req = make_request({
            "reorder_rule": "ipv4,input,10",
            "new_rule_number": "50",
        })
        with app.test_request_context():
            result = reorder_filter_rule_in_data(mock_session, req)

        assert result == "ipv4input"
        filt = capture.written_data["ipv4"]["filters"]["input"]
        assert "50" in filt["rule-order"]
        assert "10" not in filt["rule-order"]
        assert "50" in filt["rules"]
        assert "10" not in filt["rules"]

    def test_same_number_error(self, app, mock_session, mock_read_write):
        data = _data_with_filter()
        mock_read_write("package.filter_functions", data)
        req = make_request({
            "reorder_rule": "ipv4,input,10",
            "new_rule_number": "10",
        })
        with app.test_request_context():
            result = reorder_filter_rule_in_data(mock_session, req)

        assert result is None

    def test_non_integer_error(self, app, mock_session, mock_read_write):
        data = _data_with_filter()
        mock_read_write("package.filter_functions", data)
        req = make_request({
            "reorder_rule": "ipv4,input,10",
            "new_rule_number": "xyz",
        })
        with app.test_request_context():
            result = reorder_filter_rule_in_data(mock_session, req)

        assert result is None

    def test_duplicate_number_error(self, app, mock_session, mock_read_write):
        data = _data_with_two_filter_rules()
        mock_read_write("package.filter_functions", data)
        req = make_request({
            "reorder_rule": "ipv4,input,10",
            "new_rule_number": "20",
        })
        with app.test_request_context():
            result = reorder_filter_rule_in_data(mock_session, req)

        assert result is None

    def test_malformed_rule_string(self, app, mock_session, mock_read_write):
        data = _data_with_filter()
        mock_read_write("package.filter_functions", data)
        req = make_request({
            "reorder_rule": "ipv4,input",  # only 2 parts
            "new_rule_number": "50",
        })
        with app.test_request_context():
            result = reorder_filter_rule_in_data(mock_session, req)

        assert result is None
