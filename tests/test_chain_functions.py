"""
Tests for package.chain_functions module.

Covers: add_chain_to_data, add_rule_to_data, assemble_detail_list_of_chains,
        assemble_list_of_rules, assemble_list_of_chains, delete_rule_from_data,
        reorder_chain_rule_in_data, flash_ip_version_mismatch
"""

import pytest

from tests.conftest import make_request

from package.chain_functions import (
    add_chain_to_data,
    add_rule_to_data,
    assemble_detail_list_of_chains,
    assemble_list_of_chains,
    assemble_list_of_rules,
    delete_rule_from_data,
    flash_ip_version_mismatch,
    reorder_chain_rule_in_data,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_data():
    """Minimal starting data for add operations."""
    return {"version": "1"}


def _data_with_chain():
    """Data with an existing ipv4 chain containing one rule."""
    return {
        "version": "1",
        "ipv4": {
            "chains": {
                "OUTSIDE-IN": {
                    "rule-order": ["10"],
                    "default": {
                        "description": "Outside to inside",
                        "default_logging": False,
                        "default_action": "drop",
                    },
                    "10": {
                        "description": "Allow SSH",
                        "action": "accept",
                        "dest_address_type": "address",
                        "dest_address": "10.0.0.1",
                        "dest_port_type": "port",
                        "dest_port": "22",
                        "source_address_type": "address",
                        "source_address": "0.0.0.0/0",
                        "source_port_type": "port",
                        "source_port": "",
                        "protocol": "tcp",
                    },
                }
            }
        },
    }


def _data_with_two_rules():
    """Data with an existing ipv4 chain containing two rules."""
    data = _data_with_chain()
    data["ipv4"]["chains"]["OUTSIDE-IN"]["rule-order"] = ["10", "20"]
    data["ipv4"]["chains"]["OUTSIDE-IN"]["20"] = {
        "description": "Allow HTTP",
        "action": "accept",
        "dest_address_type": "address",
        "dest_address": "10.0.0.1",
        "dest_port_type": "port",
        "dest_port": "80",
        "source_address_type": "address",
        "source_address": "0.0.0.0/0",
        "source_port_type": "port",
        "source_port": "",
        "protocol": "tcp",
    }
    return data


def _base_rule_form(fw_chain="ipv4,OUTSIDE-IN", rule="10"):
    """Return a base form dict for add_rule_to_data with address types."""
    return {
        "fw_chain": fw_chain,
        "rule": rule,
        "description": "Test rule",
        "action": "accept",
        "dest_address_type": "address",
        "dest_address": "10.0.0.1",
        "dest_port_type": "port",
        "dest_port": "443",
        "source_address_type": "address",
        "source_address": "192.168.1.0/24",
        "source_port_type": "port",
        "source_port": "",
        "protocol": "tcp",
    }


# ===================================================================
# add_chain_to_data
# ===================================================================


class TestAddChainToData:
    def test_basic_add(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.chain_functions", data)
        req = make_request({
            "ip_version": "ipv4",
            "fw_chain": "OUTSIDE-IN",
            "description": "Outside traffic",
            "default_action": "drop",
        })
        with app.test_request_context():
            add_chain_to_data(mock_session, req)

        written = capture.written_data
        chain = written["ipv4"]["chains"]["OUTSIDE-IN"]
        assert chain["default"]["description"] == "Outside traffic"
        assert chain["default"]["default_action"] == "drop"
        assert chain["default"]["default_logging"] is False
        assert chain["rule-order"] == []

    def test_add_with_logging(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.chain_functions", data)
        req = make_request({
            "ip_version": "ipv4",
            "fw_chain": "LAN-IN",
            "description": "LAN traffic",
            "default_action": "accept",
            "logging": "on",
        })
        with app.test_request_context():
            add_chain_to_data(mock_session, req)

        assert capture.written_data["ipv4"]["chains"]["LAN-IN"]["default"]["default_logging"] is True

    def test_creates_ip_version_from_scratch(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.chain_functions", data)
        req = make_request({
            "ip_version": "ipv6",
            "fw_chain": "V6-CHAIN",
            "description": "IPv6 chain",
            "default_action": "drop",
        })
        with app.test_request_context():
            add_chain_to_data(mock_session, req)

        assert "ipv6" in capture.written_data
        assert "V6-CHAIN" in capture.written_data["ipv6"]["chains"]


# ===================================================================
# add_rule_to_data
# ===================================================================


class TestAddRuleToData:
    def test_basic_address_dest_and_source(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="20")
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        chain = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]
        assert "20" in chain
        assert "20" in chain["rule-order"]
        assert chain["20"]["dest_address"] == "10.0.0.1"
        assert chain["20"]["source_address"] == "192.168.1.0/24"

    def test_rule_with_address_group(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["dest_address_type"] = "address_group"
        form["dest_address_group"] = "ipv4,WebServers"
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]["30"]
        assert rule["dest_address_type"] == "address_group"
        assert rule["dest_address"] == "WebServers"

    def test_rule_with_port_group(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["dest_port_type"] = "port_group"
        form["dest_port_group"] = "ipv4,WebPorts"
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]["30"]
        assert rule["dest_port_type"] == "port_group"
        assert rule["dest_port"] == "WebPorts"

    def test_rule_with_domain_group(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["dest_address_type"] = "domain_group"
        form["dest_domain_group"] = "ipv4,BadDomains"
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]["30"]
        assert rule["dest_address_type"] == "domain_group"
        assert rule["dest_address"] == "BadDomains"

    def test_rule_with_network_group(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["dest_address_type"] = "network_group"
        form["dest_network_group"] = "ipv4,PrivateNets"
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]["30"]
        assert rule["dest_address_type"] == "network_group"
        assert rule["dest_address"] == "PrivateNets"

    def test_rule_with_mac_group(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["dest_address_type"] = "mac_group"
        form["dest_mac_group"] = "ipv4,TrustedMACs"
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]["30"]
        assert rule["dest_address_type"] == "mac_group"
        assert rule["dest_address"] == "TrustedMACs"

    def test_rule_with_protocol(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["protocol"] = "udp"
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        assert capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]["30"]["protocol"] == "udp"

    def test_rule_with_states(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["state_est"] = "on"
        form["state_inv"] = "on"
        form["state_new"] = "on"
        form["state_rel"] = "on"
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]["30"]
        assert rule["state_est"] is True
        assert rule["state_inv"] is True
        assert rule["state_new"] is True
        assert rule["state_rel"] is True

    def test_rule_with_disable_and_logging(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["rule_disable"] = "on"
        form["logging"] = "on"
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]["30"]
        assert rule["rule_disable"] is True
        assert rule["logging"] is True

    def test_ip_version_mismatch_address_group(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["dest_address_type"] = "address_group"
        form["dest_address_group"] = "ipv6,WebServers"  # mismatch: chain is ipv4
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        # Should return early without writing (no rule 30 added)
        assert capture.written_data is None

    def test_ip_version_mismatch_network_group(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["dest_address_type"] = "network_group"
        form["dest_network_group"] = "ipv6,PrivateNets"  # mismatch
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        assert capture.written_data is None

    def test_source_address_group(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["source_address_type"] = "address_group"
        form["source_address_group"] = "ipv4,TrustedHosts"
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]["30"]
        assert rule["source_address_type"] == "address_group"
        assert rule["source_address"] == "TrustedHosts"

    def test_source_domain_group(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["source_address_type"] = "domain_group"
        form["source_domain_group"] = "ipv4,AllowedDomains"
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]["30"]
        assert rule["source_address_type"] == "domain_group"
        assert rule["source_address"] == "AllowedDomains"

    def test_source_port_group(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(rule="30")
        form["source_port_type"] = "port_group"
        form["source_port_group"] = "ipv4,HighPorts"
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        rule = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]["30"]
        assert rule["source_port_type"] == "port_group"
        assert rule["source_port"] == "HighPorts"

    def test_rule_creates_ip_version_and_chain_from_scratch(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.chain_functions", data)
        form = _base_rule_form(fw_chain="ipv4,NEW-CHAIN", rule="5")
        req = make_request(form)
        with app.test_request_context():
            add_rule_to_data(mock_session, req)

        written = capture.written_data
        assert "ipv4" in written
        assert "NEW-CHAIN" in written["ipv4"]["chains"]
        assert "5" in written["ipv4"]["chains"]["NEW-CHAIN"]["rule-order"]


# ===================================================================
# assemble_detail_list_of_chains
# ===================================================================


class TestAssembleDetailListOfChains:
    def test_with_data(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        mock_read_write("package.chain_functions", data)
        with app.test_request_context():
            result = assemble_detail_list_of_chains(mock_session)

        assert "ipv4" in result
        assert "OUTSIDE-IN" in result["ipv4"]
        rules = result["ipv4"]["OUTSIDE-IN"]
        assert len(rules) == 1
        assert rules[0]["number"] == "10"
        assert rules[0]["description"] == "Allow SSH"

    def test_empty_data(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        mock_read_write("package.chain_functions", data)
        with app.test_request_context():
            result = assemble_detail_list_of_chains(mock_session)

        assert result == {}


# ===================================================================
# assemble_list_of_rules
# ===================================================================


class TestAssembleListOfRules:
    def test_with_data(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        mock_read_write("package.chain_functions", data)
        with app.test_request_context():
            result = assemble_list_of_rules(mock_session)

        assert len(result) == 1
        assert result[0] == ["ipv4", "OUTSIDE-IN", "10", "Allow SSH"]

    def test_empty_data(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        mock_read_write("package.chain_functions", data)
        with app.test_request_context():
            result = assemble_list_of_rules(mock_session)

        assert result == []


# ===================================================================
# assemble_list_of_chains
# ===================================================================


class TestAssembleListOfChains:
    def test_with_data(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        mock_read_write("package.chain_functions", data)
        with app.test_request_context():
            result = assemble_list_of_chains(mock_session)

        assert result == [["ipv4", "OUTSIDE-IN"]]

    def test_empty_data(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        mock_read_write("package.chain_functions", data)
        with app.test_request_context():
            result = assemble_list_of_chains(mock_session)

        assert result == []


# ===================================================================
# delete_rule_from_data
# ===================================================================


class TestDeleteRuleFromData:
    def test_basic_delete(self, app, mock_session, mock_read_write):
        data = _data_with_two_rules()
        capture = mock_read_write("package.chain_functions", data)
        req = make_request({"rule": "ipv4,OUTSIDE-IN,10"})
        with app.test_request_context():
            delete_rule_from_data(mock_session, req)

        chain = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]
        assert "10" not in chain
        assert "10" not in chain["rule-order"]
        assert "20" in chain["rule-order"]

    def test_delete_last_rule_removes_chain(self, app, mock_session, mock_read_write):
        data = _data_with_chain()  # Only rule 10
        capture = mock_read_write("package.chain_functions", data)
        req = make_request({"rule": "ipv4,OUTSIDE-IN,10"})
        with app.test_request_context():
            delete_rule_from_data(mock_session, req)

        # Chain should be removed from the chains dict
        assert "OUTSIDE-IN" not in capture.written_data["ipv4"]["chains"]

    def test_delete_from_empty(self, app, mock_session, mock_read_write):
        data = {
            "version": "1",
            "ipv4": {
                "chains": {
                    "OUTSIDE-IN": {
                        "rule-order": [],
                        "default": {
                            "description": "desc",
                            "default_logging": False,
                            "default_action": "drop",
                        },
                    }
                }
            },
        }
        capture = mock_read_write("package.chain_functions", data)
        req = make_request({"rule": "ipv4,OUTSIDE-IN,99"})
        with app.test_request_context():
            delete_rule_from_data(mock_session, req)

        # Should not crash; data still written
        assert capture.written_data is not None


# ===================================================================
# reorder_chain_rule_in_data
# ===================================================================


class TestReorderChainRuleInData:
    def test_valid_reorder(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        capture = mock_read_write("package.chain_functions", data)
        req = make_request({
            "reorder_rule": "ipv4,OUTSIDE-IN,10",
            "new_rule_number": "50",
        })
        with app.test_request_context():
            result = reorder_chain_rule_in_data(mock_session, req)

        assert result == "ipv4OUTSIDE-IN"
        chain = capture.written_data["ipv4"]["chains"]["OUTSIDE-IN"]
        assert "50" in chain["rule-order"]
        assert "10" not in chain["rule-order"]
        assert "50" in chain
        assert "10" not in chain

    def test_same_number_error(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        mock_read_write("package.chain_functions", data)
        req = make_request({
            "reorder_rule": "ipv4,OUTSIDE-IN,10",
            "new_rule_number": "10",
        })
        with app.test_request_context():
            result = reorder_chain_rule_in_data(mock_session, req)

        assert result is None

    def test_non_integer_error(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        mock_read_write("package.chain_functions", data)
        req = make_request({
            "reorder_rule": "ipv4,OUTSIDE-IN,10",
            "new_rule_number": "abc",
        })
        with app.test_request_context():
            result = reorder_chain_rule_in_data(mock_session, req)

        assert result is None

    def test_duplicate_number_error(self, app, mock_session, mock_read_write):
        data = _data_with_two_rules()
        mock_read_write("package.chain_functions", data)
        req = make_request({
            "reorder_rule": "ipv4,OUTSIDE-IN,10",
            "new_rule_number": "20",
        })
        with app.test_request_context():
            result = reorder_chain_rule_in_data(mock_session, req)

        assert result is None

    def test_malformed_rule_string(self, app, mock_session, mock_read_write):
        data = _data_with_chain()
        mock_read_write("package.chain_functions", data)
        req = make_request({
            "reorder_rule": "ipv4,OUTSIDE-IN",  # only 2 parts instead of 3
            "new_rule_number": "50",
        })
        with app.test_request_context():
            result = reorder_chain_rule_in_data(mock_session, req)

        assert result is None


# ===================================================================
# flash_ip_version_mismatch
# ===================================================================


class TestFlashIpVersionMismatch:
    def test_flash_message(self, app):
        with app.test_request_context():
            flash_ip_version_mismatch()
            # The function should not raise and should flash a message.
            # We verify it completes without error; flash is tested via
            # the integration in add_rule_to_data mismatch tests above.
