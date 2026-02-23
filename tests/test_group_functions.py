"""
Tests for package.group_funtions module.

Note: The source filename has a historical typo (group_funtions, not group_functions).

Covers: add_group_to_data, assemble_detail_list_of_groups,
        assemble_list_of_groups, delete_group_from_data
"""

import pytest

from tests.conftest import make_request

from package.group_funtions import (
    add_group_to_data,
    assemble_detail_list_of_groups,
    assemble_list_of_groups,
    delete_group_from_data,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_data():
    """Minimal starting data for add operations."""
    return {"version": "1"}


def _data_with_group():
    """Data with an existing ipv4 address group."""
    return {
        "version": "1",
        "ipv4": {
            "groups": {
                "WebServers": {
                    "group_desc": "Web server addresses",
                    "group_type": "address-group",
                    "group_value": ["10.0.0.1", "10.0.0.2"],
                }
            }
        },
    }


def _data_with_two_groups():
    """Data with two groups under ipv4."""
    data = _data_with_group()
    data["ipv4"]["groups"]["DBServers"] = {
        "group_desc": "Database servers",
        "group_type": "address-group",
        "group_value": ["10.0.1.1"],
    }
    return data


# ===================================================================
# add_group_to_data
# ===================================================================


class TestAddGroupToData:
    def test_address_group_ipv4(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({
            "group_type": "address-group",
            "ip_version": "ipv4",
            "group_desc": "Web servers",
            "group_name": "WebServers",
            "group_value": "10.0.0.1,10.0.0.2",
        })
        with app.test_request_context():
            add_group_to_data(mock_session, req)

        grp = capture.written_data["ipv4"]["groups"]["WebServers"]
        assert grp["group_desc"] == "Web servers"
        assert grp["group_type"] == "address-group"
        assert grp["group_value"] == ["10.0.0.1", "10.0.0.2"]

    def test_address_group_ipv6(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({
            "group_type": "address-group",
            "ip_version": "ipv6",
            "group_desc": "IPv6 servers",
            "group_name": "V6Servers",
            "group_value": "::1,fe80::1",
        })
        with app.test_request_context():
            add_group_to_data(mock_session, req)

        assert "ipv6" in capture.written_data
        grp = capture.written_data["ipv6"]["groups"]["V6Servers"]
        assert grp["group_type"] == "address-group"
        assert grp["group_value"] == ["::1", "fe80::1"]

    def test_network_group(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({
            "group_type": "network-group",
            "ip_version": "ipv4",
            "group_desc": "Private networks",
            "group_name": "PrivateNets",
            "group_value": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
        })
        with app.test_request_context():
            add_group_to_data(mock_session, req)

        grp = capture.written_data["ipv4"]["groups"]["PrivateNets"]
        assert grp["group_type"] == "network-group"
        assert len(grp["group_value"]) == 3

    def test_port_group_defaults_to_ipv4(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({
            "group_type": "port-group",
            "group_desc": "Web ports",
            "group_name": "WebPorts",
            "group_value": "80,443,8080",
        })
        with app.test_request_context():
            add_group_to_data(mock_session, req)

        # port-group should default to ipv4
        grp = capture.written_data["ipv4"]["groups"]["WebPorts"]
        assert grp["group_type"] == "port-group"
        assert grp["group_value"] == ["80", "443", "8080"]

    def test_domain_group(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({
            "group_type": "domain-group",
            "group_desc": "Bad domains",
            "group_name": "BadDomains",
            "group_value": "evil.com,bad.org",
        })
        with app.test_request_context():
            add_group_to_data(mock_session, req)

        grp = capture.written_data["ipv4"]["groups"]["BadDomains"]
        assert grp["group_type"] == "domain-group"
        assert grp["group_value"] == ["evil.com", "bad.org"]

    def test_mac_group(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({
            "group_type": "mac-group",
            "group_desc": "Trusted MACs",
            "group_name": "TrustedMACs",
            "group_value": "00:11:22:33:44:55,AA:BB:CC:DD:EE:FF",
        })
        with app.test_request_context():
            add_group_to_data(mock_session, req)

        grp = capture.written_data["ipv4"]["groups"]["TrustedMACs"]
        assert grp["group_type"] == "mac-group"
        assert len(grp["group_value"]) == 2

    def test_interface_group(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({
            "group_type": "interface-group",
            "group_desc": "LAN interfaces",
            "group_name": "LANInterfaces",
            "group_value": "eth0,eth1,eth2",
        })
        with app.test_request_context():
            add_group_to_data(mock_session, req)

        grp = capture.written_data["ipv4"]["groups"]["LANInterfaces"]
        assert grp["group_type"] == "interface-group"
        assert grp["group_value"] == ["eth0", "eth1", "eth2"]

    def test_whitespace_trimming(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({
            "group_type": "port-group",
            "group_desc": "Ports",
            "group_name": "Ports",
            "group_value": " 80 , 443 , 8080 ",
        })
        with app.test_request_context():
            add_group_to_data(mock_session, req)

        grp = capture.written_data["ipv4"]["groups"]["Ports"]
        assert grp["group_value"] == ["80", "443", "8080"]

    def test_name_with_spaces_removed(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({
            "group_type": "port-group",
            "group_desc": "Web Ports",
            "group_name": "Web Ports Group",
            "group_value": "80,443",
        })
        with app.test_request_context():
            add_group_to_data(mock_session, req)

        assert "WebPortsGroup" in capture.written_data["ipv4"]["groups"]
        assert "Web Ports Group" not in capture.written_data["ipv4"]["groups"]

    def test_comma_separated_values(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({
            "group_type": "address-group",
            "ip_version": "ipv4",
            "group_desc": "Multiple hosts",
            "group_name": "Hosts",
            "group_value": "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4",
        })
        with app.test_request_context():
            add_group_to_data(mock_session, req)

        grp = capture.written_data["ipv4"]["groups"]["Hosts"]
        assert len(grp["group_value"]) == 4
        assert grp["group_value"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]


# ===================================================================
# assemble_detail_list_of_groups
# ===================================================================


class TestAssembleDetailListOfGroups:
    def test_with_groups(self, app, mock_session, mock_read_write):
        data = _data_with_group()
        mock_read_write("package.group_funtions", data)
        with app.test_request_context():
            result = assemble_detail_list_of_groups(mock_session)

        assert len(result) == 1
        assert result[0]["ip_version"] == "ipv4"
        assert result[0]["group_name"] == "WebServers"
        assert result[0]["group_desc"] == "Web server addresses"
        assert result[0]["group_type"] == "address-group"
        assert result[0]["group_value"] == ["10.0.0.1", "10.0.0.2"]

    def test_empty_data(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        mock_read_write("package.group_funtions", data)
        with app.test_request_context():
            result = assemble_detail_list_of_groups(mock_session)

        assert result == []


# ===================================================================
# assemble_list_of_groups
# ===================================================================


class TestAssembleListOfGroups:
    def test_with_groups(self, app, mock_session, mock_read_write):
        data = _data_with_group()
        mock_read_write("package.group_funtions", data)
        with app.test_request_context():
            result = assemble_list_of_groups(mock_session)

        assert result == [["ipv4", "WebServers"]]

    def test_empty_data(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        mock_read_write("package.group_funtions", data)
        with app.test_request_context():
            result = assemble_list_of_groups(mock_session)

        assert result == []


# ===================================================================
# delete_group_from_data
# ===================================================================


class TestDeleteGroupFromData:
    def test_basic_delete(self, app, mock_session, mock_read_write):
        data = _data_with_two_groups()
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({"group": "ipv4,WebServers"})
        with app.test_request_context():
            delete_group_from_data(mock_session, req)

        assert "WebServers" not in capture.written_data["ipv4"]["groups"]
        assert "DBServers" in capture.written_data["ipv4"]["groups"]

    def test_last_group_cleanup(self, app, mock_session, mock_read_write):
        data = _data_with_group()  # Only WebServers
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({"group": "ipv4,WebServers"})
        with app.test_request_context():
            delete_group_from_data(mock_session, req)

        # ip_version should be cleaned up
        assert "ipv4" not in capture.written_data

    def test_delete_from_empty(self, app, mock_session, mock_read_write):
        data = {
            "version": "1",
            "ipv4": {
                "groups": {}
            },
        }
        capture = mock_read_write("package.group_funtions", data)
        req = make_request({"group": "ipv4,NonExistent"})
        with app.test_request_context():
            delete_group_from_data(mock_session, req)

        # Should not crash; data is still written
        assert capture.written_data is not None
