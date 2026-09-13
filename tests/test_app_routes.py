"""Tests for app.py route handlers.

Tests Flask routes using the real app with mocked package-level functions.
Templates render for real to catch variable mismatches.
"""

import os
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Login-required guard
# ---------------------------------------------------------------------------
class TestLoginRequired:
    """Unauthenticated requests redirect to /user_login."""

    def test_index_requires_login(self, client):
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/user_login" in resp.headers["Location"]

    def test_chain_view_requires_login(self, client):
        resp = client.get("/chain_view")
        assert resp.status_code == 302
        assert "/user_login" in resp.headers["Location"]

    def test_group_delete_requires_login(self, client):
        resp = client.post("/group_delete")
        assert resp.status_code == 302
        assert "/user_login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------
class TestAuthRoutes:
    """Login, registration, logout, and password change."""

    def test_login_get(self, client):
        resp = client.get("/user_login")
        assert resp.status_code == 200

    def test_login_get_registration_enabled(self, client):
        with patch.dict(os.environ, {"DISABLE_REGISTRATION": "False"}):
            resp = client.get("/user_login")
            assert resp.status_code == 200
            assert b"Register" in resp.data

    def test_login_get_registration_disabled(self, client):
        with patch.dict(os.environ, {"DISABLE_REGISTRATION": "True"}):
            resp = client.get("/user_login")
            assert resp.status_code == 200
            assert b"Register" not in resp.data

    def test_login_post_success(self, client):
        with patch(
            "app.process_login",
            return_value=(True, "data/testuser", "testuser"),
        ):
            resp = client.post(
                "/user_login",
                data={"username": "testuser", "password": "testpass"},
            )
            assert resp.status_code == 302
            assert resp.headers["Location"] == "/"

    def test_login_post_failure(self, client):
        with patch(
            "app.process_login", return_value=(False, None, None)
        ):
            resp = client.post(
                "/user_login",
                data={"username": "bad", "password": "bad"},
            )
            assert resp.status_code == 302
            assert "/user_login" in resp.headers["Location"]

    def test_registration_get_enabled(self, client):
        with patch.dict(os.environ, {"DISABLE_REGISTRATION": "False"}):
            resp = client.get("/user_registration")
            assert resp.status_code == 200

    def test_registration_get_disabled(self, client):
        with patch.dict(os.environ, {"DISABLE_REGISTRATION": "True"}):
            resp = client.get("/user_registration")
            assert resp.status_code == 302
            assert "/user_login" in resp.headers["Location"]

    def test_registration_post_success(self, client):
        with patch.dict(os.environ, {"DISABLE_REGISTRATION": "False"}), patch(
            "app.register_user", return_value=True
        ) as mock_reg:
            resp = client.post(
                "/user_registration",
                data={
                    "username": "newuser",
                    "password": "pass",
                    "email": "a@b.com",
                },
            )
            assert resp.status_code == 302
            assert "/user_login" in resp.headers["Location"]
            mock_reg.assert_called_once()

    def test_registration_post_failure(self, client):
        with patch.dict(os.environ, {"DISABLE_REGISTRATION": "False"}), patch(
            "app.register_user", return_value=False
        ):
            resp = client.post(
                "/user_registration",
                data={"username": "bad", "password": "bad"},
            )
            assert resp.status_code == 302
            assert "/user_registration" in resp.headers["Location"]

    def test_registration_post_disabled(self, client):
        with patch.dict(os.environ, {"DISABLE_REGISTRATION": "True"}):
            resp = client.post(
                "/user_registration", data={"username": "new"}
            )
            assert resp.status_code == 302
            assert "/user_login" in resp.headers["Location"]

    def test_logout(self, auth_client):
        # Logout takes the name straight from the session; no user lookup.
        resp = auth_client.get("/user_logout")
        assert resp.status_code == 302

    def test_change_password_get(self, auth_client):
        with patch("app.list_user_files", return_value=[]), patch(
            "app.list_snapshots", return_value=[]
        ):
            resp = auth_client.get("/user_change_password")
            assert resp.status_code == 200

    def test_change_password_post_success(self, auth_client):
        with patch("app.change_password", return_value=True):
            resp = auth_client.post(
                "/user_change_password",
                data={
                    "current_password": "old",
                    "new_password": "new",
                    "confirm_password": "new",
                },
            )
            assert resp.status_code == 302
            assert resp.headers["Location"] == "/"

    def test_change_password_post_failure(self, auth_client):
        with patch("app.change_password", return_value=False):
            resp = auth_client.post(
                "/user_change_password",
                data={"current_password": "wrong"},
            )
            assert resp.status_code == 302
            assert "/user_change_password" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Group routes
# ---------------------------------------------------------------------------
class TestGroupRoutes:
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        with patch("app.list_user_files", return_value=["test_firewall"]), patch(
            "app.list_snapshots", return_value=[]
        ):
            yield

    def test_group_add_get(self, auth_client):
        resp = auth_client.get("/group_add")
        assert resp.status_code == 200

    def test_group_add_post_add(self, auth_client):
        with patch("app.add_group_to_data") as mock_add:
            resp = auth_client.post(
                "/group_add",
                data={
                    "type": "add",
                    "ip_version": "ipv4",
                    "group_type": "address-group",
                    "group_name": "test",
                    "group_values": "1.1.1.1",
                },
            )
            assert resp.status_code == 302
            assert "/group_view" in resp.headers["Location"]
            mock_add.assert_called_once()

    def test_group_add_post_edit(self, auth_client):
        resp = auth_client.post(
            "/group_add",
            data={
                "type": "edit",
                "ip_version": "ipv4",
                "group_type": "address-group",
                "group_name": "test",
                "group_values": "1.1.1.1",
            },
        )
        assert resp.status_code == 200

    def test_group_delete(self, auth_client):
        with patch("app.delete_group_from_data") as mock_del:
            resp = auth_client.post(
                "/group_delete",
                data={
                    "ip_version": "ipv4",
                    "group_type": "address-group",
                    "group_name": "test",
                },
            )
            assert resp.status_code == 302
            assert "/group_view" in resp.headers["Location"]
            mock_del.assert_called_once()

    def test_group_view(self, auth_client):
        with patch("app.assemble_detail_list_of_groups", return_value=[]):
            resp = auth_client.get("/group_view")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Interface routes
# ---------------------------------------------------------------------------
class TestInterfaceRoutes:
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        with patch("app.list_user_files", return_value=["test_firewall"]), patch(
            "app.list_snapshots", return_value=[]
        ):
            yield

    def test_interface_add_get(self, auth_client):
        resp = auth_client.get("/interface_add")
        assert resp.status_code == 200

    def test_interface_add_post_add(self, auth_client):
        with patch("app.add_interface_to_data") as mock_add:
            resp = auth_client.post(
                "/interface_add",
                data={
                    "type": "add",
                    "interface_name": "eth0",
                    "interface_desc": "WAN",
                },
            )
            assert resp.status_code == 302
            assert "/interface_view" in resp.headers["Location"]
            mock_add.assert_called_once()

    def test_interface_delete_post(self, auth_client):
        with patch("app.delete_interface_from_data") as mock_del:
            resp = auth_client.post(
                "/interface_delete", data={"interface_name": "eth0"}
            )
            assert resp.status_code == 302
            assert "/interface_view" in resp.headers["Location"]
            mock_del.assert_called_once()

    def test_interface_delete_get(self, auth_client):
        resp = auth_client.get("/interface_delete")
        assert resp.status_code == 302
        assert "/display_config" in resp.headers["Location"]

    def test_interface_view(self, auth_client):
        with patch("app.list_interfaces", return_value=[]):
            resp = auth_client.get("/interface_view")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Flowtable routes
# ---------------------------------------------------------------------------
class TestFlowtableRoutes:
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        with patch("app.list_user_files", return_value=["test_firewall"]), patch(
            "app.list_snapshots", return_value=[]
        ), patch("app.list_interfaces", return_value=[]):
            yield

    def test_flowtable_add_get(self, auth_client):
        resp = auth_client.get("/flowtable_add")
        assert resp.status_code == 200

    def test_flowtable_add_post_add(self, auth_client):
        with patch("app.add_flowtable_to_data") as mock_add:
            resp = auth_client.post(
                "/flowtable_add", data={"type": "add"}
            )
            assert resp.status_code == 302
            assert "/flowtable_view" in resp.headers["Location"]
            mock_add.assert_called_once()

    def test_flowtable_delete_post(self, auth_client):
        with patch("app.delete_flowtable_from_data") as mock_del:
            resp = auth_client.post(
                "/flowtable_delete", data={"flowtable_name": "ft1"}
            )
            assert resp.status_code == 302
            assert "/flowtable_view" in resp.headers["Location"]
            mock_del.assert_called_once()

    def test_flowtable_delete_get(self, auth_client):
        resp = auth_client.get("/flowtable_delete")
        assert resp.status_code == 302
        assert "/display_config" in resp.headers["Location"]

    def test_flowtable_view(self, auth_client):
        with patch("app.list_flowtables", return_value=[]):
            resp = auth_client.get("/flowtable_view")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Chain routes
# ---------------------------------------------------------------------------
class TestChainRoutes:
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        with patch("app.list_user_files", return_value=["test_firewall"]), patch(
            "app.list_snapshots", return_value=[]
        ):
            yield

    def test_chain_add_get(self, auth_client):
        resp = auth_client.get("/chain_add")
        assert resp.status_code == 200

    def test_chain_add_post(self, auth_client):
        with patch("app.add_chain_to_data") as mock_add:
            resp = auth_client.post(
                "/chain_add",
                data={"chain_name": "test", "ip_version": "ipv4"},
            )
            assert resp.status_code == 302
            assert "/chain_view" in resp.headers["Location"]
            mock_add.assert_called_once()

    def test_chain_rule_add_get_chains_exist(self, auth_client):
        with patch(
            "app.assemble_list_of_chains", return_value=["test_chain"]
        ), patch("app.assemble_detail_list_of_groups", return_value=[]):
            resp = auth_client.get("/chain_rule_add")
            assert resp.status_code == 200

    def test_chain_rule_add_get_no_chains(self, auth_client):
        with patch("app.assemble_list_of_chains", return_value=[]), patch(
            "app.assemble_detail_list_of_groups", return_value=[]
        ):
            resp = auth_client.get("/chain_rule_add")
            assert resp.status_code == 302
            assert "/chain_add" in resp.headers["Location"]

    def test_chain_rule_add_post_add_valid(self, auth_client):
        with patch("app.add_rule_to_data") as mock_add:
            resp = auth_client.post(
                "/chain_rule_add",
                data={
                    "type": "add",
                    "fw_chain": "test_chain",
                    "action": "accept",
                },
            )
            assert resp.status_code == 302
            assert "/chain_view" in resp.headers["Location"]
            mock_add.assert_called_once()

    def test_chain_rule_add_post_add_empty_chain(self, auth_client):
        resp = auth_client.post(
            "/chain_rule_add",
            data={"type": "add", "fw_chain": "", "action": "accept"},
        )
        assert resp.status_code == 302
        assert "/chain_view" in resp.headers["Location"]

    def test_chain_rule_add_post_edit(self, auth_client):
        with patch(
            "app.assemble_list_of_chains", return_value=["test_chain"]
        ), patch("app.assemble_detail_list_of_groups", return_value=[]):
            resp = auth_client.post(
                "/chain_rule_add",
                data={
                    "type": "edit",
                    "fw_chain": "test_chain",
                    "action": "accept",
                    "rule_number": "10",
                    "protocol": "tcp",
                },
            )
            assert resp.status_code == 200

    def test_chain_rule_delete(self, auth_client):
        with patch("app.delete_rule_from_data") as mock_del:
            resp = auth_client.post(
                "/chain_rule_delete",
                data={"fw_chain": "test_chain", "rule_number": "10"},
            )
            assert resp.status_code == 302
            assert "/chain_view" in resp.headers["Location"]
            mock_del.assert_called_once()

    def test_chain_rule_reorder_post(self, auth_client):
        with patch(
            "app.reorder_chain_rule_in_data", return_value="test_chain"
        ) as mock_reorder:
            resp = auth_client.post(
                "/chain_rule_reorder",
                data={
                    "fw_chain": "test_chain",
                    "rule_number": "10",
                    "direction": "up",
                },
            )
            assert resp.status_code == 302
            assert "/chain_view" in resp.headers["Location"]
            mock_reorder.assert_called_once()

    def test_chain_rule_reorder_get(self, auth_client):
        resp = auth_client.get("/chain_rule_reorder")
        assert resp.status_code == 302
        assert "/chain_view" in resp.headers["Location"]

    def test_chain_rule_move_post(self, auth_client):
        with patch(
            "app.move_chain_rule_in_data", return_value="ipv4test_chain"
        ) as mock_move:
            resp = auth_client.post(
                "/chain_rule_move",
                data={"move_rule": "ipv4,test_chain,10", "direction": "up"},
            )
            assert resp.status_code == 302
            assert "/chain_view" in resp.headers["Location"]
            assert "#ipv4test_chain" in resp.headers["Location"]
            mock_move.assert_called_once()

    def test_chain_rule_move_failure_has_no_anchor(self, auth_client):
        with patch("app.move_chain_rule_in_data", return_value=None):
            resp = auth_client.post(
                "/chain_rule_move",
                data={"move_rule": "ipv4,test_chain,10", "direction": "up"},
            )
            assert resp.status_code == 302
            assert "#" not in resp.headers["Location"]

    def test_chain_rules_resequence_post(self, auth_client):
        with patch(
            "app.resequence_chain_rules_in_data", return_value="ipv4test_chain"
        ) as mock_resequence:
            resp = auth_client.post(
                "/chain_rules_resequence",
                data={"chain": "ipv4,test_chain"},
            )
            assert resp.status_code == 302
            assert "/chain_view" in resp.headers["Location"]
            mock_resequence.assert_called_once()

    def test_chain_view_chains_exist(self, auth_client):
        with patch(
            "app.assemble_detail_list_of_chains",
            return_value={"ipv4": {}, "ipv6": {}},
        ):
            resp = auth_client.get("/chain_view")
            assert resp.status_code == 200

    def test_chain_view_no_chains(self, auth_client):
        with patch(
            "app.assemble_detail_list_of_chains", return_value={}
        ):
            resp = auth_client.get("/chain_view")
            assert resp.status_code == 302
            assert "/chain_add" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Filter routes
# ---------------------------------------------------------------------------
class TestFilterRoutes:
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        with patch("app.list_user_files", return_value=["test_firewall"]), patch(
            "app.list_snapshots", return_value=[]
        ):
            yield

    def test_filter_add_get(self, auth_client):
        with patch("app.list_flowtables", return_value=[]):
            resp = auth_client.get("/filter_add")
            assert resp.status_code == 200

    def test_filter_add_post(self, auth_client):
        with patch("app.add_filter_to_data") as mock_add:
            resp = auth_client.post(
                "/filter_add",
                data={"filter_name": "test", "ip_version": "ipv4"},
            )
            assert resp.status_code == 302
            assert "/filter_view" in resp.headers["Location"]
            mock_add.assert_called_once()

    def test_filter_rule_add_get_all_deps(self, auth_client):
        with patch(
            "app.assemble_list_of_chains", return_value=["chain1"]
        ), patch(
            "app.assemble_list_of_filters", return_value=["filter1"]
        ), patch(
            "app.list_interfaces",
            return_value=[{"interface_name": "eth0"}],
        ), patch(
            "app.list_flowtables", return_value=[]
        ):
            resp = auth_client.get("/filter_rule_add")
            assert resp.status_code == 200

    def test_filter_rule_add_get_no_filters(self, auth_client):
        with patch(
            "app.assemble_list_of_chains", return_value=["chain1"]
        ), patch(
            "app.assemble_list_of_filters", return_value=[]
        ), patch(
            "app.list_interfaces",
            return_value=[{"interface_name": "eth0"}],
        ), patch(
            "app.list_flowtables", return_value=[]
        ):
            resp = auth_client.get("/filter_rule_add")
            assert resp.status_code == 302
            assert "/filter_add" in resp.headers["Location"]

    def test_filter_rule_add_get_no_chains(self, auth_client):
        with patch(
            "app.assemble_list_of_chains", return_value=[]
        ), patch(
            "app.assemble_list_of_filters", return_value=["filter1"]
        ), patch(
            "app.list_interfaces",
            return_value=[{"interface_name": "eth0"}],
        ), patch(
            "app.list_flowtables", return_value=[]
        ):
            resp = auth_client.get("/filter_rule_add")
            assert resp.status_code == 302
            assert "/filter_add" in resp.headers["Location"]

    def test_filter_rule_add_get_no_interfaces(self, auth_client):
        with patch(
            "app.assemble_list_of_chains", return_value=["chain1"]
        ), patch(
            "app.assemble_list_of_filters", return_value=["filter1"]
        ), patch("app.list_interfaces", return_value=[]), patch(
            "app.list_flowtables", return_value=[]
        ):
            resp = auth_client.get("/filter_rule_add")
            assert resp.status_code == 302
            assert "/interface_add" in resp.headers["Location"]

    def test_filter_rule_add_post_add(self, auth_client):
        with patch("app.add_filter_rule_to_data") as mock_add:
            resp = auth_client.post(
                "/filter_rule_add",
                data={
                    "type": "add",
                    "filter": "test_filter",
                    "action": "accept",
                },
            )
            assert resp.status_code == 302
            assert "/filter_view" in resp.headers["Location"]
            mock_add.assert_called_once()

    def test_filter_rule_add_post_edit(self, auth_client):
        with patch(
            "app.assemble_list_of_chains", return_value=["chain1"]
        ), patch(
            "app.assemble_list_of_filters", return_value=["filter1"]
        ), patch(
            "app.list_interfaces",
            return_value=[{"interface_name": "eth0"}],
        ), patch(
            "app.list_flowtables", return_value=[]
        ):
            resp = auth_client.post(
                "/filter_rule_add",
                data={
                    "type": "edit",
                    "filter": "test_filter",
                    "action": "accept",
                    "rule_number": "10",
                },
            )
            assert resp.status_code == 200

    def test_filter_rule_delete(self, auth_client):
        with patch("app.delete_filter_rule_from_data") as mock_del:
            resp = auth_client.post(
                "/filter_rule_delete",
                data={"filter": "test_filter", "rule_number": "10"},
            )
            assert resp.status_code == 302
            assert "/filter_view" in resp.headers["Location"]
            mock_del.assert_called_once()

    def test_filter_rule_reorder_post(self, auth_client):
        with patch(
            "app.reorder_filter_rule_in_data",
            return_value="test_filter",
        ) as mock_reorder:
            resp = auth_client.post(
                "/filter_rule_reorder",
                data={
                    "filter": "test_filter",
                    "rule_number": "10",
                    "direction": "up",
                },
            )
            assert resp.status_code == 302
            assert "/filter_view" in resp.headers["Location"]
            mock_reorder.assert_called_once()

    def test_filter_rule_reorder_get(self, auth_client):
        resp = auth_client.get("/filter_rule_reorder")
        assert resp.status_code == 302
        assert "/filter_view" in resp.headers["Location"]

    def test_filter_rule_move_post(self, auth_client):
        with patch(
            "app.move_filter_rule_in_data", return_value="ipv4test_filter"
        ) as mock_move:
            resp = auth_client.post(
                "/filter_rule_move",
                data={"move_rule": "ipv4,test_filter,10", "direction": "down"},
            )
            assert resp.status_code == 302
            assert "/filter_view" in resp.headers["Location"]
            assert "#ipv4test_filter" in resp.headers["Location"]
            mock_move.assert_called_once()

    def test_filter_rule_move_failure_has_no_anchor(self, auth_client):
        with patch("app.move_filter_rule_in_data", return_value=None):
            resp = auth_client.post(
                "/filter_rule_move",
                data={"move_rule": "ipv4,test_filter,10", "direction": "down"},
            )
            assert resp.status_code == 302
            assert "#" not in resp.headers["Location"]

    def test_filter_rules_resequence_post(self, auth_client):
        with patch(
            "app.resequence_filter_rules_in_data", return_value="ipv4test_filter"
        ) as mock_resequence:
            resp = auth_client.post(
                "/filter_rules_resequence",
                data={"filter": "ipv4,test_filter"},
            )
            assert resp.status_code == 302
            assert "/filter_view" in resp.headers["Location"]
            mock_resequence.assert_called_once()

    def test_filter_view_filters_exist(self, auth_client):
        with patch(
            "app.assemble_detail_list_of_filters",
            return_value={"ipv4": {}, "ipv6": {}},
        ):
            resp = auth_client.get("/filter_view")
            assert resp.status_code == 200

    def test_filter_view_no_filters(self, auth_client):
        with patch(
            "app.assemble_detail_list_of_filters", return_value={}
        ):
            resp = auth_client.get("/filter_view")
            assert resp.status_code == 302
            assert "/filter_add" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Configuration routes
# ---------------------------------------------------------------------------
class TestConfigRoutes:
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        with patch("app.list_user_files", return_value=["test_firewall"]), patch(
            "app.list_snapshots", return_value=[]
        ):
            yield

    def test_index_redirects(self, auth_client):
        resp = auth_client.get("/")
        assert resp.status_code == 302
        assert "/display_config" in resp.headers["Location"]

    def test_display_config_firewall_selected(self, auth_client):
        with patch(
            "app.generate_config",
            return_value=("config output", ["line1"]),
        ):
            resp = auth_client.get("/display_config")
            assert resp.status_code == 200

    def test_display_config_no_firewall(self, flask_app):
        test_client = flask_app.test_client()
        with test_client.session_transaction() as sess:
            sess["_user_id"] = "1"
            sess["data_dir"] = "data/testuser"
            sess["username"] = "testuser"
        with patch(
            "app.list_user_files", return_value=[]
        ), patch("app.list_snapshots", return_value=[]):
            resp = test_client.get("/display_config")
            assert resp.status_code == 200
            assert b"No firewall selected" in resp.data

    def test_download_config(self, auth_client):
        with patch(
            "app.generate_config",
            return_value=("line1<br>line2", ["line1", "line2"]),
        ):
            resp = auth_client.get("/download_config")
            assert resp.status_code == 200
            assert b"line1\nline2" in resp.data
            assert "attachment" in resp.headers.get("Content-Disposition", "")
            assert resp.headers.get("Content-Disposition", "").endswith(".conf")
            assert resp.mimetype == "text/plain"

    def test_download_json(self, auth_client):
        with patch(
            "app.download_json_data",
            return_value='{"test": "data"}',
        ):
            resp = auth_client.get("/download_json")
            assert resp.status_code == 200
            assert b'{"test": "data"}' in resp.data
            assert "attachment" in resp.headers.get("Content-Disposition", "")
            assert resp.mimetype == "application/json"

    def test_create_config_valid(self, auth_client):
        with patch("app.write_user_data_file") as mock_write:
            resp = auth_client.post(
                "/create_config", data={"config_name": "new_fw"}
            )
            assert resp.status_code == 302
            assert "/display_config" in resp.headers["Location"]
            mock_write.assert_called_once()

    def test_create_config_empty(self, auth_client):
        resp = auth_client.post(
            "/create_config", data={"config_name": ""}
        )
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/"

    def test_select_firewall_config_file(self, auth_client):
        with patch("app.read_user_data_file"), patch(
            "app.get_system_name", return_value=("192.168.1.1", "22")
        ):
            resp = auth_client.post(
                "/select_firewall_config",
                data={"file": "my_firewall"},
            )
            assert resp.status_code == 302
            assert "/display_config" in resp.headers["Location"]

    def test_select_firewall_config_snapshot_create(self, auth_client):
        with patch("app.create_snapshot") as mock_create, patch(
            "app.get_system_name", return_value=("192.168.1.1", "22")
        ):
            resp = auth_client.post(
                "/select_firewall_config",
                data={"file": "my_fw/create"},
            )
            assert resp.status_code == 302
            mock_create.assert_called_once_with("data/testuser/my_fw")

    def test_select_firewall_config_snapshot_load_auto_snapshots_first(
        self, auth_client
    ):
        """Loading a snapshot must save the working copy it overwrites."""
        call_order = []

        def fake_create(*args, **kwargs):
            call_order.append("create")
            return "09-06-2026 12:00:00"

        with patch("app.create_snapshot", side_effect=fake_create) as mock_create, patch(
            "app.restore_snapshot",
            side_effect=lambda *a, **k: call_order.append("restore"),
        ) as mock_restore, patch(
            "app.get_system_name", return_value=("192.168.1.1", "22")
        ):
            resp = auth_client.post(
                "/select_firewall_config",
                data={"file": "my_fw/snap1"},
            )

        assert resp.status_code == 302
        assert call_order == ["create", "restore"]
        mock_create.assert_called_once_with(
            "data/testuser/my_fw", "auto-snapshot before reloading snapshot"
        )
        mock_restore.assert_called_once_with("data/testuser/my_fw", "snap1")

    def test_select_firewall_config_snapshot_delete(self, auth_client):
        with patch("app.read_user_data_file"), patch(
            "app.delete_user_data_file"
        ) as mock_delete, patch(
            "app.get_system_name", return_value=("192.168.1.1", "22")
        ):
            resp = auth_client.post(
                "/select_firewall_config",
                data={"file": "my_fw/delete/snap1"},
            )
            assert resp.status_code == 302
            mock_delete.assert_called_once()

    def test_select_firewall_config_snapshot_diff(self, auth_client):
        resp = auth_client.post(
            "/select_firewall_config",
            data={"file": "Snapshot Diff"},
        )
        assert resp.status_code == 302
        assert "/snapshot_diff_choose" in resp.headers["Location"]

    def test_delete_config_valid(self, auth_client):
        with patch("app.delete_user_data_file") as mock_del:
            resp = auth_client.post(
                "/delete_config", data={"delete_config": "old_fw"}
            )
            assert resp.status_code == 302
            assert "/display_config" in resp.headers["Location"]
            mock_del.assert_called_once()

    def test_delete_config_empty(self, auth_client):
        resp = auth_client.post(
            "/delete_config", data={"delete_config": ""}
        )
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/"

    def test_upload_json(self, auth_client):
        with patch("app.process_upload") as mock_upload:
            resp = auth_client.post(
                "/upload_json",
                content_type="multipart/form-data",
                data={"file": (None, "")},
            )
            assert resp.status_code == 302
            assert resp.headers["Location"] == "/"
            mock_upload.assert_called_once()

    def test_configuration_extra_items_get(self, auth_client):
        with patch("app.get_extra_items", return_value=""):
            resp = auth_client.get("/configuration_extra_items")
            assert resp.status_code == 200

    def test_configuration_extra_items_post(self, auth_client):
        with patch("app.add_extra_items") as mock_add:
            resp = auth_client.post(
                "/configuration_extra_items",
                data={"extra_items": "set firewall ..."},
            )
            assert resp.status_code == 302
            assert "/display_config" in resp.headers["Location"]
            mock_add.assert_called_once()

    def test_configuration_hostname_add_get(self, auth_client):
        resp = auth_client.get("/configuration_hostname_add")
        assert resp.status_code == 200

    def test_configuration_hostname_add_post(self, auth_client):
        with patch("app.add_hostname") as mock_add:
            resp = auth_client.post(
                "/configuration_hostname_add",
                data={"hostname": "10.0.0.1", "port": "22"},
            )
            assert resp.status_code == 302
            assert "/configuration_push" in resp.headers["Location"]
            mock_add.assert_called_once()

    def test_configuration_push_get_hostname_set(self, auth_client):
        with patch(
            "app.generate_config",
            return_value=("config", ["line"]),
        ), patch("app.test_connection", return_value=True), patch(
            "app.list_user_keys", return_value=[]
        ):
            resp = auth_client.get("/configuration_push")
            assert resp.status_code == 200

    def test_configuration_push_get_hostname_none(self, flask_app):
        test_client = flask_app.test_client()
        with test_client.session_transaction() as sess:
            sess["_user_id"] = "1"
            sess["data_dir"] = "data/testuser"
            sess["firewall_name"] = "test_firewall"
            sess["username"] = "testuser"
            sess["hostname"] = "None"
            sess["port"] = "22"
            sess["ssh_user"] = ""
            sess["ssh_pass"] = ""  # nosec
            sess["ssh_keyname"] = ""
        with patch(
            "app.list_user_files", return_value=[]
        ), patch("app.list_snapshots", return_value=[]):
            resp = test_client.get("/configuration_push")
            assert resp.status_code == 302
            assert (
                "/configuration_hostname_add"
                in resp.headers["Location"]
            )

    def test_configuration_push_renders_bare_key_names(self, auth_client):
        """The radio value must be the bare key name, with no .key suffix.

        SSH keys moved into MongoDB in 2.5.0, addressed by bare name
        (ssh_key_store._document_id -> "<user>/<name>"). The template kept
        appending ".key" -- which the pre-2.5.0 on-disk path needed -- so every
        lookup missed and all key-based auth failed with "No stored SSH key
        named 'x.key'".
        """
        with patch(
            "app.generate_config",
            return_value=("config", ["line"]),
        ), patch("app.test_connection", return_value=True), patch(
            "app.list_user_keys", return_value=["mykey"]
        ):
            resp = auth_client.get("/configuration_push")

            assert resp.status_code == 200
            body = resp.data.decode()
            assert 'name="ssh_key_name" value="mykey"' in body
            assert 'value="mykey.key"' not in body

    def test_configuration_push_forwards_bare_key_name(self, auth_client):
        with patch(
            "app.generate_config",
            return_value=("config", ["line"]),
        ), patch(
            "app.commit_to_firewall",
            return_value="Commit successful",
        ) as mock_commit, patch(
            "app.list_user_keys", return_value=["mykey"]
        ):
            resp = auth_client.post(
                "/configuration_push",
                data={
                    "username": "vyos",
                    "password": "fernet-key",
                    "action": "Commit",
                    "ssh_key_name": "mykey",
                },
            )
            assert resp.status_code == 200
            assert mock_commit.call_args[0][0]["ssh_key_name"] == "mykey"

    def test_configuration_push_strips_legacy_key_suffix(self, auth_client):
        """A browser holding the pre-fix cached form still resolves."""
        with patch(
            "app.generate_config",
            return_value=("config", ["line"]),
        ), patch(
            "app.commit_to_firewall",
            return_value="Commit successful",
        ) as mock_commit, patch(
            "app.list_user_keys", return_value=["mykey"]
        ):
            resp = auth_client.post(
                "/configuration_push",
                data={
                    "username": "vyos",
                    "password": "fernet-key",
                    "action": "Commit",
                    "ssh_key_name": "mykey.key",
                },
            )
            assert resp.status_code == 200
            assert mock_commit.call_args[0][0]["ssh_key_name"] == "mykey"

    def test_configuration_push_post_commit(self, auth_client):
        with patch(
            "app.generate_config",
            return_value=("config", ["line"]),
        ), patch(
            "app.commit_to_firewall",
            return_value="Commit successful",
        ) as mock_commit, patch(
            "app.list_user_keys", return_value=[]
        ):
            resp = auth_client.post(
                "/configuration_push",
                data={
                    "username": "vyos",
                    "password": "vyos",
                    "action": "Commit",
                },
            )
            assert resp.status_code == 200
            mock_commit.assert_called_once()
            # The rendered command string is forwarded, not a file path.
            assert mock_commit.call_args[0][2] == "line"

    def test_configuration_push_post_view_diffs(self, auth_client):
        with patch(
            "app.generate_config",
            return_value=("config", ["line"]),
        ), patch(
            "app.get_diffs_from_firewall",
            return_value="diff output",
        ) as mock_diffs, patch(
            "app.list_user_keys", return_value=[]
        ):
            resp = auth_client.post(
                "/configuration_push",
                data={
                    "username": "vyos",
                    "password": "vyos",
                    "action": "View Diffs",
                },
            )
            assert resp.status_code == 200
            mock_diffs.assert_called_once()
            assert mock_diffs.call_args[0][2] == "line"

    def test_configuration_push_post_commit_delete_before_set(self, auth_client):
        """The delete_before_set checkbox prepends the teardown command."""
        with patch(
            "app.generate_config",
            return_value=("config", ["line"]),
        ), patch(
            "app.commit_to_firewall",
            return_value="Commit successful",
        ) as mock_commit, patch(
            "app.list_user_keys", return_value=[]
        ):
            resp = auth_client.post(
                "/configuration_push",
                data={
                    "username": "vyos",
                    "password": "vyos",
                    "action": "Commit",
                    "delete_before_set": "true",
                },
            )
            assert resp.status_code == 200
            assert mock_commit.call_args[0][2] == "delete firewall\nline"

    def test_configuration_push_post_commit_all_comments(self, auth_client):
        """A config of only banners and blanks forwards an empty string.

        commit_to_firewall guards on that rather than handing NAPALM a falsy
        config, which would raise MergeConfigException.
        """
        with patch(
            "app.generate_config",
            return_value=("config", ["# banner", ""]),
        ), patch(
            "app.commit_to_firewall",
            return_value="No configuration commands to send.",
        ) as mock_commit, patch(
            "app.list_user_keys", return_value=[]
        ):
            resp = auth_client.post(
                "/configuration_push",
                data={
                    "username": "vyos",
                    "password": "vyos",
                    "action": "Commit",
                },
            )
            assert resp.status_code == 200
            assert mock_commit.call_args[0][2] == ""

    def test_snapshot_diff_choose(self, auth_client):
        with patch(
            "app.generate_config",
            return_value=("config", ["line"]),
        ):
            resp = auth_client.get("/snapshot_diff_choose")
            assert resp.status_code == 200

    def test_snapshot_diff_display_valid(self, auth_client):
        with patch(
            "app.process_diff", return_value="<div>diff</div>"
        ):
            resp = auth_client.post(
                "/snapshot_diff_display",
                data={"snapshot_1": "snap1", "snapshot_2": "snap2"},
            )
            assert resp.status_code == 200

    def test_snapshot_diff_display_same_snapshots(self, auth_client):
        resp = auth_client.post(
            "/snapshot_diff_display",
            data={"snapshot_1": "snap1", "snapshot_2": "snap1"},
        )
        assert resp.status_code == 302
        assert "/snapshot_diff_choose" in resp.headers["Location"]

    def test_snapshot_diff_choose_shows_tags(self, auth_client):
        """The chooser must distinguish snapshots by tag, not timestamp alone."""
        with patch("app.generate_config", return_value=("config", ["line"])), patch(
            "app.list_snapshots",
            return_value=[
                {"name": "snap1", "id": "test_firewall", "tag": "pre-upgrade"},
                {"name": "snap2", "id": "test_firewall", "tag": ""},
            ],
        ):
            resp = auth_client.get("/snapshot_diff_choose")
            body = resp.data.decode()

        assert resp.status_code == 200
        assert "pre-upgrade" in body
        # An untagged snapshot shows only its name.
        assert ">snap2</option>" in body

    def test_snapshot_manage_get_shows_tag(self, auth_client):
        with patch("app.generate_config", return_value=("config", ["line"])), patch(
            "app.list_snapshots",
            return_value=[{"name": "snap1", "id": "test_firewall", "tag": "my-tag"}],
        ):
            resp = auth_client.get("/snapshots")
            body = resp.data.decode()

        assert resp.status_code == 200
        assert 'value="my-tag"' in body

    def test_snapshot_tag_post_updates_and_redirects(self, auth_client):
        with patch("app.tag_snapshot", return_value=True) as mock_tag:
            resp = auth_client.post(
                "/snapshot_tag",
                data={
                    "firewall_name": "test_firewall",
                    "snapshot_name": "snap1",
                    "snapshot_tag": "my-tag",
                },
            )

        assert resp.status_code == 302
        assert "/snapshots" in resp.headers["Location"]
        mock_tag.assert_called_once()

    def test_snapshot_tag_create_redirects_to_manage(self, auth_client):
        """The old tag-only URL is kept as a redirect for existing links."""
        resp = auth_client.get("/snapshot_tag_create")
        assert resp.status_code == 302
        assert "/snapshots" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------
class TestAdminRoutes:
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        with patch("app.list_user_files", return_value=["test_firewall"]), patch(
            "app.list_snapshots", return_value=[]
        ), patch("app.list_full_backups", return_value=[]):
            yield

    def test_admin_settings_get(self, auth_client):
        resp = auth_client.get("/admin_settings")
        assert resp.status_code == 200

    def test_admin_settings_does_not_claim_keys_are_excluded(self, auth_client):
        """Backups DO contain SSH keys as of 2.5.0.

        The zip walk skips the on-disk .key files, but the ciphertext arrives via
        keys.bson in the Mongo dump, so telling the operator keys are excluded
        would misrepresent what leaves the host in an archive.
        """
        resp = auth_client.get("/admin_settings")

        body = resp.data.decode()
        assert "excluded from backups" not in body
        assert "MongoDB dump" in body

    def test_admin_settings_shows_instance_counts(self, auth_client):
        stats = {
            "users": 4,
            "disabled_users": 1,
            "configurations": 7,
            "snapshots": 12,
        }
        with patch("app.gather_instance_stats", return_value=stats):
            resp = auth_client.get("/admin_settings")

        body = resp.data.decode()
        assert "Registered Users" in body
        assert "4" in body
        assert "1 disabled" in body
        assert "Firewall Configurations" in body
        assert ">7<" in body
        assert "Snapshots" in body
        assert ">12<" in body

    def test_admin_settings_renders_zero_counts_not_na(self, auth_client):
        """A fresh instance has real zeros; showing "N/A" would look broken."""
        stats = {
            "users": 0,
            "disabled_users": 0,
            "configurations": 0,
            "snapshots": 0,
        }
        with patch("app.gather_instance_stats", return_value=stats):
            resp = auth_client.get("/admin_settings")

        body = resp.data.decode()
        assert "N/A" not in body
        assert "disabled)" not in body

    def test_admin_settings_post_full_backup(self, auth_client):
        with patch("app.create_backup") as mock_backup:
            resp = auth_client.post(
                "/admin_settings", data={"backup": "full_backup"}
            )
            assert resp.status_code == 200
            mock_backup.assert_called_once()

    def test_download_route_is_gone(self, auth_client):
        """Removed in 2.5.0: it read any file under data/ for any logged-in user."""
        resp = auth_client.post(
            "/download",
            data={"path": "data/testuser/", "filename": "anything.txt"},
        )
        assert resp.status_code == 404


class TestSessionCookieHardening:
    def test_cookie_flags(self, flask_app):
        assert flask_app.config["SESSION_COOKIE_HTTPONLY"] is True
        assert flask_app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
        # SESSION_COOKIE_SECURE is not set in the test env -> defaults False.
        assert flask_app.config["SESSION_COOKIE_SECURE"] is False


class TestSecurityHeaders:
    def test_headers_present_on_response(self, client):
        resp = client.get("/user_login")
        assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN"
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    def test_hsts_absent_without_https(self, client):
        # SESSION_COOKIE_SECURE is False in the test env -> no HSTS.
        resp = client.get("/user_login")
        assert "Strict-Transport-Security" not in resp.headers


class TestRegistrationEnabled:
    def test_parsing(self, monkeypatch):
        import app

        cases = {
            "False": True,
            "false": True,
            "": True,
            "True": False,
            "true": False,
            "1": False,
            "yes": False,
        }
        for val, expected in cases.items():
            monkeypatch.setenv("DISABLE_REGISTRATION", val)
            assert app.registration_enabled() is expected

    def test_unset_defaults_enabled(self, monkeypatch):
        import app

        monkeypatch.delenv("DISABLE_REGISTRATION", raising=False)
        assert app.registration_enabled() is True


class TestRequiresFirewall:
    def test_redirects_when_no_firewall_selected(self, auth_client):
        with auth_client.session_transaction() as sess:
            sess.pop("firewall_name", None)
        resp = auth_client.get("/group_view")
        assert resp.status_code == 302
        assert "/display_config" in resp.headers["Location"]

class TestErrorHandlers:
    def test_404_friendly_page(self, client):
        resp = client.get("/definitely-not-a-route")
        assert resp.status_code == 404
        assert b"Error 404" in resp.data
