"""Tests for app.py route handlers.

Tests Flask routes using the real app with mocked package-level functions.
Templates render for real to catch variable mismatches.
"""

import os
from unittest.mock import Mock, patch

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
        mock_user = Mock(username="testuser")
        with patch("app.query_user_by_id", return_value=mock_user):
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

    def test_download_json(self, auth_client):
        with patch(
            "app.download_json_data",
            return_value='{"test": "data"}',
        ):
            resp = auth_client.get("/download_json")
            assert resp.status_code == 200

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
        with patch(
            "app.read_user_data_file", return_value={"test": "data"}
        ), patch("app.write_user_data_file") as mock_write, patch(
            "app.get_system_name", return_value=("192.168.1.1", "22")
        ):
            resp = auth_client.post(
                "/select_firewall_config",
                data={"file": "my_fw/create"},
            )
            assert resp.status_code == 302
            mock_write.assert_called_once()

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

    def test_configuration_push_post_commit(self, auth_client):
        with patch(
            "app.generate_config",
            return_value=("config", ["line"]),
        ), patch("app.write_user_command_conf_file"), patch(
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

    def test_configuration_push_post_view_diffs(self, auth_client):
        with patch(
            "app.generate_config",
            return_value=("config", ["line"]),
        ), patch("app.write_user_command_conf_file"), patch(
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

    def test_admin_settings_post_full_backup(self, auth_client):
        with patch("app.create_backup") as mock_backup:
            resp = auth_client.post(
                "/admin_settings", data={"backup": "full_backup"}
            )
            assert resp.status_code == 200
            mock_backup.assert_called_once()

    def test_download_valid_path(self, auth_client):
        data_dir = os.path.join(os.getcwd(), "data", "testuser")
        os.makedirs(data_dir, exist_ok=True)
        test_file = os.path.join(data_dir, "_test_download.txt")
        try:
            with open(test_file, "wb") as f:
                f.write(b"test content")
            resp = auth_client.post(
                "/download",
                data={
                    "path": "data/testuser/",
                    "filename": "_test_download.txt",
                },
            )
            assert resp.status_code == 200
            assert resp.data == b"test content"
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

    def test_download_path_traversal(self, auth_client):
        resp = auth_client.post(
            "/download",
            data={"path": "../", "filename": "etc/passwd"},
        )
        assert resp.status_code == 302

    def test_snapshot_tag_create_get(self, auth_client):
        with patch(
            "app.generate_config",
            return_value=("config", ["line"]),
        ):
            resp = auth_client.get("/snapshot_tag_create")
            assert resp.status_code == 200
