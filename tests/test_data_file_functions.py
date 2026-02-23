"""
Tests for package/data_file_functions.py

Covers: allowed_file, update_schema, get_extra_items, get_system_name,
        list_user_keys, list_full_backups, list_user_files, list_snapshots,
        read_user_data_file, write_user_data_file, delete_user_data_file,
        add_extra_items, add_hostname, write_user_command_conf_file,
        tag_snapshot, validate_mongodb_connection, upload_backup_file.
"""

import copy
import os
import sys
from unittest.mock import MagicMock, patch

import mongomock
import pytest

from package.data_file_functions import (
    add_extra_items,
    add_hostname,
    allowed_file,
    delete_user_data_file,
    get_extra_items,
    get_system_name,
    list_full_backups,
    list_snapshots,
    list_user_files,
    list_user_keys,
    read_user_data_file,
    tag_snapshot,
    update_schema,
    upload_backup_file,
    validate_mongodb_connection,
    write_user_command_conf_file,
    write_user_data_file,
)
from tests.conftest import make_request


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_mongo(monkeypatch):
    """Provide a mongomock client patched into data_file_functions."""
    client = mongomock.MongoClient()
    monkeypatch.setattr("package.data_file_functions._mongo_client", client)
    monkeypatch.setattr("package.data_file_functions._get_mongo_client", lambda: client)
    monkeypatch.setenv("MONGODB_DATABASE", "test_db")
    monkeypatch.setenv("MONGODB_URI", "mongodb://localhost:27017")
    return client


@pytest.fixture
def sample_user_data():
    """Minimal user data structure for testing."""
    return {
        "version": "1",
        "ipv4": {
            "chains": {"WAN_LOCAL": {"rule-order": [], "default": {"default_action": "drop"}}},
            "groups": {},
            "filters": {},
        },
        "ipv6": {
            "chains": {},
            "groups": {},
            "filters": {},
        },
        "system": {
            "hostname": "192.168.1.1",
            "port": "22",
        },
    }


# ===========================================================================
# allowed_file
# ===========================================================================


class TestAllowedFile:
    def test_json_extension(self):
        assert allowed_file("config.json") is True

    def test_key_extension(self):
        assert allowed_file("mykey.key") is True

    def test_txt_extension(self):
        assert allowed_file("notes.txt") is False

    def test_no_extension(self):
        assert allowed_file("noextension") is False

    def test_empty_string(self):
        assert allowed_file("") is False

    def test_multi_dot_json(self):
        assert allowed_file("file.backup.json") is True

    def test_multi_dot_key(self):
        assert allowed_file("server.prod.key") is True

    def test_case_insensitive_json_upper(self):
        assert allowed_file("config.JSON") is True

    def test_case_insensitive_key_mixed(self):
        assert allowed_file("mykey.Key") is True

    def test_dot_only(self):
        # "." has an empty extension string
        assert allowed_file(".") is False

    def test_hidden_file_json(self):
        assert allowed_file(".hidden.json") is True

    def test_yaml_extension(self):
        assert allowed_file("config.yaml") is False


# ===========================================================================
# update_schema
# ===========================================================================


class TestUpdateSchema:
    def test_v0_to_v1_renames_tables_to_chains(self):
        user_data = {
            "version": "0",
            "ipv4": {
                "tables": {"CHAIN_A": {"rule-order": []}},
                "filters": {},
            },
            "ipv6": {
                "tables": {"CHAIN_B": {"rule-order": []}},
                "filters": {},
            },
        }
        result = update_schema(user_data)
        assert "chains" in result["ipv4"]
        assert "tables" not in result["ipv4"]
        assert "chains" in result["ipv6"]
        assert "tables" not in result["ipv6"]
        assert result["version"] == "1"

    def test_v0_to_v1_renames_fw_table_to_fw_chain(self):
        user_data = {
            "version": "0",
            "ipv4": {
                "filters": {
                    "input": {
                        "rule-order": ["10"],
                        "rules": {
                            "10": {"fw_table": "WAN_LOCAL", "action": "jump"}
                        },
                    }
                },
            },
            "ipv6": {"filters": {}},
        }
        result = update_schema(user_data)
        rule = result["ipv4"]["filters"]["input"]["rules"]["10"]
        assert "fw_chain" in rule
        assert "fw_table" not in rule
        assert rule["fw_chain"] == "WAN_LOCAL"

    def test_v0_to_v1_forward_and_output_filters(self):
        user_data = {
            "version": "0",
            "ipv4": {
                "filters": {
                    "forward": {
                        "rule-order": ["5"],
                        "rules": {"5": {"fw_table": "FWD_CHAIN", "action": "jump"}},
                    },
                    "output": {
                        "rule-order": ["1"],
                        "rules": {"1": {"fw_table": "OUT_CHAIN", "action": "jump"}},
                    },
                },
            },
            "ipv6": {"filters": {}},
        }
        result = update_schema(user_data)
        assert result["ipv4"]["filters"]["forward"]["rules"]["5"]["fw_chain"] == "FWD_CHAIN"
        assert result["ipv4"]["filters"]["output"]["rules"]["1"]["fw_chain"] == "OUT_CHAIN"

    def test_already_v1_no_op(self):
        user_data = {
            "version": "1",
            "ipv4": {"chains": {"A": {}}, "filters": {}},
            "ipv6": {"chains": {}, "filters": {}},
        }
        original = copy.deepcopy(user_data)
        result = update_schema(user_data)
        # Version stays "1" (set at the end regardless)
        assert result["version"] == "1"
        assert result["ipv4"]["chains"] == original["ipv4"]["chains"]

    def test_empty_ipv4_ipv6(self):
        user_data = {"version": "0"}
        result = update_schema(user_data)
        assert result["version"] == "1"

    def test_ipv4_only_no_ipv6(self):
        user_data = {
            "version": "0",
            "ipv4": {
                "tables": {"X": {}},
                "filters": {},
            },
        }
        result = update_schema(user_data)
        assert "chains" in result["ipv4"]
        assert result["version"] == "1"


# ===========================================================================
# get_extra_items
# ===========================================================================


class TestGetExtraItems:
    def test_with_extra_items(self, app, mock_session, mock_mongo, sample_user_data):
        sample_user_data["extra-items"] = ["set firewall foo", "set firewall bar"]
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **sample_user_data})
        with app.test_request_context():
            result = get_extra_items(mock_session)
        assert result == ["set firewall foo", "set firewall bar"]

    def test_without_extra_items_returns_defaults(self, app, mock_session, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **sample_user_data})
        with app.test_request_context():
            result = get_extra_items(mock_session)
        assert len(result) == 3
        assert result[0] == "# Enter set commands here, one per line."

    def test_without_extra_items_flashes_warning(self, app, mock_session, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **sample_user_data})
        with app.test_request_context():
            from flask import get_flashed_messages

            get_extra_items(mock_session)
            messages = get_flashed_messages(with_categories=True)
        assert any("warning" in cat for cat, msg in messages)


# ===========================================================================
# get_system_name
# ===========================================================================


class TestGetSystemName:
    def test_with_system(self, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **sample_user_data})
        session = {"data_dir": "data/testuser", "firewall_name": "test_firewall"}
        hostname, port = get_system_name(session)
        assert hostname == "192.168.1.1"
        assert port == "22"

    def test_without_system(self, mock_mongo):
        user_data = {"version": "1", "ipv4": {}, "ipv6": {}}
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **user_data})
        session = {"data_dir": "data/testuser", "firewall_name": "test_firewall"}
        # read_user_data_file auto-adds system when missing, so hostname will be "None"
        hostname, port = get_system_name(session)
        assert hostname == "None"
        assert port == "None"

    def test_no_data_raises_on_none_return(self, mock_mongo):
        # When the document does not exist, read_user_data_file returns None.
        # get_system_name then raises TypeError because it cannot check
        # 'in' on None. This verifies the current behavior.
        session = {"data_dir": "data/testuser", "firewall_name": "nonexistent"}
        with pytest.raises(TypeError):
            get_system_name(session)


# ===========================================================================
# list_user_keys
# ===========================================================================


class TestListUserKeys:
    def test_with_keys(self, monkeypatch):
        monkeypatch.setattr(
            "os.listdir",
            lambda path: ["server1.key", "server2.key", "config.json"],
        )
        session = {"data_dir": "data/testuser"}
        result = list_user_keys(session)
        assert result == ["server1", "server2"]

    def test_empty_dir(self, monkeypatch):
        monkeypatch.setattr("os.listdir", lambda path: [])
        session = {"data_dir": "data/testuser"}
        result = list_user_keys(session)
        assert result == []

    def test_no_key_files(self, monkeypatch):
        monkeypatch.setattr("os.listdir", lambda path: ["config.json", "backup.zip"])
        session = {"data_dir": "data/testuser"}
        result = list_user_keys(session)
        assert result == []

    def test_keys_are_sorted(self, monkeypatch):
        monkeypatch.setattr(
            "os.listdir",
            lambda path: ["zebra.key", "alpha.key", "middle.key"],
        )
        session = {"data_dir": "data/testuser"}
        result = list_user_keys(session)
        assert result == ["alpha", "middle", "zebra"]


# ===========================================================================
# list_full_backups
# ===========================================================================


class TestListFullBackups:
    def test_with_zip_files(self, monkeypatch):
        monkeypatch.setattr(
            "os.listdir",
            lambda path: ["full-backup-2024-01-01.zip", "full-backup-2024-02-01.zip", "readme.txt"],
        )
        result = list_full_backups({})
        assert result == ["full-backup-2024-01-01.zip", "full-backup-2024-02-01.zip"]

    def test_empty_backup_dir(self, monkeypatch):
        monkeypatch.setattr("os.listdir", lambda path: [])
        result = list_full_backups({})
        assert result == []

    def test_no_zip_files(self, monkeypatch):
        monkeypatch.setattr("os.listdir", lambda path: ["data.json", "log.txt"])
        result = list_full_backups({})
        assert result == []

    def test_backups_are_sorted(self, monkeypatch):
        monkeypatch.setattr(
            "os.listdir",
            lambda path: ["c-backup.zip", "a-backup.zip", "b-backup.zip"],
        )
        result = list_full_backups({})
        assert result == ["a-backup.zip", "b-backup.zip", "c-backup.zip"]


# ===========================================================================
# list_user_files (MongoDB)
# ===========================================================================


class TestListUserFiles:
    def test_returns_firewall_configs(self, mock_mongo):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one({"_id": "fw_alpha", "version": "1"})
        coll.insert_one({"_id": "fw_beta", "version": "1"})
        session = {"username": "testuser"}
        result = list_user_files(session)
        assert result == ["fw_alpha", "fw_beta"]

    def test_excludes_snapshot_documents(self, mock_mongo):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one({"_id": "fw_main", "version": "1"})
        coll.insert_one(
            {"_id": "snap1", "firewall": "fw_main", "snapshot": "2024-01-01", "version": "1"}
        )
        session = {"username": "testuser"}
        result = list_user_files(session)
        assert result == ["fw_main"]

    def test_empty_collection(self, mock_mongo):
        session = {"username": "testuser"}
        result = list_user_files(session)
        assert result == []

    def test_sorted_output(self, mock_mongo):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one({"_id": "zulu", "version": "1"})
        coll.insert_one({"_id": "alpha", "version": "1"})
        coll.insert_one({"_id": "mike", "version": "1"})
        session = {"username": "testuser"}
        result = list_user_files(session)
        assert result == ["alpha", "mike", "zulu"]


# ===========================================================================
# list_snapshots (MongoDB)
# ===========================================================================


class TestListSnapshots:
    def test_returns_snapshots_for_firewall(self, mock_mongo):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one(
            {"_id": "snap_a", "firewall": "test_firewall", "snapshot": "2024-01-01T00:00:00"}
        )
        coll.insert_one(
            {"_id": "snap_b", "firewall": "test_firewall", "snapshot": "2024-02-01T00:00:00"}
        )
        session = {"username": "testuser", "firewall_name": "test_firewall"}
        result = list_snapshots(session)
        assert len(result) == 2
        assert result[0]["name"] == "2024-01-01T00:00:00"
        assert result[0]["id"] == "test_firewall"

    def test_snapshot_with_tag(self, mock_mongo):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one(
            {
                "_id": "snap_tagged",
                "firewall": "test_firewall",
                "snapshot": "2024-03-01",
                "tag": "before-upgrade",
            }
        )
        session = {"username": "testuser", "firewall_name": "test_firewall"}
        result = list_snapshots(session)
        assert result[0]["tag"] == "before-upgrade"

    def test_snapshot_without_tag_returns_empty_string(self, mock_mongo):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one(
            {"_id": "snap_notag", "firewall": "test_firewall", "snapshot": "2024-04-01"}
        )
        session = {"username": "testuser", "firewall_name": "test_firewall"}
        result = list_snapshots(session)
        assert result[0]["tag"] == ""

    def test_no_firewall_in_session_returns_empty(self, mock_mongo):
        session = {"username": "testuser"}
        result = list_snapshots(session)
        assert result == []

    def test_excludes_other_firewall_snapshots(self, mock_mongo):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one(
            {"_id": "s1", "firewall": "fw_a", "snapshot": "2024-01-01"}
        )
        coll.insert_one(
            {"_id": "s2", "firewall": "fw_b", "snapshot": "2024-01-02"}
        )
        session = {"username": "testuser", "firewall_name": "fw_a"}
        result = list_snapshots(session)
        assert len(result) == 1
        assert result[0]["id"] == "fw_a"


# ===========================================================================
# read_user_data_file (MongoDB)
# ===========================================================================


class TestReadUserDataFile:
    def test_read_current(self, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **sample_user_data})
        result = read_user_data_file("data/testuser/test_firewall")
        assert result["version"] == "1"
        assert "ipv4" in result

    def test_read_nonexistent_returns_none(self, mock_mongo):
        # When no document matches, the for-loop doesn't execute and the
        # function falls through the try block returning None implicitly.
        result = read_user_data_file("data/testuser/nonexistent")
        assert result is None

    def test_auto_adds_system_when_missing(self, mock_mongo):
        user_data = {"version": "1", "ipv4": {}, "ipv6": {}}
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **user_data})
        result = read_user_data_file("data/testuser/test_firewall")
        assert "system" in result
        assert result["system"]["hostname"] == "None"
        assert result["system"]["port"] == "None"

    def test_auto_upgrades_v0_to_v1(self, mock_mongo):
        user_data = {
            "ipv4": {
                "tables": {"CHAIN_A": {"rule-order": []}},
                "filters": {},
            },
            "ipv6": {"filters": {}},
        }
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **user_data})
        result = read_user_data_file("data/testuser/test_firewall")
        assert result["version"] == "1"
        assert "chains" in result["ipv4"]
        assert "tables" not in result["ipv4"]

    def test_read_snapshot(self, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        # Insert current document
        coll.insert_one({"_id": "test_firewall", **sample_user_data})
        # Insert snapshot document
        snap_data = copy.deepcopy(sample_user_data)
        snap_data["firewall"] = "test_firewall"
        snap_data["snapshot"] = "2024-01-01"
        coll.insert_one(snap_data)
        result = read_user_data_file(
            "data/testuser/test_firewall", snapshot="2024-01-01"
        )
        assert result["version"] == "1"

    def test_read_snapshot_with_diff_true_does_not_overwrite(self, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one({"_id": "test_firewall", **sample_user_data})
        snap_data = copy.deepcopy(sample_user_data)
        snap_data["firewall"] = "test_firewall"
        snap_data["snapshot"] = "snap1"
        snap_data["extra-items"] = ["snapshot item"]
        coll.insert_one(snap_data)
        result = read_user_data_file(
            "data/testuser/test_firewall", snapshot="snap1", diff=True
        )
        assert "extra-items" in result
        # Original current doc should still exist unchanged
        current = coll.find_one({"_id": "test_firewall"})
        assert current is not None
        assert "extra-items" not in current


# ===========================================================================
# write_user_data_file (MongoDB)
# ===========================================================================


class TestWriteUserDataFile:
    def test_write_current(self, mock_mongo, sample_user_data):
        write_user_data_file("data/testuser/test_firewall", sample_user_data)
        db = mock_mongo["test_db"]
        doc = db["testuser"].find_one({"_id": "test_firewall"})
        assert doc is not None
        assert doc["version"] == "1"

    def test_write_upsert_creates_new(self, mock_mongo):
        data = {"version": "1", "ipv4": {}}
        write_user_data_file("data/testuser/new_fw", data)
        db = mock_mongo["test_db"]
        doc = db["testuser"].find_one({"_id": "new_fw"})
        assert doc is not None

    def test_write_upsert_updates_existing(self, mock_mongo, sample_user_data):
        write_user_data_file("data/testuser/test_firewall", sample_user_data)
        sample_user_data["extra-items"] = ["set foo bar"]
        write_user_data_file("data/testuser/test_firewall", sample_user_data)
        db = mock_mongo["test_db"]
        doc = db["testuser"].find_one({"_id": "test_firewall"})
        assert doc["extra-items"] == ["set foo bar"]

    def test_write_removes_id_field(self, mock_mongo):
        data = {"_id": "should_be_removed", "version": "1"}
        write_user_data_file("data/testuser/myfirewall", data)
        db = mock_mongo["test_db"]
        doc = db["testuser"].find_one({"_id": "myfirewall"})
        assert doc is not None
        assert doc["_id"] == "myfirewall"

    def test_write_snapshot(self, mock_mongo, sample_user_data):
        write_user_data_file(
            "data/testuser/test_firewall", sample_user_data, snapshot="snap_2024"
        )
        db = mock_mongo["test_db"]
        doc = db["testuser"].find_one(
            {"firewall": "test_firewall", "snapshot": "snap_2024"}
        )
        assert doc is not None
        assert doc["firewall"] == "test_firewall"
        assert doc["snapshot"] == "snap_2024"

    def test_write_current_removes_firewall_and_snapshot_fields(self, mock_mongo):
        data = {
            "version": "1",
            "firewall": "leftover",
            "snapshot": "leftover_snap",
        }
        write_user_data_file("data/testuser/test_firewall", data)
        db = mock_mongo["test_db"]
        doc = db["testuser"].find_one({"_id": "test_firewall"})
        assert "firewall" not in doc
        assert "snapshot" not in doc


# ===========================================================================
# delete_user_data_file (MongoDB)
# ===========================================================================


class TestDeleteUserDataFile:
    def test_delete_current(self, mock_mongo, sample_user_data):
        write_user_data_file("data/testuser/test_firewall", sample_user_data)
        delete_user_data_file("data/testuser/test_firewall")
        db = mock_mongo["test_db"]
        doc = db["testuser"].find_one({"_id": "test_firewall"})
        assert doc is None

    def test_delete_snapshot(self, mock_mongo, sample_user_data):
        write_user_data_file(
            "data/testuser/test_firewall", sample_user_data, snapshot="snap1"
        )
        delete_user_data_file("data/testuser/test_firewall/snap1")
        db = mock_mongo["test_db"]
        doc = db["testuser"].find_one(
            {"firewall": "test_firewall", "snapshot": "snap1"}
        )
        assert doc is None

    def test_delete_nonexistent_no_error(self, mock_mongo):
        # Should not raise an exception
        delete_user_data_file("data/testuser/nonexistent_fw")


# ===========================================================================
# add_extra_items
# ===========================================================================


class TestAddExtraItems:
    def test_add_custom_extra_items(self, app, mock_session, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **sample_user_data})
        form_text = "set firewall foo\r\nset firewall bar"
        request = make_request({"extra_items": form_text})
        with app.test_request_context():
            add_extra_items(mock_session, request)
        doc = db["testuser"].find_one({"_id": "test_firewall"})
        assert doc["extra-items"] == ["set firewall foo", "set firewall bar"]

    def test_add_default_items_shows_warning(self, app, mock_session, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **sample_user_data})
        default_text = (
            "# Enter set commands here, one per line.\r\n"
            "# set firewall global-options all-ping 'enable'\r\n"
            "# set firewall global-options log-martians 'disable'"
        )
        request = make_request({"extra_items": default_text})
        with app.test_request_context():
            from flask import get_flashed_messages

            add_extra_items(mock_session, request)
            messages = get_flashed_messages(with_categories=True)
        assert any("warning" in cat for cat, msg in messages)

    def test_add_extra_items_flashes_success(self, app, mock_session, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **sample_user_data})
        request = make_request({"extra_items": "set firewall custom-rule"})
        with app.test_request_context():
            from flask import get_flashed_messages

            add_extra_items(mock_session, request)
            messages = get_flashed_messages(with_categories=True)
        assert any("success" in cat for cat, msg in messages)

    def test_add_extra_items_strips_empty_lines(self, app, mock_session, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **sample_user_data})
        form_text = "set foo\r\n\r\nset bar\r\n"
        request = make_request({"extra_items": form_text})
        with app.test_request_context():
            add_extra_items(mock_session, request)
        doc = db["testuser"].find_one({"_id": "test_firewall"})
        # Empty lines are stripped out
        assert "" not in doc["extra-items"]


# ===========================================================================
# add_hostname
# ===========================================================================


class TestAddHostname:
    def test_updates_hostname_and_port(self, mock_mongo, mock_session, sample_user_data):
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **sample_user_data})
        request = make_request({"hostname": "10.0.0.1", "port": "2222"})
        add_hostname(mock_session, request)
        doc = db["testuser"].find_one({"_id": "test_firewall"})
        assert doc["system"]["hostname"] == "10.0.0.1"
        assert doc["system"]["port"] == "2222"

    def test_overwrites_existing_hostname(self, mock_mongo, mock_session, sample_user_data):
        db = mock_mongo["test_db"]
        db["testuser"].insert_one({"_id": "test_firewall", **sample_user_data})
        request = make_request({"hostname": "first.host", "port": "22"})
        add_hostname(mock_session, request)
        request2 = make_request({"hostname": "second.host", "port": "8022"})
        add_hostname(mock_session, request2)
        doc = db["testuser"].find_one({"_id": "test_firewall"})
        assert doc["system"]["hostname"] == "second.host"
        assert doc["system"]["port"] == "8022"


# ===========================================================================
# write_user_command_conf_file
# ===========================================================================


class TestWriteUserCommandConfFile:
    def test_write_without_delete(self, tmp_path):
        session = {
            "data_dir": str(tmp_path),
            "firewall_name": "test_fw",
        }
        commands = ["set firewall name WAN_LOCAL", "set firewall name WAN_IN"]
        write_user_command_conf_file(session, commands)
        conf_path = tmp_path / "test_fw.conf"
        content = conf_path.read_text()
        assert "set firewall name WAN_LOCAL\n" in content
        assert "set firewall name WAN_IN\n" in content
        assert "delete firewall" not in content

    def test_write_with_delete(self, tmp_path):
        session = {
            "data_dir": str(tmp_path),
            "firewall_name": "test_fw",
        }
        commands = ["set firewall name WAN_LOCAL"]
        write_user_command_conf_file(session, commands, delete=True)
        conf_path = tmp_path / "test_fw.conf"
        content = conf_path.read_text()
        assert content.startswith("#\n# Delete all firewall before setting new values\ndelete firewall\n")
        assert "set firewall name WAN_LOCAL\n" in content

    def test_empty_command_list(self, tmp_path):
        session = {
            "data_dir": str(tmp_path),
            "firewall_name": "test_fw",
        }
        write_user_command_conf_file(session, [])
        conf_path = tmp_path / "test_fw.conf"
        content = conf_path.read_text()
        assert content == ""

    def test_empty_command_list_with_delete(self, tmp_path):
        session = {
            "data_dir": str(tmp_path),
            "firewall_name": "test_fw",
        }
        write_user_command_conf_file(session, [], delete=True)
        conf_path = tmp_path / "test_fw.conf"
        content = conf_path.read_text()
        assert "delete firewall" in content


# ===========================================================================
# tag_snapshot
# ===========================================================================


class TestTagSnapshot:
    def test_tag_snapshot_updates_tag(self, app, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        # Write a snapshot
        snap_data = copy.deepcopy(sample_user_data)
        snap_data["firewall"] = "test_firewall"
        snap_data["snapshot"] = "snap_2024"
        coll.insert_one(snap_data)
        session = {"username": "testuser"}
        request = make_request(
            {
                "firewall_name": "test_firewall",
                "snapshot_name": "snap_2024",
                "snapshot_tag": "pre-upgrade",
            }
        )
        with app.test_request_context():
            tag_snapshot(session, request)
        doc = coll.find_one({"firewall": "test_firewall", "snapshot": "snap_2024"})
        assert doc["tag"] == "pre-upgrade"

    def test_tag_snapshot_flashes_success(self, app, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        snap_data = copy.deepcopy(sample_user_data)
        snap_data["firewall"] = "test_firewall"
        snap_data["snapshot"] = "snap_2024"
        coll.insert_one(snap_data)
        session = {"username": "testuser"}
        request = make_request(
            {
                "firewall_name": "test_firewall",
                "snapshot_name": "snap_2024",
                "snapshot_tag": "my-tag",
            }
        )
        with app.test_request_context():
            from flask import get_flashed_messages

            tag_snapshot(session, request)
            messages = get_flashed_messages(with_categories=True)
        assert any("success" in cat for cat, msg in messages)


# ===========================================================================
# validate_mongodb_connection
# ===========================================================================


class TestValidateMongodbConnection:
    def test_successful_connection(self, monkeypatch):
        mock_client = MagicMock()
        mock_client.server_info.return_value = {"version": "6.0.0"}
        monkeypatch.setattr(
            "package.data_file_functions.pymongo.MongoClient",
            lambda uri, **kwargs: mock_client,
        )
        result = validate_mongodb_connection("mongodb://localhost:27017")
        assert result is True
        mock_client.close.assert_called_once()

    def test_failed_connection_exits(self, monkeypatch):
        def raise_error(uri, **kwargs):
            raise Exception("Connection refused")

        monkeypatch.setattr(
            "package.data_file_functions.pymongo.MongoClient", raise_error
        )
        with pytest.raises(SystemExit):
            validate_mongodb_connection("mongodb://badhost:27017")


# ===========================================================================
# upload_backup_file
# ===========================================================================


class TestUploadBackupFile:
    def test_no_bucket_name_configured(self, monkeypatch):
        monkeypatch.delenv("BUCKET_NAME", raising=False)
        # Should not raise -- just logs and returns
        upload_backup_file("data/backups/test.zip")

    def test_successful_upload(self, monkeypatch):
        monkeypatch.setenv("BUCKET_NAME", "my-bucket")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake-key")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake-secret")
        mock_s3 = MagicMock()
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        monkeypatch.setattr("package.data_file_functions.boto3", mock_boto3)
        # Need app context for flash
        from flask import Flask

        test_app = Flask(__name__)
        test_app.config["SECRET_KEY"] = "test"
        with test_app.test_request_context():
            upload_backup_file("data/backups/full-backup-2024.zip")
        mock_s3.upload_file.assert_called_once_with(
            "data/backups/full-backup-2024.zip",
            "my-bucket",
            "fw-gui/backups/full-backup-2024.zip",
        )

    def test_upload_user_backup_key_format(self, monkeypatch):
        monkeypatch.setenv("BUCKET_NAME", "my-bucket")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake-key")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake-secret")
        mock_s3 = MagicMock()
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        monkeypatch.setattr("package.data_file_functions.boto3", mock_boto3)
        from flask import Flask

        test_app = Flask(__name__)
        test_app.config["SECRET_KEY"] = "test"
        with test_app.test_request_context():
            upload_backup_file("data/myuser/user-myuser-backup-2024.zip")
        # "data/" prefix is removed, so key becomes "fw-gui/backups/myuser/user-myuser-backup-2024.zip"
        mock_s3.upload_file.assert_called_once_with(
            "data/myuser/user-myuser-backup-2024.zip",
            "my-bucket",
            "fw-gui/backups/myuser/user-myuser-backup-2024.zip",
        )

    def test_upload_failure_does_not_raise(self, monkeypatch):
        monkeypatch.setenv("BUCKET_NAME", "my-bucket")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake-key")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake-secret")
        mock_boto3 = MagicMock()
        mock_boto3.client.return_value.upload_file.side_effect = Exception("S3 error")
        monkeypatch.setattr("package.data_file_functions.boto3", mock_boto3)
        # Should not raise
        upload_backup_file("data/backups/test.zip")
