"""
Tests for package/data_file_functions.py

Covers: allowed_file, update_schema, get_extra_items, get_system_name,
        list_user_keys, list_full_backups, list_user_files, list_snapshots,
        read_user_data_file, write_user_data_file, delete_user_data_file,
        add_extra_items, add_hostname, sweep_legacy_user_files,
        set_snapshot_tag, tag_snapshot, validate_mongodb_connection,
        upload_backup_file.
"""

import copy
import logging
import os
import sys
import zipfile
from datetime import datetime
from unittest.mock import MagicMock, patch

import mongomock
import pytest

from package.data_file_functions import (
    add_extra_items,
    add_hostname,
    allowed_file,
    create_backup,
    create_snapshot,
    delete_user_data_file,
    get_extra_items,
    get_system_name,
    list_full_backups,
    list_snapshots,
    list_user_files,
    list_user_keys,
    read_user_data_file,
    restore_snapshot,
    set_snapshot_tag,
    tag_snapshot,
    sweep_legacy_user_files,
    update_schema,
    upload_backup_file,
    validate_mongodb_connection,
    write_user_data_file,
)
# Captured at import time on purpose: conftest's session-scoped mongo_client
# fixture replaces package.data_file_functions._get_mongo_client with a
# mongomock lambda, so looking the name up later would test the stub.
from package.data_file_functions import _get_mongo_client as _real_get_client
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
    """Keys come from MongoDB as of 2.5.0, not from scanning the user's dir."""

    @pytest.fixture
    def keys(self, mock_mongo):
        from package import ssh_key_store

        return ssh_key_store.collection()

    def _store(self, keys, user, *names):
        for name in names:
            keys.insert_one({"_id": f"{user}/{name}", "user": user, "name": name})

    def test_with_keys(self, keys):
        self._store(keys, "testuser", "server1", "server2")
        assert list_user_keys({"username": "testuser"}) == ["server1", "server2"]

    def test_no_keys(self, keys):
        assert list_user_keys({"username": "testuser"}) == []

    def test_scoped_to_the_session_user(self, keys):
        """Another user's keys must not be listed, let alone offered."""
        self._store(keys, "testuser", "mine")
        self._store(keys, "someone-else", "theirs")

        assert list_user_keys({"username": "testuser"}) == ["mine"]

    def test_keys_are_sorted(self, keys):
        self._store(keys, "testuser", "zebra", "alpha", "middle")
        assert list_user_keys({"username": "testuser"}) == ["alpha", "middle", "zebra"]

    def test_two_users_may_share_a_key_name(self, keys):
        self._store(keys, "testuser", "id_rsa")
        self._store(keys, "someone-else", "id_rsa")

        assert list_user_keys({"username": "testuser"}) == ["id_rsa"]
        assert list_user_keys({"username": "someone-else"}) == ["id_rsa"]


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

    def test_read_snapshot_is_non_destructive(self, mock_mongo, sample_user_data):
        # A plain read of a snapshot must NOT overwrite current.
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one({"_id": "test_firewall", **sample_user_data})
        snap_data = copy.deepcopy(sample_user_data)
        snap_data["firewall"] = "test_firewall"
        snap_data["snapshot"] = "snap1"
        snap_data["extra-items"] = ["snapshot item"]
        coll.insert_one(snap_data)
        read_user_data_file("data/testuser/test_firewall", snapshot="snap1")
        current = coll.find_one({"_id": "test_firewall"})
        assert "extra-items" not in current

    def test_read_raises_on_db_error(self, monkeypatch):
        # A DB error must propagate, not be swallowed into {} (which callers
        # would treat as an empty config and could overwrite real data).
        import pymongo

        class BoomColl:
            def find(self, *a, **k):
                raise pymongo.errors.PyMongoError("boom")

        class BoomDB:
            def __getitem__(self, name):
                return BoomColl()

        class BoomClient:
            def __getitem__(self, name):
                return BoomDB()

        monkeypatch.setattr(
            "package.data_file_functions._get_mongo_client", lambda: BoomClient()
        )
        with pytest.raises(pymongo.errors.PyMongoError):
            read_user_data_file("data/testuser/test_firewall")


class TestRestoreSnapshot:
    def test_restore_overwrites_current(self, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one({"_id": "test_firewall", **sample_user_data})
        snap_data = copy.deepcopy(sample_user_data)
        snap_data["firewall"] = "test_firewall"
        snap_data["snapshot"] = "snap1"
        snap_data["extra-items"] = ["snapshot item"]
        coll.insert_one(snap_data)

        result = restore_snapshot("data/testuser/test_firewall", "snap1")

        assert result["extra-items"] == ["snapshot item"]
        # Current now reflects the snapshot, with snapshot/firewall fields stripped.
        current = coll.find_one({"_id": "test_firewall"})
        assert current["extra-items"] == ["snapshot item"]
        assert "snapshot" not in current
        assert "firewall" not in current

    def test_restore_missing_snapshot_leaves_current(self, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one({"_id": "test_firewall", **sample_user_data})

        result = restore_snapshot("data/testuser/test_firewall", "does-not-exist")

        assert result == {}
        # Current must be untouched.
        assert coll.find_one({"_id": "test_firewall"}) is not None

    def test_restore_does_not_leak_tag_to_current(self, mock_mongo, sample_user_data):
        """The snapshot's tag must not follow it onto the working copy."""
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one({"_id": "test_firewall", **copy.deepcopy(sample_user_data)})
        snap_data = copy.deepcopy(sample_user_data)
        snap_data["firewall"] = "test_firewall"
        snap_data["snapshot"] = "snap1"
        snap_data["tag"] = "pre-upgrade"
        coll.insert_one(snap_data)

        restore_snapshot("data/testuser/test_firewall", "snap1")

        assert "tag" not in coll.find_one({"_id": "test_firewall"})
        # The snapshot keeps its own tag.
        assert (
            coll.find_one({"firewall": "test_firewall", "snapshot": "snap1"})["tag"]
            == "pre-upgrade"
        )


class TestCreateSnapshot:
    def test_copies_current_into_a_new_snapshot(self, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        current = copy.deepcopy(sample_user_data)
        current["extra-items"] = ["current item"]
        coll.insert_one({"_id": "test_firewall", **current})

        name = create_snapshot("data/testuser/test_firewall")

        snap = coll.find_one({"firewall": "test_firewall", "snapshot": name})
        assert snap["extra-items"] == ["current item"]
        assert "tag" not in snap
        # The working copy is left alone.
        assert coll.find_one({"_id": "test_firewall"})["extra-items"] == ["current item"]

    def test_applies_the_tag(self, mock_mongo, sample_user_data):
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one({"_id": "test_firewall", **copy.deepcopy(sample_user_data)})

        name = create_snapshot("data/testuser/test_firewall", "my-tag")

        snap = coll.find_one({"firewall": "test_firewall", "snapshot": name})
        assert snap["tag"] == "my-tag"

    def test_no_current_config_creates_nothing(self, mock_mongo):
        db = mock_mongo["test_db"]
        coll = db["testuser"]

        assert create_snapshot("data/testuser/test_firewall") is None
        assert coll.count_documents({}) == 0

    def test_name_collision_steps_to_the_next_second(
        self, mock_mongo, sample_user_data
    ):
        """A snapshot in the same second must not overwrite an existing one."""
        db = mock_mongo["test_db"]
        coll = db["testuser"]
        coll.insert_one({"_id": "test_firewall", **copy.deepcopy(sample_user_data)})

        first = create_snapshot("data/testuser/test_firewall", "first")
        with patch("package.data_file_functions.datetime") as mock_datetime:
            # Force the second create back onto the first one's timestamp.
            mock_datetime.now.return_value = datetime.strptime(
                first, "%m-%d-%Y %H:%M:%S"
            )
            second = create_snapshot("data/testuser/test_firewall", "second")

        assert second != first
        assert coll.count_documents({"firewall": "test_firewall"}) == 2
        assert coll.find_one({"snapshot": first})["tag"] == "first"
        assert coll.find_one({"snapshot": second})["tag"] == "second"


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

    def test_write_current_unsets_snapshot_only_keys(self, mock_mongo):
        """$set alone would leave a previously leaked tag stored forever."""
        db = mock_mongo["test_db"]
        db["testuser"].insert_one(
            {
                "_id": "myfirewall",
                "version": "1",
                "tag": "leaked",
                "firewall": "myfirewall",
                "snapshot": "old-snap",
            }
        )

        write_user_data_file("data/testuser/myfirewall", {"version": "1"})

        doc = db["testuser"].find_one({"_id": "myfirewall"})
        assert "tag" not in doc
        assert "firewall" not in doc
        assert "snapshot" not in doc

    def test_write_current_strips_tag_from_input(self, mock_mongo):
        write_user_data_file(
            "data/testuser/myfirewall", {"version": "1", "tag": "should not persist"}
        )
        db = mock_mongo["test_db"]
        assert "tag" not in db["testuser"].find_one({"_id": "myfirewall"})

    def test_write_snapshot_keeps_tag(self, mock_mongo, sample_user_data):
        data = copy.deepcopy(sample_user_data)
        data["tag"] = "keep-me"
        write_user_data_file("data/testuser/test_firewall", data, snapshot="snap_2024")
        db = mock_mongo["test_db"]
        doc = db["testuser"].find_one(
            {"firewall": "test_firewall", "snapshot": "snap_2024"}
        )
        assert doc["tag"] == "keep-me"

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
# set_snapshot_tag / tag_snapshot
# ===========================================================================


def _insert_snapshot(coll, sample_user_data, snapshot="snap_2024", **extra):
    """Insert a snapshot document for test_firewall and return it."""
    snap_data = copy.deepcopy(sample_user_data)
    snap_data["firewall"] = "test_firewall"
    snap_data["snapshot"] = snapshot
    snap_data.update(extra)
    coll.insert_one(snap_data)
    return snap_data


class TestSetSnapshotTag:
    def test_sets_tag(self, mock_mongo, sample_user_data):
        coll = mock_mongo["test_db"]["testuser"]
        _insert_snapshot(coll, sample_user_data)

        assert (
            set_snapshot_tag("data/testuser/test_firewall", "snap_2024", "pre-upgrade")
            is True
        )

        doc = coll.find_one({"firewall": "test_firewall", "snapshot": "snap_2024"})
        assert doc["tag"] == "pre-upgrade"

    def test_empty_tag_removes_the_field(self, mock_mongo, sample_user_data):
        coll = mock_mongo["test_db"]["testuser"]
        _insert_snapshot(coll, sample_user_data, tag="old-tag")

        assert set_snapshot_tag("data/testuser/test_firewall", "snap_2024", "") is True

        doc = coll.find_one({"firewall": "test_firewall", "snapshot": "snap_2024"})
        assert "tag" not in doc

    def test_unknown_snapshot_writes_nothing(self, mock_mongo, sample_user_data):
        coll = mock_mongo["test_db"]["testuser"]
        _insert_snapshot(coll, sample_user_data)
        before = coll.count_documents({})

        assert (
            set_snapshot_tag("data/testuser/test_firewall", "no_such_snap", "x") is False
        )

        # No upsert: a bad name must not create a ghost snapshot document.
        assert coll.count_documents({}) == before

    def test_does_not_rewrite_config_data(self, mock_mongo, sample_user_data):
        coll = mock_mongo["test_db"]["testuser"]
        _insert_snapshot(coll, sample_user_data)
        coll.update_one(
            {"firewall": "test_firewall", "snapshot": "snap_2024"},
            {"$set": {"ipv4": {"marker": True}}},
        )

        set_snapshot_tag("data/testuser/test_firewall", "snap_2024", "note")

        doc = coll.find_one({"firewall": "test_firewall", "snapshot": "snap_2024"})
        assert doc["ipv4"] == {"marker": True}


class TestTagSnapshot:
    def test_tag_snapshot_updates_tag(self, app, mock_mongo, sample_user_data):
        coll = mock_mongo["test_db"]["testuser"]
        _insert_snapshot(coll, sample_user_data)
        session = {"username": "testuser", "data_dir": "data/testuser"}
        request = make_request(
            {
                "firewall_name": "test_firewall",
                "snapshot_name": "snap_2024",
                "snapshot_tag": "pre-upgrade",
            }
        )
        with app.test_request_context():
            assert tag_snapshot(session, request) is True
        doc = coll.find_one({"firewall": "test_firewall", "snapshot": "snap_2024"})
        assert doc["tag"] == "pre-upgrade"

    def test_tag_snapshot_flashes_success(self, app, mock_mongo, sample_user_data):
        coll = mock_mongo["test_db"]["testuser"]
        _insert_snapshot(coll, sample_user_data)
        session = {"username": "testuser", "data_dir": "data/testuser"}
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

    def test_tag_snapshot_trims_and_truncates(self, app, mock_mongo, sample_user_data):
        coll = mock_mongo["test_db"]["testuser"]
        _insert_snapshot(coll, sample_user_data)
        session = {"username": "testuser", "data_dir": "data/testuser"}
        request = make_request(
            {
                "firewall_name": "test_firewall",
                "snapshot_name": "snap_2024",
                "snapshot_tag": "  " + "x" * 150 + "  ",
            }
        )
        with app.test_request_context():
            tag_snapshot(session, request)
        doc = coll.find_one({"firewall": "test_firewall", "snapshot": "snap_2024"})
        assert doc["tag"] == "x" * 100

    def test_tag_snapshot_clears_tag(self, app, mock_mongo, sample_user_data):
        coll = mock_mongo["test_db"]["testuser"]
        _insert_snapshot(coll, sample_user_data, tag="old-tag")
        session = {"username": "testuser", "data_dir": "data/testuser"}
        request = make_request(
            {
                "firewall_name": "test_firewall",
                "snapshot_name": "snap_2024",
                "snapshot_tag": "   ",
            }
        )
        with app.test_request_context():
            assert tag_snapshot(session, request) is True
        doc = coll.find_one({"firewall": "test_firewall", "snapshot": "snap_2024"})
        assert "tag" not in doc

    @pytest.mark.parametrize(
        "form",
        [
            {"firewall_name": "../escape", "snapshot_name": "snap_2024"},
            {"firewall_name": "test_firewall", "snapshot_name": "a/b"},
            {"firewall_name": "", "snapshot_name": "snap_2024"},
        ],
    )
    def test_tag_snapshot_rejects_unsafe_names(
        self, app, mock_mongo, sample_user_data, form
    ):
        coll = mock_mongo["test_db"]["testuser"]
        _insert_snapshot(coll, sample_user_data)
        session = {"username": "testuser", "data_dir": "data/testuser"}
        request = make_request({**form, "snapshot_tag": "nope"})
        with app.test_request_context():
            from flask import get_flashed_messages

            assert tag_snapshot(session, request) is False
            messages = get_flashed_messages(with_categories=True)
        assert any(cat == "danger" for cat, msg in messages)

    def test_tag_snapshot_missing_snapshot_flashes_danger(
        self, app, mock_mongo, sample_user_data
    ):
        """A name that does not resolve used to raise TypeError (an HTTP 500)."""
        coll = mock_mongo["test_db"]["testuser"]
        _insert_snapshot(coll, sample_user_data)
        session = {"username": "testuser", "data_dir": "data/testuser"}
        request = make_request(
            {
                "firewall_name": "test_firewall",
                "snapshot_name": "no_such_snap",
                "snapshot_tag": "nope",
            }
        )
        with app.test_request_context():
            from flask import get_flashed_messages

            assert tag_snapshot(session, request) is False
            messages = get_flashed_messages(with_categories=True)
        assert any(cat == "danger" for cat, msg in messages)


# ===========================================================================
# validate_mongodb_connection
# ===========================================================================


class TestMongoClientTimeout:
    """The shared client must not use pymongo's 30s server-selection default.

    Every stalled request holds a waitress thread, so an unreachable database
    would wedge the server instead of failing fast.
    """

    def test_shared_client_bounds_server_selection(self, monkeypatch):
        import package.data_file_functions as dff

        captured = {}

        def fake_client(uri, **kwargs):
            captured["uri"] = uri
            captured["kwargs"] = kwargs
            return MagicMock()

        monkeypatch.setattr(dff, "_mongo_client", None)
        monkeypatch.setattr(dff.pymongo, "MongoClient", fake_client)
        monkeypatch.setenv("MONGODB_URI", "mongodb://localhost:27017")

        _real_get_client()

        assert (
            captured["kwargs"]["serverSelectionTimeoutMS"]
            == dff.SERVER_SELECTION_TIMEOUT_MS
        )
        # A bound only helps if it is meaningfully below pymongo's 30s default.
        assert 0 < dff.SERVER_SELECTION_TIMEOUT_MS <= 10000

    def test_client_is_reused(self, monkeypatch):
        """The bound must not come at the cost of a client per call."""
        import package.data_file_functions as dff

        calls = []

        def fake_client(uri, **kwargs):
            calls.append(uri)
            return MagicMock()

        monkeypatch.setattr(dff, "_mongo_client", None)
        monkeypatch.setattr(dff.pymongo, "MongoClient", fake_client)

        _real_get_client()
        _real_get_client()

        assert len(calls) == 1


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

    def test_probe_uses_the_shared_timeout(self, monkeypatch):
        """Was 1ms, which is shorter than a real connection takes.

        A mongod that is up but still starting -- the normal case behind
        Compose's healthcheck-less depends_on -- would fail the probe and exit the
        app into a restart loop.
        """
        import package.data_file_functions as dff

        captured = {}

        def fake_client(uri, **kwargs):
            captured.update(kwargs)
            return MagicMock()

        monkeypatch.setattr(dff.pymongo, "MongoClient", fake_client)

        validate_mongodb_connection("mongodb://localhost:27017")

        assert (
            captured["serverSelectionTimeoutMS"] == dff.SERVER_SELECTION_TIMEOUT_MS
        )
        # Long enough for a starting mongod, short enough not to hang a boot.
        assert 1000 <= dff.SERVER_SELECTION_TIMEOUT_MS <= 10000


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


# ---------------------------------------------------------------------------
# create_backup
# ---------------------------------------------------------------------------


class TestCreateBackup:
    @pytest.fixture
    def data_tree(self, tmp_path, monkeypatch):
        """Build a data/ tree in a temp cwd and return its root."""
        data = tmp_path / "data"
        (data / "backups").mkdir(parents=True)
        (data / "database").mkdir()
        (data / "tmp").mkdir()
        (data / "uploads").mkdir()
        (data / "myuser").mkdir()
        (data / "database" / "instance.id.migrated").write_text("abc")
        (data / "database" / "auth.db.migrated").write_bytes(b"legacy bcrypt hashes")
        (data / "myuser" / "old_rsa.key.migrated").write_bytes(b"retired ciphertext")
        (data / "myuser" / "id_rsa.key").write_bytes(b"encrypted key")
        (data / "myuser" / "firewall.json").write_text("{}")
        (data / "tmp" / "scratch").write_text("x")
        (data / "uploads" / "upload.json").write_text("{}")
        monkeypatch.chdir(tmp_path)
        return data

    def _zip_names(self, data):
        archives = list((data / "backups").glob("full-backup-*.zip"))
        assert len(archives) == 1
        with zipfile.ZipFile(archives[0]) as zf:
            return set(zf.namelist())

    def test_full_backup_excludes_legacy_auth_db_and_keys(
        self, data_tree, monkeypatch
    ):
        monkeypatch.setattr("package.data_file_functions.mongo_dump", lambda: None)
        monkeypatch.setattr(
            "package.data_file_functions.upload_backup_file", lambda path: None
        )
        from flask import Flask

        test_app = Flask(__name__)
        test_app.config["SECRET_KEY"] = "test"
        with test_app.test_request_context():
            create_backup({"username": "myuser"}, user=False)

        names = self._zip_names(data_tree)
        # Ordinary per-user files are still archived.
        assert "myuser/firewall.json" in names
        # The retired instance id is not a secret, so unlike auth.db* it is kept.
        assert "database/instance.id.migrated" in names
        # Legacy bcrypt hashes must not leave the host in a backup zip.
        assert not any(n.startswith("database/auth.db") for n in names)
        # Pre-existing exclusions still hold.
        assert not any(n.endswith(".key") for n in names)
        # The retained key file is a redundant second copy of a secret the Mongo
        # dump already carries -- endswith(".key") does not match it.
        assert not any(n.endswith(".key.migrated") for n in names)
        assert not any(n.startswith(("backups/", "tmp/", "uploads/")) for n in names)


# ---------------------------------------------------------------------------
# sweep_legacy_user_files
# ---------------------------------------------------------------------------


class TestSweepLegacyUserFiles:
    @pytest.fixture
    def data_tree(self, tmp_path, monkeypatch):
        """Build a data/ tree in a temp cwd and return its root."""
        data = tmp_path / "data"
        (data / "alice").mkdir(parents=True)
        (data / "other_tmp").mkdir()
        monkeypatch.chdir(tmp_path)
        return data

    def test_removes_legacy_files_and_keeps_everything_else(self, data_tree):
        """The .json survival assertion is the load-bearing one.

        mongo_converter still needs to import those, so the sweep must never
        widen to them.
        """
        (data_tree / "alice" / "fw.conf").write_text("set firewall")
        (data_tree / "alice" / "fw.old").write_text('{"version": "1"}')
        (data_tree / "alice" / "fw.json").write_text("{}")
        (data_tree / "alice" / "id_rsa.key").write_bytes(b"encrypted key")
        (data_tree / "alice" / "id_rsa.key.migrated").write_bytes(b"retired")
        (data_tree / "alice" / "user-alice-backup-2026.zip").write_bytes(b"PK")

        sweep_legacy_user_files(["alice"])

        assert not (data_tree / "alice" / "fw.conf").exists()
        assert not (data_tree / "alice" / "fw.old").exists()
        assert (data_tree / "alice" / "fw.json").exists()
        assert (data_tree / "alice" / "id_rsa.key").exists()
        # .key.migrated is the SSH-key rollback copy; the sweep must never take it.
        assert (data_tree / "alice" / "id_rsa.key.migrated").exists()
        assert (data_tree / "alice" / "user-alice-backup-2026.zip").exists()

    def test_leaves_non_user_directories_alone(self, data_tree):
        """The sweep is bounded to account directories.

        A data/*/* glob would also delete from stray directories that never
        belonged to a user.
        """
        (data_tree / "other_tmp" / "firewall.conf").write_text("set firewall")
        (data_tree / "other_tmp" / "firewall.old").write_text("{}")

        sweep_legacy_user_files(["alice"])

        assert (data_tree / "other_tmp" / "firewall.conf").exists()
        assert (data_tree / "other_tmp" / "firewall.old").exists()

    @pytest.mark.parametrize("suffix", ["conf", "old"])
    def test_removes_names_with_spaces_and_parens(self, data_tree, suffix):
        """Firewall names allow spaces and parentheses, so filenames do too."""
        target = data_tree / "alice" / f"vyos-ue-1 (AWS).{suffix}"
        target.write_text("set firewall")

        sweep_legacy_user_files(["alice"])

        assert not target.exists()

    def test_username_without_directory_is_not_an_error(self, data_tree):
        sweep_legacy_user_files(["alice", "nonexistent-user"])

    def test_remove_failure_does_not_raise(self, data_tree, monkeypatch, caplog):
        """Housekeeping must never stop startup."""
        (data_tree / "alice" / "fw.conf").write_text("set firewall")

        def boom(path):
            raise OSError("permission denied")

        monkeypatch.setattr("package.data_file_functions.os.remove", boom)

        with caplog.at_level(logging.WARNING):
            sweep_legacy_user_files(["alice"])

        assert any("Error sweeping legacy" in r.message for r in caplog.records)

    def test_list_usernames_failure_does_not_raise(self, data_tree, caplog):
        """A MongoDB failure mid-iteration is swallowed too."""

        def exploding_usernames():
            yield "alice"
            raise RuntimeError("mongo went away")

        with caplog.at_level(logging.WARNING):
            sweep_legacy_user_files(exploding_usernames())

        assert any("Error sweeping legacy" in r.message for r in caplog.records)
