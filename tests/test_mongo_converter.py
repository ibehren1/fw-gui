"""Tests for package/mongo_converter.py"""

import json
from unittest.mock import patch, mock_open

import mongomock
import pytest

from package import user_store
from package.mongo_converter import mongo_converter


@pytest.fixture
def users(monkeypatch):
    """Patch a mongomock client in and return the users collection."""
    client = mongomock.MongoClient()
    monkeypatch.setattr("package.data_file_functions._mongo_client", client)
    monkeypatch.setattr("package.data_file_functions._get_mongo_client", lambda: client)
    monkeypatch.setenv("MONGODB_DATABASE", "test_db")
    monkeypatch.delenv("MONGODB_USERS_COLLECTION", raising=False)
    return user_store.collection()


def _add_user(users, username, **extra):
    doc = {
        "_id": username,
        "email": f"{username}@test.com",
        "password": "hashed",
        "disabled": False,
    }
    doc.update(extra)
    users.insert_one(doc)


def test_mongo_converter_full_flow(users):
    _add_user(users, "testuser")

    json_data = {"version": "1", "ipv4": {"chains": {}}}

    with (
        patch("package.mongo_converter.os.listdir") as mock_listdir,
        patch("package.mongo_converter.write_user_data_file") as mock_write,
        patch("package.mongo_converter.os.rename") as mock_rename,
        patch("builtins.open", mock_open(read_data=json.dumps(json_data))),
    ):
        mock_listdir.return_value = ["firewall.json"]

        mongo_converter()

        mock_write.assert_called_once()
        mock_rename.assert_called_once()


def test_mongo_converter_no_users(users):
    # No users, so no files to process.
    with patch("package.mongo_converter.os.listdir") as mock_listdir:
        mongo_converter()

        mock_listdir.assert_not_called()


def test_mongo_converter_includes_disabled_users(users):
    """A disabled user's leftover JSON is still imported."""
    _add_user(users, "disableduser", disabled=True)

    json_data = {"version": "1", "ipv4": {}}

    with (
        patch("package.mongo_converter.os.listdir") as mock_listdir,
        patch("package.mongo_converter.write_user_data_file") as mock_write,
        patch("package.mongo_converter.os.rename"),
        patch("builtins.open", mock_open(read_data=json.dumps(json_data))),
    ):
        mock_listdir.return_value = ["firewall.json"]

        mongo_converter()

        assert mock_write.call_args[0][0] == "data/disableduser/firewall"


def test_mongo_converter_no_json_files(users):
    _add_user(users, "testuser")

    with (
        patch("package.mongo_converter.os.listdir") as mock_listdir,
        patch("package.mongo_converter.write_user_data_file") as mock_write,
    ):
        mock_listdir.return_value = ["notes.txt", "backup.zip"]

        mongo_converter()

        mock_write.assert_not_called()


def test_mongo_converter_user_dir_missing(users):
    _add_user(users, "ghostuser")

    with (
        patch(
            "package.mongo_converter.os.listdir",
            side_effect=FileNotFoundError("No such directory"),
        ),
        patch("package.mongo_converter.write_user_data_file") as mock_write,
    ):
        # Should handle missing user directory gracefully
        mongo_converter()

        mock_write.assert_not_called()


def test_mongo_converter_removes_id_field(users):
    _add_user(users, "testuser")

    json_data = {"_id": "old_id", "version": "1", "ipv4": {}}

    with (
        patch("package.mongo_converter.os.listdir") as mock_listdir,
        patch("package.mongo_converter.write_user_data_file") as mock_write,
        patch("package.mongo_converter.os.rename"),
        patch("builtins.open", mock_open(read_data=json.dumps(json_data))),
    ):
        mock_listdir.return_value = ["firewall.json"]

        mongo_converter()

        written_data = mock_write.call_args[0][1]
        assert "_id" not in written_data
