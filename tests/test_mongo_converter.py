"""Tests for package/mongo_converter.py"""

import json
import os
import sqlite3
from unittest.mock import patch, mock_open, MagicMock

import pytest

from package.mongo_converter import mongo_converter


@pytest.fixture
def converter_env(tmp_path):
    """Set up a temporary environment for mongo_converter tests."""
    # Create SQLite database with user table
    db_dir = tmp_path / "data" / "database"
    db_dir.mkdir(parents=True)
    db_path = db_dir / "auth.db"

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE User (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)"
    )
    conn.commit()
    conn.close()

    return tmp_path, db_path


def _add_user(db_path, username):
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO User (username, password, email) VALUES (?, ?, ?)",
        (username, "hashed", f"{username}@test.com"),
    )
    conn.commit()
    conn.close()


def test_mongo_converter_full_flow(converter_env):
    tmp_path, db_path = converter_env

    _add_user(db_path, "testuser")

    # Create user directory with JSON file
    user_dir = tmp_path / "data" / "testuser"
    user_dir.mkdir(parents=True)
    json_file = user_dir / "firewall.json"
    json_data = {"version": "1", "ipv4": {"chains": {}}}
    json_file.write_text(json.dumps(json_data))

    with (
        patch(
            "package.mongo_converter.sqlite3.connect",
            return_value=sqlite3.connect(str(db_path)),
        ),
        patch("package.mongo_converter.os.listdir") as mock_listdir,
        patch("package.mongo_converter.write_user_data_file") as mock_write,
        patch("package.mongo_converter.os.rename") as mock_rename,
        patch("builtins.open", mock_open(read_data=json.dumps(json_data))),
    ):
        mock_listdir.return_value = ["firewall.json"]

        mongo_converter()

        mock_write.assert_called_once()
        mock_rename.assert_called_once()


def test_mongo_converter_no_users(converter_env):
    tmp_path, db_path = converter_env

    with patch(
        "package.mongo_converter.sqlite3.connect",
        return_value=sqlite3.connect(str(db_path)),
    ):
        # No users, so no files to process
        mongo_converter()


def test_mongo_converter_no_json_files(converter_env):
    tmp_path, db_path = converter_env

    _add_user(db_path, "testuser")

    with (
        patch(
            "package.mongo_converter.sqlite3.connect",
            return_value=sqlite3.connect(str(db_path)),
        ),
        patch("package.mongo_converter.os.listdir") as mock_listdir,
        patch("package.mongo_converter.write_user_data_file") as mock_write,
    ):
        mock_listdir.return_value = ["notes.txt", "backup.zip"]

        mongo_converter()

        mock_write.assert_not_called()


def test_mongo_converter_user_dir_missing(converter_env):
    tmp_path, db_path = converter_env

    _add_user(db_path, "ghostuser")

    with (
        patch(
            "package.mongo_converter.sqlite3.connect",
            return_value=sqlite3.connect(str(db_path)),
        ),
        patch(
            "package.mongo_converter.os.listdir",
            side_effect=FileNotFoundError("No such directory"),
        ),
        patch("package.mongo_converter.write_user_data_file") as mock_write,
    ):
        # Should handle missing user directory gracefully
        mongo_converter()

        mock_write.assert_not_called()


def test_mongo_converter_removes_id_field(converter_env):
    tmp_path, db_path = converter_env

    _add_user(db_path, "testuser")

    json_data = {"_id": "old_id", "version": "1", "ipv4": {}}

    with (
        patch(
            "package.mongo_converter.sqlite3.connect",
            return_value=sqlite3.connect(str(db_path)),
        ),
        patch("package.mongo_converter.os.listdir") as mock_listdir,
        patch("package.mongo_converter.write_user_data_file") as mock_write,
        patch("package.mongo_converter.os.rename"),
        patch("builtins.open", mock_open(read_data=json.dumps(json_data))),
    ):
        mock_listdir.return_value = ["firewall.json"]

        mongo_converter()

        written_data = mock_write.call_args[0][1]
        assert "_id" not in written_data
