import os
from unittest.mock import Mock, patch

import mongomock
import pytest
from flask import Flask
from flask_login import LoginManager

from package import user_store
from package.auth_functions import (
    change_password,
    check_version,
    process_login,
    register_user,
)


# Fixtures (app, bcrypt, user_model inherited from conftest.py)


@pytest.fixture
def users(monkeypatch):
    """Patch a mongomock client in and return the users collection."""
    client = mongomock.MongoClient()
    monkeypatch.setattr("package.data_file_functions._mongo_client", client)
    monkeypatch.setattr("package.data_file_functions._get_mongo_client", lambda: client)
    monkeypatch.setenv("MONGODB_DATABASE", "test_db")
    monkeypatch.delenv("MONGODB_USERS_COLLECTION", raising=False)
    return user_store.collection()


def seed(users, username="testuser", password="hashed_oldpass", **extra):
    """Insert a user document. Password defaults to a MockBcrypt-style hash."""
    doc = {"_id": username, "email": f"{username}@test.com", "password": password}
    doc.update(extra)
    users.insert_one(doc)
    return doc


def stored(users, username="testuser"):
    return users.find_one({"_id": username})


@pytest.fixture
def version_file(tmp_path):
    target_output = os.path.join(tmp_path, ".version")
    with open(target_output, "w") as f:
        f.write("v1.0.0")
    return target_output


# Test change_password function
def test_change_password_success(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "newpass123",
                "confirm_password": "newpass123",
            }

        seed(users)

        result = change_password(bcrypt, "testuser", MockRequest())

        assert result is True
        # Stored as str, not BSON Binary: the production path decodes the hash.
        assert stored(users)["password"] == "hashed_newpass123"
        assert isinstance(stored(users)["password"], str)


def test_change_password_mismatch(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "newpass",
                "confirm_password": "different",
            }

        result = change_password(bcrypt, "testuser", MockRequest())

        assert result is False


def test_change_password_empty(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "",
                "confirm_password": "",
            }

        result = change_password(bcrypt, "testuser", MockRequest())

        assert result is False


def test_change_password_unknown_user(app, bcrypt, users):
    """A session can outlive its account; that must not 500."""
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "newpass123",
                "confirm_password": "newpass123",
            }

        result = change_password(bcrypt, "ghost", MockRequest())

        assert result is False


def test_change_password_disabled_user(app, bcrypt, users):
    """A disabled account must not be able to rotate its way back in."""
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "newpass123",
                "confirm_password": "newpass123",
            }

        seed(users, disabled=True)

        result = change_password(bcrypt, "testuser", MockRequest())

        assert result is False
        assert stored(users)["password"] == "hashed_oldpass"


def test_change_password_unusable_stored_hash(app, bcrypt, users):
    """An empty stored hash fails the login rather than raising ValueError."""
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "newpass123",
                "confirm_password": "newpass123",
            }

        seed(users, password="")

        class RaisingBcrypt:
            def check_password_hash(self, hashed, password):
                raise ValueError("invalid salt")

            def generate_password_hash(self, password, rounds=None, prefix=None):
                return b"unused"

        assert change_password(RaisingBcrypt(), "testuser", MockRequest()) is False


# Test check_version function
def test_check_version_update_available(app, version_file):
    with app.test_request_context():
        with patch("package.auth_functions.urllib3.request") as mock_request:
            mock_response = Mock()
            mock_response.data.decode.return_value = "v3.0.0"
            mock_request.return_value = mock_response

            with patch("builtins.open", create=True) as mock_open:
                from io import StringIO

                mock_open.return_value.__enter__ = lambda s: StringIO("v1.0.0")
                mock_open.return_value.__exit__ = Mock(return_value=False)

                # Use the real version_file fixture
                with open(version_file, "r") as f:
                    local_ver = f.read()
                assert local_ver == "v1.0.0"

                with patch("builtins.open", return_value=open(version_file, "r")):
                    check_version()


def test_check_version_current(app, version_file):
    with app.test_request_context():
        with patch("package.auth_functions.urllib3.request") as mock_request:
            mock_response = Mock()
            mock_response.data.decode.return_value = "v1.0.0"
            mock_request.return_value = mock_response

            with patch("builtins.open", return_value=open(version_file, "r")):
                check_version()


def test_check_version_dev_version(app, tmp_path):
    dev_version_file = os.path.join(tmp_path, ".version")
    with open(dev_version_file, "w") as f:
        f.write("v99.0.0")

    with app.test_request_context():
        with patch("package.auth_functions.urllib3.request") as mock_request:
            mock_response = Mock()
            mock_response.data.decode.return_value = "v1.0.0"
            mock_request.return_value = mock_response

            with patch("builtins.open", return_value=open(dev_version_file, "r")):
                check_version()


def test_check_version_network_error(app, version_file):
    with app.test_request_context():
        with patch("package.auth_functions.urllib3.request") as mock_request:
            mock_request.side_effect = Exception("Network error")

            with patch("builtins.open", return_value=open(version_file, "r")):
                check_version()


# Test process_login function
def test_process_login_success(app, bcrypt, users):
    with app.test_request_context():
        with patch("package.auth_functions.check_version") as mock_check_version, patch(
            "package.auth_functions.telemetry_instance"
        ):
            mock_check_version.return_value = None

            class MockRequest:
                form = {"username": "testuser", "password": "testpass"}

            seed(users, password="hashed_testpass")

            success, data_dir, username = process_login(bcrypt, MockRequest())

            assert success is True
            assert username == "testuser"
            assert data_dir == "data/testuser"


def test_process_login_failure(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {"username": "testuser", "password": "wrongpass"}

        seed(users, password="hashed_testpass")

        success, data_dir, username = process_login(bcrypt, MockRequest())

        assert success is False
        assert data_dir is None
        assert username is None


def test_process_login_empty_username(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {"username": "", "password": "testpass"}

        success, data_dir, username = process_login(bcrypt, MockRequest())

        assert success is False
        assert data_dir is None
        assert username is None


def test_process_login_user_not_found(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {"username": "nonexistent", "password": "testpass"}

        success, data_dir, username = process_login(bcrypt, MockRequest())

        assert success is False
        assert data_dir is None
        assert username is None


def test_process_login_disabled_user(app, bcrypt, users):
    """Correct password, disabled account: refused before login_user()."""
    with app.test_request_context():

        class MockRequest:
            form = {"username": "testuser", "password": "testpass"}

        seed(users, password="hashed_testpass", disabled=True)

        success, data_dir, username = process_login(bcrypt, MockRequest())

        assert success is False
        assert data_dir is None
        assert username is None


def test_process_login_without_disabled_field(app, bcrypt, users):
    """A document predating the flag is usable -- absent means enabled."""
    with app.test_request_context():
        with patch("package.auth_functions.check_version"), patch(
            "package.auth_functions.telemetry_instance"
        ):

            class MockRequest:
                form = {"username": "testuser", "password": "testpass"}

            users.insert_one(
                {
                    "_id": "testuser",
                    "email": "test@test.com",
                    "password": "hashed_testpass",
                }
            )

            success, _, username = process_login(bcrypt, MockRequest())

            assert success is True
            assert username == "testuser"


def test_process_login_unusable_stored_hash(app, users):
    """A corrupt stored hash fails the login rather than 500ing it."""
    with app.test_request_context():

        class MockRequest:
            form = {"username": "testuser", "password": "testpass"}

        seed(users, password="")

        class RaisingBcrypt:
            def check_password_hash(self, hashed, password):
                raise ValueError("invalid salt")

            def generate_password_hash(self, password, rounds=None, prefix=None):
                return b"unused"

        success, _, _ = process_login(RaisingBcrypt(), MockRequest())

        assert success is False


def test_process_login_mongo_errors_are_not_swallowed(app, bcrypt, users, monkeypatch):
    """An outage must not be rendered as "Login incorrect."."""
    from pymongo.errors import ServerSelectionTimeoutError

    with app.test_request_context():

        class MockRequest:
            form = {"username": "testuser", "password": "testpass"}

        def boom(*args, **kwargs):
            raise ServerSelectionTimeoutError("no server")

        monkeypatch.setattr(user_store, "get_user_by_username", boom)

        with pytest.raises(ServerSelectionTimeoutError):
            process_login(bcrypt, MockRequest())


# Test register_user function
def test_register_user_success(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": "newuser",
                "email": "new@test.com",
                "password": "newpass123",
                "confirm_password": "newpass123",
            }

        result = register_user(bcrypt, MockRequest())

        assert result is True
        doc = stored(users, "newuser")
        assert doc["email"] == "new@test.com"
        # str, not BSON Binary.
        assert doc["password"] == "hashed_newpass123"
        assert isinstance(doc["password"], str)
        assert doc["disabled"] is False


def test_register_user_existing_username(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": "existinguser",
                "email": "new@test.com",
                "password": "newpass123",
                "confirm_password": "newpass123",
            }

        seed(users, "existinguser")

        result = register_user(bcrypt, MockRequest())

        assert result is False
        # The existing account is untouched.
        assert stored(users, "existinguser")["password"] == "hashed_oldpass"


def test_register_user_password_mismatch(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": "newuser",
                "email": "new@test.com",
                "password": "newpass",
                "confirm_password": "different",
            }

        result = register_user(bcrypt, MockRequest())

        assert result is False


def test_register_user_empty_username(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": "",
                "email": "new@test.com",
                "password": "newpass",
                "confirm_password": "newpass",
            }

        result = register_user(bcrypt, MockRequest())

        assert result is False


def test_register_user_empty_email(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": "newuser",
                "email": "",
                "password": "newpass",
                "confirm_password": "newpass",
            }

        result = register_user(bcrypt, MockRequest())

        assert result is False


def test_register_user_empty_password(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": "newuser",
                "email": "new@test.com",
                "password": "",
                "confirm_password": "",
            }

        result = register_user(bcrypt, MockRequest())

        assert result is False


@pytest.mark.parametrize("name", ["users", "sessions", "Users", "SESSIONS"])
def test_register_user_reserved_username(app, bcrypt, users, name):
    """A username is a collection name; the application's own are off limits."""
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": name,
                "email": "new@test.com",
                "password": "newpass123",
                "confirm_password": "newpass123",
            }

        assert register_user(bcrypt, MockRequest()) is False
        assert users.count_documents({}) == 0


def test_change_password_same_as_username(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "testuser",
                "confirm_password": "testuser",
            }

        result = change_password(bcrypt, "testuser", MockRequest())

        assert result is False


def test_change_password_same_as_current(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "oldpass",
                "confirm_password": "oldpass",
            }

        result = change_password(bcrypt, "testuser", MockRequest())

        assert result is False


def test_change_password_wrong_current(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "wrongpass",
                "new_password": "newpass",
                "confirm_password": "newpass",
            }

        seed(users, password="hashed_correctpass")

        result = change_password(bcrypt, "testuser", MockRequest())

        assert result is False
        assert stored(users)["password"] == "hashed_correctpass"


def test_register_user_short_password(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": "newuser",
                "email": "new@test.com",
                "password": "short",
                "confirm_password": "short",
            }

        assert register_user(bcrypt, MockRequest()) is False


def test_register_user_invalid_email(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": "newuser",
                "email": "not-an-email",
                "password": "newpass123",
                "confirm_password": "newpass123",
            }

        assert register_user(bcrypt, MockRequest()) is False


def test_change_password_short(app, bcrypt, users):
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "short",
                "confirm_password": "short",
            }

        assert change_password(bcrypt, "testuser", MockRequest()) is False
