import os
from unittest.mock import Mock, patch

import pytest
from flask import Flask
from flask_login import LoginManager

from package.auth_functions import (
    change_password,
    check_version,
    process_login,
    query_user_by_id,
    query_user_by_username,
    register_user,
)


# Fixtures
@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test_secret_key"
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "user_login"
    return app


@pytest.fixture
def bcrypt():
    class MockBcrypt:
        def check_password_hash(self, hashed, password):
            return hashed == f"hashed_{password}"

        def generate_password_hash(self, password):
            return f"hashed_{password}"

    return MockBcrypt()


@pytest.fixture
def db():
    class MockDB:
        def __init__(self):
            self.session = Mock()

        def select(self, model):
            return self

        def filter_by(self, **kwargs):
            return self

    return MockDB()


@pytest.fixture
def user_model():
    class User:
        def __init__(self, username, password, email, id=1):
            self.id = id
            self.username = username
            self.password = password
            self.email = email
            self.is_active = True

        def get_id(self):
            return str(self.id)

    return User


@pytest.fixture
def version_file(tmp_path):
    target_output = os.path.join(tmp_path, ".version")
    with open(target_output, "w") as f:
        f.write("v1.0.0")
    return target_output


# Test change_password function
def test_change_password_success(app, bcrypt, db, user_model):
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "newpass",
                "confirm_password": "newpass",
            }

        mock_user = user_model("testuser", "hashed_oldpass", "test@test.com")
        db.session.execute().scalar_one.return_value = mock_user

        result = change_password(bcrypt, db, user_model, "testuser", MockRequest())

        assert result is True
        assert mock_user.password == "hashed_newpass"


def test_change_password_mismatch(app, bcrypt, db, user_model):
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "newpass",
                "confirm_password": "different",
            }

        result = change_password(bcrypt, db, user_model, "testuser", MockRequest())

        assert result is False


def test_change_password_empty(app, bcrypt, db, user_model):
    with app.test_request_context():

        class MockRequest:
            form = {
                "current_password": "oldpass",
                "new_password": "",
                "confirm_password": "",
            }

        result = change_password(bcrypt, db, user_model, "testuser", MockRequest())

        assert result is False


# Test check_version function
@patch("urllib3.request")
def test_check_version_update_available(mock_request):
    with open(f"/tmp/{version_file}", "w") as f:
        f.write("v1.0.0")

    mock_response = Mock()
    mock_response.data.decode.return_value = "v3.0.0"
    mock_request.return_value = mock_response

    with pytest.raises(Exception):
        check_version()


# TODO
# @patch("urllib3.request")
# def test_check_version_current(mock_request):
#     with open(f"/tmp/{version_file}", "w") as f:
#         f.write("v1.0.0")

#     mock_response = Mock()
#     mock_response.data.decode.return_value = "v1.0.0"
#     mock_request.return_value = mock_response

#     check_version()


# Test process_login function
def test_process_login_success(app, bcrypt, db, user_model):
    with app.test_request_context():
        with patch("package.auth_functions.check_version") as mock_check_version:
            mock_check_version.return_value = None

            class MockRequest:
                form = {"username": "testuser", "password": "testpass"}

            mock_user = user_model("testuser", "hashed_testpass", "test@test.com")
            db.session.execute().scalar_one.return_value = mock_user

            success, data_dir, username = process_login(
                bcrypt, db, MockRequest(), user_model
            )

            assert success is True
            assert username == "testuser"
            assert data_dir == "data/testuser"


def test_process_login_failure(app, bcrypt, db, user_model):
    with app.test_request_context():

        class MockRequest:
            form = {"username": "testuser", "password": "wrongpass"}

        mock_user = user_model("testuser", "hashed_testpass", "test@test.com")
        db.session.execute().scalar_one.return_value = mock_user

        success, data_dir, username = process_login(
            bcrypt, db, MockRequest(), user_model
        )

        assert success is False
        assert data_dir is None
        assert username is None


# Test query functions
def test_query_user_by_id_found(db, user_model):
    mock_user = user_model("testuser", "hashedpass", "test@test.com", id=1)
    db.session.execute().scalar_one.return_value = mock_user

    result = query_user_by_id(db, user_model, 1)

    assert result.username == "testuser"
    assert result.id == 1


def test_query_user_by_id_not_found(db, user_model):
    db.session.execute().scalar_one.side_effect = Exception()

    result = query_user_by_id(db, user_model, 999)

    assert result is None


def test_query_user_by_username_found(db, user_model):
    mock_user = user_model("testuser", "hashedpass", "test@test.com")
    db.session.execute().scalar_one.return_value = mock_user

    result = query_user_by_username(db, user_model, "testuser")

    assert result.username == "testuser"


def test_query_user_by_username_not_found(db, user_model):
    db.session.execute().scalar_one.side_effect = Exception()

    result = query_user_by_username(db, user_model, "nonexistent")

    assert result is None


# Test register_user function
def test_register_user_success(app, bcrypt, db, user_model):
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": "newuser",
                "email": "new@test.com",
                "password": "newpass",
                "confirm_password": "newpass",
            }

        db.session.execute().scalar_one.side_effect = Exception()  # User doesn't exist

        result = register_user(bcrypt, db, MockRequest(), user_model)

        assert result is True
        db.session.add.assert_called_once()
        db.session.commit.assert_called_once()


def test_register_user_existing_username(app, bcrypt, db, user_model):
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": "existinguser",
                "email": "new@test.com",
                "password": "newpass",
                "confirm_password": "newpass",
            }

        mock_user = user_model("existinguser", "hashedpass", "test@test.com")
        db.session.execute().scalar_one.return_value = mock_user

        result = register_user(bcrypt, db, MockRequest(), user_model)

        assert result is False


def test_register_user_password_mismatch(app, bcrypt, db, user_model):
    with app.test_request_context():

        class MockRequest:
            form = {
                "username": "newuser",
                "email": "new@test.com",
                "password": "newpass",
                "confirm_password": "different",
            }

        result = register_user(bcrypt, db, MockRequest(), user_model)

        assert result is False
