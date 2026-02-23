"""
Shared test fixtures for FW-GUI test suite.
"""

import os

# Set environment defaults before any imports could trigger app.py loading.
os.environ.setdefault("APP_SECRET_KEY", "test-secret-key")
os.environ.setdefault("DISABLE_REGISTRATION", "False")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017/")
os.environ.setdefault("MONGODB_DATABASE", "test_db")
os.environ.setdefault("SESSION_TIMEOUT", "120")

import copy
import json

import pytest
from flask import Flask
from flask_login import LoginManager
from unittest.mock import Mock
from werkzeug.datastructures import ImmutableMultiDict


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test_secret_key"
    app.config["TESTING"] = True
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "user_login"
    return app


@pytest.fixture
def mock_session():
    return {
        "data_dir": "data/testuser",
        "firewall_name": "test_firewall",
        "username": "testuser",
        "hostname": "192.168.1.1",
        "port": "22",
    }


@pytest.fixture
def example_user_data():
    with open(
        os.path.join(os.path.dirname(__file__), "..", "examples", "example.json")
    ) as f:
        data = json.load(f)
    return copy.deepcopy(data)


@pytest.fixture
def mock_read_write(monkeypatch):
    """Factory fixture that patches read_user_data_file/write_user_data_file for a module.

    Usage:
        capture = mock_read_write("package.chain_functions", initial_data)
        # ... call function under test ...
        assert capture.written_data[...] == expected
    """

    class Capture:
        def __init__(self, data):
            self.data = data
            self.written_data = None
            self.written_filename = None
            self.written_snapshot = None

        def read(self, *args, **kwargs):
            return copy.deepcopy(self.data)

        def write(self, filename, data, snapshot="current"):
            self.written_data = copy.deepcopy(data)
            self.written_filename = filename
            self.written_snapshot = snapshot
            self.data = copy.deepcopy(data)

    def _factory(module_path, initial_data):
        capture = Capture(initial_data)
        monkeypatch.setattr(f"{module_path}.read_user_data_file", capture.read)
        monkeypatch.setattr(f"{module_path}.write_user_data_file", capture.write)
        return capture

    return _factory


def make_request(form_dict):
    """Create a mock request object from a dict of form data."""
    form = ImmutableMultiDict(list(form_dict.items()))
    return type("Request", (), {"form": form})()


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


@pytest.fixture(scope="session")
def flask_app():
    """Real Flask app from app.py configured for testing.

    Uses the app's existing SQLite database with TESTING=True.
    Creates a dedicated test user if one does not already exist.
    """
    from app import app as flask_application
    from app import bcrypt as flask_bcrypt
    from app import db as flask_db
    from app import User

    flask_application.config["TESTING"] = True

    with flask_application.app_context():
        flask_db.create_all()

        # Create test user if not already present.
        existing = flask_db.session.execute(
            flask_db.select(User).filter_by(username="testuser")
        ).scalar_one_or_none()
        if not existing:
            hashed_pw = flask_bcrypt.generate_password_hash("testpass").decode(
                "utf-8"
            )
            test_user = User(
                username="testuser", email="test@test.com", password=hashed_pw
            )
            flask_db.session.add(test_user)
            flask_db.session.commit()

        yield flask_application

        flask_db.session.remove()


@pytest.fixture
def client(flask_app):
    """Unauthenticated test client."""
    return flask_app.test_client()


@pytest.fixture
def auth_client(flask_app):
    """Authenticated test client that logs in via the real login flow."""
    from unittest.mock import patch

    test_client = flask_app.test_client()
    # Log in through the real endpoint; mock only the network side-effects
    # that process_login triggers (telemetry + version check).
    with patch("package.auth_functions.telemetry_instance"), patch(
        "package.auth_functions.check_version"
    ):
        test_client.post(
            "/user_login",
            data={"username": "testuser", "password": "testpass"},
        )
    # Set additional session state that routes expect.
    with test_client.session_transaction() as sess:
        sess["firewall_name"] = "test_firewall"
        sess["hostname"] = "192.168.1.1"
        sess["port"] = "22"
        sess["ssh_user"] = ""
        sess["ssh_pass"] = ""  # nosec
        sess["ssh_keyname"] = ""
    return test_client
