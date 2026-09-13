"""
Shared test fixtures for FW-GUI test suite.
"""

import os
import uuid

# Set environment defaults before any imports could trigger app.py loading.
os.environ.setdefault("APP_SECRET_KEY", "test-secret-key")
os.environ.setdefault("DISABLE_REGISTRATION", "False")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017/")
os.environ.setdefault("MONGODB_DATABASE", "test_db")
os.environ.setdefault("SESSION_TIMEOUT", "120")
# Use a local, offline session backend for tests (no live MongoDB required).
os.environ.setdefault("SESSION_TYPE", "filesystem")

# Bootstrap the data directories the app normally creates via
# initialize_data_dir() at startup. pytest imports the app without running its
# __main__ block, so on a fresh checkout (e.g. CI) these do not yet exist and
# telemetry would fail. Make the suite self-contained.
os.makedirs("data/database", exist_ok=True)
os.makedirs("data/tmp", exist_ok=True)
# Pre-create the test user's data dir so the first login does not trigger the
# example-config write to MongoDB (which is not available in the offline suite).
os.makedirs("data/testuser", exist_ok=True)
if not os.path.exists("data/database/instance.id"):
    with open("data/database/instance.id", "w") as _f:
        _f.write(str(uuid.uuid4()))

import copy
import json

import pytest
from flask import Flask
from flask_login import LoginManager
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
            if isinstance(hashed, bytes):
                hashed = hashed.decode("utf-8")
            return hashed == f"hashed_{password}"

        def generate_password_hash(self, password, rounds=None, prefix=None):
            # Real flask_bcrypt returns bytes, so mirror that: the production
            # code decodes the result and the tests must exercise that path.
            return f"hashed_{password}".encode("utf-8")

    return MockBcrypt()


@pytest.fixture
def user_model():
    """The real user_store.User, built from a document.

    Deliberately not a stand-in: the get_id() contract ("u:<username>") and the
    disabled/is_active mapping are what the auth path depends on, so tests
    should exercise the real thing.
    """
    from package.user_store import User

    def make_user(username, password, email, disabled=False):
        return User(
            {
                "_id": username,
                "password": password,
                "email": email,
                "disabled": disabled,
            }
        )

    return make_user


@pytest.fixture(scope="session")
def mongo_client():
    """Session-wide mongomock client patched into the data layer.

    Must be in place before flask_app runs: auth_client logs in through the real
    /user_login endpoint, which reads the users collection, and without this the
    suite would try to reach a live mongod. The built-in monkeypatch fixture is
    function-scoped, so drive MonkeyPatch directly.
    """
    import mongomock

    mp = pytest.MonkeyPatch()
    client = mongomock.MongoClient()
    mp.setattr("package.data_file_functions._mongo_client", client)
    mp.setattr("package.data_file_functions._get_mongo_client", lambda: client)
    yield client
    mp.undo()


@pytest.fixture(scope="session")
def flask_app(mongo_client):
    """Real Flask app from app.py configured for testing.

    Seeds the test user into the mongomock users collection with a real bcrypt
    hash (at minimum cost rounds) so the real login flow works offline.
    """
    from app import app as flask_application
    from app import bcrypt as flask_bcrypt
    from package import user_store

    flask_application.config["TESTING"] = True
    # Disable CSRF validation so tests can POST to forms without a token.
    flask_application.config["WTF_CSRF_ENABLED"] = False

    with flask_application.app_context():
        users = user_store.collection()
        if users.find_one({"_id": "testuser"}) is None:
            hashed_pw = flask_bcrypt.generate_password_hash(
                "testpass", rounds=4
            ).decode("utf-8")
            user_store.create_user("testuser", "test@test.com", hashed_pw)

        yield flask_application


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
