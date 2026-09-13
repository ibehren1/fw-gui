"""
Tests for package/user_store.py

Covers: collection, User (is_active / get_id), get_user_by_username,
        get_user_by_session_id, create_user, set_password, count_users,
        list_usernames.
"""

import mongomock
import pytest
from pymongo.errors import DuplicateKeyError

from package import user_store
from package.user_store import (
    SESSION_ID_PREFIX,
    User,
    count_users,
    create_user,
    get_user_by_session_id,
    get_user_by_username,
    list_usernames,
    set_password,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def users(monkeypatch):
    """Patch a mongomock client in and return the users collection."""
    client = mongomock.MongoClient()
    monkeypatch.setattr("package.data_file_functions._mongo_client", client)
    monkeypatch.setattr("package.data_file_functions._get_mongo_client", lambda: client)
    monkeypatch.setenv("MONGODB_DATABASE", "test_db")
    monkeypatch.delenv("MONGODB_USERS_COLLECTION", raising=False)
    return user_store.collection()


def seed(users, username, password="hash", **extra):
    doc = {"_id": username, "email": f"{username}@example.com", "password": password}
    doc.update(extra)
    users.insert_one(doc)
    return doc


# ---------------------------------------------------------------------------
# collection
# ---------------------------------------------------------------------------


class TestCollection:
    def test_defaults_to_users(self, users):
        assert user_store.collection().name == "users"

    def test_honors_env_override(self, users, monkeypatch):
        monkeypatch.setenv("MONGODB_USERS_COLLECTION", "fwgui_accounts")
        assert user_store.collection().name == "fwgui_accounts"

    def test_uses_default_database_when_unset(self, users, monkeypatch):
        """An unset MONGODB_DATABASE must not take the login path down."""
        monkeypatch.delenv("MONGODB_DATABASE", raising=False)
        assert user_store.collection().database.name == "fwgui_database"


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------


class TestUser:
    def test_maps_document_fields(self):
        user = User({"_id": "alice", "email": "a@b.c", "password": "hash"})
        assert user.username == "alice"
        assert user.email == "a@b.c"
        assert user.password == "hash"

    def test_get_id_is_namespaced(self):
        assert User({"_id": "alice"}).get_id() == "u:alice"

    def test_get_id_namespaces_all_digit_usernames(self):
        # The whole point of the prefix: "1" must not collide with the integer
        # primary key that pre-3.0.0 sessions carry.
        assert User({"_id": "1"}).get_id() == "u:1"

    def test_missing_disabled_field_means_active(self):
        user = User({"_id": "alice"})
        assert user.disabled is False
        assert user.is_active is True

    def test_disabled_document_is_inactive(self):
        assert User({"_id": "alice", "disabled": True}).is_active is False

    def test_disabled_false_is_active(self):
        assert User({"_id": "alice", "disabled": False}).is_active is True


# ---------------------------------------------------------------------------
# get_user_by_username
# ---------------------------------------------------------------------------


class TestGetUserByUsername:
    def test_returns_user(self, users):
        seed(users, "alice")
        user = get_user_by_username("alice")
        assert user.username == "alice"
        assert user.password == "hash"

    def test_returns_none_when_missing(self, users):
        assert get_user_by_username("nobody") is None

    def test_returns_none_for_empty(self, users):
        assert get_user_by_username("") is None
        assert get_user_by_username(None) is None

    def test_returns_disabled_users(self, users):
        """The caller decides; this is how change_password tells them apart."""
        seed(users, "alice", disabled=True)
        assert get_user_by_username("alice").disabled is True

    def test_matching_is_case_sensitive(self, users):
        seed(users, "Bob")
        assert get_user_by_username("bob") is None
        assert get_user_by_username("Bob") is not None


# ---------------------------------------------------------------------------
# get_user_by_session_id
# ---------------------------------------------------------------------------


class TestGetUserBySessionId:
    def test_resolves_prefixed_token(self, users):
        seed(users, "alice")
        assert get_user_by_session_id("u:alice").username == "alice"

    def test_rejects_unprefixed_token(self, users):
        seed(users, "alice")
        assert get_user_by_session_id("alice") is None

    def test_rejects_legacy_integer_token(self, users):
        """A pre-3.0.0 session id must not authenticate as anyone."""
        seed(users, "1")
        assert get_user_by_session_id("1") is None

    def test_rejects_disabled_user(self, users):
        seed(users, "alice", disabled=True)
        assert get_user_by_session_id("u:alice") is None

    def test_rejects_unknown_user(self, users):
        assert get_user_by_session_id("u:nobody") is None

    def test_rejects_non_strings_and_empty(self, users):
        assert get_user_by_session_id(None) is None
        assert get_user_by_session_id(42) is None
        assert get_user_by_session_id("") is None
        assert get_user_by_session_id(SESSION_ID_PREFIX) is None


# ---------------------------------------------------------------------------
# create_user
# ---------------------------------------------------------------------------


class TestCreateUser:
    def test_inserts_enabled_account(self, users):
        create_user("alice", "a@b.c", "hash")
        doc = users.find_one({"_id": "alice"})
        assert doc["email"] == "a@b.c"
        assert doc["password"] == "hash"
        assert doc["disabled"] is False
        assert doc["created"] is not None

    def test_duplicate_username_raises(self, users):
        create_user("alice", "a@b.c", "hash")
        with pytest.raises(DuplicateKeyError):
            create_user("alice", "other@b.c", "other")

    def test_duplicate_check_is_case_sensitive(self, users):
        create_user("Bob", "b@b.c", "hash")
        create_user("bob", "b2@b.c", "hash2")
        assert users.count_documents({}) == 2


# ---------------------------------------------------------------------------
# set_password
# ---------------------------------------------------------------------------


class TestSetPassword:
    def test_replaces_hash(self, users):
        seed(users, "alice", password="old")
        assert set_password("alice", "new") is True
        assert users.find_one({"_id": "alice"})["password"] == "new"

    def test_reports_missing_account(self, users):
        assert set_password("nobody", "new") is False

    def test_does_not_change_disabled_flag(self, users):
        seed(users, "alice", password="old", disabled=True)
        set_password("alice", "new")
        assert users.find_one({"_id": "alice"})["disabled"] is True


# ---------------------------------------------------------------------------
# list_usernames
# ---------------------------------------------------------------------------


class TestCountUsers:
    def test_counts_total_and_disabled(self, users):
        seed(users, "alice")
        seed(users, "bob", disabled=True)
        seed(users, "carol", disabled=False)
        assert count_users() == {"total": 3, "disabled": 1}

    def test_document_without_disabled_field_counts_as_enabled(self, users):
        """Pre-3.0.0 and hand-written documents may omit the field."""
        users.insert_one({"_id": "legacy", "password": "hash"})
        assert count_users() == {"total": 1, "disabled": 0}

    def test_empty_collection(self, users):
        assert count_users() == {"total": 0, "disabled": 0}


class TestListUsernames:
    def test_returns_all_usernames(self, users):
        seed(users, "alice")
        seed(users, "bob")
        assert sorted(list_usernames()) == ["alice", "bob"]

    def test_includes_disabled_users(self, users):
        """mongo_converter needs the full set to find per-user directories."""
        seed(users, "alice")
        seed(users, "bob", disabled=True)
        assert sorted(list_usernames()) == ["alice", "bob"]

    def test_empty_collection(self, users):
        assert list_usernames() == []
