"""
Tests for package/user_migration.py

Covers: the pre-3.0.0 SQLite -> MongoDB account migration, its idempotency,
        the TEXT/BLOB password-hash mix, the reserved-username and
        config-collection abort paths, session purging, and the rename that
        acts as the "already migrated" marker.
"""

import logging
import os
import sqlite3

import mongomock
import pytest

from package import user_migration, user_store
from package.user_migration import migrate_sqlite_users

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


@pytest.fixture
def legacy_db(tmp_path, monkeypatch):
    """Point the migration at a temp auth.db path and return a builder.

    The migration also purges the filesystem session directory, so that is
    redirected into tmp_path too rather than wiping the developer's.
    """
    db_path = tmp_path / "auth.db"
    monkeypatch.setattr(user_migration, "LEGACY_AUTH_DB", str(db_path))
    monkeypatch.setattr(
        user_migration, "MIGRATED_AUTH_DB", str(tmp_path / "auth.db.migrated")
    )
    monkeypatch.setattr(
        user_migration, "_FILESYSTEM_SESSION_DIR", str(tmp_path / "flask_session")
    )

    def build(rows):
        """rows: list of (username, email, password) with str or bytes password."""
        con = sqlite3.connect(str(db_path))
        con.execute(
            "CREATE TABLE user "
            "(id INTEGER PRIMARY KEY, username VARCHAR(20), "
            "email VARCHAR(40), password VARCHAR(80))"
        )
        con.executemany(
            "INSERT INTO user (username, email, password) VALUES (?, ?, ?)", rows
        )
        con.commit()
        con.close()
        return db_path

    build.path = db_path
    return build


# ---------------------------------------------------------------------------
# No-op paths
# ---------------------------------------------------------------------------


class TestNoLegacyDatabase:
    def test_absent_database_is_a_noop(self, users, legacy_db):
        migrate_sqlite_users()
        assert users.count_documents({}) == 0

    def test_already_renamed_database_is_a_noop(self, users, legacy_db, tmp_path):
        """The rename is the marker: nothing left to find, nothing opened."""
        legacy_db([("alice", "a@b.c", "hash")])
        migrate_sqlite_users()
        assert not os.path.exists(legacy_db.path)

        users.delete_many({})
        migrate_sqlite_users()
        assert users.count_documents({}) == 0


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestMigration:
    def test_copies_accounts(self, users, legacy_db):
        legacy_db([("alice", "a@b.c", "hash-a"), ("bob", "b@b.c", "hash-b")])

        migrate_sqlite_users()

        assert sorted(user_store.list_usernames()) == ["alice", "bob"]
        alice = users.find_one({"_id": "alice"})
        assert alice["email"] == "a@b.c"
        assert alice["password"] == "hash-a"
        assert alice["disabled"] is False
        assert alice["legacy_id"] == 1
        assert alice["migrated_from_sqlite"] is True

    def test_renames_legacy_database(self, users, legacy_db, tmp_path):
        legacy_db([("alice", "a@b.c", "hash")])

        migrate_sqlite_users()

        assert not os.path.exists(legacy_db.path)
        assert os.path.exists(tmp_path / "auth.db.migrated")

    def test_does_not_clobber_an_existing_retained_database(
        self, users, legacy_db, tmp_path
    ):
        """The earlier snapshot is the rollback path; it must survive."""
        keeper = tmp_path / "auth.db.migrated"
        keeper.write_bytes(b"earlier snapshot")
        legacy_db([("alice", "a@b.c", "hash")])

        migrate_sqlite_users()

        assert keeper.read_bytes() == b"earlier snapshot"
        # Renamed to a timestamped sibling instead.
        assert len(list(tmp_path.glob("auth.db.migrated*"))) == 2

    def test_empty_table_still_retires_the_database(self, users, legacy_db):
        legacy_db([])

        migrate_sqlite_users()

        assert users.count_documents({}) == 0
        assert not os.path.exists(legacy_db.path)


# ---------------------------------------------------------------------------
# Password hash normalisation
# ---------------------------------------------------------------------------


class TestPasswordHashes:
    def test_normalises_blob_and_text_hashes(self, users, legacy_db):
        """The legacy column really does hold both; both must end up str."""
        legacy_db(
            [("textuser", "t@b.c", "hash-text"), ("blobuser", "b@b.c", b"hash-blob")]
        )

        migrate_sqlite_users()

        text_hash = users.find_one({"_id": "textuser"})["password"]
        blob_hash = users.find_one({"_id": "blobuser"})["password"]
        assert text_hash == "hash-text"
        assert blob_hash == "hash-blob"
        assert isinstance(text_hash, str)
        assert isinstance(blob_hash, str)

    def test_real_bcrypt_hashes_still_verify(self, users, legacy_db):
        """End-to-end: a BLOB-stored hash must still authenticate afterwards."""
        import bcrypt as bcrypt_lib

        raw = bcrypt_lib.hashpw(b"correct horse", bcrypt_lib.gensalt(rounds=4))
        legacy_db([("alice", "a@b.c", raw)])

        migrate_sqlite_users()

        stored = users.find_one({"_id": "alice"})["password"]
        assert isinstance(stored, str)
        assert bcrypt_lib.checkpw(b"correct horse", stored.encode("utf-8"))

    def test_skips_undecodable_hash(self, users, legacy_db):
        legacy_db([("alice", "a@b.c", b"\xff\xfe not utf-8"), ("bob", "b@b.c", "ok")])

        migrate_sqlite_users()

        assert user_store.list_usernames() == ["bob"]

    def test_skips_rows_missing_username_or_password(self, users, legacy_db):
        legacy_db(
            [
                (None, "n@b.c", "hash"),
                ("", "e@b.c", "hash"),
                ("nopassword", "p@b.c", None),
                ("alice", "a@b.c", "hash"),
            ]
        )

        migrate_sqlite_users()

        assert user_store.list_usernames() == ["alice"]


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_rerun_does_not_resurrect_the_old_password(self, users, legacy_db):
        """The $setOnInsert regression test.

        With $set, a re-run would restore the pre-cutover hash -- including one
        rotated because it leaked.
        """
        legacy_db([("alice", "a@b.c", "old-hash")])
        migrate_sqlite_users()

        user_store.set_password("alice", "new-hash")

        # Put the legacy file back, as a restored data/ volume would.
        legacy_db([("alice", "a@b.c", "old-hash")])
        migrate_sqlite_users()

        assert users.find_one({"_id": "alice"})["password"] == "new-hash"

    def test_rerun_does_not_reenable_a_disabled_account(self, users, legacy_db):
        legacy_db([("alice", "a@b.c", "hash")])
        migrate_sqlite_users()

        users.update_one({"_id": "alice"}, {"$set": {"disabled": True}})

        legacy_db([("alice", "a@b.c", "hash")])
        migrate_sqlite_users()

        assert users.find_one({"_id": "alice"})["disabled"] is True

    def test_rerun_does_not_duplicate_accounts(self, users, legacy_db):
        legacy_db([("alice", "a@b.c", "hash")])
        migrate_sqlite_users()

        legacy_db([("alice", "a@b.c", "hash")])
        migrate_sqlite_users()

        assert users.count_documents({}) == 1

    def test_rerun_warns_which_accounts_it_left_alone(self, users, legacy_db, caplog):
        """The signal an operator needs after a downgrade / re-upgrade."""
        legacy_db([("alice", "a@b.c", "old-hash")])
        migrate_sqlite_users()

        user_store.set_password("alice", "new-hash")
        legacy_db([("alice", "a@b.c", "old-hash")])

        with caplog.at_level(logging.WARNING):
            migrate_sqlite_users()

        warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("already existed in MongoDB" in m for m in warnings)
        assert any("alice" in m for m in warnings)
        # The warning is about which copy won, not a failure.
        assert users.find_one({"_id": "alice"})["password"] == "new-hash"

    def test_first_migration_does_not_warn(self, users, legacy_db, caplog):
        """Guards the targeting: this must not fire on every upgrade."""
        legacy_db([("alice", "a@b.c", "hash"), ("bob", "b@b.c", "hash")])

        with caplog.at_level(logging.WARNING):
            migrate_sqlite_users()

        warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert not any("already existed in MongoDB" in m for m in warnings)


# ---------------------------------------------------------------------------
# Failure and abort paths
# ---------------------------------------------------------------------------


class TestUnreadableDatabase:
    def test_missing_table_is_logged_and_retried(self, users, legacy_db):
        """No rename, so the next boot tries again."""
        con = sqlite3.connect(str(legacy_db.path))
        con.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
        con.commit()
        con.close()

        migrate_sqlite_users()

        assert users.count_documents({}) == 0
        assert os.path.exists(legacy_db.path)

    def test_corrupt_file_is_logged_and_retried(self, users, legacy_db):
        legacy_db.path.write_bytes(b"not a database")

        migrate_sqlite_users()

        assert users.count_documents({}) == 0
        assert os.path.exists(legacy_db.path)


class TestAborts:
    def test_reserved_username_aborts_startup(self, users, legacy_db):
        legacy_db([("alice", "a@b.c", "hash"), ("sessions", "s@b.c", "hash")])

        with pytest.raises(SystemExit):
            migrate_sqlite_users()

        # Nothing migrated, and the legacy file is left for the operator to fix.
        assert users.count_documents({}) == 0
        assert os.path.exists(legacy_db.path)

    def test_instance_username_does_not_abort(self, users, legacy_db):
        """Reserved for new registrations, but not worth refusing to boot over.

        A legacy account named "instance" collides only with the telemetry id, so
        it migrates and telemetry degrades instead (see package/instance_id.py).
        """
        legacy_db([("alice", "a@b.c", "hash"), ("instance", "i@b.c", "hash")])

        migrate_sqlite_users()

        assert sorted(user_store.list_usernames()) == ["alice", "instance"]
        assert not os.path.exists(legacy_db.path)

    @pytest.mark.parametrize("name", ["users", "sessions", "keys"])
    def test_auth_critical_username_aborts_startup(self, users, legacy_db, name):
        """keys holds every user's SSH key ciphertext, so it aborts like users."""
        legacy_db([("alice", "a@b.c", "hash"), (name, "x@b.c", "hash")])

        with pytest.raises(SystemExit):
            migrate_sqlite_users()

        assert users.count_documents({}) == 0
        assert os.path.exists(legacy_db.path)

    def test_config_collection_collision_aborts_startup(self, users, legacy_db):
        """A user named "users" already owns the target collection."""
        users.insert_one({"_id": "example", "ipv4": {}, "ipv6": {}})
        legacy_db([("alice", "a@b.c", "hash")])

        with pytest.raises(SystemExit):
            migrate_sqlite_users()

        assert os.path.exists(legacy_db.path)


# ---------------------------------------------------------------------------
# Session purge
# ---------------------------------------------------------------------------


class TestSessionPurge:
    def test_clears_mongodb_sessions(self, users, legacy_db):
        sessions = users.database["sessions"]
        sessions.insert_one({"id": "abc", "val": b"stale"})
        legacy_db([("alice", "a@b.c", "hash")])

        migrate_sqlite_users()

        assert sessions.count_documents({}) == 0

    def test_clears_filesystem_sessions(self, users, legacy_db, tmp_path):
        session_dir = tmp_path / "flask_session"
        session_dir.mkdir()
        stale = session_dir / "stale-session"
        stale.write_text("x")
        legacy_db([("alice", "a@b.c", "hash")])

        migrate_sqlite_users()

        assert not stale.exists()

    def test_missing_session_dir_is_fine(self, users, legacy_db):
        legacy_db([("alice", "a@b.c", "hash")])

        migrate_sqlite_users()

        assert user_store.list_usernames() == ["alice"]
