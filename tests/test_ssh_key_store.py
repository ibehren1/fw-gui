"""
Tests for package/ssh_key_store.py

Covers: storing and listing encrypted SSH keys, the decrypt-and-stage path and
        its security properties (0600, outside data/, wrong key rejected), and
        adoption of pre-3.0.0 data/<user>/*.key files.
"""

import os
import stat

import mongomock
import pytest
from cryptography.fernet import Fernet, InvalidToken

from package import ssh_key_store
from package.ssh_key_store import (
    decrypt_ssh_key,
    get_ciphertext,
    list_key_names,
    migrate_legacy_key_files,
    store_key,
)
from package.validators import KEYS_COLLECTION

# A stand-in for a private key: binary, with a newline, so a bad round trip shows.
PLAINTEXT_KEY = b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\x00\xff\n"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keys(monkeypatch):
    """mongomock client patched in; returns the keys collection."""
    client = mongomock.MongoClient()
    monkeypatch.setattr("package.data_file_functions._mongo_client", client)
    monkeypatch.setattr("package.data_file_functions._get_mongo_client", lambda: client)
    monkeypatch.setenv("MONGODB_DATABASE", "test_db")
    return client["test_db"][KEYS_COLLECTION]


@pytest.fixture
def fernet_key():
    return Fernet.generate_key()


@pytest.fixture
def staged(keys):
    """Tracks temp files created during a test so they cannot leak."""
    created = []
    real_mkstemp = ssh_key_store.tempfile.mkstemp

    def tracking_mkstemp(*args, **kwargs):
        fd, path = real_mkstemp(*args, **kwargs)
        created.append(path)
        return fd, path

    ssh_key_store.tempfile.mkstemp = tracking_mkstemp
    yield created
    ssh_key_store.tempfile.mkstemp = real_mkstemp
    for path in created:
        if os.path.exists(path):
            os.remove(path)


# ---------------------------------------------------------------------------
# store / list / get
# ---------------------------------------------------------------------------


class TestStoreAndList:
    def test_stores_ciphertext_as_binary(self, keys, fernet_key):
        ciphertext = Fernet(fernet_key).encrypt(PLAINTEXT_KEY)

        store_key("alice", "id_rsa", ciphertext)

        doc = keys.find_one({"_id": "alice/id_rsa"})
        assert doc["user"] == "alice"
        assert doc["name"] == "id_rsa"
        assert bytes(doc["key"]) == ciphertext
        assert doc["created"] is not None

    def test_plaintext_is_never_stored(self, keys, fernet_key):
        """The whole point: the server holds a blob it cannot read."""
        store_key("alice", "id_rsa", Fernet(fernet_key).encrypt(PLAINTEXT_KEY))

        stored = bytes(keys.find_one({"_id": "alice/id_rsa"})["key"])
        assert PLAINTEXT_KEY not in stored
        assert b"BEGIN OPENSSH" not in stored

    def test_reupload_replaces(self, keys):
        """A user who lost their Fernet key uploads again; the old blob is dead."""
        store_key("alice", "id_rsa", b"first")
        store_key("alice", "id_rsa", b"second")

        assert keys.count_documents({}) == 1
        assert get_ciphertext("alice", "id_rsa") == b"second"

    def test_list_is_scoped_and_sorted(self, keys):
        store_key("alice", "zebra", b"x")
        store_key("alice", "alpha", b"x")
        store_key("bob", "bobs-key", b"x")

        assert list_key_names("alice") == ["alpha", "zebra"]
        assert list_key_names("bob") == ["bobs-key"]

    def test_two_users_may_share_a_key_name(self, keys):
        store_key("alice", "id_rsa", b"alice-blob")
        store_key("bob", "id_rsa", b"bob-blob")

        assert keys.count_documents({}) == 2
        assert get_ciphertext("alice", "id_rsa") == b"alice-blob"
        assert get_ciphertext("bob", "id_rsa") == b"bob-blob"

    def test_get_missing_returns_none(self, keys):
        assert get_ciphertext("alice", "nope") is None

    def test_list_empty(self, keys):
        assert list_key_names("alice") == []


# ---------------------------------------------------------------------------
# decrypt_ssh_key
# ---------------------------------------------------------------------------


class TestDecryptSshKey:
    def test_round_trip(self, keys, fernet_key, staged):
        store_key("alice", "id_rsa", Fernet(fernet_key).encrypt(PLAINTEXT_KEY))

        path = decrypt_ssh_key("alice", "id_rsa", fernet_key)

        with open(path, "rb") as f:
            assert f.read() == PLAINTEXT_KEY

    def test_staged_file_is_owner_only(self, keys, fernet_key, staged):
        """A plaintext private key must not be world-readable."""
        store_key("alice", "id_rsa", Fernet(fernet_key).encrypt(PLAINTEXT_KEY))

        path = decrypt_ssh_key("alice", "id_rsa", fernet_key)

        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600

    def test_staged_file_is_outside_the_data_volume(self, keys, fernet_key, staged):
        """3.0.0 moved staging to TMPDIR so data/ holds no secrets."""
        store_key("alice", "id_rsa", Fernet(fernet_key).encrypt(PLAINTEXT_KEY))

        path = decrypt_ssh_key("alice", "id_rsa", fernet_key)

        data_root = os.path.realpath("data")
        assert os.path.commonpath([os.path.realpath(path), data_root]) != data_root

    def test_wrong_fernet_key_raises(self, keys, fernet_key, staged):
        store_key("alice", "id_rsa", Fernet(fernet_key).encrypt(PLAINTEXT_KEY))

        with pytest.raises(InvalidToken):
            decrypt_ssh_key("alice", "id_rsa", Fernet.generate_key())

    def test_wrong_fernet_key_stages_nothing(self, keys, fernet_key, staged):
        """Decryption happens before mkstemp, so there is no file to clean up."""
        store_key("alice", "id_rsa", Fernet(fernet_key).encrypt(PLAINTEXT_KEY))

        with pytest.raises(InvalidToken):
            decrypt_ssh_key("alice", "id_rsa", Fernet.generate_key())

        assert staged == []

    def test_missing_key_raises_clearly(self, keys, fernet_key, staged):
        with pytest.raises(FileNotFoundError, match="No stored SSH key named 'nope'"):
            decrypt_ssh_key("alice", "nope", fernet_key)

    def test_another_users_key_is_not_reachable(self, keys, fernet_key, staged):
        store_key("bob", "id_rsa", Fernet(fernet_key).encrypt(PLAINTEXT_KEY))

        with pytest.raises(FileNotFoundError):
            decrypt_ssh_key("alice", "id_rsa", fernet_key)


# ---------------------------------------------------------------------------
# migrate_legacy_key_files
# ---------------------------------------------------------------------------


class TestMigration:
    @pytest.fixture
    def data_tree(self, tmp_path, monkeypatch):
        data = tmp_path / "data"
        (data / "alice").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)
        return data

    def test_adopts_and_retires_the_file(self, keys, data_tree, fernet_key):
        ciphertext = Fernet(fernet_key).encrypt(PLAINTEXT_KEY)
        (data_tree / "alice" / "id_rsa.key").write_bytes(ciphertext)

        migrate_legacy_key_files(["alice"])

        # Same bytes, so the user's existing Fernet key still works.
        assert get_ciphertext("alice", "id_rsa") == ciphertext
        assert keys.find_one({"_id": "alice/id_rsa"})["migrated_from_file"] is True
        assert not (data_tree / "alice" / "id_rsa.key").exists()
        assert (data_tree / "alice" / "id_rsa.key.migrated").read_bytes() == ciphertext

    def test_migrated_key_decrypts_with_the_original_fernet_key(
        self, keys, data_tree, fernet_key, staged
    ):
        """End to end: the upgrade must not invalidate the user's saved key."""
        (data_tree / "alice" / "id_rsa.key").write_bytes(
            Fernet(fernet_key).encrypt(PLAINTEXT_KEY)
        )

        migrate_legacy_key_files(["alice"])

        with open(decrypt_ssh_key("alice", "id_rsa", fernet_key), "rb") as f:
            assert f.read() == PLAINTEXT_KEY

    def test_rerun_does_not_clobber_a_reupload(self, keys, data_tree, fernet_key):
        """The $setOnInsert regression test.

        With $set, a re-run would replace a key the user re-uploaded with one whose
        Fernet key they no longer have.
        """
        (data_tree / "alice" / "id_rsa.key").write_bytes(b"old-ciphertext")
        migrate_legacy_key_files(["alice"])

        store_key("alice", "id_rsa", b"re-uploaded-ciphertext")

        # Put the legacy file back, as a restored data/ volume would.
        (data_tree / "alice" / "id_rsa.key").write_bytes(b"old-ciphertext")
        migrate_legacy_key_files(["alice"])

        assert get_ciphertext("alice", "id_rsa") == b"re-uploaded-ciphertext"

    def test_does_not_clobber_an_existing_retired_file(self, keys, data_tree):
        keeper = data_tree / "alice" / "id_rsa.key.migrated"
        keeper.write_bytes(b"earlier retirement")
        (data_tree / "alice" / "id_rsa.key").write_bytes(b"ciphertext")

        migrate_legacy_key_files(["alice"])

        assert keeper.read_bytes() == b"earlier retirement"
        assert len(list((data_tree / "alice").glob("id_rsa.key.migrated*"))) == 2

    def test_multiple_keys_and_users(self, keys, data_tree):
        (data_tree / "bob").mkdir()
        (data_tree / "alice" / "one.key").write_bytes(b"a1")
        (data_tree / "alice" / "two.key").write_bytes(b"a2")
        (data_tree / "bob" / "one.key").write_bytes(b"b1")

        migrate_legacy_key_files(["alice", "bob"])

        assert list_key_names("alice") == ["one", "two"]
        assert list_key_names("bob") == ["one"]
        assert get_ciphertext("bob", "one") == b"b1"

    def test_skips_an_empty_file(self, keys, data_tree):
        (data_tree / "alice" / "empty.key").write_bytes(b"")

        migrate_legacy_key_files(["alice"])

        assert keys.count_documents({}) == 0
        # Left in place rather than retired, so it is visible to the operator.
        assert (data_tree / "alice" / "empty.key").exists()

    def test_does_not_touch_other_files(self, keys, data_tree):
        (data_tree / "alice" / "fw.json").write_text("{}")
        (data_tree / "alice" / "user-alice-backup.zip").write_bytes(b"PK")

        migrate_legacy_key_files(["alice"])

        assert (data_tree / "alice" / "fw.json").exists()
        assert (data_tree / "alice" / "user-alice-backup.zip").exists()

    def test_username_without_directory_is_not_an_error(self, keys, data_tree):
        migrate_legacy_key_files(["alice", "nonexistent-user"])

    def test_failure_leaves_the_file_for_a_retry(self, keys, data_tree, monkeypatch):
        """Housekeeping must not stop startup, and must not lose the ciphertext."""
        (data_tree / "alice" / "id_rsa.key").write_bytes(b"ciphertext")

        def boom(*args, **kwargs):
            raise OSError("permission denied")

        monkeypatch.setattr(ssh_key_store.os, "rename", boom)

        migrate_legacy_key_files(["alice"])

        assert (data_tree / "alice" / "id_rsa.key").exists()
