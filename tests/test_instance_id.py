"""
Tests for package/instance_id.py

Covers: MongoDB-backed creation, the process cache, adoption of the pre-3.0.0
        data/database/instance.id file and its retirement, the FWGUI_INSTANCE_ID
        override, and the guarantee that nothing here ever raises.
"""

import os
import uuid

import mongomock
import pytest

from package import instance_id
from package.instance_id import get_or_create_instance_id
from package.validators import INSTANCE_COLLECTION

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def collection(monkeypatch):
    """mongomock client patched in, cache cleared, override unset."""
    client = mongomock.MongoClient()
    monkeypatch.setattr("package.data_file_functions._mongo_client", client)
    monkeypatch.setattr("package.data_file_functions._get_mongo_client", lambda: client)
    monkeypatch.setenv("MONGODB_DATABASE", "test_db")
    monkeypatch.delenv(instance_id.INSTANCE_ID_ENV_VAR, raising=False)
    monkeypatch.setattr(instance_id, "_instance_id", None)
    return client["test_db"][INSTANCE_COLLECTION]


@pytest.fixture
def legacy_file(tmp_path, monkeypatch):
    """Redirect the pre-3.0.0 file paths into tmp_path and return a writer."""
    legacy = tmp_path / "instance.id"
    monkeypatch.setattr(instance_id, "LEGACY_INSTANCE_FILE", str(legacy))
    monkeypatch.setattr(
        instance_id, "MIGRATED_INSTANCE_FILE", str(tmp_path / "instance.id.migrated")
    )

    def write(value):
        legacy.write_text(value)
        return legacy

    write.path = legacy
    write.migrated = tmp_path / "instance.id.migrated"
    return write


def stored(collection):
    doc = collection.find_one({"_id": "instance_id"})
    return doc["value"] if doc else None


# ---------------------------------------------------------------------------
# Fresh install
# ---------------------------------------------------------------------------


class TestFreshInstall:
    def test_creates_and_persists_a_uuid(self, collection, legacy_file):
        value = get_or_create_instance_id()

        uuid.UUID(value)  # raises if it is not a well-formed UUID
        assert stored(collection) == value

    def test_marks_the_document_as_not_migrated(self, collection, legacy_file):
        get_or_create_instance_id()
        assert (
            collection.find_one({"_id": "instance_id"})["migrated_from_file"] is False
        )

    def test_no_legacy_file_is_created(self, collection, legacy_file):
        get_or_create_instance_id()
        assert not os.path.exists(legacy_file.path)
        assert not os.path.exists(legacy_file.migrated)

    def test_second_call_returns_the_same_value(self, collection, legacy_file):
        first = get_or_create_instance_id()
        assert get_or_create_instance_id() == first
        assert collection.count_documents({}) == 1


class TestCaching:
    def test_second_call_does_not_query_mongodb(
        self, collection, legacy_file, monkeypatch
    ):
        """Without the cache every telemetry event becomes a round trip."""
        first = get_or_create_instance_id()

        def boom():
            raise AssertionError("MongoDB was queried again despite the cache")

        monkeypatch.setattr(instance_id, "_collection", boom)

        assert get_or_create_instance_id() == first

    def test_failure_is_not_cached(self, collection, legacy_file, monkeypatch):
        """A transient outage must not pin "" for the life of the process."""
        monkeypatch.setattr(
            instance_id,
            "_collection",
            lambda: (_ for _ in ()).throw(Exception("MongoDB is down")),
        )
        assert get_or_create_instance_id() == ""

        monkeypatch.undo()
        assert get_or_create_instance_id() != ""


# ---------------------------------------------------------------------------
# Adoption of the pre-3.0.0 file
# ---------------------------------------------------------------------------


class TestLegacyAdoption:
    def test_adopts_the_file_value(self, collection, legacy_file):
        """The install keeps its telemetry identity across the upgrade."""
        legacy_file("11111111-2222-3333-4444-555555555555")

        value = get_or_create_instance_id()

        assert value == "11111111-2222-3333-4444-555555555555"
        assert stored(collection) == value
        assert collection.find_one({"_id": "instance_id"})["migrated_from_file"] is True

    def test_strips_whitespace(self, collection, legacy_file):
        legacy_file("  padded-id  \n")
        assert get_or_create_instance_id() == "padded-id"

    def test_retires_the_file(self, collection, legacy_file):
        legacy_file("some-id")

        get_or_create_instance_id()

        assert not os.path.exists(legacy_file.path)
        assert legacy_file.migrated.read_text() == "some-id"

    def test_does_not_clobber_an_existing_retired_file(self, collection, legacy_file):
        legacy_file.migrated.write_text("earlier retirement")
        legacy_file("some-id")

        get_or_create_instance_id()

        assert legacy_file.migrated.read_text() == "earlier retirement"
        assert len(list(legacy_file.migrated.parent.glob("instance.id.migrated*"))) == 2

    def test_empty_file_falls_back_to_a_new_uuid(self, collection, legacy_file):
        legacy_file("   \n")

        value = get_or_create_instance_id()

        uuid.UUID(value)

    def test_stored_value_wins_over_the_file(self, collection, legacy_file):
        """A file left behind by a downgrade must not override MongoDB."""
        collection.insert_one({"_id": "instance_id", "value": "already-stored"})
        legacy_file("stale-from-downgrade")

        assert get_or_create_instance_id() == "already-stored"
        # Nothing was adopted, so the file is left for the operator.
        assert os.path.exists(legacy_file.path)


# ---------------------------------------------------------------------------
# Environment override
# ---------------------------------------------------------------------------


class TestEnvOverride:
    def test_override_wins(self, collection, legacy_file, monkeypatch):
        monkeypatch.setenv(instance_id.INSTANCE_ID_ENV_VAR, "github-actions-ci")
        assert get_or_create_instance_id() == "github-actions-ci"

    def test_override_never_touches_mongodb(self, collection, legacy_file, monkeypatch):
        monkeypatch.setenv(instance_id.INSTANCE_ID_ENV_VAR, "pinned-id")
        monkeypatch.setattr(
            instance_id,
            "_collection",
            lambda: (_ for _ in ()).throw(AssertionError("MongoDB was queried")),
        )
        assert get_or_create_instance_id() == "pinned-id"
        assert collection.count_documents({}) == 0

    def test_override_is_stripped(self, collection, legacy_file, monkeypatch):
        monkeypatch.setenv(instance_id.INSTANCE_ID_ENV_VAR, "  spaced  ")
        assert get_or_create_instance_id() == "spaced"

    def test_empty_override_is_ignored(self, collection, legacy_file, monkeypatch):
        monkeypatch.setenv(instance_id.INSTANCE_ID_ENV_VAR, "")
        uuid.UUID(get_or_create_instance_id())


# ---------------------------------------------------------------------------
# Failure handling -- nothing here may raise
# ---------------------------------------------------------------------------


class TestNeverRaises:
    def test_mongodb_error_returns_empty(self, collection, legacy_file, monkeypatch):
        monkeypatch.setattr(
            instance_id.data_file_functions,
            "_get_mongo_db",
            lambda: (_ for _ in ()).throw(Exception("MongoDB is down")),
        )
        assert get_or_create_instance_id() == ""

    def test_unrenamable_legacy_file_still_yields_the_id(
        self, collection, legacy_file, monkeypatch
    ):
        """A read-only data directory must not cost us the id we just stored."""
        legacy_file("some-id")
        monkeypatch.setattr(
            instance_id.os,
            "rename",
            lambda *a: (_ for _ in ()).throw(OSError("read-only filesystem")),
        )

        assert get_or_create_instance_id() == "some-id"
        assert stored(collection) == "some-id"
        # The file is left behind, but the stored value wins on every later read.
        assert os.path.exists(legacy_file.path)

    def test_lookup_is_time_bounded(self, collection, legacy_file, monkeypatch):
        """The shared client has no serverSelectionTimeoutMS.

        Without an explicit bound, an unreachable database costs pymongo's 30s
        default on every telemetry event -- and telemetry_instance sits in the
        login path, telemetry_commit in the commit path. Measured at 121s for
        four calls before this bound was added.
        """
        calls = []
        real_timeout = instance_id.pymongo.timeout

        def recording_timeout(seconds):
            calls.append(seconds)
            return real_timeout(seconds)

        monkeypatch.setattr(instance_id.pymongo, "timeout", recording_timeout)

        get_or_create_instance_id()

        assert calls == [instance_id._LOOKUP_TIMEOUT_SECONDS]
        assert 0 < instance_id._LOOKUP_TIMEOUT_SECONDS <= 5

    def test_foreign_document_degrades_rather_than_aborting(
        self, collection, legacy_file
    ):
        """A user registered "instance" before the name was reserved."""
        collection.insert_one({"_id": "instance_id", "ipv4": {}, "ipv6": {}})

        assert get_or_create_instance_id() == ""


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


class TestConcurrentSeeding:
    def test_a_competing_writer_wins_and_both_agree(
        self, collection, legacy_file, monkeypatch
    ):
        """$setOnInsert, so two processes converge instead of overwriting."""
        real_find_one = collection.find_one
        calls = {"n": 0}

        def find_one_then_insert(*args, **kwargs):
            # Simulate another process inserting between our read and our write.
            calls["n"] += 1
            result = real_find_one(*args, **kwargs)
            if calls["n"] == 1:
                collection.insert_one({"_id": "instance_id", "value": "other-process"})
            return result

        monkeypatch.setattr(collection, "find_one", find_one_then_insert)
        monkeypatch.setattr(instance_id, "_collection", lambda: collection)

        assert get_or_create_instance_id() == "other-process"
        assert collection.count_documents({}) == 1
