"""
Tests for package/backup_scheduler.py

Covers: next_run_after, default_settings, settings_from_document,
        scheduler_settings, ensure_schedule_document, read_schedule,
        update_settings, describe_schedule, _claim_run, _release_run,
        prune_mongo_dumps, prune_backup_zips, prune_preview,
        run_scheduled_backup, start/stop_backup_scheduler.

All configuration lives in the schedule document; this module reads no
environment variables, so there is nothing to stub out for that.
"""

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import mongomock
import pytest

from package import backup_scheduler
from package.backup_scheduler import (
    DEFAULT_DAY_OF_WEEK,
    DEFAULT_HOUR_UTC,
    DEFAULT_LEASE_SECONDS,
    DEFAULT_POLL_SECONDS,
    DEFAULT_RETENTION,
    SCHEDULE_DOCUMENT_ID,
    _claim_run,
    _release_run,
    default_settings,
    describe_schedule,
    ensure_schedule_document,
    next_run_after,
    prune_backup_zips,
    prune_mongo_dumps,
    prune_preview,
    read_schedule,
    run_scheduled_backup,
    scheduler_settings,
    settings_from_document,
    start_backup_scheduler,
    stop_backup_scheduler,
    update_settings,
)
from package.validators import INSTANCE_COLLECTION

# Monday 2026-09-14 12:00 UTC. weekday() == 0.
MONDAY = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def schedule(monkeypatch):
    """A mongomock-backed instance collection, as data_file_functions sees it."""
    client = mongomock.MongoClient()
    monkeypatch.setattr("package.data_file_functions._mongo_client", client)
    monkeypatch.setattr("package.data_file_functions._get_mongo_client", lambda: client)
    monkeypatch.setenv("MONGODB_DATABASE", "test_db")
    monkeypatch.setenv("MONGODB_URI", "mongodb://localhost:27017/")
    return client["test_db"][INSTANCE_COLLECTION]


@pytest.fixture
def broken_mongo(monkeypatch):
    """Makes every database access raise, to exercise the never-raise contract."""

    def boom():
        raise RuntimeError("mongo is down")

    monkeypatch.setattr("package.data_file_functions._get_mongo_db", boom)


@pytest.fixture
def backup_tree(tmp_path, monkeypatch):
    """
    A data/ tree with dumps and archives whose mtimes are controlled.

    Names and mtimes are deliberately in the *same* order here; the test that
    proves mtime ordering inverts them explicitly.
    """
    data = tmp_path / "data"
    (data / "backups").mkdir(parents=True)
    (data / "mongo_dumps").mkdir()
    (data / "tmp").mkdir()

    base = 1_700_000_000
    for index in range(5):
        dump = data / "mongo_dumps" / f"2026-01-0{index + 1}-03:00:00.000000"
        (dump / "test_db").mkdir(parents=True)
        (dump / "test_db" / "users.bson").write_bytes(b"x")
        os.utime(dump, (base + index, base + index))

        archive = data / "backups" / f"full-backup-2026-01-0{index + 1}-03:00:00.zip"
        archive.write_bytes(b"PK")
        os.utime(archive, (base + index, base + index))

    monkeypatch.chdir(tmp_path)
    return data


def _utc(value):
    """
    Attaches UTC to a datetime read back from the database.

    Both pymongo and mongomock hand back naive datetimes that are really UTC, so
    comparing a stored value with an aware one raises TypeError. The production
    code normalizes for the same reason.
    """
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _seed(collection, **overrides):
    """Inserts a schedule document, defaulting to enabled and due."""
    document = {
        "_id": SCHEDULE_DOCUMENT_ID,
        "enabled": True,
        "day_of_week": 6,
        "hour": 3,
        "retention": DEFAULT_RETENTION,
        "poll_seconds": DEFAULT_POLL_SECONDS,
        "lease_seconds": DEFAULT_LEASE_SECONDS,
        "next_run": MONDAY - timedelta(hours=1),
        "claimed_by": None,
        "claimed_at": None,
        "last_run_started": None,
        "last_run_finished": None,
        "last_result": None,
        "last_error": None,
        "last_backup_path": None,
    }
    document.update(overrides)
    collection.insert_one(document)
    return document


# ---------------------------------------------------------------------------
# next_run_after
# ---------------------------------------------------------------------------


class TestNextRunAfter:
    def test_midweek_finds_the_coming_sunday(self):
        assert next_run_after(MONDAY, 6, 3) == datetime(
            2026, 9, 20, 3, 0, tzinfo=timezone.utc
        )

    def test_exactly_on_the_slot_moves_a_week(self):
        """Strictly-after: called with the slot that just ran, never returns it."""
        slot = datetime(2026, 9, 20, 3, 0, tzinfo=timezone.utc)
        assert next_run_after(slot, 6, 3) == slot + timedelta(days=7)

    def test_one_second_before_the_slot_returns_that_slot(self):
        slot = datetime(2026, 9, 20, 3, 0, tzinfo=timezone.utc)
        assert next_run_after(slot - timedelta(seconds=1), 6, 3) == slot

    def test_same_day_later_hour_is_today(self):
        sunday_one_am = datetime(2026, 9, 20, 1, 0, tzinfo=timezone.utc)
        assert next_run_after(sunday_one_am, 6, 3) == datetime(
            2026, 9, 20, 3, 0, tzinfo=timezone.utc
        )

    def test_same_day_earlier_hour_is_next_week(self):
        sunday_four_am = datetime(2026, 9, 20, 4, 0, tzinfo=timezone.utc)
        assert next_run_after(sunday_four_am, 6, 3) == datetime(
            2026, 9, 27, 3, 0, tzinfo=timezone.utc
        )

    def test_monday_midnight_bounds(self):
        result = next_run_after(MONDAY, 0, 0)
        assert result == datetime(2026, 9, 21, 0, 0, tzinfo=timezone.utc)
        assert result.weekday() == 0

    def test_result_is_tz_aware_utc_and_zeroed(self):
        result = next_run_after(MONDAY, 6, 3)
        assert result.tzinfo == timezone.utc
        assert (result.minute, result.second, result.microsecond) == (0, 0, 0)

    def test_crosses_year_boundary(self):
        # 2026-12-31 is a Thursday; the next Sunday is 2027-01-03.
        new_years_eve = datetime(2026, 12, 31, 12, 0, tzinfo=timezone.utc)
        assert next_run_after(new_years_eve, 6, 3) == datetime(
            2027, 1, 3, 3, 0, tzinfo=timezone.utc
        )

    @pytest.mark.parametrize(
        "reference",
        [
            # Either side of the 2026 US DST end (Nov 1) and EU end (Oct 25).
            datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
            datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc),
        ],
    )
    def test_hour_is_always_the_same_utc_hour_across_dst(self, reference):
        """The schedule is UTC precisely so no DST arithmetic is needed."""
        assert next_run_after(reference, 6, 3).hour == 3


# ---------------------------------------------------------------------------
# Settings, read out of the document
# ---------------------------------------------------------------------------


class TestSettingsFromDocument:
    def test_defaults_are_disabled_and_sunday_three_utc(self):
        assert default_settings() == {
            "enabled": False,
            "day_of_week": 6,
            "hour": 3,
            "retention": 4,
            "poll_seconds": 300,
            "lease_seconds": 3600,
        }

    @pytest.mark.parametrize("document", [None, {}])
    def test_no_document_yields_defaults(self, document):
        assert settings_from_document(document) == default_settings()

    def test_reads_stored_values(self):
        settings = settings_from_document(
            {
                "enabled": True,
                "day_of_week": 0,
                "hour": 23,
                "retention": 10,
                "poll_seconds": 60,
                "lease_seconds": 7200,
            }
        )
        assert settings == {
            "enabled": True,
            "day_of_week": 0,
            "hour": 23,
            "retention": 10,
            "poll_seconds": 60,
            "lease_seconds": 7200,
        }

    def test_missing_fields_fall_back(self):
        """A document written by a release that predated a field must still work."""
        settings = settings_from_document({"enabled": True})
        assert settings["enabled"] is True
        assert settings["day_of_week"] == DEFAULT_DAY_OF_WEEK
        assert settings["hour"] == DEFAULT_HOUR_UTC
        assert settings["retention"] == DEFAULT_RETENTION
        assert settings["poll_seconds"] == DEFAULT_POLL_SECONDS
        assert settings["lease_seconds"] == DEFAULT_LEASE_SECONDS

    def test_out_of_range_values_are_clamped(self):
        """Guards a value edited directly in MongoDB."""
        settings = settings_from_document(
            {"day_of_week": 99, "hour": -5, "poll_seconds": 1, "retention": -3}
        )
        assert settings["day_of_week"] == 6
        assert settings["hour"] == 0
        assert settings["poll_seconds"] == 30
        assert settings["retention"] == 0

    @pytest.mark.parametrize("value", ["four", "", None, [], {}])
    def test_unusable_values_fall_back(self, value):
        assert settings_from_document({"retention": value})["retention"] == (
            DEFAULT_RETENTION
        )

    def test_numeric_strings_are_accepted(self):
        """The Admin form posts strings; they are stored as ints but be tolerant."""
        assert settings_from_document({"hour": "7"})["hour"] == 7

    def test_enabled_is_always_a_bool(self):
        assert settings_from_document({"enabled": "yes"})["enabled"] is True
        assert settings_from_document({"enabled": 0})["enabled"] is False


class TestSchedulerSettings:
    def test_reads_the_stored_document(self, schedule):
        _seed(schedule, enabled=True, day_of_week=2, hour=5, retention=9)
        settings = scheduler_settings()
        assert settings["enabled"] is True
        assert settings["day_of_week"] == 2
        assert settings["hour"] == 5
        assert settings["retention"] == 9

    def test_falls_back_to_defaults_when_unavailable(self, broken_mongo):
        assert scheduler_settings() == default_settings()


# ---------------------------------------------------------------------------
# ensure_schedule_document
# ---------------------------------------------------------------------------


class TestEnsureScheduleDocument:
    def test_creates_the_document_with_a_future_slot(self, schedule):
        document = ensure_schedule_document(MONDAY)
        assert document["_id"] == SCHEDULE_DOCUMENT_ID
        assert document["enabled"] is False
        assert _utc(document["next_run"]) > MONDAY
        assert document["day_of_week"] == 6
        assert document["hour"] == 3

    def test_first_boot_does_not_schedule_a_run_in_the_past(self, schedule):
        """An upgrade must not back up (and prune) during startup."""
        document = ensure_schedule_document(MONDAY)
        assert _claim_run(MONDAY, 3600) is None
        assert _utc(document["next_run"]) > MONDAY

    def test_seeds_every_setting(self, schedule):
        document = ensure_schedule_document(MONDAY)
        for key, value in default_settings().items():
            assert document[key] == value

    def test_second_call_does_not_overwrite_saved_settings(self, schedule):
        """A restart must never undo what an administrator saved."""
        first = ensure_schedule_document(MONDAY)
        schedule.update_one(
            {"_id": SCHEDULE_DOCUMENT_ID},
            {"$set": {"enabled": True, "day_of_week": 2, "hour": 5, "retention": 9}},
        )

        second = ensure_schedule_document(MONDAY + timedelta(days=1))

        assert second["enabled"] is True
        assert second["day_of_week"] == 2
        assert second["hour"] == 5
        assert second["retention"] == 9
        assert _utc(second["next_run"]) == _utc(first["next_run"])

    def test_returns_none_without_raising_when_mongo_is_down(self, broken_mongo):
        assert ensure_schedule_document(MONDAY) is None

    def test_coexists_with_the_telemetry_instance_id(
        self, schedule, caplog, monkeypatch
    ):
        """
        The schedule document shares the instance collection with the telemetry
        id, which is why no new reserved username was needed.

        FWGUI_INSTANCE_ID has to go: it short-circuits the lookup before MongoDB
        is touched, so with it set this would assert nothing about the two
        documents coexisting. CI sets it (.github/workflows/ci.yml), which is
        exactly where the earlier version of this test failed.
        """
        from package import instance_id

        monkeypatch.delenv(instance_id.INSTANCE_ID_ENV_VAR, raising=False)
        monkeypatch.setattr(instance_id, "_instance_id", None)
        schedule.insert_one({"_id": "instance_id", "value": "abc-123"})

        ensure_schedule_document(MONDAY)

        with caplog.at_level(logging.ERROR):
            assert instance_id.get_or_create_instance_id() == "abc-123"
        assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []


# ---------------------------------------------------------------------------
# read_schedule / update_settings / describe_schedule
# ---------------------------------------------------------------------------


class TestReadSchedule:
    def test_returns_the_document(self, schedule):
        _seed(schedule)
        assert read_schedule()["_id"] == SCHEDULE_DOCUMENT_ID

    def test_returns_none_when_absent(self, schedule):
        assert read_schedule() is None

    def test_returns_none_without_raising_when_mongo_is_down(self, broken_mongo):
        assert read_schedule() is None


class TestUpdateSettings:
    def test_stores_every_setting(self, schedule):
        _seed(schedule, enabled=False)
        document = update_settings(True, day_of_week=2, hour=5, retention=9, now=MONDAY)
        assert document["enabled"] is True
        assert document["day_of_week"] == 2
        assert document["hour"] == 5
        assert document["retention"] == 9

    def test_accepts_the_strings_a_form_posts(self, schedule):
        _seed(schedule, enabled=False)
        document = update_settings(
            True, day_of_week="2", hour="5", retention="9", now=MONDAY
        )
        assert (document["day_of_week"], document["hour"], document["retention"]) == (
            2,
            5,
            9,
        )

    def test_enabling_sets_a_future_slot(self, schedule):
        _seed(schedule, enabled=False, next_run=MONDAY - timedelta(days=30))
        document = update_settings(True, now=MONDAY)
        assert _utc(document["next_run"]) > MONDAY

    def test_enabling_a_long_disabled_schedule_does_not_fire_at_once(self, schedule):
        """A month-old next_run would otherwise back up and prune immediately."""
        _seed(schedule, enabled=False, next_run=MONDAY - timedelta(days=30))
        update_settings(True, now=MONDAY)
        assert _claim_run(MONDAY, 3600) is None

    def test_changing_the_day_moves_the_slot(self, schedule):
        _seed(schedule, enabled=True, day_of_week=6, hour=3)
        document = update_settings(True, day_of_week=2, hour=5, now=MONDAY)
        # Monday 2026-09-14 -> Wednesday 2026-09-16 at 05:00 UTC.
        assert _utc(document["next_run"]) == datetime(
            2026, 9, 16, 5, 0, tzinfo=timezone.utc
        )

    def test_saving_an_unchanged_schedule_leaves_the_slot_alone(self, schedule):
        """Re-saving must not push the next run a week out."""
        seeded = _seed(
            schedule,
            enabled=True,
            day_of_week=6,
            hour=3,
            next_run=MONDAY + timedelta(days=6),
        )
        document = update_settings(True, day_of_week=6, hour=3, now=MONDAY)
        assert _utc(document["next_run"]) == _utc(seeded["next_run"])

    def test_retention_zero_is_stored(self, schedule):
        _seed(schedule, retention=4)
        assert update_settings(True, retention=0, now=MONDAY)["retention"] == 0

    def test_out_of_range_values_are_clamped(self, schedule):
        _seed(schedule)
        document = update_settings(
            True, day_of_week=99, hour=-1, retention=99999, now=MONDAY
        )
        assert document["day_of_week"] == 6
        assert document["hour"] == 0
        assert document["retention"] == 1000

    def test_unusable_values_keep_the_stored_ones(self, schedule):
        """A mangled POST must not silently move the schedule."""
        _seed(schedule, day_of_week=2, hour=5, retention=9)
        document = update_settings(
            True, day_of_week="tuesday", hour=None, retention="lots", now=MONDAY
        )
        assert document["day_of_week"] == 2
        assert document["hour"] == 5
        assert document["retention"] == 9

    def test_disabling(self, schedule):
        _seed(schedule, enabled=True)
        assert update_settings(False, now=MONDAY)["enabled"] is False

    def test_disabling_keeps_the_other_settings(self, schedule):
        _seed(schedule, enabled=True, day_of_week=2, hour=5, retention=9)
        document = update_settings(
            False, day_of_week=2, hour=5, retention=9, now=MONDAY
        )
        assert document["day_of_week"] == 2
        assert document["retention"] == 9

    def test_creates_the_document_when_it_is_missing(self, schedule):
        assert update_settings(True, now=MONDAY)["enabled"] is True

    def test_returns_none_without_raising_when_mongo_is_down(self, broken_mongo):
        assert update_settings(True) is None


class TestDescribeSchedule:
    def test_renders_an_enabled_schedule(self, schedule):
        _seed(
            schedule,
            enabled=True,
            next_run=datetime(2026, 9, 20, 3, 0, tzinfo=timezone.utc),
            last_run_finished=datetime(2026, 9, 13, 3, 2, tzinfo=timezone.utc),
            last_result="success",
        )
        described = describe_schedule()
        assert described["enabled"] is True
        assert described["schedule_text"] == "Sundays at 03:00 UTC"
        assert described["last_run_text"] == "2026-09-13 03:02 UTC (success)"
        assert described["next_run_text"] == "2026-09-20 03:00 UTC"
        assert described["retention"] == 4
        assert described["running"] is False

    def test_disabled_has_no_next_run(self, schedule):
        _seed(schedule, enabled=False)
        described = describe_schedule()
        assert described["next_run_text"] == "Not scheduled"

    def test_never_run(self, schedule):
        _seed(schedule)
        assert describe_schedule()["last_run_text"] == "Never"

    def test_reports_a_run_in_flight(self, schedule):
        _seed(schedule, claimed_at=MONDAY, claimed_by="host:1")
        assert describe_schedule()["running"] is True

    def test_carries_the_values_the_form_pre_selects(self, schedule):
        """The document is the only place these live, so the form reads them back."""
        _seed(schedule, enabled=True, day_of_week=2, hour=5, retention=9)
        described = describe_schedule()
        assert described["day_of_week"] == 2
        assert described["hour"] == 5
        assert described["retention"] == 9
        assert described["schedule_text"] == "Wednesdays at 05:00 UTC"

    def test_offers_all_seven_days_and_24_hours(self, schedule):
        _seed(schedule)
        described = describe_schedule()
        assert len(described["day_choices"]) == 7
        assert described["day_choices"][0] == (0, "Mondays")
        assert described["day_choices"][6] == (6, "Sundays")
        assert described["hour_choices"] == list(range(24))

    def test_surfaces_the_last_error(self, schedule):
        _seed(schedule, last_result="failed", last_error="disk full")
        assert describe_schedule()["last_error"] == "disk full"

    def test_returns_none_when_unavailable(self, broken_mongo):
        assert describe_schedule() is None


# ---------------------------------------------------------------------------
# _claim_run
# ---------------------------------------------------------------------------


class TestClaimRun:
    def test_claims_a_due_run(self, schedule):
        _seed(schedule)
        document = _claim_run(MONDAY, 3600)
        assert document is not None
        assert document["claimed_by"] == backup_scheduler._worker_id()
        assert _utc(document["claimed_at"]) == MONDAY
        assert _utc(document["last_run_started"]) == MONDAY

    def test_second_immediate_call_gets_nothing(self, schedule):
        """
        The double-fire guard: the dev reloader's two processes and any extra
        Helm replica all issue this same update.

        mongomock serialises these, so what this proves is that the *filter* is
        right. MongoDB's single-document atomicity is what makes it hold under
        real concurrency.
        """
        _seed(schedule)
        assert _claim_run(MONDAY, 3600) is not None
        assert _claim_run(MONDAY, 3600) is None

    def test_only_one_of_two_threads_wins(self, schedule):
        _seed(schedule)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: _claim_run(MONDAY, 3600), range(2)))
        assert len([r for r in results if r is not None]) == 1

    def test_does_not_advance_next_run(self, schedule):
        """
        A process killed mid-zip must not have consumed the week -- _release_run
        advances the slot, not the claim.
        """
        seeded = _seed(schedule)
        _claim_run(MONDAY, 3600)
        assert _utc(
            schedule.find_one({"_id": SCHEDULE_DOCUMENT_ID})["next_run"]
        ) == _utc(seeded["next_run"])

    def test_future_next_run_is_not_due(self, schedule):
        _seed(schedule, next_run=MONDAY + timedelta(days=1))
        assert _claim_run(MONDAY, 3600) is None

    def test_disabled_is_never_claimed(self, schedule):
        _seed(schedule, enabled=False)
        assert _claim_run(MONDAY, 3600) is None

    def test_a_live_lease_blocks_the_claim(self, schedule):
        _seed(schedule, claimed_at=MONDAY - timedelta(minutes=10), claimed_by="other")
        assert _claim_run(MONDAY, 3600) is None

    def test_an_expired_lease_is_reclaimed(self, schedule):
        """How a process killed mid-backup gets its window retried."""
        _seed(schedule, claimed_at=MONDAY - timedelta(hours=2), claimed_by="dead:1")
        document = _claim_run(MONDAY, 3600)
        assert document is not None
        assert document["claimed_by"] == backup_scheduler._worker_id()

    def test_missing_document_is_not_created(self, schedule):
        assert _claim_run(MONDAY, 3600) is None
        assert schedule.find_one({"_id": SCHEDULE_DOCUMENT_ID}) is None

    def test_returns_none_without_raising_when_mongo_is_down(self, broken_mongo):
        assert _claim_run(MONDAY, 3600) is None


# ---------------------------------------------------------------------------
# _release_run
# ---------------------------------------------------------------------------


class TestReleaseRun:
    def test_success_clears_the_claim_and_advances(self, schedule):
        _seed(schedule, claimed_at=MONDAY, claimed_by="host:1")
        _release_run(MONDAY, "success", backup_path="data/backups/full-backup-x.zip")
        document = schedule.find_one({"_id": SCHEDULE_DOCUMENT_ID})
        assert document["claimed_at"] is None
        assert document["claimed_by"] is None
        assert document["last_result"] == "success"
        assert document["last_backup_path"] == "data/backups/full-backup-x.zip"
        assert _utc(document["next_run"]) > MONDAY

    def test_failure_still_advances_the_slot(self, schedule):
        """Otherwise a broken backup retries every poll, forever."""
        _seed(schedule, claimed_at=MONDAY, claimed_by="host:1")
        _release_run(MONDAY, "failed", error=RuntimeError("mongo is down"))
        document = schedule.find_one({"_id": SCHEDULE_DOCUMENT_ID})
        assert document["last_result"] == "failed"
        assert "mongo is down" in document["last_error"]
        assert _utc(document["next_run"]) > MONDAY

    def test_long_error_is_truncated(self, schedule):
        _seed(schedule)
        _release_run(MONDAY, "failed", error="x" * 5000)
        document = schedule.find_one({"_id": SCHEDULE_DOCUMENT_ID})
        assert len(document["last_error"]) == 500

    def test_after_a_long_outage_the_new_slot_is_in_the_future(self, schedule):
        """One overdue run, then back on cadence -- not one per missed week."""
        _seed(schedule, next_run=MONDAY - timedelta(days=21))
        _release_run(MONDAY, "success")
        document = schedule.find_one({"_id": SCHEDULE_DOCUMENT_ID})
        assert _utc(document["next_run"]) > MONDAY

    def test_does_not_raise_when_mongo_is_down(self, broken_mongo):
        _release_run(MONDAY, "success")


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


def _dump_names(data):
    return sorted(p.name for p in (data / "mongo_dumps").iterdir())


def _zip_names(data):
    return sorted(p.name for p in (data / "backups").iterdir())


class TestPruning:
    def test_keeps_the_newest_dumps(self, backup_tree):
        assert prune_mongo_dumps(2) == 3
        assert _dump_names(backup_tree) == [
            "2026-01-04-03:00:00.000000",
            "2026-01-05-03:00:00.000000",
        ]

    def test_keeps_the_newest_zips(self, backup_tree):
        assert prune_backup_zips(2) == 3
        assert _zip_names(backup_tree) == [
            "full-backup-2026-01-04-03:00:00.zip",
            "full-backup-2026-01-05-03:00:00.zip",
        ]

    def test_keep_zero_removes_everything(self, backup_tree):
        """What a retention of 1 asks for: clear out, then write this week's."""
        assert prune_mongo_dumps(0) == 5
        assert _dump_names(backup_tree) == []

    def test_negative_keep_is_a_no_op(self, backup_tree):
        assert prune_mongo_dumps(-1) == 0
        assert len(_dump_names(backup_tree)) == 5

    def test_fewer_entries_than_kept_removes_nothing(self, backup_tree):
        assert prune_backup_zips(50) == 0
        assert len(_zip_names(backup_tree)) == 5

    def test_prunes_by_mtime_not_by_name(self, backup_tree):
        """
        A DST fall-back gives a genuinely newer directory an earlier-sorting name,
        because the names come from naive local time. Pruning by name would delete
        the newest backup.
        """
        newest_name = backup_tree / "mongo_dumps" / "2026-01-05-03:00:00.000000"
        oldest_name = backup_tree / "mongo_dumps" / "2026-01-01-03:00:00.000000"
        # Invert: the name that sorts last is now the oldest by mtime.
        os.utime(newest_name, (1, 1))
        os.utime(oldest_name, (2_000_000_000, 2_000_000_000))

        prune_mongo_dumps(4)

        assert not newest_name.exists()
        assert oldest_name.exists()

    def test_a_similar_looking_file_is_not_deleted(self, backup_tree):
        """
        endswith('.zip'), not list_full_backups()'s '.zip' in name -- this
        function deletes what it matches.
        """
        bystander = backup_tree / "backups" / "notes.zip.bak"
        bystander.write_text("keep me")
        prune_backup_zips(1)
        assert bystander.exists()

    def test_stray_file_among_the_dumps_survives(self, backup_tree):
        stray = backup_tree / "mongo_dumps" / "README.txt"
        stray.write_text("not a dump")
        prune_mongo_dumps(0)
        assert stray.exists()

    def test_missing_directories_return_zero(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert prune_mongo_dumps(2) == 0
        assert prune_backup_zips(2) == 0

    def test_one_failing_removal_does_not_stop_the_rest(self, backup_tree, monkeypatch):
        real_rmtree = backup_scheduler.shutil.rmtree
        calls = []

        def flaky(path):
            calls.append(path)
            if len(calls) == 1:
                raise OSError("permission denied")
            real_rmtree(path)

        monkeypatch.setattr(backup_scheduler.shutil, "rmtree", flaky)

        assert prune_mongo_dumps(2) == 2
        assert len(_dump_names(backup_tree)) == 3

    def test_refuses_to_follow_a_symlink_out_of_the_dump_directory(
        self, backup_tree, tmp_path
    ):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "precious.txt").write_text("do not delete")
        link = backup_tree / "mongo_dumps" / "2026-01-00-escape"
        link.symlink_to(outside, target_is_directory=True)
        os.utime(link, (1, 1), follow_symlinks=False)

        prune_mongo_dumps(1)

        assert (outside / "precious.txt").exists()


class TestPrunePreview:
    def test_counts_without_deleting(self, backup_tree):
        preview = prune_preview(2)
        # Dumps are pruned to retention - 1, so the fresh dump lands on exactly 2.
        assert preview == {"dumps": 4, "zips": 3}
        assert len(_dump_names(backup_tree)) == 5
        assert len(_zip_names(backup_tree)) == 5

    def test_zero_retention_previews_nothing(self, backup_tree):
        assert prune_preview(0) == {"dumps": 0, "zips": 0}

    def test_never_negative(self, backup_tree):
        assert prune_preview(500) == {"dumps": 0, "zips": 0}


# ---------------------------------------------------------------------------
# run_scheduled_backup
# ---------------------------------------------------------------------------


class TestRunScheduledBackup:
    @pytest.fixture
    def stub_backup(self, monkeypatch, backup_tree):
        """Records the call order of pruning and the backup itself."""
        calls = []

        def fake_backup(actor="scheduler"):
            calls.append(("backup", actor))
            path = "data/backups/full-backup-new.zip"
            (backup_tree / "backups" / "full-backup-new.zip").write_bytes(b"PK")
            return path

        monkeypatch.setattr(
            "package.data_file_functions.perform_full_backup", fake_backup
        )
        monkeypatch.setattr(
            backup_scheduler,
            "prune_mongo_dumps",
            lambda keep: calls.append(("dumps", keep)),
        )
        monkeypatch.setattr(
            backup_scheduler,
            "prune_backup_zips",
            lambda keep: calls.append(("zips", keep)),
        )
        return calls

    def test_happy_path(self, schedule, stub_backup):
        _seed(schedule)
        assert run_scheduled_backup(MONDAY) is True
        document = schedule.find_one({"_id": SCHEDULE_DOCUMENT_ID})
        assert document["last_result"] == "success"
        assert document["last_backup_path"] == "data/backups/full-backup-new.zip"
        assert document["claimed_at"] is None
        assert _utc(document["next_run"]) > MONDAY

    def test_prunes_dumps_before_and_zips_after(self, schedule, stub_backup):
        """
        Dumps first is what bounds the new archive: every zip re-archives whatever
        sits in data/mongo_dumps. Zips last so a failed backup does not shrink
        the set.
        """
        _seed(schedule)
        run_scheduled_backup(MONDAY)
        assert stub_backup == [
            ("dumps", 3),
            ("backup", "scheduler"),
            ("zips", 4),
        ]

    def test_not_due_does_nothing(self, schedule, stub_backup):
        _seed(schedule, next_run=MONDAY + timedelta(days=1))
        assert run_scheduled_backup(MONDAY) is False
        assert stub_backup == []

    def test_disabled_does_nothing(self, schedule, stub_backup):
        _seed(schedule, enabled=False)
        assert run_scheduled_backup(MONDAY) is False
        assert stub_backup == []

    def test_zero_retention_prunes_nothing(self, schedule, stub_backup):
        _seed(schedule, retention=0)
        assert run_scheduled_backup(MONDAY) is True
        assert stub_backup == [("backup", "scheduler")]

    def test_a_failing_backup_is_recorded_and_does_not_raise(
        self, schedule, backup_tree, monkeypatch
    ):
        def boom(actor="scheduler"):
            raise RuntimeError("disk full")

        monkeypatch.setattr("package.data_file_functions.perform_full_backup", boom)
        _seed(schedule)

        assert run_scheduled_backup(MONDAY) is False

        document = schedule.find_one({"_id": SCHEDULE_DOCUMENT_ID})
        assert document["last_result"] == "failed"
        assert "disk full" in document["last_error"]
        assert document["claimed_at"] is None
        assert _utc(document["next_run"]) > MONDAY

    def test_a_second_call_does_not_run_twice(self, schedule, stub_backup):
        _seed(schedule)
        assert run_scheduled_backup(MONDAY) is True
        assert run_scheduled_backup(MONDAY) is False

    def test_returns_false_without_raising_when_mongo_is_down(self, broken_mongo):
        assert run_scheduled_backup(MONDAY) is False


# ---------------------------------------------------------------------------
# Thread
# ---------------------------------------------------------------------------


class TestSchedulerThread:
    @pytest.fixture(autouse=True)
    def always_stop(self):
        yield
        stop_backup_scheduler(timeout=2)

    def test_starts_a_daemon_thread_and_stops(self, schedule, monkeypatch):
        _seed(schedule, poll_seconds=30)
        monkeypatch.setattr(backup_scheduler, "run_scheduled_backup", lambda: False)

        thread = start_backup_scheduler()

        assert thread is not None
        assert thread.daemon is True
        assert thread.is_alive()

        stop_backup_scheduler(timeout=5)
        assert not thread.is_alive()

    def test_a_second_start_reuses_the_thread(self, schedule, monkeypatch):
        _seed(schedule, poll_seconds=30)
        monkeypatch.setattr(backup_scheduler, "run_scheduled_backup", lambda: False)
        first = start_backup_scheduler()
        assert start_backup_scheduler() is first

    def test_does_not_start_when_the_document_is_unavailable(self, broken_mongo):
        assert start_backup_scheduler() is None

    def test_stop_is_safe_when_never_started(self):
        stop_backup_scheduler()

    def test_the_loop_survives_a_failing_poll(self, monkeypatch):
        """A loop that could die silently would leave an app that never backs up."""
        stop_event = threading.Event()
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("transient")
            stop_event.set()

        monkeypatch.setattr(backup_scheduler, "run_scheduled_backup", flaky)
        backup_scheduler._scheduler_loop(stop_event, 0.01)

        assert len(calls) >= 2
