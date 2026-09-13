"""
Automatic Weekly Backup

Runs a full backup on a chosen day and hour each week without anyone clicking a
button. A daemon thread polls a single schedule document in MongoDB and claims
each due run with one atomic ``find_one_and_update``:

    {"_id": "backup_schedule", "enabled": bool, "day_of_week": int, "hour": int,
     "retention": int, "poll_seconds": int, "lease_seconds": int,
     "next_run": datetime, "claimed_by": str, "claimed_at": datetime, ...}

**The document is the only configuration.** There are no environment variables
for any of this: the Admin Settings page writes the settings and every read comes
back through ``settings_from_document()``, which defaults and clamps each field.
That keeps one source of truth -- an env var and a stored value that disagree
would need a precedence rule, and whichever lost would look like a bug to whoever
set it -- and it means a change takes effect without a restart.

**The claim, not the thread, is what makes this safe.** Flask's dev reloader runs
``__main__`` in two processes, and the Helm chart can scale past one replica, so
"one thread per process" is not "one backup per week". MongoDB's single-document
atomicity means exactly one caller's filter matches; every other caller gets
``None`` and does nothing.

The document lives in the *existing* ``instance`` collection rather than a new
one, because a collection name is also a username (``validators.py``) -- a new
collection would mean reserving another username. ``instance_id`` looks its value
up by ``_id``, so a second document there is invisible to it.

**Nothing in here may raise.** It is called from a background thread with no
request to fail and no user to tell, and from the Admin Settings page where a
database blip must not 500 the whole page. Every public function returns a
sentinel (``None``, ``False``, ``0``) instead of propagating.
"""

import atexit
import logging
import os
import shutil
import socket
import threading
from datetime import datetime, timedelta, timezone

import pymongo

from package import data_file_functions
from package.validators import INSTANCE_COLLECTION

# Fixed _id of the schedule document, alongside instance_id's "instance_id" in
# the same collection.
SCHEDULE_DOCUMENT_ID = "backup_schedule"

# Values a new schedule document is seeded with, and the fallback for any field
# that is missing or unusable when one is read back. Only ever defaults: the
# stored document is what the scheduler actually runs on, and the Admin Settings
# page is what changes it.
#
# Sunday 03:00 UTC. datetime.weekday() numbering: Monday=0 .. Sunday=6.
DEFAULT_DAY_OF_WEEK = 6
DEFAULT_HOUR_UTC = 3

# Kept archives and Mongo dumps. Four *weekly* backups, so roughly a month.
#
# Retention is not a nicety here. Every zip re-archives whatever is in
# data/mongo_dumps, and before 3.0.0 nothing ever pruned either one, so archive
# size grew quadratically -- a real install reached 944 MB of zips and 119 dump
# directories. Automating backups without a bound would add gigabytes a year.
DEFAULT_RETENTION = 4

# How often the thread checks whether a run is due. 300s is ~288 single-document
# queries a day, which is nothing, and bounds post-restart lateness to five
# minutes. A shorter interval is pointless chatter for a weekly job; an hour
# means a restart just before the slot could miss it by an hour.
#
# Stored on the document like the rest, but deliberately not on the Admin page:
# it is tuning with no user-visible effect, and a form field inviting someone to
# set it to 30s would only add load. Editable directly in MongoDB if ever needed.
DEFAULT_POLL_SECONDS = 300

# How long a claim is honoured before another process may take the run. This is
# the crash-recovery mechanism: a process killed mid-zip leaves claimed_at set
# and next_run still due, and nothing else would ever pick it up. Must exceed the
# longest plausible backup, or two processes could zip at once. Stored, and off
# the Admin page, for the same reason as the poll interval.
DEFAULT_LEASE_SECONDS = 3600

# Upper bound on any single MongoDB call here. Deliberately looser than
# instance_id's 2.0s: that one sits in the login and commit paths, this is a
# background job and the Admin Settings page.
_MONGO_TIMEOUT_SECONDS = 10.0

# Directories this module prunes. Bare relative paths, like everything else in
# the app -- the process CWD is the app root.
_MONGO_DUMP_DIR = "data/mongo_dumps"
_BACKUP_DIR = "data/backups"

# Accepted ranges for the stored settings. Everything arriving from the Admin
# Settings form is clamped to these, so a hand-edited POST cannot store an hour of
# 99 or a poll interval of zero that would spin the thread.
DAY_OF_WEEK_RANGE = (0, 6)
HOUR_RANGE = (0, 23)
RETENTION_RANGE = (0, 1000)
POLL_SECONDS_RANGE = (30, 3600)
LEASE_SECONDS_RANGE = (60, 86400)

_DAY_NAMES = (
    "Mondays",
    "Tuesdays",
    "Wednesdays",
    "Thursdays",
    "Fridays",
    "Saturdays",
    "Sundays",
)

# Longest stored last_error. The field exists to hint at what went wrong on the
# Admin page, not to hold a traceback.
_MAX_ERROR_LENGTH = 500

# Thread state. _thread is kept so a second start_backup_scheduler() call in one
# process cannot start a second thread.
_thread = None
_stop_event = None


def _collection():
    return data_file_functions._get_mongo_db()[INSTANCE_COLLECTION]


def _worker_id():
    """Identifies the claiming process in the log and on the document."""
    return f"{socket.gethostname()}:{os.getpid()}"


def _coerce_int(value, default, bounds):
    """
    Returns ``value`` as an int inside ``bounds``, or ``default`` if it is not
    usable at all.

    Never raises. The inputs are form fields from the Admin Settings page and
    fields read back out of the schedule document, so "unparseable" is a normal
    case -- a hand-crafted POST, or a document written by an older release that
    did not have the field yet.
    """
    if isinstance(value, bool) or value is None:
        return default
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    low, high = bounds
    return min(max(parsed, low), high)


def default_settings():
    """The settings a brand-new schedule document is created with."""
    return {
        "enabled": False,
        "day_of_week": DEFAULT_DAY_OF_WEEK,
        "hour": DEFAULT_HOUR_UTC,
        "retention": DEFAULT_RETENTION,
        "poll_seconds": DEFAULT_POLL_SECONDS,
        "lease_seconds": DEFAULT_LEASE_SECONDS,
    }


def settings_from_document(document):
    """
    Reads the effective settings out of a schedule document.

    Args:
        document (dict): a schedule document, or None

    Returns:
        dict: the same keys as default_settings(), always populated

    Every field is defaulted and clamped on the way out rather than trusted. The
    document is the only source of configuration -- there are no environment
    variables for any of this -- so a field that is missing (a document written by
    a release that predates it) or out of range (edited directly in MongoDB) must
    still yield a usable schedule instead of an exception on a background thread.
    """
    settings = default_settings()
    if not document:
        return settings

    settings["enabled"] = bool(document.get("enabled", False))
    settings["day_of_week"] = _coerce_int(
        document.get("day_of_week"), DEFAULT_DAY_OF_WEEK, DAY_OF_WEEK_RANGE
    )
    settings["hour"] = _coerce_int(document.get("hour"), DEFAULT_HOUR_UTC, HOUR_RANGE)
    settings["retention"] = _coerce_int(
        document.get("retention"), DEFAULT_RETENTION, RETENTION_RANGE
    )
    settings["poll_seconds"] = _coerce_int(
        document.get("poll_seconds"), DEFAULT_POLL_SECONDS, POLL_SECONDS_RANGE
    )
    settings["lease_seconds"] = _coerce_int(
        document.get("lease_seconds"), DEFAULT_LEASE_SECONDS, LEASE_SECONDS_RANGE
    )
    return settings


def scheduler_settings():
    """The stored settings, or the defaults if the document cannot be read."""
    return settings_from_document(read_schedule())


def next_run_after(reference, day_of_week, hour):
    """
    Returns the first ``day_of_week`` at ``hour`` UTC strictly after ``reference``.

    Args:
        reference (datetime): tz-aware UTC instant to search forward from
        day_of_week (int): Monday=0 .. Sunday=6, matching datetime.weekday()
        hour (int): hour of day, UTC

    Returns:
        datetime: tz-aware UTC, minutes/seconds/microseconds zeroed

    Strictly after, never equal: called with the slot that just ran, it must
    return next week's, not the same one again.

    Everything here is UTC, which is the whole reason the schedule is specified
    in UTC -- no DST arithmetic, so plain timedelta days are exact.
    """
    days_ahead = (day_of_week - reference.weekday()) % 7
    candidate = (reference + timedelta(days=days_ahead)).replace(
        hour=hour, minute=0, second=0, microsecond=0
    )
    if candidate <= reference:
        candidate += timedelta(days=7)
    return candidate


# ---------------------------------------------------------------------------
# Schedule document
# ---------------------------------------------------------------------------


def ensure_schedule_document(now=None):
    """
    Creates the schedule document with default settings if it does not exist.

    Returns:
        dict: the stored document, or None if MongoDB could not be reached

    Everything is written with $setOnInsert, so this is idempotent and a restart
    can never overwrite what an administrator set on the Admin Settings page. That
    page is the only way these values change; there are no environment variables
    to reconcile against.

    $setOnInsert rather than a find-then-insert so two processes starting at once
    -- the dev reloader's pair, or several replicas -- converge on one document
    instead of racing.

    The seeded ``next_run`` is always a *future* slot, and the schedule is seeded
    disabled, so a fresh install and an upgrade both do nothing until somebody
    turns it on. Backing up (and pruning) during startup would be a poor surprise.
    """
    now = now or datetime.now(timezone.utc)
    settings = default_settings()
    seeded_next_run = next_run_after(now, settings["day_of_week"], settings["hour"])

    try:
        with pymongo.timeout(_MONGO_TIMEOUT_SECONDS):
            collection = _collection()
            collection.update_one(
                {"_id": SCHEDULE_DOCUMENT_ID},
                {
                    "$setOnInsert": {
                        "enabled": settings["enabled"],
                        "day_of_week": settings["day_of_week"],
                        "hour": settings["hour"],
                        "retention": settings["retention"],
                        "poll_seconds": settings["poll_seconds"],
                        "lease_seconds": settings["lease_seconds"],
                        "next_run": seeded_next_run,
                        "claimed_by": None,
                        "claimed_at": None,
                        "last_run_started": None,
                        "last_run_finished": None,
                        "last_result": None,
                        "last_error": None,
                        "last_backup_path": None,
                        "created": now,
                    }
                },
                upsert=True,
            )
            return collection.find_one({"_id": SCHEDULE_DOCUMENT_ID})
    except Exception as e:
        logging.warning(f"Could not read or create the backup schedule: {e}")
        return None


def read_schedule():
    """Returns the schedule document, or None if it is unavailable."""
    try:
        with pymongo.timeout(_MONGO_TIMEOUT_SECONDS):
            return _collection().find_one({"_id": SCHEDULE_DOCUMENT_ID})
    except Exception as e:
        logging.warning(f"Could not read the backup schedule: {e}")
        return None


def update_settings(enabled, day_of_week=None, hour=None, retention=None, now=None):
    """
    Stores the schedule settings from the Admin Settings form.

    Args:
        enabled (bool): whether the weekly backup runs at all
        day_of_week: Monday=0 .. Sunday=6. Unparseable or out of range falls back
                     to the stored value, so a mangled field cannot silently move
                     the schedule
        hour: hour of the run, UTC
        retention: archives and Mongo dumps to keep; 0 keeps everything
        now (datetime): injectable for tests

    Returns:
        dict: the updated document, or None if it could not be stored

    ``next_run`` is recomputed whenever the day or hour changes, and whenever the
    schedule is switched on. The second part matters as much as the first: a
    schedule left off for a month holds a long-past ``next_run``, and without
    recomputing it, enabling would fire a backup -- and a prune -- within seconds
    of the click rather than at the hour the administrator just chose.

    Values are clamped rather than rejected. These arrive from a <select> and a
    number input, so anything out of range is either a hand-made POST or a browser
    quirk; there is no useful error to show a user for it, and refusing the whole
    save would lose the parts that were fine.
    """
    now = now or datetime.now(timezone.utc)

    try:
        with pymongo.timeout(_MONGO_TIMEOUT_SECONDS):
            collection = _collection()
            document = collection.find_one({"_id": SCHEDULE_DOCUMENT_ID})
            if document is None:
                # Normally seeded at startup, but the database may have been
                # unreachable then.
                document = ensure_schedule_document(now)
                if document is None:
                    return None

            current = settings_from_document(document)

            new_day = _coerce_int(
                day_of_week, current["day_of_week"], DAY_OF_WEEK_RANGE
            )
            new_hour = _coerce_int(hour, current["hour"], HOUR_RANGE)
            new_retention = _coerce_int(
                retention, current["retention"], RETENTION_RANGE
            )
            enabled = bool(enabled)

            updates = {
                "enabled": enabled,
                "day_of_week": new_day,
                "hour": new_hour,
                "retention": new_retention,
                "updated": now,
            }

            schedule_moved = (
                new_day != current["day_of_week"] or new_hour != current["hour"]
            )
            if enabled and (schedule_moved or not current["enabled"]):
                updates["next_run"] = next_run_after(now, new_day, new_hour)

            return collection.find_one_and_update(
                {"_id": SCHEDULE_DOCUMENT_ID},
                {"$set": updates},
                return_document=pymongo.ReturnDocument.AFTER,
            )
    except Exception as e:
        logging.warning(f"Could not update the backup schedule: {e}")
        return None


def _format_timestamp(value):
    """Renders a stored datetime for the Admin page, or 'Never' if unset."""
    if not isinstance(value, datetime):
        return "Never"
    # Stored as UTC; pymongo hands naive UTC back, mongomock may keep the tzinfo.
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return f"{value:%Y-%m-%d %H:%M} UTC"


def day_choices():
    """(value, label) pairs for the day-of-week select on the Admin page."""
    return list(enumerate(_DAY_NAMES))


def describe_schedule():
    """
    Returns the state and settings the Admin Settings page renders, or None.

    Carries both the current values -- so the form can pre-select what is stored,
    which is the only place these settings exist -- and pre-formatted strings, so
    the template holds no date logic and the wording is directly assertable in
    tests.
    """
    document = read_schedule()
    if document is None:
        return None

    settings = settings_from_document(document)
    day = settings["day_of_week"]
    hour = settings["hour"]

    last_run = _format_timestamp(document.get("last_run_finished"))
    result = document.get("last_result")
    if result and last_run != "Never":
        last_run = f"{last_run} ({result})"

    next_run = (
        _format_timestamp(document.get("next_run"))
        if settings["enabled"]
        else "Not scheduled"
    )

    return {
        "enabled": settings["enabled"],
        "day_of_week": day,
        "hour": hour,
        "retention": settings["retention"],
        "day_choices": day_choices(),
        "hour_choices": list(range(24)),
        "running": document.get("claimed_at") is not None,
        "schedule_text": f"{_DAY_NAMES[day]} at {hour:02d}:00 UTC",
        "last_run_text": last_run,
        "next_run_text": next_run,
        "last_error": document.get("last_error"),
    }


# ---------------------------------------------------------------------------
# Claiming a run
# ---------------------------------------------------------------------------


def _claim_run(now, lease_seconds):
    """
    Atomically claims the due run, or returns None if there is nothing to claim.

    This single update is the entire concurrency story. Two reloader processes or
    N Helm replicas all issue it; MongoDB applies updates to one document
    serially, so exactly one matches the filter and the rest see a document that
    no longer satisfies it.

    Note what is *not* here: ``next_run`` is not advanced. If it were, a process
    killed mid-zip would have already consumed the week and the backup would
    silently not happen until the next slot. Advancing it is _release_run()'s
    job, once the attempt has actually finished. The stale-claim branch below is
    what recovers that killed process's window.
    """
    lease_cutoff = now - timedelta(seconds=lease_seconds)
    try:
        with pymongo.timeout(_MONGO_TIMEOUT_SECONDS):
            return _collection().find_one_and_update(
                {
                    "_id": SCHEDULE_DOCUMENT_ID,
                    "enabled": True,
                    "next_run": {"$lte": now},
                    "$or": [
                        {"claimed_at": None},
                        {"claimed_at": {"$lte": lease_cutoff}},
                    ],
                },
                {
                    "$set": {
                        "claimed_by": _worker_id(),
                        "claimed_at": now,
                        "last_run_started": now,
                    }
                },
                return_document=pymongo.ReturnDocument.AFTER,
            )
    except Exception as e:
        logging.warning(f"Could not claim the weekly backup run: {e}")
        return None


def _release_run(now, result, error=None, backup_path=None):
    """
    Records the outcome, clears the claim and moves ``next_run`` forward a week.

    ``next_run`` advances **on failure too**. A failing backup that kept its slot
    would retry every poll interval, which turns one broken backup into a machine
    that writes and deletes archives every five minutes. One attempt per week,
    with the failure visible on the Admin page, is the right cadence.

    The new slot is computed from ``max(now, stored next_run)`` so an instance
    that was down for weeks lands on a future slot rather than a past one, which
    is what makes the catch-up in run_scheduled_backup() fire once and not once
    per poll.
    """
    try:
        with pymongo.timeout(_MONGO_TIMEOUT_SECONDS):
            collection = _collection()
            document = collection.find_one({"_id": SCHEDULE_DOCUMENT_ID}) or {}
            settings = settings_from_document(document)

            reference = now
            stored = document.get("next_run")
            if isinstance(stored, datetime):
                if stored.tzinfo is None:
                    stored = stored.replace(tzinfo=timezone.utc)
                reference = max(now, stored)

            updates = {
                "claimed_by": None,
                "claimed_at": None,
                "last_run_finished": now,
                "last_result": result,
                "last_error": str(error)[:_MAX_ERROR_LENGTH] if error else None,
                "next_run": next_run_after(
                    reference, settings["day_of_week"], settings["hour"]
                ),
                "updated": now,
            }
            if backup_path:
                updates["last_backup_path"] = backup_path

            collection.update_one({"_id": SCHEDULE_DOCUMENT_ID}, {"$set": updates})
    except Exception as e:
        # The lease is the backstop: an unreleased claim expires and the run is
        # retried by whoever next polls.
        logging.warning(f"Could not record the weekly backup outcome: {e}")


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


def _dated_entries(paths):
    """
    Returns [(mtime, name, path)] sorted oldest first.

    Sorted by mtime rather than by the timestamp in the name, even though that
    name format does sort lexicographically. The names come from
    ``str(datetime.now())``, which is naive *local* time: at the end of DST a
    genuinely newer directory gets a name that sorts earlier, and pruning by name
    would then delete the newest backup. mtime cannot lie about ordering, and it
    also keeps working for operator-copied files and any future name change. The
    name is only a tiebreaker, so equal mtimes still prune deterministically.
    """
    dated = []
    for path in paths:
        try:
            dated.append((os.path.getmtime(path), os.path.basename(path), path))
        except OSError:
            # Vanished between listing and stat, or unreadable. Not ours to prune.
            continue
    dated.sort()
    return dated


def _prune_entries(paths, keep, remover):
    """
    Removes all but the ``keep`` newest entries. Returns the count removed.

    ``keep`` is a count, not the retention setting: ``keep=0`` removes
    everything, and a negative value is a no-op. Whether pruning happens at all
    is the caller's decision -- run_scheduled_backup() makes it, from the stored
    retention.

    Per-entry try/except and a never-raise contract, like
    sweep_legacy_user_files(): housekeeping must not be able to fail a backup
    that already succeeded.
    """
    if keep < 0:
        return 0

    dated = _dated_entries(paths)
    doomed = dated[: len(dated) - keep] if keep else dated
    removed = 0
    for _, _, path in doomed:
        try:
            remover(path)
            removed += 1
            logging.info(f" |--> Pruned {path}")
        except OSError as e:
            logging.warning(f" |--X Could not prune {path}: {e}")
    return removed


def _contained_in(path, parent):
    """True if ``path`` really sits inside ``parent`` after resolving symlinks.

    Guards the rmtree below: a symlinked dump directory must not be able to
    redirect a recursive delete somewhere else.
    """
    resolved_parent = os.path.realpath(parent)
    resolved = os.path.realpath(path)
    return os.path.commonpath([resolved_parent, resolved]) == resolved_parent


def _dump_dirs():
    """Timestamped dump directories, ignoring stray files."""
    try:
        names = os.listdir(_MONGO_DUMP_DIR)
    except OSError:
        return []
    paths = [os.path.join(_MONGO_DUMP_DIR, name) for name in names]
    return [p for p in paths if os.path.isdir(p)]


def _backup_zips():
    """
    Full-backup archives.

    endswith(".zip"), deliberately not list_full_backups()'s ``".zip" in file``:
    that also matches names like ``notes.zip.bak``, and this function deletes
    what it matches.
    """
    try:
        names = os.listdir(_BACKUP_DIR)
    except OSError:
        return []
    return [os.path.join(_BACKUP_DIR, name) for name in names if name.endswith(".zip")]


def _remove_dump_dir(path):
    if not _contained_in(path, _MONGO_DUMP_DIR):
        raise OSError(f"{path} resolves outside {_MONGO_DUMP_DIR}; refusing to remove")
    shutil.rmtree(path)


def prune_mongo_dumps(keep):
    """
    Keeps the ``keep`` newest dump directories. Returns the count removed.

    ``keep=0`` removes all of them, which is exactly what the weekly run wants
    with a retention of 1: clear the directory, then write this week's dump.
    """
    return _prune_entries(_dump_dirs(), keep, _remove_dump_dir)


def prune_backup_zips(keep):
    """Keeps the ``keep`` newest archives. Returns the count removed."""
    return _prune_entries(_backup_zips(), keep, os.remove)


def prune_preview(retention):
    """
    Counts what a prune at ``retention`` would remove, without removing anything.

    Exists for the Admin page: on an install that has never pruned -- and until
    now none had, since nothing in the app deleted a dump or a zip -- enabling
    the schedule can mean deleting hundreds of directories hours later in a
    background thread. Showing the number at the moment of consent turns that
    from a surprise into a decision.
    """
    if retention <= 0:
        return {"dumps": 0, "zips": 0}
    dumps = max(len(_dump_dirs()) - (retention - 1), 0)
    zips = max(len(_backup_zips()) - retention, 0)
    return {"dumps": dumps, "zips": zips}


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def run_scheduled_backup(now=None):
    """
    Runs the weekly backup if it is due and unclaimed.

    Returns:
        bool: True only if a backup was taken and succeeded

    Catch-up is a side effect of ``next_run`` being an absolute timestamp
    compared with ``$lte``: an instance down for three weeks finds one overdue
    slot, backs up once, and jumps to the next future slot. Three identical
    stale backups in a row would be pure waste.

    Dumps are pruned to ``retention - 1`` *before* the dump runs, and archives to
    ``retention`` *after* the zip is in place. The order is load-bearing in both
    halves: every zip re-archives whatever is in data/mongo_dumps, so pruning
    dumps first is what actually bounds the new archive's size (and the fresh
    dump then brings the count to exactly ``retention``); pruning archives last
    means a failed backup does not leave the set one short.
    """
    now = now or datetime.now(timezone.utc)

    # The lease has to be known before claiming; retention is taken from the
    # claimed document afterwards, so a value saved on the Admin page seconds
    # earlier is the one that applies.
    lease_seconds = settings_from_document(read_schedule())["lease_seconds"]

    document = _claim_run(now, lease_seconds)
    if document is None:
        return False

    retention = settings_from_document(document)["retention"]
    logging.info(f"Starting the weekly backup as <{_worker_id()}>.")

    try:
        if retention:
            preview = prune_preview(retention)
            if preview["dumps"] or preview["zips"]:
                logging.info(
                    f"Retention {retention}: pruning {preview['dumps']} MongoDB "
                    f"dump(s) and {preview['zips']} archive(s)."
                )
            prune_mongo_dumps(retention - 1)

        backup_path = data_file_functions.perform_full_backup(actor="scheduler")

        if retention:
            prune_backup_zips(retention)

        _release_run(datetime.now(timezone.utc), "success", backup_path=backup_path)
        logging.info(f"Weekly backup finished: {backup_path}")
        return True
    except Exception as e:
        logging.error(f"Weekly backup failed: {e}")
        _release_run(datetime.now(timezone.utc), "failed", error=e)
        return False


# ---------------------------------------------------------------------------
# Thread
# ---------------------------------------------------------------------------


def _scheduler_loop(stop_event, poll_seconds=None):
    """
    Polls until stopped.

    ``stop_event.wait(poll)`` rather than time.sleep(poll) so shutdown is
    immediate instead of up to a poll interval late. The body catches everything:
    run_scheduled_backup() is already defensive, but a loop that can die silently
    would leave an app that looks fine and never backs up again.

    The interval is re-read from the schedule document after each pass, so it is
    stored configuration like everything else rather than something fixed at
    thread start. ``poll_seconds`` is only an override for tests.
    """
    fixed_poll = poll_seconds
    poll = fixed_poll or settings_from_document(read_schedule())["poll_seconds"]

    logging.info(
        f"Backup scheduler thread started as <{_worker_id()}>, polling every {poll}s."
    )
    while not stop_event.wait(poll):
        try:
            run_scheduled_backup()
        except Exception as e:
            logging.error(f"Backup scheduler poll failed: {e}")
        if fixed_poll is None:
            poll = settings_from_document(read_schedule())["poll_seconds"]
    logging.info("Backup scheduler thread stopped.")


def start_backup_scheduler():
    """
    Seeds the schedule document and starts the polling thread.

    Returns:
        threading.Thread: the running thread, or None if it could not start

    Called from app.py's ``__main__`` only -- never at module scope, which would
    start a thread in every pytest run and in any WSGI import of app.

    The thread starts whether or not the schedule is enabled: ``enabled`` is
    enforced in the claim filter, so the Admin Settings toggle can turn the
    schedule on without a restart.

    ensure_schedule_document() runs here, synchronously, on the main thread. That
    surfaces an unreachable database in the startup log rather than in a thread
    nobody is watching, and it warms data_file_functions' shared client global,
    which is assigned without a lock -- so the thread cannot race a request into
    building a second client.
    """
    global _thread, _stop_event

    if _thread is not None and _thread.is_alive():
        logging.debug("Backup scheduler already running.")
        return _thread

    document = ensure_schedule_document()
    if document is None:
        logging.warning(
            "Backup scheduler not started: the schedule document is unavailable. "
            "It will be retried on the next start."
        )
        return None

    settings = settings_from_document(document)

    _stop_event = threading.Event()
    _thread = threading.Thread(
        target=_scheduler_loop,
        args=(_stop_event,),
        name="fwgui-backup-scheduler",
        daemon=True,
    )
    _thread.start()
    atexit.register(stop_backup_scheduler)

    if settings["enabled"]:
        logging.info(
            f"Automatic weekly backup is enabled: {_DAY_NAMES[settings['day_of_week']]}"
            f" at {settings['hour']:02d}:00 UTC, keeping "
            f"{settings['retention']} archive(s)."
        )
    else:
        logging.info(
            "Automatic weekly backup is disabled. Enable it on the Admin Settings "
            "page."
        )

    return _thread


def stop_backup_scheduler(timeout=5):
    """
    Signals the thread to stop and waits briefly for it.

    The wait is deliberately short and the thread is a daemon: a backup can take
    minutes, and a container SIGTERM must not block on a zip. Worst case the
    process exits mid-backup, the claim goes stale, and the lease lets the next
    start retry the same window.
    """
    global _thread, _stop_event

    if _stop_event is not None:
        _stop_event.set()
    if _thread is not None and _thread.is_alive():
        _thread.join(timeout=timeout)
    _thread = None
    _stop_event = None
