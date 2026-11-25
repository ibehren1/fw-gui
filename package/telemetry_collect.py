"""
Telemetry collectors: what a FW-GUI install reports about itself.

Everything here is anonymous and coarse. Sizes are bucketed, never exact, and
features are yes/no flags. Nothing from a firewall configuration is ever read
out: rules are only counted, and no name, address, port, description,
credential or key leaves the install. See README.md, "Telemetry".

**Nothing in here may raise.** Each collector is wrapped, so one that fails
reports None and the rest still go out, and every MongoDB read is time-bounded.
Telemetry runs at startup and on a daily heartbeat (see telemetry_functions);
an exception or a long wait here would turn it into a problem for the app.
"""

import logging
import os
import platform

import pymongo

from package import data_file_functions

# Upper bound on any one MongoDB read made for telemetry.
_MONGO_TIMEOUT_SECONDS = 2

# Size buckets: (upper bound inclusive, label). Counts above the last bound
# report the overflow label.
_BUCKETS = ((0, "0"), (1, "1"), (5, "2-5"), (20, "6-20"), (100, "21-100"))
_BUCKET_OVERFLOW = "101+"

_ARCH_ALIASES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "armv7",
}


def bucket(count):
    """Maps an exact count to its coarse bucket label; None stays None."""
    if count is None:
        return None
    for upper, label in _BUCKETS:
        if count <= upper:
            return label
    return _BUCKET_OVERFLOW


def _safe(collector):
    """Runs a collector, returning None instead of raising."""
    try:
        with pymongo.timeout(_MONGO_TIMEOUT_SECONDS):
            return collector()
    except Exception as e:  # noqa: BLE001 -- telemetry must never break the app
        logging.debug(f"Telemetry collector {collector.__name__} failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------


def deployment_type():
    """kubernetes, docker, or source."""
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return "kubernetes"
    if os.path.exists("/.dockerenv"):
        return "docker"
    return "source"


def cpu_arch():
    machine = platform.machine().lower()
    return _ARCH_ALIASES.get(machine, machine or None)


def mongodb_version():
    """The MongoDB server's major.minor, e.g. "8.2".

    From server_info rather than the FCV check, which needs admin rights.
    """
    version = data_file_functions._get_mongo_client().server_info()["version"]
    major, minor = version.split(".")[:2]
    return f"{int(major)}.{int(minor)}"


def collect_deployment():
    return {
        "type": _safe(deployment_type),
        "arch": _safe(cpu_arch),
        "python": platform.python_version(),
        "mongodb": _safe(mongodb_version),
    }


# ---------------------------------------------------------------------------
# Size and feature use, from the configurations
# ---------------------------------------------------------------------------

# Only the fields counted below are read from each configuration.
_CONFIG_PROJECTION = {
    "ipv4.chains": 1,
    "ipv6.chains": 1,
    "ipv4.filters": 1,
    "ipv6.filters": 1,
    "flowtables": 1,
    "interfaces": 1,
    "origin": 1,
    "system.vyos_release.rolling": 1,
}


def _current_configs():
    """Yields every user's working-copy configurations (snapshots excluded)."""
    from package import user_store

    db = data_file_functions._get_mongo_db()
    query = {"firewall": {"$exists": False}, "snapshot": {"$exists": False}}
    for username in user_store.list_usernames():
        yield from db[username].find(query, _CONFIG_PROJECTION)


def _scan_configs():
    """One pass over the configurations for everything telemetry counts."""
    totals = {"configs": 0, "rules": 0, "flowtables": False,
              "interface_types": False, "quick_start": False,
              "rolling_release": False}
    for config in _current_configs():
        totals["configs"] += 1
        for ip_version in ("ipv4", "ipv6"):
            version = config.get(ip_version) or {}
            for chain in (version.get("chains") or {}).values():
                totals["rules"] += len(chain.get("rule-order") or [])
            for filt in (version.get("filters") or {}).values():
                totals["rules"] += len(filt.get("rule-order") or [])
        if config.get("flowtables"):
            totals["flowtables"] = True
        if any(i.get("type") for i in config.get("interfaces") or []):
            totals["interface_types"] = True
        if config.get("origin") == "quick_start":
            totals["quick_start"] = True
        if ((config.get("system") or {}).get("vyos_release") or {}).get("rolling"):
            totals["rolling_release"] = True
    return totals


def _account_count():
    from package import user_store

    return user_store.count_users()["total"]


def _any_light_theme():
    from package import user_store

    return user_store.collection().find_one({"theme": "light"}, {"_id": 1}) is not None


def _scheduled_backup_on():
    from package import backup_scheduler

    doc = backup_scheduler._collection().find_one(
        {"_id": backup_scheduler.SCHEDULE_DOCUMENT_ID}, {"enabled": 1}
    )
    return bool(doc and doc.get("enabled"))


def _ssh_keys_stored():
    from package import ssh_key_store

    return ssh_key_store.collection().find_one({}, {"_id": 1}) is not None


def _registration_open():
    # Same parsing as app.registration_enabled().
    return os.environ.get("DISABLE_REGISTRATION", "False").strip().lower() not in (
        "true", "1", "yes",
    )


def collect_usage():
    """Returns (size, features) for the payload."""
    scan = _safe(_scan_configs) or {}
    size = {
        "accounts": bucket(_safe(_account_count)),
        "configs": bucket(scan.get("configs")),
        "rules": bucket(scan.get("rules")),
    }
    features = {
        "light_theme": _safe(_any_light_theme),
        "quick_start": scan.get("quick_start"),
        "flowtables": scan.get("flowtables"),
        "interface_types": scan.get("interface_types"),
        "rolling_release": scan.get("rolling_release"),
        "scheduled_backup": _safe(_scheduled_backup_on),
        "s3_backup": bool(os.environ.get("BUCKET_NAME")),
        "ssh_keys": _safe(_ssh_keys_stored),
        "registration_open": _registration_open(),
    }
    return size, features
