"""
Tests for package/telemetry_collect.py and the schema-2 /instance payload.

Covers: bucket, deployment detection, the configuration scan, feature flags,
        failure isolation, and build_instance_payload for each event
"""

import json
from unittest.mock import patch

import mongomock
import pytest

from package import telemetry_collect
from package.telemetry_collect import bucket


@pytest.mark.parametrize("count, label", [
    (None, None), (0, "0"), (1, "1"), (2, "2-5"), (5, "2-5"), (6, "6-20"),
    (20, "6-20"), (21, "21-100"), (100, "21-100"), (101, "101+"), (5000, "101+"),
])
def test_bucket(count, label):
    assert bucket(count) == label


def test_deployment_type(monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    assert telemetry_collect.deployment_type() == "kubernetes"
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST")
    with patch("package.telemetry_collect.os.path.exists", return_value=True):
        assert telemetry_collect.deployment_type() == "docker"
    with patch("package.telemetry_collect.os.path.exists", return_value=False):
        assert telemetry_collect.deployment_type() == "source"


@pytest.mark.parametrize("machine, arch", [("x86_64", "amd64"), ("aarch64", "arm64"),
                                           ("arm64", "arm64"), ("riscv64", "riscv64")])
def test_cpu_arch(machine, arch):
    with patch("package.telemetry_collect.platform.machine", return_value=machine):
        assert telemetry_collect.cpu_arch() == arch


@pytest.fixture
def db(monkeypatch):
    client = mongomock.MongoClient()
    monkeypatch.setattr("package.data_file_functions._mongo_client", client)
    monkeypatch.setattr("package.data_file_functions._get_mongo_client", lambda: client)
    monkeypatch.setenv("MONGODB_DATABASE", "telemetry_test")
    monkeypatch.delenv("MONGODB_USERS_COLLECTION", raising=False)
    monkeypatch.delenv("BUCKET_NAME", raising=False)
    monkeypatch.setenv("DISABLE_REGISTRATION", "True")
    d = client["telemetry_test"]
    d["users"].insert_many([{"_id": "alice", "theme": "light"}, {"_id": "bob"}])
    d["alice"].insert_many([
        {"_id": "edge", "origin": "quick_start",
         "interfaces": [{"name": "eth0", "type": "public_wan"}],
         "flowtables": [{"name": "FT"}],
         "ipv4": {"chains": {"WAN_IN": {"rule-order": ["10", "20"]}},
                  "filters": {"input": {"rule-order": ["10"]}}},
         "ipv6": {"chains": {"WAN_IN": {"rule-order": ["10"]}}}},
        # A snapshot: never counted.
        {"firewall": "edge", "snapshot": "s1", "ipv4": {"chains": {"X": {"rule-order": ["1"] * 50}}}},
    ])
    d["bob"].insert_one({"_id": "lab", "interfaces": [{"name": "eth0"}]})
    d["instance"].insert_one({"_id": "backup_schedule", "enabled": True})
    return d


def test_collect_usage(db):
    size, features = telemetry_collect.collect_usage()
    assert size == {"accounts": "2-5", "configs": "2-5", "rules": "2-5"}
    assert features == {
        "light_theme": True, "quick_start": True, "flowtables": True,
        "interface_types": True, "scheduled_backup": True, "s3_backup": False,
        "ssh_keys": False, "registration_open": False, "rolling_release": False,
        "config_import": False,
    }


def test_collect_usage_config_import(db):
    db["bob"].update_one({"_id": "lab"}, {"$set": {"origin": "import"}})
    assert telemetry_collect.collect_usage()[1]["config_import"] is True


def test_config_import_ignores_snapshots(db):
    db["bob"].insert_one({"firewall": "lab", "snapshot": "s1", "origin": "import"})
    assert telemetry_collect.collect_usage()[1]["config_import"] is False


def test_collect_usage_rolling_release(db):
    db["bob"].update_one(
        {"_id": "lab"},
        {"$set": {"system": {"vyos_release": {"rolling": True, "milestone": "2026-08"}}}},
    )
    assert telemetry_collect.collect_usage()[1]["rolling_release"] is True


def test_rolling_release_ignores_rolling_off_and_snapshots(db):
    db["bob"].update_one(
        {"_id": "lab"},
        {"$set": {"system": {"vyos_release": {"rolling": False, "milestone": "2026-08"}}}},
    )
    db["bob"].insert_one({"firewall": "lab", "snapshot": "s1",
                          "system": {"vyos_release": {"rolling": True}}})
    assert telemetry_collect.collect_usage()[1]["rolling_release"] is False


def test_collect_usage_never_reports_names(db):
    # Chains and filters are read only to count rule-order entries; no name,
    # interface or config identifier reaches the payload.
    size, features = telemetry_collect.collect_usage()
    payload = json.dumps({"size": size, "features": features})
    assert "WAN_IN" not in payload and "eth0" not in payload and "edge" not in payload


def test_collectors_fail_independently(monkeypatch):
    def boom():
        raise RuntimeError("MongoDB is down")
    monkeypatch.setattr("package.data_file_functions._get_mongo_db", boom)
    monkeypatch.setattr("package.data_file_functions._get_mongo_client", boom)
    monkeypatch.delenv("BUCKET_NAME", raising=False)
    size, features = telemetry_collect.collect_usage()
    assert size == {"accounts": None, "configs": None, "rules": None}
    assert features["light_theme"] is None and features["s3_backup"] is False
    dep = telemetry_collect.collect_deployment()
    assert dep["mongodb"] is None and dep["python"]


# ---------------------------------------------------------------------------
# build_instance_payload
# ---------------------------------------------------------------------------

from package.telemetry_functions import build_instance_payload  # noqa: E402


@pytest.fixture
def basics():
    with patch("package.telemetry_functions.get_instance_id", return_value="uuid-1"), \
            patch("package.telemetry_functions.get_version", return_value="4.0.49\n"):
        yield


def test_login_payload_is_minimal(basics):
    with patch("package.telemetry_collect.collect_usage") as usage:
        payload = build_instance_payload("login")
    usage.assert_not_called()
    assert payload == {"schema": 2, "instance_id": "uuid-1", "version": "4.0.49", "event": "login"}


@pytest.mark.parametrize("event", ["startup", "heartbeat"])
def test_full_payload_events(basics, event):
    with patch("package.telemetry_collect.collect_deployment", return_value={"type": "docker"}), \
            patch("package.telemetry_collect.collect_usage", return_value=({"configs": "1"}, {"flowtables": True})):
        payload = build_instance_payload(event)
    assert payload["event"] == event
    assert payload["deployment"] == {"type": "docker"}
    assert payload["size"] == {"configs": "1"}
    assert payload["features"] == {"flowtables": True}
    # Still readable by the original backend.
    assert payload["instance_id"] == "uuid-1" and payload["version"] == "4.0.49"


def test_full_payload_survives_collector_crash(basics):
    with patch("package.telemetry_collect.collect_deployment", side_effect=RuntimeError("x")):
        payload = build_instance_payload("startup")
    assert payload["instance_id"] == "uuid-1" and "deployment" not in payload
