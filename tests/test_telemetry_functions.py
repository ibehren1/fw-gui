"""Tests for package/telemetry_functions.py"""

import json
from unittest.mock import Mock, patch, mock_open

from package.telemetry_functions import (
    get_instance_id,
    get_version,
    post_telemetry,
    telemetry_commit,
    telemetry_diff,
    telemetry_instance,
    telemetry_rule_usage,
)


def test_get_instance_id():
    """Delegates to package.instance_id, which owns the MongoDB lookup."""
    with patch(
        "package.telemetry_functions.get_or_create_instance_id",
        return_value="test-uuid-1234",
    ):
        assert get_instance_id() == "test-uuid-1234"


def test_get_instance_id_unavailable():
    with patch(
        "package.telemetry_functions.get_or_create_instance_id", return_value=""
    ):
        assert get_instance_id() == ""


def test_telemetry_calls_never_raise_on_instance_id_failure(monkeypatch):
    """The property that matters: telemetry must not break a firewall push.

    telemetry_commit/telemetry_diff are called from napalm_ssh_functions outside
    the try blocks that guard the push, so an exception from the instance-id
    lookup would turn a telemetry call into a failed commit.
    """
    from package import instance_id as instance_id_module

    monkeypatch.delenv(instance_id_module.INSTANCE_ID_ENV_VAR, raising=False)
    monkeypatch.setattr(instance_id_module, "_instance_id", None)
    monkeypatch.setattr(
        instance_id_module.data_file_functions,
        "_get_mongo_db",
        Mock(side_effect=Exception("MongoDB is down")),
    )

    with patch("package.telemetry_functions.post_telemetry") as mock_post, patch(
        "package.telemetry_functions.get_version", return_value="1.0.0"
    ):
        # None of these may raise.
        telemetry_commit()
        telemetry_diff()
        telemetry_rule_usage()
        telemetry_instance()

    assert mock_post.call_count == 4
    # An unavailable id is posted as empty rather than withheld.
    assert json.loads(mock_post.call_args_list[0][0][0])["instance_id"] == ""


def test_get_version():
    with patch("builtins.open", mock_open(read_data="v2.1.0")):
        result = get_version()
        assert result == "2.1.0"


def test_get_version_strips_v_prefix():
    with patch("builtins.open", mock_open(read_data="v1.0.0")):
        result = get_version()
        assert "v" not in result


@patch("package.telemetry_functions.urllib3.request")
def test_post_telemetry_success(mock_request):
    body = json.dumps({"instance_id": "test-uuid"})
    post_telemetry(body, "instance", background=False)

    mock_request.assert_called_once_with(
        "POST",
        "https://telemetry.fw-gui.com/instance",
        headers={"Content-Type": "application/json"},
        body=body,
        timeout=5.0,
    )


@patch("package.telemetry_functions.urllib3.request")
def test_post_telemetry_exception(mock_request):
    mock_request.side_effect = Exception("Network error")
    body = json.dumps({"instance_id": "test-uuid"})

    # Should not raise
    post_telemetry(body, "instance", background=False)


@patch("package.telemetry_functions.post_telemetry")
@patch("package.telemetry_functions.get_instance_id", return_value="test-uuid")
def test_telemetry_commit(mock_id, mock_post):
    telemetry_commit()

    mock_post.assert_called_once()
    body = json.loads(mock_post.call_args[0][0])
    assert body["instance_id"] == "test-uuid"
    assert mock_post.call_args[0][1] == "commit"


@patch("package.telemetry_functions.post_telemetry")
@patch("package.telemetry_functions.get_instance_id", return_value="test-uuid")
def test_telemetry_diff(mock_id, mock_post):
    telemetry_diff()

    mock_post.assert_called_once()
    body = json.loads(mock_post.call_args[0][0])
    assert body["instance_id"] == "test-uuid"
    assert mock_post.call_args[0][1] == "diff"


@patch("package.telemetry_functions.post_telemetry")
@patch("package.telemetry_functions.get_instance_id", return_value="test-uuid")
@patch("package.telemetry_functions.get_version", return_value="2.1.0")
def test_telemetry_instance(mock_ver, mock_id, mock_post):
    telemetry_instance()

    mock_post.assert_called_once()
    body = json.loads(mock_post.call_args[0][0])
    assert body["instance_id"] == "test-uuid"
    assert body["version"] == "2.1.0"
    assert mock_post.call_args[0][1] == "instance"


@patch("package.telemetry_functions.post_telemetry")
@patch("package.telemetry_functions.get_instance_id", return_value="test-uuid")
def test_telemetry_rule_usage(mock_id, mock_post):
    telemetry_rule_usage()

    mock_post.assert_called_once()
    body = json.loads(mock_post.call_args[0][0])
    assert body["instance_id"] == "test-uuid"
    assert mock_post.call_args[0][1] == "rule_usage"


# ---------------------------------------------------------------------------
# Background posting and the daily heartbeat
# ---------------------------------------------------------------------------

import threading  # noqa: E402

from package import telemetry_functions  # noqa: E402


def test_post_telemetry_runs_off_the_calling_thread():
    started = threading.Event()
    release = threading.Event()

    def slow_request(*args, **kwargs):
        started.set()
        release.wait(5)

    with patch("package.telemetry_functions.urllib3.request", side_effect=slow_request):
        thread = post_telemetry("{}", "instance")
        # The caller is back while the request is still in flight.
        assert started.wait(2)
        assert thread.is_alive() and thread.daemon
        release.set()
        thread.join(2)
    assert not thread.is_alive()


def test_heartbeat_posts_heartbeat_events(monkeypatch):
    sent = []
    done = threading.Event()

    def record(event="login"):
        sent.append(event)
        if len(sent) >= 2:
            done.set()

    monkeypatch.setattr(telemetry_functions, "_heartbeat_delay", lambda: 0.01)
    monkeypatch.setattr(telemetry_functions, "telemetry_instance", record)
    thread = telemetry_functions.start_telemetry_heartbeat()
    try:
        assert done.wait(2)
        assert set(sent) == {"heartbeat"}
        # Idempotent: a second start returns the running thread.
        assert telemetry_functions.start_telemetry_heartbeat() is thread
    finally:
        telemetry_functions.stop_telemetry_heartbeat()
        thread.join(2)
    assert not thread.is_alive()


def test_heartbeat_survives_a_failing_check_in(monkeypatch):
    calls = []
    done = threading.Event()

    def flaky(event="login"):
        calls.append(event)
        if len(calls) >= 2:
            done.set()
        raise RuntimeError("telemetry server down")

    monkeypatch.setattr(telemetry_functions, "_heartbeat_delay", lambda: 0.01)
    monkeypatch.setattr(telemetry_functions, "telemetry_instance", flaky)
    thread = telemetry_functions.start_telemetry_heartbeat()
    try:
        assert done.wait(2)
    finally:
        telemetry_functions.stop_telemetry_heartbeat()
        thread.join(2)


def test_heartbeat_delay_is_about_a_day():
    for _ in range(20):
        delay = telemetry_functions._heartbeat_delay()
        assert telemetry_functions.HEARTBEAT_SECONDS <= delay < telemetry_functions.HEARTBEAT_SECONDS + 3600
