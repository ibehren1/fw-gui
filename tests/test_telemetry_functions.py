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
def test_post_telemetry_success(mock_request, real_telemetry_send):
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
def test_post_telemetry_exception(mock_request, real_telemetry_send):
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


def test_post_telemetry_runs_off_the_calling_thread(real_telemetry_send):
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


# ---------------------------------------------------------------------------
# The suite never posts telemetry (tests/conftest.py no_real_telemetry)
# ---------------------------------------------------------------------------


def _counter_calls_in_foreground(monkeypatch):
    """Runs the three counters with post_telemetry(background=False)."""
    real_post = telemetry_functions.post_telemetry
    monkeypatch.setattr(
        telemetry_functions,
        "post_telemetry",
        lambda body, route, background=True: real_post(body, route, background=False),
    )
    telemetry_commit()
    telemetry_diff()
    telemetry_rule_usage()


def _spy_on_http(monkeypatch):
    """Records any request that gets as far as an urllib3 connection pool."""
    import urllib3

    sent = []
    monkeypatch.setattr(
        urllib3.connectionpool.HTTPConnectionPool,
        "urlopen",
        lambda self, method, url, *a, **k: sent.append((self.host, method, url)),
    )
    return sent


def test_counters_make_no_http_request(monkeypatch, no_real_telemetry):
    """Regression: commit/diff/rule-usage counters reached telemetry.fw-gui.com
    from every local test run, as a new install each time."""
    sent = _spy_on_http(monkeypatch)
    before = list(no_real_telemetry)

    _counter_calls_in_foreground(monkeypatch)

    assert sent == []
    assert no_real_telemetry == before


def test_guard_stops_a_path_that_skips_the_send_stub(
    monkeypatch, no_real_telemetry, real_telemetry_send
):
    """With the real _send (as a future code path might use), the urllib3
    guard refuses and records the attempt; nothing reaches a socket."""
    sent = _spy_on_http(monkeypatch)
    before = len(no_real_telemetry)

    _counter_calls_in_foreground(monkeypatch)

    assert sent == []
    routes = [url.rsplit("/", 1)[1] for _, url in no_real_telemetry[before:]]
    assert routes == ["commit", "diff", "rule_usage"]
    del no_real_telemetry[before:]


def test_guard_fails_loudly_for_a_direct_telemetry_request(no_real_telemetry):
    import urllib3
    import pytest

    before = len(no_real_telemetry)
    with pytest.raises(AssertionError, match="tried to post telemetry"):
        urllib3.request("POST", "https://telemetry.fw-gui.com/commit", body="{}")
    assert no_real_telemetry[before:] == [("POST", "https://telemetry.fw-gui.com/commit")]
    del no_real_telemetry[before:]
    with pytest.raises(RuntimeError, match="network access is blocked"):
        urllib3.request("GET", "https://example.com/")
