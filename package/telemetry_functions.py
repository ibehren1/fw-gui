"""
    Telemetry Functions to provide feedback on usage to the developer.

    Posts to telemetry.fw-gui.com:
    - instance check-ins (startup, login, daily heartbeat): the install's random
      UUID and FW-GUI version, plus, on startup and heartbeat, anonymous
      deployment details, bucketed sizes and feature flags (see
      telemetry_collect and README.md, "Telemetry")
    - a bare counter ping, with only the UUID, for each diff, commit and
      operational command

    Never sent: usernames, emails, configuration contents, addresses, hostnames,
    credentials or keys.
"""

import json
import logging
import secrets
import threading

import urllib3

from package.instance_id import get_or_create_instance_id


def get_instance_id():
    """Returns the install's telemetry id, or "" if unavailable.

    Thin delegate to package.instance_id, which stores the id in MongoDB as of
    3.0.0. Contract unchanged: this never raises. The callers below sit outside
    the try blocks that guard a firewall push, so an exception here would turn a
    telemetry lookup into a failed commit.
    """
    instance_id = get_or_create_instance_id()
    if not instance_id:
        logging.debug("No instance id available; telemetry degraded.")
    return instance_id


def get_version():
    try:
        with open(".version", "r") as f:
            local_version = f.read().replace("v", "")
            logging.debug(f"Local version: {local_version}")
    except OSError:
        return "0.0.0"

    return local_version


def post_telemetry(body, route, background=True):
    """Posts to the telemetry server. Never raises.

    By default the request runs on a short-lived daemon thread, so a slow or
    unreachable telemetry server never holds up a login or a commit. Returns
    the thread (or None when background=False, which tests use).
    """
    if not background:
        _send(body, route)
        return None
    thread = threading.Thread(target=_send, args=(body, route), name="telemetry-post", daemon=True)
    thread.start()
    return thread


def _send(body, route):
    try:
        urllib3.request(
            "POST",
            f"https://telemetry.fw-gui.com/{route}",
            headers={"Content-Type": "application/json"},
            body=body,
            timeout=5.0,
        )
        logging.debug("Posted instance ID and version to https://telemetry.fw-gui.com.")

    except Exception:
        logging.debug("Unable to post instance ID.")


def telemetry_commit():
    instance_id = get_instance_id()

    body = json.dumps({"instance_id": instance_id})

    post_telemetry(body, "commit")


def telemetry_diff():
    instance_id = get_instance_id()

    body = json.dumps({"instance_id": instance_id})

    post_telemetry(body, "diff")


# Payload format sent to /instance. The backend accepts this and the original
# {instance_id, version} form, which this still contains.
TELEMETRY_SCHEMA = 2

# Check-in events that carry the full payload. A login only says "still here",
# so it stays cheap: no configuration scan on every login.
_FULL_EVENTS = ("startup", "heartbeat")


def build_instance_payload(event):
    """Returns the /instance payload for a check-in event. Never raises."""
    payload = {
        "schema": TELEMETRY_SCHEMA,
        "instance_id": get_instance_id(),
        "version": get_version().replace("\n", ""),
        "event": event,
    }
    if event in _FULL_EVENTS:
        try:
            from package import telemetry_collect

            payload["deployment"] = telemetry_collect.collect_deployment()
            payload["size"], payload["features"] = telemetry_collect.collect_usage()
        except Exception as e:  # noqa: BLE001 -- send the basic check-in anyway
            logging.debug(f"Telemetry details unavailable: {e}")
    return payload


def telemetry_instance(event="login"):
    """Posts an instance check-in: event is "startup", "login" or "heartbeat"."""
    post_telemetry(json.dumps(build_instance_payload(event)), "instance")


def telemetry_rule_usage():
    instance_id = get_instance_id()

    body = json.dumps({"instance_id": instance_id})

    post_telemetry(body, "rule_usage")


# ---------------------------------------------------------------------------
# Daily heartbeat
# ---------------------------------------------------------------------------

HEARTBEAT_SECONDS = 24 * 60 * 60
# Spread heartbeats over an hour so restarted fleets don't all post at once.
_HEARTBEAT_JITTER_SECONDS = 60 * 60

_heartbeat_stop = threading.Event()
_heartbeat_thread = None


def _heartbeat_delay():
    return HEARTBEAT_SECONDS + secrets.randbelow(_HEARTBEAT_JITTER_SECONDS)


def _heartbeat_loop(stop):
    while not stop.wait(_heartbeat_delay()):
        try:
            telemetry_instance("heartbeat")
        except Exception as e:  # noqa: BLE001 -- the loop must survive anything
            logging.debug(f"Telemetry heartbeat failed: {e}")


def start_telemetry_heartbeat():
    """Starts the once-a-day check-in thread (idempotent).

    Startup already posts a check-in, so the first heartbeat comes about a day
    later. It keeps a long-running install that nobody logs into visible.
    """
    global _heartbeat_thread
    if _heartbeat_thread is not None and _heartbeat_thread.is_alive():
        return _heartbeat_thread
    _heartbeat_stop.clear()
    _heartbeat_thread = threading.Thread(
        target=_heartbeat_loop, args=(_heartbeat_stop,), name="telemetry-heartbeat", daemon=True
    )
    _heartbeat_thread.start()
    return _heartbeat_thread


def stop_telemetry_heartbeat():
    """Stops the heartbeat thread; for tests."""
    _heartbeat_stop.set()
