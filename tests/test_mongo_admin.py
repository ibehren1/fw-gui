"""
Tests for package/mongo_admin.py and the Admin Settings MongoDB card.

Covers: fcv_status states, and the card on /admin_settings
"""

from unittest.mock import patch

import pytest

from package import mongo_admin


class FakeAdmin:
    def __init__(self, fcv_doc, calls):
        self.fcv_doc = fcv_doc
        self.calls = calls

    def command(self, cmd):
        self.calls.append(cmd)
        if "getParameter" in cmd:
            return {"featureCompatibilityVersion": self.fcv_doc, "ok": 1}
        return {"ok": 1}


class FakeClient:
    def __init__(self, server, fcv_doc):
        self.server = server
        self.calls = []
        self.admin = FakeAdmin(fcv_doc, self.calls)

    def server_info(self):
        return {"version": self.server}


@pytest.fixture
def client(monkeypatch):
    def make(server, fcv_doc):
        c = FakeClient(server, fcv_doc)
        monkeypatch.setattr("package.data_file_functions._get_mongo_client", lambda: c)
        return c
    return make


@pytest.mark.parametrize("server, fcv_doc, state", [
    ("8.2.9", {"version": "8.2"}, "current"),
    ("8.0.4", {"version": "8.0"}, "current"),
    ("8.0.4", {"version": "7.0"}, "behind"),
    ("8.2.9", {"version": "8.0"}, "behind"),
    ("8.0.4", {"version": "7.0", "targetVersion": "8.0"}, "in_progress"),
    ("7.0.12", {"version": "8.0"}, "ahead"),
])
def test_fcv_status_states(client, server, fcv_doc, state):
    client(server, fcv_doc)
    s = mongo_admin.fcv_status()
    assert s["error"] is None
    assert s["state"] == state
    assert s["target"] == ".".join(server.split(".")[:2])


def test_fcv_status_never_raises(monkeypatch):
    def boom():
        raise NotImplementedError("no admin commands here")
    monkeypatch.setattr("package.data_file_functions._get_mongo_client", boom)
    assert mongo_admin.fcv_status() == {"error": "no admin commands here"}


def test_fcv_status_missing_fcv(client):
    client("8.0.1", {})
    assert "did not report" in mongo_admin.fcv_status()["error"]


def _admin_page(client_, status):
    with patch("app.fcv_status", return_value=status), \
            patch("app.list_user_files", return_value=[]), patch("app.list_snapshots", return_value=[]), \
            patch("app.list_full_backups", return_value=[]):
        return client_.get("/admin_settings").get_data(as_text=True)


def test_admin_card_current(auth_client):
    body = _admin_page(auth_client, {"server": "8.2.9", "fcv": "8.2", "target": "8.2",
                                     "in_progress": False, "transition_to": None,
                                     "state": "current", "error": None})
    assert 'id="mongodb"' in body and "8.2.9" in body
    assert "Ready for the next major" in body
    assert "docs/mongodb-upgrade.md" in body


def test_admin_card_behind(auth_client):
    body = _admin_page(auth_client, {"server": "8.0.4", "fcv": "7.0", "target": "8.0",
                                     "in_progress": False, "transition_to": None,
                                     "state": "behind", "error": None})
    assert "FCV behind server" in body
    assert "would leave it unable to start" in body


def test_admin_card_unavailable(auth_client):
    body = _admin_page(auth_client, {"error": "not authorized"})
    assert "MongoDB version information unavailable" in body and "not authorized" in body


# ---------------------------------------------------------------------------
# raise_fcv_to_server
# ---------------------------------------------------------------------------

def _set_calls(c):
    return [cmd for cmd in c.calls if "setFeatureCompatibilityVersion" in cmd]


def test_raise_when_behind_uses_confirm_on_7_plus(client):
    c = client("8.0.4", {"version": "7.0"})
    ok, msg = mongo_admin.raise_fcv_to_server()
    assert ok and "7.0 to 8.0" in msg
    assert _set_calls(c) == [{"setFeatureCompatibilityVersion": "8.0", "confirm": True}]


def test_raise_on_6_omits_confirm(client):
    c = client("6.0.14", {"version": "5.0"})
    ok, _ = mongo_admin.raise_fcv_to_server()
    assert ok
    assert _set_calls(c) == [{"setFeatureCompatibilityVersion": "6.0"}]


def test_raise_completes_interrupted_upgrade(client):
    c = client("8.0.4", {"version": "7.0", "targetVersion": "8.0"})
    ok, _ = mongo_admin.raise_fcv_to_server()
    assert ok and _set_calls(c)[0]["setFeatureCompatibilityVersion"] == "8.0"


def test_raise_refuses_interrupted_downgrade(client):
    c = client("8.0.4", {"version": "8.0", "targetVersion": "7.0"})
    ok, msg = mongo_admin.raise_fcv_to_server()
    assert not ok and "downgrade" in msg
    assert _set_calls(c) == []


@pytest.mark.parametrize("server, fcv", [("8.2.9", "8.2"), ("7.0.1", "8.0")])
def test_raise_does_nothing_when_current_or_ahead(client, server, fcv):
    c = client(server, {"version": fcv})
    ok, _ = mongo_admin.raise_fcv_to_server()
    assert not ok and _set_calls(c) == []


def test_raise_reports_mongo_refusal(client):
    class Refused(Exception):
        details = {"errmsg": "not authorized on admin to execute command"}

    c = client("8.0.4", {"version": "7.0"})
    real = c.admin.command

    def command(cmd):
        if "setFeatureCompatibilityVersion" in cmd:
            raise Refused("refused")
        return real(cmd)
    c.admin.command = command
    ok, msg = mongo_admin.raise_fcv_to_server()
    assert not ok and "not authorized" in msg


# ---------------------------------------------------------------------------
# Admin route
# ---------------------------------------------------------------------------

BEHIND = {"server": "8.0.4", "fcv": "7.0", "target": "8.0", "in_progress": False,
          "transition_to": None, "state": "behind", "error": None}


def _post(client_, form, backup=None):
    with patch("app.fcv_status", return_value=BEHIND), \
            patch("app.raise_fcv_to_server", return_value=(True, "raised")) as raise_, \
            patch("app.perform_full_backup", side_effect=backup, return_value="data/backups/x.zip") as backup_, \
            patch("app.list_user_files", return_value=[]), patch("app.list_snapshots", return_value=[]), \
            patch("app.list_full_backups", return_value=[]):
        body = client_.post("/admin_settings", data=dict(form, fcv_form="raise")).get_data(as_text=True)
    return body, raise_, backup_


def test_form_offered_when_behind(auth_client):
    body = _admin_page(auth_client, BEHIND)
    assert 'name="fcv_form"' in body and "Raise feature compatibility version to 8.0" in body
    assert 'name="fcv_backup" value="true" checked' in body


def test_form_not_offered_when_current(auth_client):
    body = _admin_page(auth_client, dict(BEHIND, fcv="8.0", state="current"))
    assert 'name="fcv_form"' not in body


def test_route_requires_confirmation(auth_client):
    body, raise_, backup_ = _post(auth_client, {"fcv_backup": "true"})
    raise_.assert_not_called(); backup_.assert_not_called()
    assert "Confirm the feature compatibility change" in body


def test_route_backs_up_then_raises(auth_client):
    body, raise_, backup_ = _post(auth_client, {"fcv_backup": "true", "fcv_confirm": "true"})
    backup_.assert_called_once(); raise_.assert_called_once()
    assert "raised" in body


def test_route_skips_backup_when_unchecked(auth_client):
    _, raise_, backup_ = _post(auth_client, {"fcv_confirm": "true"})
    backup_.assert_not_called(); raise_.assert_called_once()


def test_route_does_not_raise_if_backup_fails(auth_client):
    body, raise_, _ = _post(auth_client, {"fcv_backup": "true", "fcv_confirm": "true"},
                            backup=RuntimeError("disk full"))
    raise_.assert_not_called()
    assert "Backup failed, so the feature compatibility version was not changed." in body
