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
