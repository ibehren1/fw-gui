"""
Route tests for /import_config: importing a running firewall's configuration.
"""

import io
import json
from pathlib import Path
from unittest.mock import Mock, patch

import paramiko
import pytest

from package import data_file_functions
from package.config_import import MAX_IMPORT_BYTES, ConfigImportError

FIXTURES = Path(__file__).parent / "fixtures" / "import"
NAME = "imported_fw"


def _full_config():
    return json.dumps({
        "firewall": json.loads((FIXTURES / "firewall.json").read_text()),
        "interfaces": json.loads((FIXTURES / "interfaces.json").read_text()),
    })


@pytest.fixture
def stored(auth_client):
    """The imported document as written to (mongomock) MongoDB."""
    collection = data_file_functions._get_mongo_db()["testuser"]
    collection.delete_one({"_id": NAME})
    yield lambda: collection.find_one({"_id": NAME})
    collection.delete_one({"_id": NAME})
    with auth_client.session_transaction() as sess:
        sess["firewall_name"] = "test_firewall"


def _post(client, existing=(), **form):
    data = {"config_name": NAME, "source": "text"}
    data.update(form)
    with patch("app.list_user_files", return_value=list(existing)):
        return client.post("/import_config", data=data, content_type="multipart/form-data")


def test_paste_creates_selects_and_reports(auth_client, stored):
    resp = _post(auth_client, config_json=_full_config())

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Import report" in body
    assert "sends exactly the firewall" in body
    assert "global-options all-ping" in body

    doc = stored()
    assert doc["origin"] == "import"
    assert doc["system"]["hostname"] == "None"
    assert len(doc["ipv4"]["chains"]) > 0
    assert len(doc["extra-items"]) == 3
    with auth_client.session_transaction() as sess:
        assert sess["firewall_name"] == NAME
        assert sess["hostname"] == "None"


def test_upload_file(auth_client, stored):
    resp = _post(auth_client, config_file=(io.BytesIO(_full_config().encode()), "fw.json"))
    assert resp.status_code == 200
    assert stored() is not None


@pytest.mark.parametrize("form, existing, message", [
    ({"config_name": ""}, (), "valid configuration name"),
    ({"config_name": "../x"}, (), "valid configuration name"),
    ({}, (NAME,), "already exists"),
    ({"source": "other"}, (), "Choose where"),
    ({"config_json": ""}, (), "Paste or choose"),
    ({"config_json": "not json"}, (), "No JSON"),
    ({"config_json": '{"system": {}}'}, (), "No firewall configuration"),
    ({"config_json": "{" + " " * MAX_IMPORT_BYTES + "}"}, (), "too large"),
])
def test_rejected_input_writes_nothing(auth_client, stored, form, existing, message):
    form.setdefault("config_json", _full_config())
    resp = _post(auth_client, existing, **form)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/configurations#import")
    assert stored() is None
    with auth_client.session_transaction() as sess:
        assert message in str(sess["_flashes"])
        assert sess["firewall_name"] == "test_firewall"


def _ssh_form(**form):
    data = {"source": "ssh", "hostname": "192.0.2.1", "port": "2222",
            "username": "vyos", "password": "pw"}
    data.update(form)
    return data


def test_ssh_import_pins_probed_key(auth_client, stored):
    host_key = paramiko.RSAKey.generate(1024)
    with (
        patch("app.probe_host_key", return_value=host_key) as probe,
        patch("app.fetch_running_config", return_value=_full_config()) as fetch,
    ):
        resp = _post(auth_client, **_ssh_form(ssh_key_name="k1"))

    assert resp.status_code == 200
    probe.assert_called_once_with("192.0.2.1", "2222")
    connection_string, _, key = fetch.call_args.args
    assert connection_string == {"hostname": "192.0.2.1", "port": "2222",
                                 "username": "vyos", "password": "pw",
                                 "ssh_key_name": "k1"}
    assert key is host_key
    system = stored()["system"]
    assert system["hostname"] == "192.0.2.1"
    assert system["port"] == "2222"
    assert system["host_key"]["host"] == "192.0.2.1:2222"
    assert system["host_key"]["key"] == host_key.get_base64()
    with auth_client.session_transaction() as sess:
        assert sess["hostname"] == "192.0.2.1"


@pytest.mark.parametrize("form, message", [
    ({"hostname": ""}, "hostname or IP"),
    ({"hostname": "a b"}, "hostname or IP"),
    ({"port": "70000"}, "port from 1"),
    ({"port": "x"}, "port from 1"),
    ({"username": ""}, "username"),
])
def test_ssh_bad_fields_never_connect(auth_client, stored, form, message):
    with patch("app.probe_host_key") as probe:
        resp = _post(auth_client, **_ssh_form(**form))
    assert resp.status_code == 302
    probe.assert_not_called()
    assert stored() is None
    with auth_client.session_transaction() as sess:
        assert message in str(sess["_flashes"])


@pytest.mark.parametrize("probe, fetch, message", [
    (OSError("refused"), None, "Could not reach"),
    (None, paramiko.AuthenticationException("no"), "Could not log in"),
    (None, ConfigImportError("The device returned no configuration."), "returned no"),
])
def test_ssh_failures_write_nothing(auth_client, stored, probe, fetch, message):
    with (
        patch("app.probe_host_key", side_effect=probe, return_value=Mock()),
        patch("app.fetch_running_config", side_effect=fetch),
    ):
        resp = _post(auth_client, **_ssh_form())
    assert resp.status_code == 302
    assert stored() is None
    with auth_client.session_transaction() as sess:
        assert message in str(sess["_flashes"])


def test_requires_login(client):
    # flask_app holds one app context open for the session, so Flask-Login's
    # cached user (g._login_user) from earlier authenticated tests leaks in.
    from flask import g
    g.pop("_login_user", None)
    resp = client.post("/import_config", data={"config_name": NAME, "source": "text"})
    assert resp.status_code == 302
    assert "/user_login" in resp.headers["Location"]


def test_configurations_page_offers_import(auth_client):
    with patch("app.list_user_keys", return_value=["k1"]):
        body = auth_client.get("/configurations").get_data(as_text=True)
    assert 'id="import"' in body
    assert 'action="/import_config"' in body
    assert "SSH key: k1" in body


def test_start_page_links_to_import(auth_client):
    body = auth_client.get("/start").get_data(as_text=True)
    assert "/configurations#import" in body
