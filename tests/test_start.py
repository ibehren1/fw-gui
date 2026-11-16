"""
Tests for the Getting started page.

Covers: config_progress, /start, and the next=start return from selecting
        or creating a configuration
"""

from unittest.mock import patch

from package.start_functions import config_progress


def _data(monkeypatch, data):
    monkeypatch.setattr("package.start_functions.read_user_data_file", lambda *a, **k: data)


def test_config_progress_counts(mock_session, monkeypatch):
    _data(monkeypatch, {
        "interfaces": [{"name": "eth0"}, {"name": "eth1"}],
        "extra-items": ["set system host-name fw"],
        "system": {"hostname": "fw.example", "port": "22"},
        "ipv4": {
            "groups": {"A": {}, "B": {}},
            "chains": {"WAN_IN": {"rule-order": ["10", "20"]}},
            "filters": {"input": {"rule-order": ["10"]}},
        },
        "ipv6": {"chains": {"WAN_IN": {"rule-order": ["10"]}}},
    })
    assert config_progress(mock_session) == {
        "interfaces": 2, "groups": 2, "chains": 2, "chain_rules": 3,
        "filters": 1, "filter_rules": 1, "extra_items": 1, "hostname_set": True,
    }


def test_config_progress_empty_and_unset_hostname(mock_session, monkeypatch):
    _data(monkeypatch, {"system": {"hostname": "None", "port": "None"}})
    p = config_progress(mock_session)
    assert p["chains"] == 0 and p["interfaces"] == 0 and p["hostname_set"] is False


def _get(client, progress=None):
    with patch("app.list_user_files", return_value=["edge", "lab"]), \
            patch("app.config_progress", return_value=progress or {
                "interfaces": 2, "groups": 0, "chains": 1, "chain_rules": 3,
                "filters": 0, "filter_rules": 0, "extra_items": 0, "hostname_set": False}):
        return client.get("/start")


def test_start_page_lists_steps_in_order(auth_client):
    body = _get(auth_client).get_data(as_text=True)
    order = [body.index(f"<h4>{t}</h4>") for t in
             ("Interfaces", "Groups", "First chain", "First filter", "Extra configs", "Deploy")]
    assert order == sorted(order)
    assert body.count("step step-done") == 2  # interfaces and chains
    assert 'name="next" value="start"' in body
    assert 'action="/create_config"' in body


def test_start_page_without_selection(auth_client):
    with auth_client.session_transaction() as sess:
        sess.pop("firewall_name", None)
    try:
        body = _get(auth_client).get_data(as_text=True)
        assert "steps-locked" in body
        assert "select or create a configuration first" in body
    finally:
        with auth_client.session_transaction() as sess:
            sess["firewall_name"] = "test_firewall"


def test_create_config_returns_to_start(auth_client):
    with patch("app.write_user_data_file"):
        resp = auth_client.post("/create_config", data={"config_name": "new-fw", "next": "start"})
    assert resp.headers["Location"].endswith("/start")
    with auth_client.session_transaction() as sess:
        assert sess["firewall_name"] == "new-fw"
        sess["firewall_name"] = "test_firewall"


def test_create_config_without_next_goes_to_display(auth_client):
    with patch("app.write_user_data_file"):
        resp = auth_client.post("/create_config", data={"config_name": "new-fw"})
    assert resp.headers["Location"].endswith("/display_config")
    with auth_client.session_transaction() as sess:
        sess["firewall_name"] = "test_firewall"
