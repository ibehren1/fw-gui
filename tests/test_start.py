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


# ---------------------------------------------------------------------------
# Quick start
# ---------------------------------------------------------------------------

from package.start_functions import build_quick_start  # noqa: E402

CHAINS = {"WAN_IN": "drop", "WAN_LOCAL": "drop", "LAN_IN": "accept",
          "LAN_OUT": "accept", "LAN_LOCAL": "accept"}


def test_quick_start_structure():
    data = build_quick_start("eth0", "eth1")
    assert [i["name"] for i in data["interfaces"]] == ["eth0", "eth1"]
    assert [i["type"] for i in data["interfaces"]] == ["public_wan", "lan"]
    for ip_version in ("ipv4", "ipv6"):
        chains = data[ip_version]["chains"]
        assert {n: c["default"]["default_action"] for n, c in chains.items()} == CHAINS
        for chain in chains.values():
            assert all(n in chain for n in chain["rule-order"])
        jumps = {(r["fw_chain"], r["interface"], r["direction"])
                 for f in data[ip_version]["filters"].values() for r in f["rules"].values()}
        assert jumps == {("WAN_LOCAL", "eth0", "inbound"), ("LAN_LOCAL", "eth1", "inbound"),
                         ("WAN_IN", "eth0", "inbound"), ("LAN_IN", "eth1", "inbound"),
                         ("LAN_OUT", "eth1", "outbound")}
        assert set(data[ip_version]["filters"]["input"]["rules"][r]["fw_chain"]
                   for r in data[ip_version]["filters"]["input"]["rule-order"]) == {"WAN_LOCAL", "LAN_LOCAL"}


def test_quick_start_wan_blocks_new_inbound():
    data = build_quick_start("eth0", "eth1")
    for chain in ("WAN_IN", "WAN_LOCAL"):
        rules = [data["ipv4"]["chains"][chain][n] for n in data["ipv4"]["chains"][chain]["rule-order"]]
        # Only return traffic is accepted; everything else falls to drop.
        assert all(r["action"] == "drop" or (r.get("state_est") and r.get("state_rel")) for r in rules)


def test_quick_start_ping_option_is_ipv4_only():
    off = build_quick_start("eth0", "eth1")["ipv4"]["chains"]["WAN_LOCAL"]
    on = build_quick_start("eth0", "eth1", allow_wan_ping=True)["ipv4"]["chains"]["WAN_LOCAL"]
    assert not any(off[n]["protocol"] == "icmp" for n in off["rule-order"])
    assert [on[n]["protocol"] for n in on["rule-order"]].count("icmp") == 1
    v6 = build_quick_start("eth0", "eth1")["ipv6"]["chains"]["WAN_LOCAL"]
    v6_rules = [v6[n] for n in v6["rule-order"]]
    assert any(r["protocol"] == "icmp" for r in v6_rules)
    assert any(r["protocol"] == "udp" and r["dest_port"] == "546" for r in v6_rules)


def test_quick_start_generates_expected_vyos_config(mock_session, monkeypatch):
    from package.generate_config import generate_config

    data = build_quick_start("eth0", "eth1")
    monkeypatch.setattr("package.generate_config.read_user_data_file", lambda *a, **k: data)
    _, config = generate_config(mock_session)
    text = "\n".join(config) if isinstance(config, list) else str(config)
    for line in [
        "set firewall ipv4 name WAN_IN default-action 'drop'",
        "set firewall ipv4 name LAN_LOCAL default-action 'accept'",
        "set firewall ipv4 input filter rule 10 inbound-interface name 'eth0'",
        "set firewall ipv4 input filter rule 10 jump-target 'WAN_LOCAL'",
        "set firewall ipv4 forward filter rule 30 outbound-interface name 'eth1'",
        "set firewall ipv4 forward filter rule 30 jump-target 'LAN_OUT'",
        "set firewall ipv6 name WAN_LOCAL rule 30 protocol 'ipv6-icmp'",
        "set firewall ipv6 name WAN_LOCAL rule 40 destination port '546'",
    ]:
        assert line in text, line


def _quick(client, existing=(), **form):
    data = {"config_name": "starter", "wan_interface": "eth0", "lan_interface": "eth1",
            "accept_responsibility": "true"}
    data.update(form)
    with patch("app.list_user_files", return_value=list(existing)), \
            patch("app.write_user_data_file") as write:
        resp = client.post("/quick_start", data=data)
    return resp, write


def test_quick_start_route_creates_and_selects(auth_client):
    resp, write = _quick(auth_client, allow_wan_ping="true")
    assert resp.headers["Location"].endswith("/start")
    path, data = write.call_args[0]
    assert path == "data/testuser/starter"
    wan_local = data["ipv4"]["chains"]["WAN_LOCAL"]
    assert any(wan_local[n]["protocol"] == "icmp" for n in wan_local["rule-order"])
    with auth_client.session_transaction() as sess:
        assert sess["firewall_name"] == "starter"
        sess["firewall_name"] = "test_firewall"


import pytest  # noqa: E402


@pytest.mark.parametrize("form, existing", [
    ({"config_name": ""}, ()),
    ({"config_name": "../x"}, ()),
    ({}, ("starter",)),
    ({"wan_interface": "eth 0"}, ()),
    ({"lan_interface": "a" * 16}, ()),
    ({"lan_interface": "eth0"}, ()),
])
def test_quick_start_route_rejects_bad_input(auth_client, form, existing):
    resp, write = _quick(auth_client, existing, **form)
    assert resp.status_code == 302
    write.assert_not_called()
    with auth_client.session_transaction() as sess:
        assert sess["firewall_name"] == "test_firewall"


def test_quick_start_requires_accepting_responsibility(auth_client):
    with patch("app.list_user_files", return_value=[]), patch("app.write_user_data_file") as write:
        auth_client.post("/quick_start", data={
            "config_name": "starter", "wan_interface": "eth0", "lan_interface": "eth1"})
    write.assert_not_called()


def test_responsibility_statement_shown(auth_client):
    body = _get(auth_client).get_data(as_text=True)
    assert 'name="accept_responsibility"' in body and "required" in body.split('name="accept_responsibility"', 1)[1][:40]
    assert "Responsibility for firewall configurations." in body
    assert "assume all risk" in body
