"""
Tests for the one-section-at-a-time view tabs.

The views show a single section chosen by the URL hash, so every route that
edits a section has to redirect back with that section's anchor.

Covers: group_section_anchor, the tab markup in chain/filter/group views, and
        the anchored redirects of /chain_add, /chain_rule_delete, /filter_add,
        /filter_rule_delete, /group_add and /group_delete
"""

from unittest.mock import patch

import pytest

from package.group_funtions import group_section_anchor


@pytest.mark.parametrize(
    "group_type, ip_version, expected",
    [
        ("address-group", "ipv4", "ipv4-address"),
        ("address-group", "ipv6", "ipv6-address"),
        ("network-group", "ipv6", "ipv6-network"),
        ("port-group", "ipv4", "port"),
        ("mac-group", "ipv6", "mac"),
        ("domain-group", None, "domain"),
        ("address-group", None, None),
        ("interface-group", "ipv4", None),
        (None, "ipv4", None),
    ],
)
def test_group_section_anchor(group_type, ip_version, expected):
    assert group_section_anchor(group_type, ip_version) == expected


def _data():
    return {
        "version": "1",
        "ipv4": {
            "chains": {
                "WAN_LOCAL": {
                    "rule-order": ["10", "20"],
                    "default": {"default_action": "drop", "default_logging": False,
                                "description": "d"},
                    "10": {"description": "SSH", "action": "accept", "protocol": "tcp"},
                    "20": {"description": "DNS", "action": "accept", "protocol": "udp"},
                }
            },
            "filters": {
                "input": {
                    "rule-order": ["1", "2"],
                    "description": "Input",
                    "rules": {
                        "1": {"description": "a", "action": "accept",
                              "ip_version": "ipv4", "interface": "eth0",
                              "direction": "in"},
                        "2": {"description": "b", "action": "accept",
                              "ip_version": "ipv4", "interface": "eth1",
                              "direction": "in"},
                    },
                }
            },
            "groups": {
                "WEB": {"group_desc": "", "group_type": "port-group",
                        "group_value": ["80", "443"]},
            },
        },
    }


class Store:
    def __init__(self):
        self.data = _data()

    def read(self, *a, **k):
        return self.data

    def write(self, path, data, *a, **k):
        self.data = data


@pytest.fixture
def store():
    store = Store()
    patches = [
        patch(f"package.{module}.{name}", getattr(store, op))
        for module in ("chain_functions", "filter_functions", "group_funtions")
        for name, op in (("read_user_data_file", "read"),
                         ("write_user_data_file", "write"))
    ] + [
        patch("app.read_user_data_file", store.read),
        patch("app.list_user_files", return_value=["testfirewall"]),
        patch("app.list_snapshots", return_value=[]),
    ]
    for p in patches:
        p.start()
    yield store
    for p in patches:
        p.stop()


@pytest.mark.parametrize(
    "path, section_ids",
    [
        ("/chain_view", ['id="ipv4WAN_LOCAL"']),
        ("/filter_view", ['id="ipv4input"']),
        ("/group_view", ['id="ipv4-address"', 'id="port"']),
    ],
)
def test_views_render_tabs(auth_client, store, path, section_ids):
    resp = auth_client.get(path)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'href="#all"' in body
    assert "section-tab" in body
    assert "tab-section" in body
    assert "section-tabs.js" in body
    assert 'href="#top"' not in body
    for section_id in section_ids:
        assert section_id in body


def _location(resp):
    assert resp.status_code == 302
    return resp.headers["Location"]


def test_chain_add_redirects_to_new_chain(auth_client, store):
    resp = auth_client.post(
        "/chain_add",
        data={"ip_version": "ipv6", "fw_chain": "LAN_IN", "description": "x",
              "default_action": "drop"},
    )
    assert _location(resp).endswith("/chain_view#ipv6LAN_IN")


def test_chain_rule_delete_redirects_to_chain(auth_client, store):
    resp = auth_client.post(
        "/chain_rule_delete",
        data={"chain": "ipv4,WAN_LOCAL", "rule": "ipv4,WAN_LOCAL,10"},
    )
    assert _location(resp).endswith("/chain_view#ipv4WAN_LOCAL")
    assert "10" not in store.data["ipv4"]["chains"]["WAN_LOCAL"]


def test_filter_add_redirects_to_new_filter(auth_client, store):
    resp = auth_client.post(
        "/filter_add",
        data={"ip_version": "ipv4", "type": "forward", "description": "x",
              "default_action": "accept"},
    )
    assert _location(resp).endswith("/filter_view#ipv4forward")


def test_filter_rule_delete_redirects_to_filter(auth_client, store):
    resp = auth_client.post("/filter_rule_delete", data={"rule": "ipv4,input,1"})
    assert _location(resp).endswith("/filter_view#ipv4input")
    assert "1" not in store.data["ipv4"]["filters"]["input"]["rules"]


def test_group_add_redirects_to_category(auth_client, store):
    resp = auth_client.post(
        "/group_add",
        data={"type": "add", "group_type": "network-group", "ip_version": "ipv6",
              "group_desc": "", "group_name": "LANS", "group_value": "fd00::/8"},
    )
    assert _location(resp).endswith("/group_view#ipv6-network")


def test_group_delete_redirects_to_category(auth_client, store):
    resp = auth_client.post(
        "/group_delete", data={"group": "ipv4,WEB", "group_type": "port-group"}
    )
    assert _location(resp).endswith("/group_view#port")


def test_group_delete_without_type_redirects_without_anchor(auth_client, store):
    # A page rendered before group_type was posted still deletes cleanly.
    resp = auth_client.post("/group_delete", data={"group": "ipv4,WEB"})
    assert _location(resp).endswith("/group_view")
