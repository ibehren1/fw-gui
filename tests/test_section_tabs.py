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


@pytest.mark.parametrize(
    "path, versions",
    [
        # The fixture has IPv4 chains and filters only, so only IPv4 gets a label.
        ("/chain_view", ["ipv4"]),
        ("/filter_view", ["ipv4"]),
        ("/group_view", ["ipv4", "ipv6", "other"]),
    ],
)
def test_version_labels_select_whole_version(auth_client, store, path, versions):
    # The IPv4/IPv6 (and Other) labels in the tab row are links whose hash
    # names the version's section group, which section-tabs.js then shows
    # in full.
    body = auth_client.get(path).get_data(as_text=True)
    for version in versions:
        assert f'href="#{version}" class="tab-sep tab-sep-{version} section-tab"' in body
        assert f'id="{version}" class="tab-section-group' in body


def test_group_references_carry_cards(auth_client, store):
    rule = store.data["ipv4"]["chains"]["WAN_LOCAL"]["10"]
    rule.update({"source_address": "MGMT", "source_address_type": "address_group",
                 "dest_port": "WEB", "dest_port_type": "port_group"})
    store.data["ipv4"]["groups"]["MGMT"] = {
        "group_desc": "Jump hosts", "group_type": "address-group",
        "group_value": ["10.0.0.1", "10.0.0.2"]}
    body = auth_client.get("/chain_view").get_data(as_text=True)
    assert 'data-ref="ipv4|address-group|MGMT"' in body
    assert 'data-ref="ipv4|port-group|WEB"' in body
    assert 'data-ref-card="ipv4|address-group|MGMT"' in body
    assert "10.0.0.2" in body
    assert "ref-cards.js" in body


def test_ipv6_rules_reference_shared_port_groups(auth_client, store):
    # Port groups are stored under ipv4 only and shared by both versions, so
    # an IPv6 rule's reference must key to the ipv4 card. Address groups stay
    # per version.
    store.data["ipv6"] = {"chains": {"WAN6_LOCAL": {
        "rule-order": ["10"],
        "default": {"default_action": "drop", "default_logging": False,
                    "description": "d"},
        "10": {"description": "SSH", "action": "accept", "protocol": "tcp",
               "source_address": "MGMT6", "source_address_type": "address_group",
               "dest_port": "WEB", "dest_port_type": "port_group"}}}}
    body = auth_client.get("/chain_view").get_data(as_text=True)
    assert 'data-ref="ipv4|port-group|WEB"' in body
    assert 'data-ref="ipv6|port-group|WEB"' not in body
    assert 'data-ref="ipv6|address-group|MGMT6"' in body


def test_chain_view_does_not_flash_when_there_are_no_groups(auth_client, store):
    store.data["ipv4"].pop("groups", None)
    body = auth_client.get("/chain_view").get_data(as_text=True)
    assert "There are no groups defined." not in body


def _default_row(body):
    row = body.split('<tr class="default-row"', 1)[1].split("</tr>", 1)[0]
    return row


def test_chain_shows_read_only_default_row(auth_client, store):
    body = auth_client.get("/chain_view").get_data(as_text=True)
    row = _default_row(body)
    assert 'act-drop' in row
    # Read-only: no form, button or input of any kind.
    assert "<form" not in row and "<button" not in row and "<input" not in row


def test_filter_default_row_without_stored_action(auth_client, store):
    body = auth_client.get("/filter_view").get_data(as_text=True)
    row = _default_row(body)
    assert "not set" in row
    assert "<form" not in row and "<button" not in row


def test_filter_default_row_with_stored_action(auth_client, store):
    store.data["ipv4"]["filters"]["input"]["default-action"] = "accept"
    store.data["ipv4"]["filters"]["input"]["log"] = True
    row = _default_row(auth_client.get("/filter_view").get_data(as_text=True))
    assert "act-accept" in row


def test_group_sections_match_chain_headers(auth_client, store):
    body = auth_client.get("/group_view").get_data(as_text=True)
    ipv4 = body.split('id="ipv4-address"', 1)[1].split("</div>", 3)
    head = "".join(ipv4[:3])
    assert "tag tag-ipv4" in head
    assert "group_type=address-group" in body and "ip_version=ipv4" in body


def test_shared_group_rows_have_no_ip_tag(auth_client, store):
    # Port, MAC, domain and interface groups serve both IP versions, so their
    # rows in the "Other" section carry no IPv4/IPv6 tag.
    body = auth_client.get("/group_view").get_data(as_text=True)
    port = body.split('id="port"', 1)[1].split("</table>", 1)[0]
    assert "WEB" in port
    assert "tag-ipv4" not in port and "tag-ipv6" not in port


@pytest.mark.parametrize("query, gtype, ipv", [
    ("?group_type=network-group&ip_version=ipv6", "network-group", "ipv6"),
    ("?group_type=port-group&ip_version=ipv4", "port-group", "ipv4"),
    ("?group_type=bogus&ip_version=ipv9", "address-group", "ipv4"),
])
def test_group_add_preselects_from_query(auth_client, store, query, gtype, ipv):
    body = auth_client.get("/group_add" + query).get_data(as_text=True)
    gt = body.split('name="group_type" value="' + gtype + '"', 1)[1][:200]
    assert "checked" in gt
    iv = body.split('name="ip_version" value="' + ipv + '"', 1)[1][:200]
    assert "checked" in iv
