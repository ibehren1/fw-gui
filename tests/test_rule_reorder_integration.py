"""
Integration tests for the chain and filter rule reordering controls.

Drives the real routes and templates with an in-memory data store so that the
route, the package function and the rendered controls are all exercised together.

Covers: /chain_rule_move, /chain_rule_reorder, /chain_rules_resequence,
        /filter_rule_move, /filter_rules_resequence
"""

from unittest.mock import patch


def _data():
    return {
        "version": "1",
        "ipv4": {
            "chains": {
                "WAN_LOCAL": {
                    "rule-order": ["10", "20", "30"],
                    "default": {"default_action": "drop", "default_logging": False,
                                "description": "d"},
                    "10": {"description": "SSH", "action": "accept", "protocol": "tcp"},
                    "20": {"description": "DNS", "action": "accept", "protocol": "udp"},
                    "30": {"description": "HTTP", "action": "accept", "protocol": "tcp"},
                }
            },
            "filters": {
                "input": {
                    "rule-order": ["1", "2"],
                    "description": "Input",
                    "rules": {
                        "1": {"description": "a", "action": "jump",
                              "fw_chain": "WAN_LOCAL", "ip_version": "ipv4",
                              "interface": "eth0", "direction": "in"},
                        "2": {"description": "b", "action": "accept",
                              "ip_version": "ipv4", "interface": "eth1",
                              "direction": "in"},
                    },
                }
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


def _patches(store):
    """Patch every data access the reorder request path makes.

    The view routes also call list_user_files and list_snapshots, which query
    MongoDB directly, so those are stubbed to keep these tests hermetic.
    """
    return [
        patch("package.chain_functions.read_user_data_file", store.read),
        patch("package.chain_functions.write_user_data_file", store.write),
        patch("package.filter_functions.read_user_data_file", store.read),
        patch("package.filter_functions.write_user_data_file", store.write),
        patch("app.read_user_data_file", store.read),
        patch("app.list_user_files", return_value=["testfirewall"]),
        patch("app.list_snapshots", return_value=[]),
    ]


def test_reorder_controls_end_to_end(auth_client):
    store = Store()
    ctx = _patches(store)
    for c in ctx:
        c.start()
    try:
        chain = lambda: store.data["ipv4"]["chains"]["WAN_LOCAL"]
        filt = lambda: store.data["ipv4"]["filters"]["input"]

        # chain_view renders with controls
        resp = auth_client.get("/chain_view")
        assert resp.status_code == 200, resp.status_code
        body = resp.get_data(as_text=True)
        assert 'name="direction" value="up"' in body
        assert "/chain_rules_resequence" in body

        # move rule 30 up -> swaps with 20
        resp = auth_client.post(
            "/chain_rule_move",
            data={"move_rule": "ipv4,WAN_LOCAL,30", "direction": "up"},
        )
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("#ipv4WAN_LOCAL")
        assert chain()["20"]["description"] == "HTTP"
        assert chain()["30"]["description"] == "DNS"

        # renumber rule 10 -> 20 (taken) shifts the block
        resp = auth_client.post(
            "/chain_rule_reorder",
            data={"reorder_rule": "ipv4,WAN_LOCAL,10", "new_rule_number": "20"},
        )
        assert resp.status_code == 302
        assert chain()["rule-order"] == ["20", "21", "30"], chain()["rule-order"]
        assert chain()["20"]["description"] == "SSH"
        assert chain()["21"]["description"] == "HTTP"
        assert chain()["30"]["description"] == "DNS"

        # resequence -> 10, 20, 30 in the same relative order
        resp = auth_client.post(
            "/chain_rules_resequence", data={"chain": "ipv4,WAN_LOCAL"}
        )
        assert resp.status_code == 302
        assert chain()["rule-order"] == ["10", "20", "30"]
        assert [chain()[n]["description"] for n in ("10", "20", "30")] == [
            "SSH", "HTTP", "DNS",
        ]
        assert chain()["default"]["default_action"] == "drop"

        # filters: view, move, resequence
        resp = auth_client.get("/filter_view")
        assert resp.status_code == 200
        assert "/filter_rule_move" in resp.get_data(as_text=True)

        resp = auth_client.post(
            "/filter_rule_move",
            data={"move_rule": "ipv4,input,1", "direction": "down"},
        )
        assert resp.status_code == 302
        assert filt()["rules"]["1"]["description"] == "b"
        assert filt()["rules"]["2"]["description"] == "a"

        resp = auth_client.post(
            "/filter_rules_resequence", data={"filter": "ipv4,input"}
        )
        assert resp.status_code == 302
        assert filt()["rule-order"] == ["10", "20"]
        assert filt()["rules"]["10"]["description"] == "b"
        assert filt()["description"] == "Input"
    finally:
        for c in ctx:
            c.stop()
