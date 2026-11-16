"""
Tests for the shared page layout (basic_page.html) and the Configurations page.

Covers: theme attribute on <html>, top-bar config switcher, nav, /configurations
"""

from unittest.mock import patch


def _patched():
    return [
        patch("app.list_user_files", return_value=["edge-fw-01", "lab-fw"]),
        patch("app.list_snapshots",
              return_value=[{"id": "edge-fw-01", "name": "2026-11-14", "tag": "pre-bgp"}]),
    ]


def _get(client, path):
    ctx = _patched()
    for c in ctx:
        c.start()
    try:
        return client.get(path)
    finally:
        for c in ctx:
            c.stop()


def test_logged_out_page_is_dark(client, flask_app):
    # flask_app keeps an app context pushed for the whole session, and
    # Flask-Login caches the user on g; a fresh context drops any user an
    # earlier test logged in.
    with flask_app.app_context():
        body = client.get("/user_login").get_data(as_text=True)
    assert 'data-theme="dark"' in body
    assert 'class="nav"' not in body


def test_configurations_page_lists_configs_and_snapshots(auth_client):
    resp = _get(auth_client, "/configurations")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'value="edge-fw-01"' in body
    assert 'value="lab-fw"' in body
    assert 'value="test_firewall/create"' in body
    assert 'value="edge-fw-01/2026-11-14"' in body
    assert 'value="edge-fw-01/delete/2026-11-14"' in body
    assert "pre-bgp" in body
    for action in ("/create_config", "/delete_config", "/upload_json"):
        assert f'action="{action}"' in body
    assert 'href="/download_config"' in body
    assert 'href="/download_json"' in body


def test_top_bar_switcher_and_nav(auth_client):
    body = _get(auth_client, "/configurations").get_data(as_text=True)
    assert 'id="cfg-select"' in body
    assert 'class="nav-item active" href="/configurations"' in body
    # A firewall is selected in auth_client, so Build/Deploy links are shown.
    assert 'href="/chain_view"' in body
    assert 'href="/configuration_push"' in body
    # Downloads live on the Configurations page, not in the nav.
    nav = body.split('<nav class="nav"', 1)[1].split("</nav>", 1)[0]
    assert "download_config" not in nav


def test_configurations_without_firewall(auth_client):
    with auth_client.session_transaction() as sess:
        sess.pop("firewall_name", None)
    body = _get(auth_client, "/configurations").get_data(as_text=True)
    assert 'value="test_firewall/create"' not in body
    assert 'href="/chain_view"' not in body


def test_page_without_config_list_still_shows_selected_config(auth_client):
    # The change-password route passes neither file_list nor firewall_name;
    # the top bar falls back to the session and links to the Configurations page.
    body = auth_client.get("/user_change_password").get_data(as_text=True)
    assert 'class="cfg-select cfg-link"' in body
    assert ">test_firewall</a>" in body
    assert 'href="/chain_view"' in body


def test_logged_in_user_on_login_page(auth_client):
    # user_login overrides the template's session variable with a string; the
    # layout must not treat it as the session.
    assert auth_client.get("/user_login").status_code == 200


def test_interfaces_page_shows_types_and_edit(auth_client):
    interfaces = [
        {"name": "eth0", "description": "WAN", "type": "public_wan"},
        {"name": "eth9", "description": "", "type": "custom", "type_label": "Guest", "type_color": "pink"},
        {"name": "wg0", "description": ""},
    ]
    with patch("app.list_interfaces", return_value=interfaces), \
            patch("app.list_user_files", return_value=[]), patch("app.list_snapshots", return_value=[]):
        body = auth_client.get("/interface_view").get_data(as_text=True)
    assert 'iftype iftype-public_wan' in body and "Public WAN" in body
    assert 'iftype iftype-c-pink' in body and ">Guest<" not in body.split("iftype-c-pink", 1)[0][-5:]
    assert "Unassigned" in body
    assert 'name="interface_type" value="custom"' in body
    assert 'name="interface_type" value=""' in body  # untyped interface posts no type
    assert 'value="None"' not in body


def test_interface_edit_form_preselects_type(auth_client):
    with patch("app.list_user_files", return_value=[]), patch("app.list_snapshots", return_value=[]):
        body = auth_client.post("/interface_add", data={
            "type": "edit", "interface_name": "eth9", "interface_desc": "",
            "interface_type": "custom", "type_label": "Guest", "type_color": "brown",
        }).get_data(as_text=True)
    assert "Edit Interface" in body
    assert 'value="custom" checked' in body
    assert 'value="brown" checked' in body
    assert "readonly" in body


def test_interface_types_show_on_flowtables_and_pickers(auth_client):
    interfaces = [{"name": "eth0", "description": "WAN", "type": "public_wan"},
                  {"name": "eth9", "description": "", "type": "custom", "type_label": "Guest", "type_color": "pink"}]
    with patch("app.list_interfaces", return_value=interfaces), \
            patch("app.list_flowtables", return_value=[{"name": "FT", "description": "", "interfaces": ["eth0", "eth9"]}]), \
            patch("app.list_user_files", return_value=[]), patch("app.list_snapshots", return_value=[]):
        flow = auth_client.get("/flowtable_view").get_data(as_text=True)
        form = auth_client.get("/flowtable_add").get_data(as_text=True)
    assert flow.count('class="chip chip-if"') == 2
    assert "iftype-public_wan" in flow and "iftype-c-pink" in flow
    assert "iftype-public_wan" in form and ">Guest<" in form


def test_filter_rule_interface_picker_names_the_type(auth_client):
    interfaces = [{"name": "eth0", "description": "WAN", "type": "public_wan"},
                  {"name": "eth9", "description": "", "type": "custom", "type_label": "Guest", "type_color": "pink"},
                  {"name": "wg0", "description": ""}]
    with patch("app.list_interfaces", return_value=interfaces), \
            patch("app.list_flowtables", return_value=[]), \
            patch("app.assemble_list_of_filters", return_value=[("ipv4", "input")]), \
            patch("app.assemble_list_of_chains", return_value=[("ipv4", "WAN_IN")]), \
            patch("app.list_user_files", return_value=[]), patch("app.list_snapshots", return_value=[]):
        body = auth_client.get("/filter_rule_add?filter=ipv4,input").get_data(as_text=True)
    assert "eth0 - WAN [Public WAN]</option>" in body
    assert "eth9 [Guest]</option>" in body
    assert ">wg0</option>" in body


def _filter_rule_form(client, method="get", data=None):
    flowtables = [{"name": "FT_WAN", "description": "Offload", "interfaces": ["eth0"]},
                  {"name": "FT_LAN", "description": "", "interfaces": []}]
    with patch("app.list_interfaces", return_value=[{"name": "eth0", "description": ""}]), \
            patch("app.list_flowtables", return_value=flowtables), \
            patch("app.assemble_list_of_filters", return_value=[("ipv4", "forward")]), \
            patch("app.assemble_list_of_chains", return_value=[("ipv4", "WAN_IN")]), \
            patch("app.list_user_files", return_value=[]), patch("app.list_snapshots", return_value=[]):
        if method == "get":
            return client.get("/filter_rule_add?filter=ipv4,forward")
        return client.post("/filter_rule_add", data=data)


def test_filter_rule_form_renders_with_flowtables(auth_client):
    # Regression: the template indexed flowtable[0]/[1], but list_flowtables()
    # returns dicts, so the page 500'd whenever any flowtable existed.
    resp = _filter_rule_form(auth_client)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert '<option value="FT_WAN" >' in body
    assert "FT_WAN - Offload" in body
    assert '<option value="FT_LAN" >' in body


def test_filter_rule_edit_preselects_offload_flowtable(auth_client):
    resp = _filter_rule_form(auth_client, "post", {
        "type": "edit", "filter": "ipv4,forward", "name": "20", "description": "",
        "action": "offload", "direction": "", "ip_version": "ipv4",
        "target": "FT_LAN", "interface": "",
    })
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert '<option value="FT_LAN" selected>' in body
    assert '<option value="FT_WAN" >' in body
