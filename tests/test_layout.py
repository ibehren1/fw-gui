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


def test_logged_out_page_follows_os_theme(client, flask_app):
    # flask_app keeps an app context pushed for the whole session, and
    # Flask-Login caches the user on g; a fresh context drops any user an
    # earlier test logged in.
    with flask_app.app_context():
        body = client.get("/user_login").get_data(as_text=True)
    assert 'data-theme="auto"' in body
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


def test_top_bar_switcher_and_nav(auth_client):
    body = _get(auth_client, "/configurations").get_data(as_text=True)
    assert 'id="cfg-select"' in body
    assert 'class="nav-item active" href="/configurations"' in body
    # A firewall is selected in auth_client, so Build/Deploy links are shown.
    assert 'href="/chain_view"' in body
    assert 'href="/configuration_push"' in body


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
