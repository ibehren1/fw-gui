"""
Tests for the theme chooser and the top-bar theme switch.

Covers: /choose_theme, /user_theme, the post-login redirect for accounts
        without a theme, and the data-theme attribute on rendered pages
"""

from unittest.mock import patch

import pytest

from package import user_store


@pytest.fixture
def testuser_theme(flask_app):
    """Yields a setter for testuser's theme and clears it afterwards.

    The users collection is session-wide, so a theme left behind would leak
    into every later test that renders a page.
    """
    def set_(theme):
        user_store.collection().update_one({"_id": "testuser"}, {"$set": {"theme": theme}})

    yield set_
    user_store.collection().update_one({"_id": "testuser"}, {"$unset": {"theme": ""}})


def _theme():
    return user_store.collection().find_one({"_id": "testuser"}).get("theme")


def _login(client):
    with patch("package.auth_functions.telemetry_instance"), patch(
        "package.auth_functions.check_version"
    ):
        return client.post("/user_login", data={"username": "testuser", "password": "testpass"})


def test_login_without_theme_goes_to_chooser(client, flask_app, testuser_theme):
    with flask_app.app_context():
        resp = _login(client)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/choose_theme")


def test_login_with_theme_goes_to_index(client, flask_app, testuser_theme):
    testuser_theme("light")
    with flask_app.app_context():
        resp = _login(client)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")


def test_chooser_renders_both_tiles(auth_client, testuser_theme):
    resp = auth_client.get("/choose_theme")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'name="theme" value="dark"' in body
    assert 'name="theme" value="light"' in body


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_chooser_saves_theme(auth_client, testuser_theme, theme):
    resp = auth_client.post("/choose_theme", data={"theme": theme})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/")
    assert _theme() == theme


def test_chooser_rejects_unknown_theme(auth_client, testuser_theme):
    resp = auth_client.post("/choose_theme", data={"theme": "neon"})
    assert resp.status_code == 200
    assert "Choose a theme to continue." in resp.get_data(as_text=True)
    assert _theme() is None


def test_switch_returns_to_referring_page(auth_client, testuser_theme):
    testuser_theme("dark")
    resp = auth_client.post(
        "/user_theme", data={"theme": "light"},
        headers={"Referer": "http://localhost/chain_view?x=1"},
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/chain_view?x=1")
    assert _theme() == "light"


@pytest.mark.parametrize("referer", [
    "https://evil.example/phish", "//evil.example/x", "javascript:alert(1)", "",
])
def test_switch_never_redirects_off_site(auth_client, testuser_theme, referer):
    resp = auth_client.post(
        "/user_theme", data={"theme": "dark"}, headers={"Referer": referer},
    )
    assert resp.status_code == 302
    location = resp.headers["Location"]
    assert "evil" not in location and "javascript" not in location
    assert location.endswith("/")


def test_switch_ignores_unknown_theme(auth_client, testuser_theme):
    testuser_theme("dark")
    auth_client.post("/user_theme", data={"theme": "neon"})
    assert _theme() == "dark"


def test_page_carries_account_theme(auth_client, flask_app, testuser_theme):
    testuser_theme("light")
    # Fresh app context so Flask-Login reloads the user (see test_layout.py).
    with flask_app.app_context(), patch("app.list_user_files", return_value=[]), \
            patch("app.list_snapshots", return_value=[]):
        body = auth_client.get("/configurations").get_data(as_text=True)
    assert 'data-theme="light"' in body
    assert 'value="light" aria-pressed="true"' in body
    assert 'value="dark" aria-pressed="false"' in body
