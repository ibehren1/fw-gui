"""Tests for package.validators name/username validation."""

from package.validators import (
    is_allowed_op_command,
    is_auth_critical_username,
    is_reserved_username,
    is_safe_name,
    is_valid_username,
)


class TestIsSafeName:
    def test_accepts_plain_names(self):
        assert is_safe_name("example")
        assert is_safe_name("my-firewall_1")
        assert is_safe_name("config.with.dots")

    def test_accepts_spaces_and_timestamps(self):
        # Snapshot names are timestamps with spaces/colons.
        assert is_safe_name("03-14-2025 12:00:00")

    def test_rejects_empty_and_dots(self):
        assert not is_safe_name("")
        assert not is_safe_name(".")
        assert not is_safe_name("..")

    def test_rejects_traversal(self):
        assert not is_safe_name("../secret")
        assert not is_safe_name("foo/../bar")
        assert not is_safe_name("a..b")

    def test_rejects_separators_and_null(self):
        assert not is_safe_name("foo/bar")
        assert not is_safe_name("foo\\bar")
        assert not is_safe_name("foo\x00bar")

    def test_rejects_non_strings(self):
        assert not is_safe_name(None)
        assert not is_safe_name(123)


class TestIsValidUsername:
    def test_accepts_allowlisted(self):
        assert is_valid_username("alice")
        assert is_valid_username("bob_1")
        assert is_valid_username("a-b.c_d")

    def test_rejects_empty_and_bad_chars(self):
        assert not is_valid_username("")
        assert not is_valid_username("has space")
        assert not is_valid_username("with/slash")
        assert not is_valid_username("../evil")
        assert not is_valid_username("a..b")
        assert not is_valid_username("has@sign")

    def test_rejects_non_strings(self):
        assert not is_valid_username(None)
        assert not is_valid_username(42)

    def test_rejects_reserved_names(self):
        assert not is_valid_username("users")
        assert not is_valid_username("sessions")
        assert not is_valid_username("instance")


class TestIsReservedUsername:
    def test_rejects_application_collections(self):
        assert is_reserved_username("users")
        assert is_reserved_username("sessions")
        assert is_reserved_username("instance")

    def test_matching_ignores_case_and_surrounding_space(self):
        assert is_reserved_username("Users")
        assert is_reserved_username("USERS")
        assert is_reserved_username(" sessions ")

    def test_accepts_ordinary_names(self):
        assert not is_reserved_username("alice")
        assert not is_reserved_username("user")
        assert not is_reserved_username("session")
        assert not is_reserved_username("instances")

    def test_rejects_non_strings(self):
        assert not is_reserved_username(None)
        assert not is_reserved_username(42)

    def test_custom_users_collection_is_reserved_in_addition(self, monkeypatch):
        monkeypatch.setenv("MONGODB_USERS_COLLECTION", "fwgui_accounts")
        assert is_reserved_username("fwgui_accounts")
        # The hardcoded pair is never narrowed by the override: an install that
        # renamed the collection may still hold a "users"-named leftover.
        assert is_reserved_username("users")
        assert is_reserved_username("sessions")


class TestIsAuthCriticalUsername:
    """Narrower than is_reserved_username: only collisions worth aborting for."""

    def test_covers_the_account_and_session_stores(self):
        assert is_auth_critical_username("users")
        assert is_auth_critical_username("sessions")
        assert is_auth_critical_username("SESSIONS")

    def test_excludes_the_telemetry_collection(self):
        # Reserved for new registrations, but a pre-existing account of this name
        # must not stop the app from starting -- telemetry degrades instead.
        assert is_reserved_username("instance")
        assert not is_auth_critical_username("instance")

    def test_accepts_ordinary_names(self):
        assert not is_auth_critical_username("alice")
        assert not is_auth_critical_username(None)

    def test_custom_users_collection_is_auth_critical(self, monkeypatch):
        monkeypatch.setenv("MONGODB_USERS_COLLECTION", "fwgui_accounts")
        assert is_auth_critical_username("fwgui_accounts")


class TestIsAllowedOpCommand:
    def test_accepts_show_commands(self):
        assert is_allowed_op_command("show interfaces")
        assert is_allowed_op_command("show firewall")
        assert is_allowed_op_command("  show firewall group  ")

    def test_rejects_non_show_verbs(self):
        assert not is_allowed_op_command("ping 1.1.1.1")
        assert not is_allowed_op_command("configure")
        assert not is_allowed_op_command("reboot")

    def test_rejects_shell_metacharacters(self):
        assert not is_allowed_op_command("show version; reboot")
        assert not is_allowed_op_command("show version && reboot")
        assert not is_allowed_op_command("show version | tee /tmp/x")
        assert not is_allowed_op_command("show version$(reboot)")
        assert not is_allowed_op_command("show `reboot`")
        assert not is_allowed_op_command("show > /tmp/x")

    def test_rejects_newlines(self):
        assert not is_allowed_op_command("show version\nconfigure")
        assert not is_allowed_op_command("show version\rreboot")

    def test_rejects_empty_and_non_string(self):
        assert not is_allowed_op_command("")
        assert not is_allowed_op_command("   ")
        assert not is_allowed_op_command(None)
        assert not is_allowed_op_command(["show", "version"])
