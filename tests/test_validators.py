"""Tests for package.validators name/username validation."""

from package.validators import is_safe_name, is_valid_username


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
