"""
Tests for package/config_session.py.

The fixtures under tests/fixtures/config_session are the real output of
build_script() run on a VyOS 2025.01 rolling lab box (marker fixed to
MARKER). None of those sessions changed the device: each discarded, aborted
on a failed line, had no changes, or failed commit validation.
"""

import subprocess
from pathlib import Path

import pytest

from package.config_session import (
    ERROR_PATTERN,
    build_script,
    command_lines,
    describe_errors,
    new_marker,
    parse_output,
    unsafe_reason,
)

FIXTURES = Path(__file__).parent / "fixtures" / "config_session"
MARKER = "@@FWGUI-0123456789abcdef"


def _case(name):
    output = (FIXTURES / f"{name}.txt").read_text()
    lines = command_lines((FIXTURES / f"{name}.lines").read_text())
    return parse_output(output, MARKER, lines)


class TestParseRealOutput:
    def test_diff_reports_each_rejected_line_and_the_accepted_diff(self):
        result = _case("diff_mixed")
        assert [(n, line) for n, line, _ in result["errors"]] == [
            (3, "set firewall ipv4 nosuchnode foo"),
            (4, "set firewall ipv4 name FWGUI_PROBE rule 10 action 'bogus'"),
            (5, "bogusverb firewall foo"),
        ]
        assert result["errors"][0][2] == (
            "Configuration path: firewall ipv4 [nosuchnode] is not valid\nSet failed")
        assert result["errors"][2][2] == "Invalid command: [bogusverb]"
        # "Nothing to delete" (line 6) is not an error.
        assert result["diff"].startswith("[firewall ipv4 name]\n+ FWGUI_PROBE {")
        assert result["committed"] is False
        assert result["complete"] is True

    def test_commit_aborts_on_a_rejected_line(self):
        result = _case("commit_line_error")
        assert [n for n, _, _ in result["errors"]] == [2]
        assert result["committed"] is False
        assert result["commit_error"] is None

    def test_commit_with_no_changes(self):
        result = _case("commit_no_changes")
        assert result == {"errors": [], "diff": "", "committed": False,
                          "commit_error": None, "complete": True}

    def test_failed_commit_validation(self):
        result = _case("commit_validation_fails")
        assert result["errors"] == []
        assert result["committed"] is False
        assert "Invalid jump-target" in result["commit_error"]
        assert result["commit_error"].endswith("Commit failed")
        assert "jump-target" in result["diff"]

    def test_successful_commit(self):
        lines = ["set firewall ipv4 name C default-action 'drop'"]
        output = "\n".join([
            f"{MARKER} L 1",
            f"{MARKER} COMPARE",
            "[firewall ipv4 name]",
            "+ C {",
            '+     default-action "drop"',
            "+ }",
            f"{MARKER} COMMIT",
            f"{MARKER} SAVE",
            "Saving configuration to '/config/config.boot'...",
            "Done",
            f"{MARKER} END",
        ])
        result = parse_output(output, MARKER, lines)
        assert result["committed"] is True
        assert result["errors"] == [] and result["commit_error"] is None

    def test_session_cut_short_is_incomplete(self):
        result = parse_output(f"{MARKER} L 1\n", MARKER, ["set x"])
        assert result["complete"] is False


class TestUnsafeLines:
    @pytest.mark.parametrize("line", [
        "set firewall ipv4 name C description 'a; b & c | d > e # f'",
        "set firewall ipv4 name C description \"a; b # c\"",
        "set firewall ipv4 name C description 'it'\\''s'",
        "set firewall ipv4 name C description '{ x }'",
        "set firewall group address-group A address '10.0.0.1'",
        "delete firewall",
        "set firewall ipv4 name C rule 10 description foo#bar",
        "comment firewall ipv4 name C \"note\"",
    ])
    def test_safe(self, line):
        assert unsafe_reason(line) is None

    @pytest.mark.parametrize("line, reason", [
        ("set x 'unterminated", "unterminated quote"),
        ('set x "unterminated', "unterminated quote"),
        ("set x foo\\", "backslash"),
        ("set x foo # note", "comment"),
        ("set x foo; reboot", "operator"),
        ("set x foo && y", "operator"),
        ("set x $(id)", "operator"),
        ("set x `id`", "operator"),
        ("set x > /tmp/f", "operator"),
        ("set x }", "brace"),
        ("set x\x00y", "control character"),
    ])
    def test_unsafe(self, line, reason):
        assert reason in unsafe_reason(line)


class TestBuildScript:
    def test_diff_script_never_commits(self):
        script = build_script(["set a 'b'"], MARKER, commit=False)
        assert "commit" not in script.split("compare", 1)[1]
        assert script.rstrip().endswith(f'echo "{MARKER} END"')
        assert "exit discard" in script

    def test_each_line_is_wrapped_in_its_own_redirected_group(self):
        script = build_script(["set a 'b'", "set c 'd'"], MARKER, commit=True)
        assert f'echo "{MARKER} L 2" >>"$fwgui_log"\n{{\nset c \'d\'\n}} >>"$fwgui_log" 2>&1' in script

    def test_commit_is_gated_on_the_shared_error_pattern(self):
        script = build_script(["set a 'b'"], MARKER, commit=True)
        assert script.count(f"grep -qE '{ERROR_PATTERN}'") == 2
        assert script.index("ABORT") < script.index(f"{MARKER} COMMIT")
        assert script.index("COMMIT_FAILED") < script.index("save")

    def test_script_is_valid_bash(self):
        script = build_script(
            ["set firewall ipv4 name C description 'a; b # c'", "delete firewall"],
            MARKER, commit=True)
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)  # nosec B603 B607


def test_markers_are_unique():
    assert new_marker() != new_marker()
    assert new_marker().startswith("@@FWGUI-")


def test_command_lines_drop_blanks():
    assert command_lines("set a\n\n  \nset b") == ["set a", "set b"]


def test_describe_errors():
    text = describe_errors([(3, "set x", "Bad\nSet failed")])
    assert text == "Line 3: set x\n    Bad\n    Set failed"
