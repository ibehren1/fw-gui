"""Tests for package.op_output: choosing the push page's view of op output."""

from package.op_output import build_op_view


class TestBuildOpView:
    def test_text_only_output_is_shown_raw(self):
        assert build_op_view("Version: VyOS 1.5") is None
        assert build_op_view("") is None
        assert build_op_view(None) is None

    def test_tabulated_output_is_a_table_view(self):
        view = build_op_view("A    B\n---  ---\n1    2\n\nnote")
        assert view["kind"] == "tables"
        assert view["table_count"] == 1
        assert [s["kind"] for s in view["segments"]] == ["table", "text"]


class TestCounterHistory:
    def test_key_ignores_whitespace(self):
        from package.op_output import counter_history_key

        assert counter_history_key("fw1", "show  firewall ") == "fw1|show firewall"

    def test_newest_last_and_trimmed(self):
        from package.op_output import COUNTER_HISTORY_LIMIT, remember_counters

        history = None
        for i in range(COUNTER_HISTORY_LIMIT + 2):
            history = remember_counters(history, f"k{i}", {"x": i}, "12:00:00")
        assert len(history) == COUNTER_HISTORY_LIMIT
        assert "k0" not in history and "k1" not in history
        # Re-saving an existing key moves it to newest, so it survives trimming.
        history = remember_counters(history, "k2", {"x": 99}, "12:01:00")
        assert list(history)[-1] == "k2"
        assert history["k2"] == {"at": "12:01:00", "counters": {"x": 99}}
