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
