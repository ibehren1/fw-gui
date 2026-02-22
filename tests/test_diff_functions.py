from unittest.mock import Mock, patch

from package.diff_functions import fix_list, process_diff


def test_fix_list():
    # Test empty list
    assert fix_list([]) == []

    # Test single line without newlines
    assert fix_list(["test"]) == [" test"]

    # Test single line with newlines
    assert fix_list(["line1\nline2"]) == [" line1", " line2"]

    # Test multiple lines with newlines
    input_list = ["line1\nline2", "line3\nline4\nline5", "line6"]
    expected = [" line1", " line2", " line3", " line4", " line5", " line6"]
    assert fix_list(input_list) == expected

    # Test empty strings
    assert fix_list([""]) == [" "]

    # Test strings with only newlines
    assert fix_list(["\n\n"]) == [" ", " ", " "]


def test_process_diff(app, mock_session):
    with app.test_request_context():
        mock_request = Mock()
        mock_request.form = {"snapshot_1": "snap1", "snapshot_2": "snap2"}

        with patch("package.diff_functions.generate_config") as mock_generate:
            mock_generate.side_effect = [
                ("", ["# Config A\nset firewall rule 1"]),
                ("", ["# Config B\nset firewall rule 2"]),
            ]

            result = process_diff(mock_session, mock_request)

            assert mock_generate.call_count == 2
            mock_generate.assert_any_call(mock_session, snapshot="snap1", diff=True)
            mock_generate.assert_any_call(mock_session, snapshot="snap2", diff=True)

            assert "Snapshot: snap1" in result
            assert "Snapshot: snap2" in result


def test_process_diff_identical_snapshots(app, mock_session):
    with app.test_request_context():
        mock_request = Mock()
        mock_request.form = {"snapshot_1": "snap1", "snapshot_2": "snap1"}

        config_lines = ["# Same config\nset firewall rule 1"]
        with patch("package.diff_functions.generate_config") as mock_generate:
            mock_generate.return_value = ("", config_lines)

            result = process_diff(mock_session, mock_request)

            assert isinstance(result, str)
            assert "Snapshot: snap1" in result


def test_process_diff_empty_configs(app, mock_session):
    with app.test_request_context():
        mock_request = Mock()
        mock_request.form = {"snapshot_1": "snap1", "snapshot_2": "snap2"}

        with patch("package.diff_functions.generate_config") as mock_generate:
            mock_generate.return_value = ("", [])

            result = process_diff(mock_session, mock_request)

            assert isinstance(result, str)
