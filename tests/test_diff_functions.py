from package.diff_functions import *
from unittest.mock import MagicMock, Mock, patch
import pytest


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


# TODO
# def test_process_diff():
#     # Mock session and request objects
#     mock_session = Mock()
#     mock_request = Mock()
#     mock_request.form = {"snapshot_1": "123", "snapshot_2": "456"}

#     # Mock the generate_config function
#     with patch("package.generate_config.generate_config") as mock_generate:
#         # Set up mock return values
#         mock_generate.side_effect = [
#             ["line1\nline2"],  # First snapshot
#             ["line3\nline4"],  # Second snapshot
#         ]

#         # Call the function
#         result = process_diff(mock_session, mock_request)

#         # Verify generate_config was called correctly
#         assert mock_generate.call_count == 2
#         mock_generate.assert_any_call(mock_session, snapshot="123", diff=True)
#         mock_generate.assert_any_call(mock_session, snapshot="456", diff=True)

#         # Verify HTML output contains expected elements
#         assert "Snapshot: 123" in result
#         assert "Snapshot: 456" in result
#         assert "Firewall GUI" in result
#         assert "page_background" in result
#         assert "diff_add" in result
#         assert "diff_chg" in result
#         assert "diff_sub" in result
#         assert "line1" in result
#         assert "line2" in result
#         assert "line3" in result
#         assert "line4" in result


# TODO
# def test_process_diff_empty_snapshots():
#     mock_session = MagicMock()
#     mock_request = MagicMock()
#     mock_request.form = {"snapshot_1": "", "snapshot_2": ""}

#     with patch("package.generate_config.generate_config") as mock_generate:
#         mock_generate.side_effect = [[], []]

#         result = process_diff(mock_session, mock_request)

#         assert mock_generate.call_count == 2
#         assert "Snapshot: " in result


# def test_process_diff_invalid_request():
#     mock_session = Mock()[1:999]
#     mock_request = Mock()[1:999]
#     mock_request.form = {}

#     with pytest.raises(KeyError):
#         process_diff(mock_session, mock_request)
