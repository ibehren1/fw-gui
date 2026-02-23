"""Tests for package/telemetry_functions.py"""

import json
from unittest.mock import Mock, patch, mock_open

from package.telemetry_functions import (
    get_instance_id,
    get_version,
    post_telemetry,
    telemetry_commit,
    telemetry_diff,
    telemetry_instance,
    telemetry_rule_usage,
)


def test_get_instance_id():
    with patch("builtins.open", mock_open(read_data="test-uuid-1234\n")):
        result = get_instance_id()
        assert result == "test-uuid-1234"


def test_get_instance_id_no_whitespace():
    with patch("builtins.open", mock_open(read_data="  uuid-with-spaces  \n")):
        result = get_instance_id()
        assert result == "uuid-with-spaces"


def test_get_version():
    with patch("builtins.open", mock_open(read_data="v2.1.0")):
        result = get_version()
        assert result == "2.1.0"


def test_get_version_strips_v_prefix():
    with patch("builtins.open", mock_open(read_data="v1.0.0")):
        result = get_version()
        assert "v" not in result


@patch("package.telemetry_functions.urllib3.request")
def test_post_telemetry_success(mock_request):
    body = json.dumps({"instance_id": "test-uuid"})
    post_telemetry(body, "instance")

    mock_request.assert_called_once_with(
        "POST",
        "https://telemetry.fw-gui.com/instance",
        headers={"Content-Type": "application/json"},
        body=body,
    )


@patch("package.telemetry_functions.urllib3.request")
def test_post_telemetry_exception(mock_request):
    mock_request.side_effect = Exception("Network error")
    body = json.dumps({"instance_id": "test-uuid"})

    # Should not raise
    post_telemetry(body, "instance")


@patch("package.telemetry_functions.post_telemetry")
@patch("package.telemetry_functions.get_instance_id", return_value="test-uuid")
def test_telemetry_commit(mock_id, mock_post):
    telemetry_commit()

    mock_post.assert_called_once()
    body = json.loads(mock_post.call_args[0][0])
    assert body["instance_id"] == "test-uuid"
    assert mock_post.call_args[0][1] == "commit"


@patch("package.telemetry_functions.post_telemetry")
@patch("package.telemetry_functions.get_instance_id", return_value="test-uuid")
def test_telemetry_diff(mock_id, mock_post):
    telemetry_diff()

    mock_post.assert_called_once()
    body = json.loads(mock_post.call_args[0][0])
    assert body["instance_id"] == "test-uuid"
    assert mock_post.call_args[0][1] == "diff"


@patch("package.telemetry_functions.post_telemetry")
@patch("package.telemetry_functions.get_instance_id", return_value="test-uuid")
@patch("package.telemetry_functions.get_version", return_value="2.1.0")
def test_telemetry_instance(mock_ver, mock_id, mock_post):
    telemetry_instance()

    mock_post.assert_called_once()
    body = json.loads(mock_post.call_args[0][0])
    assert body["instance_id"] == "test-uuid"
    assert body["version"] == "2.1.0"
    assert mock_post.call_args[0][1] == "instance"


@patch("package.telemetry_functions.post_telemetry")
@patch("package.telemetry_functions.get_instance_id", return_value="test-uuid")
def test_telemetry_rule_usage(mock_id, mock_post):
    telemetry_rule_usage()

    mock_post.assert_called_once()
    body = json.loads(mock_post.call_args[0][0])
    assert body["instance_id"] == "test-uuid"
    assert mock_post.call_args[0][1] == "rule_usage"
