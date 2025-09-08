import pytest
from flask import Flask
from werkzeug.datastructures import ImmutableMultiDict

from package.interface_functions import (
    add_interface_to_data,
    delete_interface_from_data,
    list_interfaces,
)


@pytest.fixture
def app():
    app = Flask(__name__)
    app.secret_key = "test_key"
    return app


@pytest.fixture
def mock_session():
    return {"data_dir": "/test/data", "firewall_name": "test_firewall"}


@pytest.fixture
def mock_user_data(monkeypatch):
    test_data = {
        "interfaces": [
            {"name": "eth0", "description": "Main interface"},
            {"name": "eth1", "description": "Secondary interface"},
        ]
    }

    def mock_read(*args):
        return test_data.copy()

    def mock_write(*args):
        test_data.update(args[1])

    monkeypatch.setattr("package.interface_functions.read_user_data_file", mock_read)
    monkeypatch.setattr("package.interface_functions.write_user_data_file", mock_write)

    return test_data


def test_add_interface(app, mock_session, mock_user_data):
    with app.test_request_context():
        # Create mock form data
        form_data = ImmutableMultiDict(
            [("interface_name", "eth2"), ("interface_desc", "Test interface")]
        )

        # Test adding new interface
        add_interface_to_data(mock_session, type("Request", (), {"form": form_data}))

        # Get updated interface list
        interface_list = list_interfaces(mock_session)

        # Verify new interface was added
        assert any(interface["name"] == "eth2" for interface in interface_list)
        assert any(
            interface["description"] == "Test interface" for interface in interface_list
        )


def test_add_interface_with_spaces(app, mock_session, mock_user_data):
    with app.test_request_context():
        # Create mock form data with spaces
        form_data = ImmutableMultiDict(
            [("interface_name", "eth 2"), ("interface_desc", "Test interface")]
        )

        # Test adding new interface
        add_interface_to_data(mock_session, type("Request", (), {"form": form_data}))

        # Get updated interface list
        interface_list = list_interfaces(mock_session)

        # Verify spaces were removed from interface name
        assert any(interface["name"] == "eth2" for interface in interface_list)


def test_delete_interface(app, mock_session, mock_user_data):
    with app.test_request_context():
        # Create mock form data
        form_data = ImmutableMultiDict([("interface", "eth0")])

        # Test deleting interface
        delete_interface_from_data(
            mock_session, type("Request", (), {"form": form_data})
        )

        # Get updated interface list
        interface_list = list_interfaces(mock_session)

        # Verify interface was deleted
        assert not any(interface["name"] == "eth0" for interface in interface_list)
        assert any(interface["name"] == "eth1" for interface in interface_list)


def test_list_interfaces_sorted(app, mock_session, mock_user_data):
    with app.test_request_context():
        interface_list = list_interfaces(mock_session)

        # Verify list is sorted by name
        names = [interface["name"] for interface in interface_list]
        assert names == sorted(names)


def test_list_interfaces_empty(app, mock_session, monkeypatch):
    # Mock empty data
    def mock_read(*args):
        return {}

    monkeypatch.setattr("package.interface_functions.read_user_data_file", mock_read)

    with app.test_request_context():
        interface_list = list_interfaces(mock_session)
        assert interface_list == []
