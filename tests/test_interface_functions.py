import pytest
from werkzeug.datastructures import ImmutableMultiDict

from package.interface_functions import (
    add_interface_to_data,
    delete_interface_from_data,
    list_interfaces,
)


# Uses app, mock_session from conftest.py


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
        form_data = ImmutableMultiDict(
            [("interface_name", "eth2"), ("interface_desc", "Test interface")]
        )

        add_interface_to_data(mock_session, type("Request", (), {"form": form_data}))

        interface_list = list_interfaces(mock_session)

        assert any(interface["name"] == "eth2" for interface in interface_list)
        assert any(
            interface["description"] == "Test interface" for interface in interface_list
        )


def test_add_interface_with_spaces(app, mock_session, mock_user_data):
    with app.test_request_context():
        form_data = ImmutableMultiDict(
            [("interface_name", "eth 2"), ("interface_desc", "Test interface")]
        )

        add_interface_to_data(mock_session, type("Request", (), {"form": form_data}))

        interface_list = list_interfaces(mock_session)

        assert any(interface["name"] == "eth2" for interface in interface_list)


def test_delete_interface(app, mock_session, mock_user_data):
    with app.test_request_context():
        form_data = ImmutableMultiDict([("interface", "eth0")])

        delete_interface_from_data(
            mock_session, type("Request", (), {"form": form_data})
        )

        interface_list = list_interfaces(mock_session)

        assert not any(interface["name"] == "eth0" for interface in interface_list)
        assert any(interface["name"] == "eth1" for interface in interface_list)


def test_list_interfaces_sorted(app, mock_session, mock_user_data):
    with app.test_request_context():
        interface_list = list_interfaces(mock_session)

        names = [interface["name"] for interface in interface_list]
        assert names == sorted(names)


def test_list_interfaces_empty(app, mock_session, monkeypatch):
    def mock_read(*args):
        return {}

    monkeypatch.setattr("package.interface_functions.read_user_data_file", mock_read)

    with app.test_request_context():
        interface_list = list_interfaces(mock_session)
        assert interface_list == []


def test_add_interface_replaces_existing(app, mock_session, mock_user_data):
    with app.test_request_context():
        form_data = ImmutableMultiDict(
            [("interface_name", "eth0"), ("interface_desc", "Updated description")]
        )

        add_interface_to_data(mock_session, type("Request", (), {"form": form_data}))

        interface_list = list_interfaces(mock_session)

        eth0_entries = [i for i in interface_list if i["name"] == "eth0"]
        assert len(eth0_entries) == 1
        assert eth0_entries[0]["description"] == "Updated description"


def test_delete_nonexistent_interface(app, mock_session, mock_user_data):
    with app.test_request_context():
        form_data = ImmutableMultiDict([("interface", "eth99")])

        delete_interface_from_data(
            mock_session, type("Request", (), {"form": form_data})
        )

        interface_list = list_interfaces(mock_session)

        assert len(interface_list) == 2


@pytest.mark.parametrize(
    "form, expected",
    [
        ({}, {}),
        ({"interface_type": ""}, {}),
        ({"interface_type": "bogus"}, {}),
        ({"interface_type": "public_wan"}, {"type": "public_wan"}),
        ({"interface_type": "lan", "type_label": "ignored"}, {"type": "lan"}),
        ({"interface_type": "custom", "type_label": "  Guest   Wi-Fi ", "type_color": "pink"},
         {"type": "custom", "type_label": "Guest Wi-Fi", "type_color": "pink"}),
        ({"interface_type": "custom", "type_label": "", "type_color": "red"},
         {"type": "custom", "type_label": "Custom", "type_color": "blue"}),
        ({"interface_type": "custom", "type_label": "x" * 40, "type_color": "gray"},
         {"type": "custom", "type_label": "x" * 24, "type_color": "gray"}),
    ],
)
def test_interface_type_fields(form, expected):
    from package.interface_functions import interface_type_fields

    assert interface_type_fields(form) == expected


def _req(form):
    return type("Request", (), {"form": ImmutableMultiDict(form)})


def test_add_interface_stores_type(app, mock_session, mock_user_data):
    with app.test_request_context():
        add_interface_to_data(mock_session, _req({
            "interface_name": "eth9", "interface_desc": "Guest",
            "interface_type": "custom", "type_label": "Guest", "type_color": "brown",
        }))
    stored = next(i for i in mock_user_data["interfaces"] if i["name"] == "eth9")
    assert stored == {"name": "eth9", "description": "Guest", "type": "custom",
                      "type_label": "Guest", "type_color": "brown"}


def test_re_adding_interface_without_type_clears_it(app, mock_session, mock_user_data):
    with app.test_request_context():
        add_interface_to_data(mock_session, _req({
            "interface_name": "eth0", "interface_desc": "", "interface_type": "lan"}))
        add_interface_to_data(mock_session, _req({"interface_name": "eth0", "interface_desc": ""}))
    stored = next(i for i in mock_user_data["interfaces"] if i["name"] == "eth0")
    assert "type" not in stored
