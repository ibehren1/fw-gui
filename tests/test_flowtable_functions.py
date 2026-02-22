"""
Tests for package.flowtable_functions module.

Covers: add_flowtable_to_data, delete_flowtable_from_data, list_flowtables
"""

import pytest

from tests.conftest import make_request

from package.flowtable_functions import (
    add_flowtable_to_data,
    delete_flowtable_from_data,
    list_flowtables,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_data():
    """Minimal starting data with no flowtables key."""
    return {"version": "1"}


def _data_with_flowtables():
    """Data with existing flowtables."""
    return {
        "version": "1",
        "flowtables": [
            {
                "name": "FT-Alpha",
                "description": "Alpha flowtable",
                "interfaces": ["eth0", "eth1"],
            },
            {
                "name": "FT-Beta",
                "description": "Beta flowtable",
                "interfaces": ["eth2"],
            },
        ],
    }


# ===================================================================
# add_flowtable_to_data
# ===================================================================


class TestAddFlowtableToData:
    def test_basic_add_with_interfaces(self, app, mock_session, mock_read_write):
        data = _data_with_flowtables()
        capture = mock_read_write("package.flowtable_functions", data)
        req = make_request({
            "flowtable_name": "FT-Gamma",
            "flowtable_desc": "Gamma flowtable",
            "interface_0": "eth3",
            "interface_1": "eth4",
        })
        with app.test_request_context():
            add_flowtable_to_data(mock_session, req)

        fts = capture.written_data["flowtables"]
        names = [ft["name"] for ft in fts]
        assert "FT-Gamma" in names
        gamma = next(ft for ft in fts if ft["name"] == "FT-Gamma")
        assert gamma["description"] == "Gamma flowtable"
        assert gamma["interfaces"] == ["eth3", "eth4"]

    def test_replace_existing(self, app, mock_session, mock_read_write):
        data = _data_with_flowtables()
        capture = mock_read_write("package.flowtable_functions", data)
        req = make_request({
            "flowtable_name": "FT-Alpha",
            "flowtable_desc": "Updated alpha",
            "interface_0": "eth5",
        })
        with app.test_request_context():
            add_flowtable_to_data(mock_session, req)

        fts = capture.written_data["flowtables"]
        alpha_entries = [ft for ft in fts if ft["name"] == "FT-Alpha"]
        assert len(alpha_entries) == 1
        assert alpha_entries[0]["description"] == "Updated alpha"
        assert alpha_entries[0]["interfaces"] == ["eth5"]

    def test_name_with_spaces(self, app, mock_session, mock_read_write):
        data = _data_with_flowtables()
        capture = mock_read_write("package.flowtable_functions", data)
        req = make_request({
            "flowtable_name": "FT Gamma Table",
            "flowtable_desc": "Spaces removed",
            "interface_0": "eth0",
        })
        with app.test_request_context():
            add_flowtable_to_data(mock_session, req)

        fts = capture.written_data["flowtables"]
        names = [ft["name"] for ft in fts]
        assert "FTGammaTable" in names
        assert "FT Gamma Table" not in names

    def test_add_with_no_existing_flowtables_key(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        capture = mock_read_write("package.flowtable_functions", data)
        req = make_request({
            "flowtable_name": "FirstFT",
            "flowtable_desc": "First flowtable",
            "interface_0": "eth0",
        })
        with app.test_request_context():
            add_flowtable_to_data(mock_session, req)

        fts = capture.written_data["flowtables"]
        assert len(fts) == 1
        assert fts[0]["name"] == "FirstFT"
        assert fts[0]["interfaces"] == ["eth0"]


# ===================================================================
# delete_flowtable_from_data
# ===================================================================


class TestDeleteFlowtableFromData:
    def test_basic_delete(self, app, mock_session, mock_read_write):
        data = _data_with_flowtables()
        capture = mock_read_write("package.flowtable_functions", data)
        req = make_request({"flowtable": "FT-Alpha"})
        with app.test_request_context():
            delete_flowtable_from_data(mock_session, req)

        fts = capture.written_data["flowtables"]
        names = [ft["name"] for ft in fts]
        assert "FT-Alpha" not in names
        assert "FT-Beta" in names

    def test_delete_nonexistent_leaves_list_unchanged(self, app, mock_session, mock_read_write):
        data = _data_with_flowtables()
        capture = mock_read_write("package.flowtable_functions", data)
        req = make_request({"flowtable": "NonExistent"})
        with app.test_request_context():
            delete_flowtable_from_data(mock_session, req)

        fts = capture.written_data["flowtables"]
        assert len(fts) == 2


# ===================================================================
# list_flowtables
# ===================================================================


class TestListFlowtables:
    def test_sorted_list(self, app, mock_session, mock_read_write):
        data = _data_with_flowtables()
        mock_read_write("package.flowtable_functions", data)
        with app.test_request_context():
            result = list_flowtables(mock_session)

        names = [ft["name"] for ft in result]
        assert names == sorted(names)

    def test_empty_list(self, app, mock_session, mock_read_write):
        data = _minimal_data()
        mock_read_write("package.flowtable_functions", data)
        with app.test_request_context():
            result = list_flowtables(mock_session)

        assert result == []

    def test_multiple_flowtables(self, app, mock_session, mock_read_write):
        data = {
            "version": "1",
            "flowtables": [
                {"name": "Zebra", "description": "Z", "interfaces": ["eth0"]},
                {"name": "Alpha", "description": "A", "interfaces": ["eth1"]},
                {"name": "Middle", "description": "M", "interfaces": ["eth2"]},
            ],
        }
        mock_read_write("package.flowtable_functions", data)
        with app.test_request_context():
            result = list_flowtables(mock_session)

        names = [ft["name"] for ft in result]
        assert names == ["Alpha", "Middle", "Zebra"]
