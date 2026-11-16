"""
Tests for renaming a firewall configuration.

Covers: rename_user_data_file and the /rename_config route
"""

from unittest.mock import patch

import mongomock
import pytest

from package.data_file_functions import rename_user_data_file


@pytest.fixture
def coll(monkeypatch):
    """A mongomock collection for user 'alice', patched into the data layer."""
    client = mongomock.MongoClient()
    monkeypatch.setattr("package.data_file_functions._mongo_client", client)
    monkeypatch.setattr("package.data_file_functions._get_mongo_client", lambda: client)
    monkeypatch.setenv("MONGODB_DATABASE", "test_db")
    return client["test_db"]["alice"]


def _seed(coll):
    coll.insert_one({"_id": "edge", "version": "1", "ipv4": {"chains": {}},
                     "system": {"hostname": "fw", "port": "22", "host_key": {"key": "k"}}})
    coll.insert_one({"firewall": "edge", "snapshot": "s1", "tag": "t", "version": "1"})
    coll.insert_one({"firewall": "edge", "snapshot": "s2", "version": "1"})
    coll.insert_one({"_id": "other", "version": "1"})
    coll.insert_one({"firewall": "other", "snapshot": "s9", "version": "1"})


class TestRenameUserDataFile:
    def test_moves_config_and_its_snapshots(self, coll):
        _seed(coll)
        ok, msg = rename_user_data_file("data/alice", "edge", "edge-new")
        assert ok, msg
        assert coll.find_one({"_id": "edge"}) is None
        doc = coll.find_one({"_id": "edge-new"})
        assert doc["system"]["host_key"] == {"key": "k"}
        assert doc["ipv4"] == {"chains": {}}
        snaps = sorted(d["snapshot"] for d in coll.find({"firewall": "edge-new"}))
        assert snaps == ["s1", "s2"]
        assert coll.find_one({"firewall": "edge"}) is None
        assert coll.find_one({"firewall": "edge-new", "snapshot": "s1"})["tag"] == "t"

    def test_leaves_other_configs_alone(self, coll):
        _seed(coll)
        rename_user_data_file("data/alice", "edge", "edge-new")
        assert coll.find_one({"_id": "other"}) is not None
        assert coll.find_one({"firewall": "other", "snapshot": "s9"}) is not None

    def test_refuses_existing_name(self, coll):
        _seed(coll)
        ok, msg = rename_user_data_file("data/alice", "edge", "other")
        assert not ok and "already exists" in msg
        assert coll.find_one({"_id": "edge"}) is not None
        assert coll.count_documents({"firewall": "edge"}) == 2

    def test_refuses_name_with_orphaned_snapshots(self, coll):
        _seed(coll)
        # A deleted config leaves its snapshots behind.
        coll.insert_one({"firewall": "gone", "snapshot": "old", "version": "1"})
        ok, msg = rename_user_data_file("data/alice", "edge", "gone")
        assert not ok and "remain" in msg
        assert coll.find_one({"_id": "edge"}) is not None
        assert coll.count_documents({"firewall": "gone"}) == 1

    def test_refuses_missing_config(self, coll):
        ok, msg = rename_user_data_file("data/alice", "nope", "x")
        assert not ok and "does not exist" in msg

    def test_refuses_same_name(self, coll):
        _seed(coll)
        ok, _ = rename_user_data_file("data/alice", "edge", "edge")
        assert not ok
        assert coll.find_one({"_id": "edge"}) is not None


class TestRenameRoute:
    def _post(self, client, data, result=(True, "renamed")):
        with patch("app.rename_user_data_file", return_value=result) as m:
            resp = client.post("/rename_config", data=data)
        return resp, m

    def test_renames_and_follows_the_selection(self, auth_client):
        resp, m = self._post(auth_client, {"old_name": "test_firewall", "new_name": "edge-2"})
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/configurations")
        m.assert_called_once_with("data/testuser", "test_firewall", "edge-2")
        with auth_client.session_transaction() as sess:
            assert sess["firewall_name"] == "edge-2"
            sess["firewall_name"] = "test_firewall"

    def test_selection_unchanged_when_renaming_another_config(self, auth_client):
        self._post(auth_client, {"old_name": "lab", "new_name": "lab-2"})
        with auth_client.session_transaction() as sess:
            assert sess["firewall_name"] == "test_firewall"

    def test_selection_unchanged_on_failure(self, auth_client):
        self._post(auth_client, {"old_name": "test_firewall", "new_name": "taken"},
                   result=(False, "exists"))
        with auth_client.session_transaction() as sess:
            assert sess["firewall_name"] == "test_firewall"

    @pytest.mark.parametrize("new_name", ["", "bad/name", "../x"])
    def test_rejects_unsafe_names(self, auth_client, new_name):
        resp, m = self._post(auth_client, {"old_name": "test_firewall", "new_name": new_name})
        assert resp.status_code == 302
        m.assert_not_called()


def test_configurations_page_offers_rename(auth_client):
    with patch("app.list_user_files", return_value=["edge-fw-01"]), \
            patch("app.list_snapshots", return_value=[]):
        body = auth_client.get("/configurations").get_data(as_text=True)
    assert 'action="/rename_config"' in body
    assert 'name="old_name" value="edge-fw-01"' in body
    assert 'name="new_name" value="edge-fw-01"' in body
