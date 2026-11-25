"""Tests for package/release_features.py (VyOS rolling-release features)."""

from package import release_features as rf


def _cfg(**release):
    return {"system": {"hostname": "None", "port": "None", "vyos_release": release}}


class TestGetRelease:
    def test_absent_is_stable(self):
        assert rf.get_release({}) == {
            "rolling": False,
            "milestone": None,
            "last_used_all": False,
        }

    def test_system_without_release_is_stable(self):
        assert rf.get_release({"system": {"hostname": "fw"}})["rolling"] is False

    def test_unknown_milestone_dropped(self):
        assert rf.get_release(_cfg(rolling=True, milestone="1999-01"))["milestone"] is None

    def test_stored_values(self):
        release = rf.get_release(_cfg(rolling=True, milestone="2026-08", last_used_all=True))
        assert release == {"rolling": True, "milestone": "2026-08", "last_used_all": True}


class TestEnabledFeatures:
    def test_stable_has_none(self):
        assert rf.enabled_features({}) == set()

    def test_rolling_aug_2026_has_last_used(self):
        assert "last_used" in rf.enabled_features(_cfg(rolling=True, milestone="2026-08"))

    def test_rolling_off_keeps_milestone_but_disables(self):
        assert rf.enabled_features(_cfg(rolling=False, milestone="2026-08")) == set()

    def test_older_milestone_excludes_newer_feature(self):
        assert rf.features_for(True, "2026-08") >= {"last_used"}
        assert rf.features_for(True, "2026-07") == set()

    def test_every_feature_has_a_milestone(self):
        ids = {m["id"] for m in rf.MILESTONES}
        for meta in rf.FEATURES.values():
            assert meta["since"] in ids

    def test_milestones_ordered(self):
        ids = [m["id"] for m in rf.MILESTONES]
        assert ids == sorted(ids)


class TestLastUsedAll:
    def test_needs_feature_enabled(self):
        assert rf.last_used_all(_cfg(rolling=False, milestone="2026-08", last_used_all=True)) is False

    def test_enabled(self):
        assert rf.last_used_all(_cfg(rolling=True, milestone="2026-08", last_used_all=True)) is True


class TestSetRelease:
    def test_enable(self):
        data = {"system": {"hostname": "fw", "port": "22"}}
        assert rf.set_release(data, True, "2026-08") is None
        assert data["system"]["vyos_release"] == {
            "rolling": True,
            "milestone": "2026-08",
            "last_used_all": False,
        }
        assert data["system"]["hostname"] == "fw"

    def test_rolling_requires_milestone(self):
        data = {}
        assert rf.set_release(data, True, None)
        assert data == {}

    def test_unknown_milestone_rejected(self):
        data = {}
        assert rf.set_release(data, True, "2030-01")
        assert rf.set_release(data, False, "bogus")
        assert data == {}

    def test_disable_keeps_milestone(self):
        data = _cfg(rolling=True, milestone="2026-08")
        assert rf.set_release(data, False, "2026-08") is None
        assert data["system"]["vyos_release"]["rolling"] is False
        assert data["system"]["vyos_release"]["milestone"] == "2026-08"


class TestMilestoneRows:
    def test_rows_list_feature_labels(self):
        rows = rf.milestone_rows()
        aug = next(r for r in rows if r["id"] == "2026-08")
        assert rf.FEATURES["last_used"]["label"] in aug["features"]


class TestSessionHelpers:
    def test_save_and_read(self, mock_session, mock_read_write):
        capture = mock_read_write("package.release_features", {"system": {}})
        err = rf.save_session_release(
            mock_session, {"rolling": "True", "milestone": "2026-08"}
        )
        assert err is None
        assert capture.written_filename == "data/testuser/test_firewall"
        release, feats = rf.get_session_release(mock_session)
        assert release["rolling"] is True
        assert feats == {"last_used"}

    def test_save_invalid_does_not_write(self, mock_session, mock_read_write):
        capture = mock_read_write("package.release_features", {"system": {}})
        err = rf.save_session_release(mock_session, {"rolling": "True", "milestone": ""})
        assert err
        assert capture.written_data is None
