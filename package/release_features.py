"""
VyOS rolling-release features, per firewall config.

VyOS rolling builds gain features before a stable release (1.4, 1.5) does.
A config can be marked as targeting a rolling build of at least a given
month; features that rolling picked up by that month are then offered in the
forms and emitted by generate_config. Configs without the marker target
stable and are generated exactly as before.

Stored on the config document as

    system.vyos_release = {"rolling": bool, "milestone": "YYYY-MM",
                           "last_used_all": bool}

and absent until the user saves the VyOS release page.

Adding a feature: add a FEATURES entry whose "since" is the rolling month it
landed in, plus a MILESTONES entry for that month if there is none yet. The
dropdown deliberately lists only months where FW-GUI gained a feature.

Turning rolling off, or choosing an earlier milestone, keeps any per-rule
flags in the document but stops them being emitted, so the generated config
stays valid for the selected release and re-enabling restores them.
"""

from package.data_file_functions import read_user_data_file, write_user_data_file

# Feature key -> metadata. "since" is the first rolling month carrying it.
FEATURES = {
    "last_used": {
        "label": "Rule last-used tracking",
        "description": "Adds 'last-used' to chain and filter rules; "
        "'show firewall ... detail' then reports when each rule last matched.",
        "since": "2026-08",
        "ref": "T8221",
        "ref_url": "https://vyos.dev/T8221",
    },
}

# Selectable milestones, oldest first. Each id is a "YYYY-MM" month.
MILESTONES = [
    {"id": "2026-08", "label": "Rolling: Aug 2026+"},
]

_MILESTONE_IDS = {m["id"] for m in MILESTONES}


def get_release(user_data):
    """Return the config's release settings, defaulting to stable."""
    stored = (user_data.get("system") or {}).get("vyos_release") or {}
    milestone = stored.get("milestone")
    return {
        "rolling": bool(stored.get("rolling")),
        "milestone": milestone if milestone in _MILESTONE_IDS else None,
        "last_used_all": bool(stored.get("last_used_all")),
    }


def features_for(rolling, milestone):
    """Feature keys available for a rolling flag and milestone id."""
    if not rolling or milestone not in _MILESTONE_IDS:
        return set()
    return {key for key, meta in FEATURES.items() if meta["since"] <= milestone}


def enabled_features(user_data):
    """Feature keys enabled for this config (empty for stable)."""
    release = get_release(user_data)
    return features_for(release["rolling"], release["milestone"])


def last_used_all(user_data):
    """True when every rule should carry last-used for this config."""
    return "last_used" in enabled_features(user_data) and get_release(user_data)[
        "last_used_all"
    ]


def set_release(user_data, rolling, milestone, last_used_all=False):
    """
    Store release settings on user_data.

    Returns an error message for an invalid choice (nothing is changed),
    else None. With rolling off the milestone is kept, so switching rolling
    back on restores the previous choice.
    """
    if rolling and milestone not in _MILESTONE_IDS:
        return "Choose a rolling release milestone."
    if milestone and milestone not in _MILESTONE_IDS:
        return "Unknown rolling release milestone."
    user_data.setdefault("system", {})["vyos_release"] = {
        "rolling": bool(rolling),
        "milestone": milestone or None,
        "last_used_all": bool(last_used_all),
    }
    return None


def milestone_rows():
    """Dropdown rows: each milestone with the feature labels it turns on."""
    return [
        {
            **m,
            "features": [
                FEATURES[key]["label"] for key in sorted(features_for(True, m["id"]))
            ],
        }
        for m in MILESTONES
    ]


def _config_path(session):
    return f"{session['data_dir']}/{session['firewall_name']}"


def get_session_release(session):
    """(release settings, enabled feature keys) for the selected config."""
    user_data = read_user_data_file(_config_path(session))
    return get_release(user_data), enabled_features(user_data)


def save_session_release(session, form):
    """Apply the VyOS release form to the selected config; error or None."""
    user_data = read_user_data_file(_config_path(session))
    error = set_release(
        user_data,
        rolling=form.get("rolling") == "True",
        milestone=form.get("milestone") or None,
        last_used_all=form.get("last_used_all") == "True",
    )
    if error is None:
        write_user_data_file(_config_path(session), user_data)
    return error
