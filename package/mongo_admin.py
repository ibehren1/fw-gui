"""
MongoDB server version and feature compatibility version (FCV).

MongoDB only starts a new major version on data whose FCV is the previous
major, and upgrading the binaries does not raise the FCV. An install whose FCV
trails its server version is therefore not ready for the next major upgrade.
See docs/mongodb-upgrade.md.

This module reports that state for Admin Settings, and can raise the FCV to
match the running server. It never lowers the FCV or sets it to anything other
than the server's own major.minor.
"""

import logging

from package import data_file_functions


def _major_minor(version):
    """'8.2.9' -> '8.2'."""
    major, minor = version.split(".")[:2]
    return f"{int(major)}.{int(minor)}"


def _as_tuple(version):
    return tuple(int(part) for part in version.split("."))


def fcv_status():
    """
    Reports the server version and feature compatibility version.

    Returns:
        dict: server (e.g. "8.2.9"), fcv (e.g. "8.0"), target (the FCV that
              matches the server, e.g. "8.2"), in_progress (an interrupted FCV
              change, whose target is in transition_to), state ("current",
              "behind", "in_progress" or "ahead") and error (None, or why the
              state could not be read, in which case the other keys are absent).
    """
    try:
        client = data_file_functions._get_mongo_client()
        server = client.server_info()["version"]
        reply = client.admin.command({"getParameter": 1, "featureCompatibilityVersion": 1})
    except Exception as e:  # noqa: BLE001 -- a status panel must never break the page
        logging.warning(f"Could not read MongoDB version/FCV: {e}")
        return {"error": str(e) or e.__class__.__name__}

    fcv_doc = reply.get("featureCompatibilityVersion", {})
    fcv = fcv_doc.get("version")
    if not fcv:
        return {"error": "MongoDB did not report a feature compatibility version."}

    target = _major_minor(server)
    # During an upgrade or downgrade MongoDB reports the old version plus
    # targetVersion. Running setFeatureCompatibilityVersion again completes it.
    transition_to = fcv_doc.get("targetVersion")

    if transition_to:
        state = "in_progress"
    elif _as_tuple(fcv) == _as_tuple(target):
        state = "current"
    elif _as_tuple(fcv) < _as_tuple(target):
        state = "behind"
    else:
        state = "ahead"

    return {
        "server": server,
        "fcv": fcv,
        "target": target,
        "in_progress": bool(transition_to),
        "transition_to": transition_to,
        "state": state,
        "error": None,
    }


def raise_fcv_to_server():
    """
    Raises the feature compatibility version to match the running server.

    Only ever raises, and only to the server's own major.minor. That is the
    step that has to happen before moving MongoDB to the next major version.
    An interrupted change is completed by running it again with its target.

    Returns:
        tuple: (ok, message). ok is False, and nothing changed, when the FCV
               already matches, is ahead of the server, the state cannot be
               read, or MongoDB refuses (for example, no admin rights).
    """
    status = fcv_status()
    if status["error"]:
        return False, f"Could not read the MongoDB version: {status['error']}"
    if status["state"] == "current":
        return False, f"The feature compatibility version already matches the server ({status['fcv']})."
    if status["state"] == "ahead":
        return False, "The feature compatibility version is ahead of the server; not changing it."

    target = status["transition_to"] if status["in_progress"] else status["target"]
    if _as_tuple(target) < _as_tuple(status["fcv"]):
        # An interrupted downgrade. Finishing it is a decision for a DBA, not
        # for a button whose job is to prepare an upgrade.
        return False, (
            f"An interrupted change towards {target} is a downgrade; complete or "
            "reverse it by hand (see docs/mongodb-upgrade.md)."
        )

    command = {"setFeatureCompatibilityVersion": target}
    # MongoDB 7.0+ requires an explicit confirm; older servers reject the field.
    if _as_tuple(status["target"])[0] >= 7:
        command["confirm"] = True

    try:
        data_file_functions._get_mongo_client().admin.command(command)
    except Exception as e:  # noqa: BLE001 -- report MongoDB's refusal to the admin
        details = getattr(e, "details", None) or {}
        reason = details.get("errmsg") or str(e) or e.__class__.__name__
        logging.error(f"setFeatureCompatibilityVersion {target} failed: {reason}")
        return False, f"MongoDB refused to change the feature compatibility version: {reason}"

    logging.warning(f"Feature compatibility version raised from {status['fcv']} to {target}.")
    return True, f"Feature compatibility version raised from {status['fcv']} to {target}."
