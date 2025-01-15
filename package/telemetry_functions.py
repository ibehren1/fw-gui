"""
    Telemetry Functions to provide feedback on usage to the developer.

    Only a UUID and FW-GUI version is posted to the telemetry server. 
"""

import json
import logging
import urllib3


def get_instance_id():
    with open("data/database/instance.id") as f:
        instance_id = f.read().strip()
        logging.debug(f"Instance ID: {instance_id}")

    return instance_id


def get_version():
    with open(".version", "r") as f:
        local_version = f.read().replace("v", "")
        logging.debug(f"Local version: {local_version}")

    return local_version


def post_telemetry(body, route):
    try:
        resp = urllib3.request(
            "POST",
            f"https://telemetry.fw-gui.com/{route}",
            headers={"Content-Type": "application/json"},
            body=body,
        )
        logging.debug("Posted instance ID and version to https://telemetry.fw-gui.com.")

    except:
        logging.debug("Unable to post instance ID.")


def telemetry_commit():
    instance_id = get_instance_id()

    body = json.dumps({"instance_id": instance_id})

    post_telemetry(body, "commit")


def telemetry_diff():
    instance_id = get_instance_id()

    body = json.dumps({"instance_id": instance_id})

    post_telemetry(body, "diff")


def telemetry_instance():
    local_version = get_version()
    instance_id = get_instance_id()

    body = json.dumps(
        {"instance_id": instance_id, "version": local_version.replace("\n", "")}
    )

    post_telemetry(body, "instance")


def telemetry_rule_usage():
    instance_id = get_instance_id()

    body = json.dumps({"instance_id": instance_id})

    post_telemetry(body, "rule_usage")
