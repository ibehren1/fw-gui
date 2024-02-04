"""
    Napalm Functions
"""

from napalm import get_network_driver


def push_config_to_firewall(config):
    driver = get_network_driver("vyos")

    firewall = {
        "hostname": "vyos-ue-1.ibehr.people.aws.dev",
        "username": "vyos",
        "password": "vyos",
        "port": 22,
    }

    print("Configuring driver")

    vyos_router = driver(
        hostname=firewall["hostname"],
        username=firewall["username"],
        password=firewall["password"],
        optional_args={"port": firewall["port"]},
    )

    print("Opening connection")

    vyos_router.open()
    vyos_router.load_merge_candidate(filename=f"{config}.conf")

    print("Comparing configuration")
    diffs = vyos_router.compare_config()

    if bool(diffs) == True:
        print(diffs)
        print("Committing configuration")
        vyos_router.commit_config()
    else:
        print("No configuration changes to commit")
        vyos_router.discard_config()

    print("Closing connection")
    vyos_router.close()
