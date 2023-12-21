"""
    VyOS Firewall Configuration Gui

    Basic Flask app to present web form and process post from it.
    Generates VyOS firewall CLI configuration commands to create
    the corresponding firewall rule.

    Copyright 2023 Isaac Behrens
"""
from flask import Flask
from flask import request
from jinja2 import Environment
from jinja2 import FileSystemLoader

app = Flask(__name__)


@app.route("/")
def root():
    # Open and return firewall_form.html
    with open("firewall_form.html", "r") as f:
        return f.read()


@app.route("/generate_config", methods=["POST"])
def generate_config():
    # Set local vars from posted form data
    ip_version = request.form["ip_version"]
    fw_table = request.form["fw_table"]
    rule = request.form["rule"]
    description = request.form["description"]
    rule_disable = True if "rule_disable" in request.form else False
    logging = True if "logging" in request.form else False
    action = request.form["action"]
    dest_address = request.form["dest_address"]
    dest_address_type = request.form["dest_address_type"]
    dest_port = request.form["dest_port"]
    dest_port_type = request.form["dest_port_type"]
    source_address = request.form["source_address"]
    source_address_type = request.form["source_address_type"]
    source_port = request.form["source_port"]
    source_port_type = request.form["source_port_type"]
    protocol = request.form["protocol"] if "protocol" in request.form else ""
    state_est = True if "state_est" in request.form else False
    state_inv = True if "state_inv" in request.form else False
    state_new = True if "state_new" in request.form else False
    state_rel = True if "state_rel" in request.form else False

    # Create firewall configuration
    config = ["<html>", '<body style="background-color:#606263;color:aliceblue">']

    config.append("#\n# Rule {0}\n#".format(rule))

    # Disable
    if rule_disable:
        config.append(
            "set firewall {0} name {1} rule {2} disable".format(
                ip_version, fw_table, rule
            )
        )

    # Description
    config.append(
        "set firewall {0} name {1} rule {2} description '{3}'".format(
            ip_version, fw_table, rule, description
        )
    )

    # Action
    config.append(
        "set firewall {0} name {1} rule {2} action {3}".format(
            ip_version, fw_table, rule, action
        )
    )

    # Destination
    if dest_address != "":
        if dest_address_type == "address":
            config.append(
                "set firewall {0} name {1} rule {2} destination address {3}".format(
                    ip_version, fw_table, rule, dest_address
                )
            )
        elif dest_address_type == "address_group":
            config.append(
                "set firewall {0} name {1} rule {2} destination group address-group {3}".format(
                    ip_version, fw_table, rule, dest_address
                )
            )
        elif dest_address_type == "network_group":
            config.append(
                "set firewall {0} name {1} rule {2} destination group network-group {3}".format(
                    ip_version, fw_table, rule, dest_address
                )
            )
    if dest_port != "":
        if dest_port_type == "port":
            config.append(
                "set firewall {0} name {1} rule {2} destination port {3}".format(
                    ip_version, fw_table, rule, dest_port
                )
            )
        elif dest_port_type == "port_group":
            config.append(
                "set firewall {0} name {1} rule {2} destination group port-group {3}".format(
                    ip_version, fw_table, rule, dest_port
                )
            )

    # Source
    if source_address != "":
        if source_address_type == "address":
            config.append(
                "set firewall {0} name {1} rule {2} source address {3}".format(
                    ip_version, fw_table, rule, source_address
                )
            )
        elif source_address_type == "address_group":
            config.append(
                "set firewall {0} name {1} rule {2} source group address-group {3}".format(
                    ip_version, fw_table, rule, source_address
                )
            )
        elif source_address_type == "network_group":
            config.append(
                "set firewall {0} name {1} rule {2} source group network-group {3}".format(
                    ip_version, fw_table, rule, source_address
                )
            )
    if source_port != "":
        if source_port_type == "port":
            config.append(
                "set firewall {0} name {1} rule {2} source port {3}".format(
                    ip_version, fw_table, rule, source_port
                )
            )
        elif source_port_type == "port_group":
            config.append(
                "set firewall {0} name {1} rule {2} source group port-group {3}".format(
                    ip_version, fw_table, rule, source_address
                )
            )

    # Protocol
    if protocol != "":
        if ip_version == "ipv6" and protocol == "icmp":
            protocol = "ipv6-icmp"
        config.append(
            "set firewall {0} name {1} rule {2} protocol {3}".format(
                ip_version, fw_table, rule, protocol
            )
        )

    # Logging
    if logging:
        config.append(
            "set firewall {0} name {1} rule {2} log".format(ip_version, fw_table, rule)
        )

    # States
    if state_est:
        config.append(
            "set firewall {0} name {1} rule {2} state 'established'".format(
                ip_version, fw_table, rule
            )
        )
    if state_inv:
        config.append(
            "set firewall {0} name {1} rule {2} state 'invalid'".format(
                ip_version, fw_table, rule
            )
        )
    if state_new:
        config.append(
            "set firewall {0} name {1} rule {2} state 'new'".format(
                ip_version, fw_table, rule
            )
        )
    if state_rel:
        config.append(
            "set firewall {0} name {1} rule {2} state 'related'".format(
                ip_version, fw_table, rule
            )
        )

    # Convert list of lines to single string
    message = ""
    for line in config:
        message = message + line.replace("\n", "<br>") + "<br>"

    # Create Jinja2 environment and get template
    environment = Environment(loader=FileSystemLoader("templates/"))
    template = environment.get_template("firewall_results.html")

    # Render template with message
    results = template.render(message=message)

    # Return html page from rendered template
    return results


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port="8080")
