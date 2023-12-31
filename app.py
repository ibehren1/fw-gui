"""
    VyOS Firewall Configuration Gui

    Basic Flask app to present web form and process post from it.
    Generates VyOS firewall CLI configuration commands to create
    the corresponding firewall rule.

    Copyright 2023 Isaac Behrens
"""

from flask import Flask, redirect, render_template, request, session, url_for
from waitress import serve
import os

from package.functions import add_rule_to_data, delete_rule_from_data, generate_config

app = Flask(__name__)
app.secret_key = "this is the secret key"


@app.route("/")
def index():
    if "firewall_name" in session:
        return redirect(url_for("display_rules"))
    else:
        return redirect(url_for("login"))


@app.route("/add_rule", methods=["POST"])
def add_rule():
    add_rule_to_data(session, request)

    return redirect(url_for("display_rules"))


@app.route("/add_rule_form")
def add_rule_form():
    if "firewall_name" not in session:
        return redirect(url_for("login"))
    else:
        return render_template(
            "add_rule_form.html", firewall_name=session["firewall_name"]
        )


@app.route("/delete_rule", methods=["POST"])
def delete_rule():
    delete_rule_from_data(session, request)

    return redirect(url_for("display_rules"))


@app.route("/delete_rule_form")
def delete_rule_form():
    if "firewall_name" not in session:
        return redirect(url_for("login"))
    else:
        return render_template(
            "delete_rule_form.html", firewall_name=session["firewall_name"]
        )


@app.route("/display_rules")
def display_rules():
    message = generate_config(session)

    return render_template(
        "firewall_results.html", message=message, firewall_name=session["firewall_name"]
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["firewall_name"] != "":
            session["firewall_name"] = request.form["firewall_name"]
            return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    # remove the firewall_name from the session if it's there
    session.pop("firewall_name", None)
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    # Look for FLASK_ENV environment variable.
    env = os.environ.get("FLASK_ENV") or False

    # If environment is set, run debug, else assume PROD
    if env:
        app.run(debug=True, host="0.0.0.0", port="8080")
    # Else, run app in production mode on port 8080.
    else:
        serve(app, host="0.0.0.0", port=8080)
