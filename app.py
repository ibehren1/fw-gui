"""
    VyOS Firewall Configuration Gui

    Basic Flask app to present web forms and process posts from them.
    Generates VyOS firewall CLI configuration commands to create
    the corresponding firewall tables and rules.

    Copyright 2024 Isaac Behrens
"""

from flask import flash, Flask, redirect, render_template, request, session, url_for
from waitress import serve
from package.filter_functions import (
    add_filter_rule_to_data,
    add_filter_to_data,
    assemble_list_of_filters,
    assemble_list_of_filter_rules,
    delete_filter_rule_from_data,
)
from package.data_file_functions import initialize_data_dir, process_upload
from package.generate_config import download_json_data, generate_config
from package.group_funtions import (
    add_group_to_data,
    assemble_list_of_groups,
    delete_group_from_data,
)
from package.table_functions import (
    add_rule_to_data,
    add_table_to_data,
    assemble_list_of_rules,
    assemble_list_of_tables,
    delete_rule_from_data,
)
import os

app = Flask(__name__)
app.secret_key = "this is the secret key"
app.config["UPLOAD_FOLDER"] = "./data/uploads"


#
# Root
@app.route("/")
def index():
    if "firewall_name" in session:
        return redirect(url_for("display_config"))
    else:
        return redirect(url_for("login"))


#
# Sessions
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


#
# Groups
@app.route("/add_group", methods=["POST"])
def add_group():
    add_group_to_data(session, request)

    return redirect(url_for("display_config"))


@app.route("/add_group_form")
def add_group_form():
    if "firewall_name" not in session:
        return redirect(url_for("login"))
    else:
        return render_template(
            "add_group_form.html",
            firewall_name=session["firewall_name"],
        )


@app.route("/delete_group", methods=["POST"])
def delete_group():
    delete_group_from_data(session, request)

    return redirect(url_for("display_config"))


@app.route("/delete_group_form")
def delete_group_form():
    if "firewall_name" not in session:
        return redirect(url_for("login"))
    else:
        group_list = assemble_list_of_groups(session)

        # If there are no groups, just display the config
        if group_list == []:
            return redirect(url_for("display_config"))

        return render_template(
            "delete_group_form.html",
            firewall_name=session["firewall_name"],
            group_list=group_list,
        )


#
# Tables
@app.route("/add_rule", methods=["POST"])
def add_rule():
    add_rule_to_data(session, request)

    return redirect(url_for("display_config"))


@app.route("/add_rule_form")
def add_rule_form():
    if "firewall_name" not in session:
        return redirect(url_for("login"))
    else:
        table_list = assemble_list_of_tables(session)
        if table_list == []:
            return redirect(url_for("add_table_form"))

        return render_template(
            "add_rule_form.html",
            firewall_name=session["firewall_name"],
            table_list=table_list,
        )


@app.route("/add_table", methods=["POST"])
def add_table():
    add_table_to_data(session, request)

    return redirect(url_for("display_config"))


@app.route("/add_table_form")
def add_table_form():
    if "firewall_name" not in session:
        return redirect(url_for("login"))
    else:
        return render_template(
            "add_table_form.html",
            firewall_name=session["firewall_name"],
        )


@app.route("/delete_rule", methods=["POST"])
def delete_rule():
    delete_rule_from_data(session, request)

    return redirect(url_for("display_config"))


@app.route("/delete_rule_form")
def delete_rule_form():
    if "firewall_name" not in session:
        return redirect(url_for("login"))
    else:
        rule_list = assemble_list_of_rules(session)

        # If there are no rules, just display the config
        if rule_list == []:
            return redirect(url_for("display_config"))

        return render_template(
            "delete_rule_form.html",
            firewall_name=session["firewall_name"],
            rule_list=rule_list,
        )


#
# Filters
@app.route("/add_filter_rule", methods=["POST"])
def add_filter_rule():
    add_filter_rule_to_data(session, request)

    return redirect(url_for("display_config"))


@app.route("/add_filter_rule_form")
def add_filter_rule_form():
    if "firewall_name" not in session:
        return redirect(url_for("login"))
    else:
        filter_list = assemble_list_of_filters(session)
        table_list = assemble_list_of_tables(session)
        if filter_list == []:
            return redirect(url_for("add_filter_form"))
        if table_list == []:
            return redirect(url_for("add_table_form"))

        return render_template(
            "add_filter_rule_form.html",
            firewall_name=session["firewall_name"],
            filter_list=filter_list,
            table_list=table_list,
        )


@app.route("/add_filter", methods=["POST"])
def add_filter():
    add_filter_to_data(session, request)

    return redirect(url_for("display_config"))


@app.route("/add_filter_form")
def add_filter_form():
    if "firewall_name" not in session:
        return redirect(url_for("login"))
    else:
        return render_template(
            "add_filter_form.html",
            firewall_name=session["firewall_name"],
        )


@app.route("/delete_filter_rule", methods=["POST"])
def delete_filter_rule():
    delete_filter_rule_from_data(session, request)

    return redirect(url_for("display_config"))


@app.route("/delete_filter_action_form")
def delete_filter_rule_form():
    if "firewall_name" not in session:
        return redirect(url_for("login"))
    else:
        rule_list = assemble_list_of_filter_rules(session)

        # If there are no rules, just display the config
        if rule_list == []:
            return redirect(url_for("display_config"))

        return render_template(
            "delete_filter_rule_form.html",
            firewall_name=session["firewall_name"],
            rule_list=rule_list,
        )


#
# Display Config
@app.route("/display_config")
def display_config():
    message = generate_config(session)

    return render_template(
        "firewall_results.html", message=message, firewall_name=session["firewall_name"]
    )


#
# Download Config
@app.route("/download_config")
def download_config():
    message = generate_config(session)

    return message.replace("<br>", "\n")


@app.route("/download_json")
def download_json():
    json_data = download_json_data(session)

    return json_data


@app.route("/upload_json", methods=["POST"])
def upload_json():
    process_upload(session, request, app)

    return redirect(url_for("index"))


if __name__ == "__main__":
    # Initialize Data Directory
    initialize_data_dir()

    # Look for FLASK_ENV environment variable.
    env = os.environ.get("FLASK_ENV") or False

    # If environment is set, run debug, else assume PROD
    if env:
        app.run(debug=True, host="0.0.0.0", port="8080")
    # Else, run app in production mode on port 8080.
    else:
        serve(app, host="0.0.0.0", port=8080)
