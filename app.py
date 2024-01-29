"""
    VyOS Firewall GUI

    Basic Flask app to present web forms and process posts from them.
    Generates VyOS firewall CLI configuration commands to create
    the corresponding firewall filters, chains and rules.

    Copyright 2024 Isaac Behrens
"""

#
# Library Imports
from datetime import datetime
from flask import flash, Flask, redirect, render_template, request, session, url_for
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from package.chain_functions import (
    add_rule_to_data,
    add_chain_to_data,
    assemble_list_of_rules,
    assemble_list_of_chains,
    assemble_detail_list_of_chains,
    delete_rule_from_data,
)
from package.database_functions import process_login, query_user_by_id, register_user
from package.data_file_functions import (
    initialize_data_dir,
    list_user_files,
    process_upload,
    write_user_data_file,
)
from package.filter_functions import (
    add_filter_rule_to_data,
    add_filter_to_data,
    assemble_list_of_filters,
    assemble_list_of_filter_rules,
    delete_filter_rule_from_data,
)
from package.generate_config import download_json_data, generate_config
from package.group_funtions import (
    add_group_to_data,
    assemble_list_of_groups,
    assemble_detail_list_of_groups,
    delete_group_from_data,
)
from waitress import serve
import os


#
# App Initialization
db_location = os.path.join(os.getcwd(), "data/database")

app = Flask(__name__)
app.secret_key = "this is the secret key"
app.config["UPLOAD_FOLDER"] = "./data/uploads"
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:////{db_location}/auth.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "user_login"


#
# Database User Table Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(40), nullable=False)
    password = db.Column(db.String(80), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    # return User.query.get(int(user_id))
    return db.session.execute(db.select(User).filter_by(id=user_id)).scalar_one()


#
# Root
@app.route("/")
@login_required
def index():
    return redirect(url_for("display_config"))


#
# Sessions
@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        login, session["data_dir"], session["username"] = process_login(
            bcrypt, db, request, User
        )
        if login:
            return redirect(url_for("index"))
    else:
        render_template("user_login_form.html", session="None")
    return render_template("user_login_form.html")


@app.route("/user_logout")
@login_required
def user_logout():
    print(
        f"{datetime.now()} User <{query_user_by_id(db, User, session['_user_id']).username}> logged out."
    )
    logout_user()
    session.clear()
    return redirect(url_for("index"))


@app.route("/user_registration", methods=["GET", "POST"])
def user_registration():
    if request.method == "POST":
        if register_user(bcrypt, db, request, User):
            return redirect(url_for("login"))
        else:
            return redirect(url_for("user_registration_form"))
    else:
        return render_template("user_registration_form.html")


#
# Groups
@app.route("/group_add", methods=["GET", "POST"])
@login_required
def group_add():
    if request.method == "POST":
        add_group_to_data(session, request)

        return redirect(url_for("group_view"))

    else:
        file_list = list_user_files(session)

        return render_template(
            "group_add_form.html",
            file_list=file_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/group_delete", methods=["GET", "POST"])
@login_required
def group_delete():
    if request.method == "POST":
        delete_group_from_data(session, request)

        return redirect(url_for("group_view"))

    else:
        file_list = list_user_files(session)
        group_list = assemble_list_of_groups(session)

        # If there are no groups, just display the config
        if group_list == []:
            return redirect(url_for("display_config"))

        return render_template(
            "group_delete_form.html",
            file_list=file_list,
            firewall_name=session["firewall_name"],
            group_list=group_list,
            username=session["username"],
        )


@app.route("/group_view")
@login_required
def group_view():
    file_list = list_user_files(session)
    group_list = assemble_detail_list_of_groups(session)

    return render_template(
        "group_view.html",
        file_list=file_list,
        firewall_name=session["firewall_name"],
        group_list=group_list,
        username=session["username"],
    )


#
# Chains
@app.route("/chain_add", methods=["GET", "POST"])
@login_required
def chain_add():
    if request.method == "POST":
        add_chain_to_data(session, request)

        return redirect(url_for("chain_view"))

    else:
        file_list = list_user_files(session)

        return render_template(
            "chain_add_form.html",
            file_list=file_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/chain_rule_add", methods=["GET", "POST"])
@login_required
def chain_rule_add():
    if request.method == "POST":
        add_rule_to_data(session, request)

        return redirect(url_for("chain_view"))

    else:
        file_list = list_user_files(session)
        chain_list = assemble_list_of_chains(session)
        if chain_list == []:
            return redirect(url_for("chain_add"))

        return render_template(
            "chain_rule_add_form.html",
            chain_list=chain_list,
            file_list=file_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/chain_rule_delete", methods=["GET", "POST"])
@login_required
def chain_rule_delete():
    if request.method == "POST":
        delete_rule_from_data(session, request)

        return redirect(url_for("chain_view"))

    else:
        file_list = list_user_files(session)
        rule_list = assemble_list_of_rules(session)

        # If there are no rules, just display the config
        if rule_list == []:
            return redirect(url_for("display_config"))

        return render_template(
            "chain_rule_delete_form.html",
            file_list=file_list,
            firewall_name=session["firewall_name"],
            rule_list=rule_list,
            username=session["username"],
        )


@app.route("/chain_view")
@login_required
def chain_view():
    file_list = list_user_files(session)
    chain_dict = assemble_detail_list_of_chains(session)

    if chain_dict == {}:
        return redirect(url_for("chain_add"))

    return render_template(
        "chain_view.html",
        chain_dict=chain_dict,
        file_list=file_list,
        firewall_name=session["firewall_name"],
        username=session["username"],
    )


#
# Filters
@app.route("/filter_add", methods=["GET", "POST"])
@login_required
def filter_add():
    if request.method == "POST":
        add_filter_to_data(session, request)

        return redirect(url_for("display_config"))

    else:
        file_list = list_user_files(session)

        return render_template(
            "filter_add_form.html",
            file_list=file_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/filter_rule_add", methods=["GET", "POST"])
@login_required
def filter_rule_add():
    if request.method == "POST":
        add_filter_rule_to_data(session, request)

        return redirect(url_for("display_config"))

    else:
        file_list = list_user_files(session)
        filter_list = assemble_list_of_filters(session)
        chain_list = assemble_list_of_chains(session)
        if filter_list == []:
            return redirect(url_for("filter_add"))
        if chain_list == []:
            flash(
                f"Cannot add a filter rule if there are not chains to target.",
                "warning",
            )
            return redirect(url_for("filter_add"))

        return render_template(
            "filter_rule_add_form.html",
            chain_list=chain_list,
            file_list=file_list,
            filter_list=filter_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/filter_rule_delete", methods=["GET", "POST"])
@login_required
def filter_rule_delete():
    if request.method == "POST":
        delete_filter_rule_from_data(session, request)

        return redirect(url_for("display_config"))

    else:
        file_list = list_user_files(session)
        rule_list = assemble_list_of_filter_rules(session)

        # If there are no rules, just display the config
        if rule_list == []:
            return redirect(url_for("display_config"))

        return render_template(
            "filter_rule_delete_form.html",
            file_list=file_list,
            firewall_name=session["firewall_name"],
            rule_list=rule_list,
            username=session["username"],
        )


#
# Display Config
@app.route("/display_config")
@login_required
def display_config():
    file_list = list_user_files(session)

    if "firewall_name" not in session:
        message = "No firewall selected.<br><br>Please select a firewall from the list on the left."

        return render_template(
            "firewall_results.html",
            file_list=file_list,
            message=message,
            username=session["username"],
        )

    else:
        message = generate_config(session)

        return render_template(
            "firewall_results.html",
            file_list=file_list,
            firewall_name=session["firewall_name"],
            message=message,
            username=session["username"],
        )


#
# Create Config
@app.route("/create_config", methods=["POST"])
@login_required
def create_config():
    if request.form["config_name"] == "":
        flash("Config name cannot be empty", "danger")
        return redirect(url_for("index"))
    else:
        user_data = {}

        session["firewall_name"] = request.form["config_name"]
        write_user_data_file(
            f'{session["data_dir"]}/{request.form["config_name"]}', user_data
        )

    return redirect(url_for("display_config"))


#
# Delete Config
@app.route("/delete_config", methods=["POST"])
@login_required
def delete_config():
    if request.form["delete_config"] == "":
        flash("You must select a config to delete.", "danger")
        return redirect(url_for("index"))

    if "firewall_name" in session:
        if session["firewall_name"] == request.form["delete_config"]:
            session.pop("firewall_name")

    os.remove(f'{session["data_dir"]}/{request.form["delete_config"]}.json')
    flash(
        f'Firewall config {request.form["delete_config"]} has been deleted.', "success"
    )

    return redirect(url_for("display_config"))


#
# Download Config
@app.route("/download_config")
@login_required
def download_config():
    message = generate_config(session)

    return message.replace("<br>", "\n")


@app.route("/download_json")
@login_required
def download_json():
    json_data = download_json_data(session)

    return json_data


@app.route("/select_firewall_config", methods=["POST"])
@login_required
def select_firewall_config():
    session["firewall_name"] = request.form["file"]

    return redirect(url_for("display_config"))


@app.route("/upload_json", methods=["POST"])
@login_required
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
