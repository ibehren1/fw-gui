"""
    VyOS Firewall Configuration Gui

    Basic Flask app to present web forms and process posts from them.
    Generates VyOS firewall CLI configuration commands to create
    the corresponding firewall tables and rules.

    Copyright 2024 Isaac Behrens
"""
from datetime import datetime
from flask import flash, Flask, redirect, render_template, request, session, url_for
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from package.database_functions import process_login, query_user_by_id, register_user
from flask_login import (
    LoginManager,
    UserMixin,
    login_required,
    login_user,
    logout_user,
)
from waitress import serve

from package.filter_functions import (
    add_filter_rule_to_data,
    add_filter_to_data,
    assemble_list_of_filters,
    assemble_list_of_filter_rules,
    delete_filter_rule_from_data,
)
from package.data_file_functions import (
    initialize_data_dir,
    list_user_files,
    process_upload,
)
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
login_manager.login_view = "login"


# class User(db.Model, UserMixin):
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(40), nullable=False)
    password = db.Column(db.String(80), nullable=False)


# Create DB if it does not exist -- should only happen on first run
if not os.path.exists("./data/database/auth.db"):
    with app.app_context():
        db.create_all()


@login_manager.user_loader
def load_user(user_id):
    # return User.query.get(int(user_id))
    return db.session.execute(db.select(User).filter_by(id=user_id)).scalar_one()


#
# Root
@app.route("/")
@login_required
def index():
    # if "firewall_name" in session:
    return redirect(url_for("display_config"))
    # else:
    # return redirect(url_for("login"))


#
# Sessions
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login, session["data_dir"] = process_login(bcrypt, db, request, User)
        if login:
            return redirect(url_for("index"))
    else:
        render_template("login.html", session="None")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    print(
        f"{datetime.now()} User <{query_user_by_id(db, User, session['_user_id']).username}> logged out."
    )
    logout_user()
    session.clear()
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def registration_form():
    if request.method == "POST":
        if register_user(bcrypt, db, request, User):
            return redirect(url_for("login"))
        else:
            return redirect(url_for("registration_form"))
    else:
        return render_template("registration_form.html")


#
# Groups
@app.route("/add_group", methods=["POST"])
def add_group():
    add_group_to_data(session, request)

    return redirect(url_for("display_config"))


@app.route("/add_group_form")
@login_required
def add_group_form():
    # if "firewall_name" not in session:
    #     return redirect(url_for("login"))
    # else:
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
@login_required
def display_config():
    # print(session["_user_id"], session["data_dir"], session["firewall_name"])
    file_list = list_user_files(session)

    if "firewall_name" not in session:
        message = "No firewall selected.<br><br>Please select a firewall from the list on the right."

        return render_template(
            "firewall_results.html", file_list=file_list, message=message
        )

    else:
        message = generate_config(session)

        return render_template(
            "firewall_results.html",
            file_list=file_list,
            firewall_name=session["firewall_name"],
            message=message,
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


@app.route("/select_firewall_config", methods=["POST"])
def select_firewall_config():
    session["firewall_name"] = request.form["file"]

    return redirect(url_for("display_config"))


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
