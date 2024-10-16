"""
    Firewall GUI for use with VyOS

    Basic Flask app to present web forms and process posts from them.
    Generates VyOS firewall CLI configuration commands to create
    the corresponding firewall filters, chains and rules.

    Copyright 2024 Isaac Behrens
"""

#
# Library Imports
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import (
    flash,
    Flask,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from io import BytesIO
from package.auth_functions import (
    change_password,
    process_login,
    query_user_by_id,
    register_user,
)
from package.chain_functions import (
    add_rule_to_data,
    add_chain_to_data,
    assemble_list_of_rules,
    assemble_list_of_chains,
    assemble_detail_list_of_chains,
    delete_rule_from_data,
    reorder_chain_rule_in_data,
)
from package.data_file_functions import (
    add_extra_items,
    add_hostname,
    create_backup,
    delete_user_data_file,
    get_extra_items,
    get_system_name,
    initialize_data_dir,
    list_full_backups,
    list_snapshots,
    list_user_backups,
    list_user_files,
    list_user_keys,
    mongo_dump,
    process_upload,
    read_user_data_file,
    tag_snapshot,
    validate_mongodb_connection,
    write_user_command_conf_file,
    write_user_data_file,
)
from package.diff_functions import process_diff
from package.filter_functions import (
    add_filter_rule_to_data,
    add_filter_to_data,
    assemble_list_of_filters,
    assemble_list_of_filter_rules,
    assemble_detail_list_of_filters,
    delete_filter_rule_from_data,
    reorder_filter_rule_in_data,
)
from package.flowtable_functions import (
    add_flowtable_to_data,
    delete_flowtable_from_data,
    list_flowtables,
)
from package.generate_config import download_json_data, generate_config
from package.group_funtions import (
    add_group_to_data,
    assemble_list_of_groups,
    assemble_detail_list_of_groups,
    delete_group_from_data,
)
from package.interface_functions import (
    add_interface_to_data,
    delete_interface_from_data,
    list_interfaces,
)
from package.mongo_converter import mongo_converter
from package.napalm_ssh_functions import (
    commit_to_firewall,
    get_diffs_from_firewall,
    show_firewall_usage,
    test_connection,
)
from waitress import serve
import difflib
import logging
import os
import sys

# Load env vars from .env and .version
load_dotenv()

#
# Create handlers for logfile and stdout
handlers = []
if os.path.exists("data/log"):
    file_handler = logging.FileHandler(filename="data/log/app.log")
    handlers.append(file_handler)
stdout_handler = logging.StreamHandler(stream=sys.stdout)
handlers.append(stdout_handler)

# if os.environ("log_level") exists:
if "LOG_LEVEL" in os.environ:
    if os.environ.get("LOG_LEVEL") in logging._nameToLevel:
        # set log_level to os.environ("log_level")
        log_level = os.environ.get("LOG_LEVEL")
else:
    # set log_level to logging.INFO
    log_level = logging.INFO

#
# Setup logging and direct to both handlers
logging.basicConfig(
    encoding="utf-8",
    format="%(asctime)s:%(levelname)s:%(funcName)s\t%(message)s",
    handlers=handlers,
    level=log_level,
)
logging.info(f"Logging Level: {log_level}")

#
# App Initialization
db_location = os.path.join(os.getcwd(), "data/database")

with open(".version", "r") as f:
    os.environ["FWGUI_VERSION"] = f.read()

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY")
app.config["VERSION"] = os.environ.get("FWGUI_VERSION")
app.config["UPLOAD_FOLDER"] = "./data/uploads"
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:////{db_location}/auth.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    minutes=int(os.environ.get("SESSION_TIMEOUT"))
)

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
# Administration Settings
@app.route("/admin_settings", methods=["GET", "POST"])
@login_required
def admin_settings():
    if request.method == "POST":
        if "backup" in request.form:
            if request.form["backup"] == "full_backup":
                create_backup(session)

            if request.form["backup"] == "user_backup":
                create_backup(session, True)

            backup_list = list_user_backups(session)
            file_list = list_user_files(session)
            full_backup_list = list_full_backups(session)
            snapshot_list = list_snapshots(session)

        return render_template(
            "admin_settings_form.html",
            backup_list=backup_list,
            file_list=file_list,
            snapshot_list=snapshot_list,
            full_backup_list=full_backup_list,
            username=session["username"],
        )

    else:
        backup_list = list_user_backups(session)
        file_list = list_user_files(session)
        full_backup_list = list_full_backups(session)
        snapshot_list = list_snapshots(session)

        return render_template(
            "admin_settings_form.html",
            backup_list=backup_list,
            file_list=file_list,
            snapshot_list=snapshot_list,
            full_backup_list=full_backup_list,
            username=session["username"],
        )


@app.route("/download", methods=["POST"])
@login_required
def download():
    path = request.form["path"]
    filename = request.form["filename"]

    with open(path + filename, "rb") as f:
        data = f.read()
    return send_file(BytesIO(data), download_name=filename, as_attachment=True)


#
# Sessions
@app.route("/user_change_password", methods=["GET", "POST"])
@login_required
def user_change_password():
    if request.method == "POST":

        result = change_password(bcrypt, db, User, session["username"], request)

        if result:
            return redirect(url_for("index"))
        else:
            return redirect(url_for("user_change_password"))

    else:
        file_list = list_user_files(session)
        snapshot_list = list_snapshots(session)

        return render_template(
            "user_change_password_form.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            username=session["username"],
        )


@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        login, session["data_dir"], session["username"] = process_login(
            bcrypt, db, request, User
        )
        if login:
            return redirect(url_for("index"))
        else:
            return redirect(url_for("user_login"))
    else:
        registration = (
            True if (os.environ["DISABLE_REGISTRATION"] == "False") else False
        )
        logging.debug(f"Registration Enabled: {registration}")

        return render_template(
            "user_login_form.html",
            session="None",
            registration=registration,
        )


@app.route("/user_logout")
@login_required
def user_logout():
    logging.info(
        f"{datetime.now()} User <{query_user_by_id(db, User, session['_user_id']).username}> logged out."
    )
    logout_user()
    session.clear()
    return redirect(url_for("index"))


@app.route("/user_registration", methods=["GET", "POST"])
def user_registration():
    if request.method == "POST":
        registration = (
            True if (os.environ["DISABLE_REGISTRATION"] == "False") else False
        )

        if registration:
            if register_user(bcrypt, db, request, User):
                return redirect(url_for("user_login"))
            else:
                return redirect(url_for("user_registration"))
        else:
            return redirect(url_for("user_login"))
    else:
        registration = (
            True if (os.environ["DISABLE_REGISTRATION"] == "False") else False
        )

        if registration:
            return render_template("user_registration_form.html")
        else:
            return redirect(url_for("user_login"))


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
        snapshot_list = list_snapshots(session)

        return render_template(
            "group_add_form.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/group_delete", methods=["POST"])
@login_required
def group_delete():
    delete_group_from_data(session, request)
    return redirect(url_for("group_view"))


@app.route("/group_view")
@login_required
def group_view():
    file_list = list_user_files(session)
    group_list = assemble_detail_list_of_groups(session)
    snapshot_list = list_snapshots(session)

    return render_template(
        "group_view.html",
        file_list=file_list,
        snapshot_list=snapshot_list,
        firewall_name=session["firewall_name"],
        group_list=group_list,
        username=session["username"],
    )


#
# Interfaces
@app.route("/interface_add", methods=["GET", "POST"])
@login_required
def interface_add():
    if request.method == "POST":
        add_interface_to_data(session, request)

        return redirect(url_for("interface_view"))

    else:
        file_list = list_user_files(session)
        snapshot_list = list_snapshots(session)

        return render_template(
            "interface_add_form.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/interface_delete", methods=["GET", "POST"])
@login_required
def interface_delete():
    if request.method == "POST":
        delete_interface_from_data(session, request)

        return redirect(url_for("interface_view"))

    else:
        return redirect(url_for("display_config"))


@app.route("/interface_view")
@login_required
def interface_view():
    file_list = list_user_files(session)
    group_list = assemble_detail_list_of_groups(session)
    interface_list = list_interfaces(session)
    snapshot_list = list_snapshots(session)

    return render_template(
        "interface_view.html",
        file_list=file_list,
        snapshot_list=snapshot_list,
        firewall_name=session["firewall_name"],
        interface_list=interface_list,
        username=session["username"],
    )


#
# Flowtables
@app.route("/flowtable_add", methods=["GET", "POST"])
@login_required
def flowtable_add():
    if request.method == "POST":
        logging.info(f"POST: {request.form}")
        add_flowtable_to_data(session, request)

        return redirect(url_for("flowtable_view"))

    else:
        file_list = list_user_files(session)
        snapshot_list = list_snapshots(session)
        interface_list = list_interfaces(session)

        return render_template(
            "flowtable_add_form.html",
            file_list=file_list,
            interface_list=interface_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/flowtable_delete", methods=["GET", "POST"])
@login_required
def flowtable_delete():
    if request.method == "POST":
        delete_flowtable_from_data(session, request)

        return redirect(url_for("flowtable_view"))

    else:
        return redirect(url_for("display_config"))


@app.route("/flowtable_view")
@login_required
def flowtable_view():
    file_list = list_user_files(session)
    group_list = assemble_detail_list_of_groups(session)
    snapshot_list = list_snapshots(session)
    flowtable_list = list_flowtables(session)

    return render_template(
        "flowtable_view.html",
        file_list=file_list,
        snapshot_list=snapshot_list,
        firewall_name=session["firewall_name"],
        flowtable_list=flowtable_list,
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
        snapshot_list = list_snapshots(session)

        return render_template(
            "chain_add_form.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/chain_rule_add", methods=["GET", "POST"])
@login_required
def chain_rule_add():
    if request.method == "POST":
        if request.form["fw_chain"] == "":
            return redirect(url_for("chain_view"))
        else:
            add_rule_to_data(session, request)
            return redirect(
                url_for("chain_view") + "#" + request.form["fw_chain"].replace(",", "")
            )

    else:
        file_list = list_user_files(session)
        chain_list = assemble_list_of_chains(session)
        group_list = assemble_detail_list_of_groups(session)
        snapshot_list = list_snapshots(session)
        if chain_list == []:
            return redirect(url_for("chain_add"))

        if request.args.get("fw_chain"):
            fw_chain = request.args.get("fw_chain")
        else:
            fw_chain = ""

        return render_template(
            "chain_rule_add_form.html",
            chain_list=chain_list,
            file_list=file_list,
            snapshot_list=snapshot_list,
            chain_name=fw_chain,
            group_list=group_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/chain_rule_delete", methods=["POST"])
@login_required
def chain_rule_delete():
    delete_rule_from_data(session, request)
    return redirect(url_for("chain_view"))


@app.route("/chain_rule_reorder", methods=["GET", "POST"])
@login_required
def chain_rule_reorder():
    if request.method == "POST":
        anchor = reorder_chain_rule_in_data(session, request)

        return redirect(url_for("chain_view", _anchor=anchor))
    else:
        return redirect(url_for("chain_view"))


@app.route("/chain_view")
@login_required
def chain_view():
    file_list = list_user_files(session)
    chain_dict = assemble_detail_list_of_chains(session)
    snapshot_list = list_snapshots(session)

    if chain_dict == {}:
        return redirect(url_for("chain_add"))

    return render_template(
        "chain_view.html",
        chain_dict=chain_dict,
        file_list=file_list,
        snapshot_list=snapshot_list,
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

        return redirect(url_for("filter_view"))

    else:
        file_list = list_user_files(session)
        snapshot_list = list_snapshots(session)
        flowtable_list = list_flowtables(session)

        return render_template(
            "filter_add_form.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            flowtable_list=flowtable_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/filter_rule_add", methods=["GET", "POST"])
@login_required
def filter_rule_add():
    if request.method == "POST":
        add_filter_rule_to_data(session, request)

        return redirect(
            url_for("filter_view") + "#" + request.form["filter"].replace(",", "")
        )

    else:
        chain_list = assemble_list_of_chains(session)
        file_list = list_user_files(session)
        filter_list = assemble_list_of_filters(session)
        interface_list = list_interfaces(session)
        snapshot_list = list_snapshots(session)
        flowtable_list = list_flowtables(session)

        if request.args.get("filter"):
            filter = request.args.get("filter")
        else:
            filter = ""

        if filter_list == []:
            return redirect(url_for("filter_add"))

        if chain_list == []:
            flash(
                f"Cannot add a filter rule if there are not chains to target.",
                "warning",
            )
            return redirect(url_for("filter_add"))

        if interface_list == []:
            flash(
                f"Cannot add a filter rule if there are no interfaces to target.",
                "warning",
            )
            return redirect(url_for("interface_add"))

        return render_template(
            "filter_rule_add_form.html",
            chain_list=chain_list,
            file_list=file_list,
            snapshot_list=snapshot_list,
            filter_name=filter,
            filter_list=filter_list,
            flowtable_list=flowtable_list,
            firewall_name=session["firewall_name"],
            interface_list=interface_list,
            username=session["username"],
        )


@app.route("/filter_rule_delete", methods=["POST"])
@login_required
def filter_rule_delete():
    delete_filter_rule_from_data(session, request)
    return redirect(url_for("filter_view"))


@app.route("/filter_rule_reorder", methods=["GET", "POST"])
@login_required
def filter_rule_reorder():
    if request.method == "POST":
        anchor = reorder_filter_rule_in_data(session, request)

        return redirect(url_for("filter_view", _anchor=anchor))
    else:
        return redirect(url_for("filter_view"))


@app.route("/filter_view")
@login_required
def filter_view():
    file_list = list_user_files(session)
    filter_dict = assemble_detail_list_of_filters(session)
    snapshot_list = list_snapshots(session)

    if filter_dict == {}:
        return redirect(url_for("filter_add"))

    return render_template(
        "filter_view.html",
        file_list=file_list,
        snapshot_list=snapshot_list,
        filter_dict=filter_dict,
        firewall_name=session["firewall_name"],
        username=session["username"],
    )


#
# Configuration
@app.route("/configuration_extra_items", methods=["Get", "POST"])
@login_required
def configuration_extra_items():
    if request.method == "POST":
        logging.info(request.form["extra_items"])

        add_extra_items(session, request)

        return redirect(url_for("display_config"))

    else:
        file_list = list_user_files(session)
        extra_items = get_extra_items(session)
        snapshot_list = list_snapshots(session)

        return render_template(
            "configuration_extra_items.html",
            extra_items=extra_items,
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/configuration_hostname_add", methods=["GET", "POST"])
@login_required
def configuration_hostname_add():
    if request.method == "POST":
        add_hostname(session, request)
        session["hostname"] = request.form["hostname"]
        session["port"] = request.form["port"]

        return redirect(url_for("configuration_push"))

    else:
        file_list = list_user_files(session)
        snapshot_list = list_snapshots(session)

        return render_template(
            "configuration_hostname_add.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
        )


@app.route("/configuration_push", methods=["GET", "POST"])
@login_required
def configuration_push():
    if request.method == "POST":

        connection_string = {
            "hostname": session["hostname"],
            "username": request.form["username"],
            "password": request.form["password"],
            "port": session["port"],
        }
        if "ssh_key_name" in request.form:
            connection_string["ssh_key_name"] = request.form["ssh_key_name"]

        # Include 'delete firewall' before set commands
        message, config = generate_config(session)
        if "delete_before_set" in request.form:
            write_user_command_conf_file(session, config, delete=True)
        else:
            write_user_command_conf_file(session, config, delete=False)

        if request.form["action"] == "Show Firewall Usage":
            message = show_firewall_usage(connection_string, session)
        if request.form["action"] == "View Diffs":
            message = get_diffs_from_firewall(connection_string, session)
        if request.form["action"] == "Commit":
            message = commit_to_firewall(connection_string, session)
        file_list = list_user_files(session)
        key_list = list_user_keys(session)
        snapshot_list = list_snapshots(session)

        return render_template(
            "configuration_push.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            firewall_hostname=session["hostname"],
            firewall_port=session["port"],
            firewall_reachable=True,
            key_list=key_list,
            message=message,
            username=session["username"],
        )

    else:
        if session["hostname"] == "None":
            flash("Need to set firewall hostname and SSH port.", "warning")
            return redirect(url_for("configuration_hostname_add"))

        file_list = list_user_files(session)
        key_list = list_user_keys(session)
        message, config = generate_config(session)
        firewall_reachable = test_connection(session)
        snapshot_list = list_snapshots(session)

        return render_template(
            "configuration_push.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            firewall_hostname=session["hostname"],
            firewall_port=session["port"],
            firewall_reachable=firewall_reachable,
            key_list=key_list,
            message=message,
            username=session["username"],
        )


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


@app.route("/display_config")
@login_required
def display_config():
    file_list = list_user_files(session)
    snapshot_list = list_snapshots(session)

    if "firewall_name" not in session:
        message = "No firewall selected.<br><br>Please select a firewall from the list on the left or create a new one."

        return render_template(
            "configuration_display.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            message=message,
            username=session["username"],
        )

    else:
        snapshot_list = list_snapshots(session)
        message, config = generate_config(session)

        return render_template(
            "configuration_display.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            message=message,
            username=session["username"],
        )


@app.route("/snapshot_diff_choose")
@login_required
def snapshot_diff_choose():
    file_list = list_user_files(session)
    snapshot_list = list_snapshots(session)

    if "firewall_name" not in session:
        message = "No firewall selected.<br><br>Please select a firewall from the list on the left or create a new one."

        return render_template(
            "configuration_display.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            message=message,
            username=session["username"],
        )

    else:
        snapshot_list = list_snapshots(session)
        message, config = generate_config(session)

        return render_template(
            "snapshot_diff_choose.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            message=message,
            username=session["username"],
        )


@app.route("/snapshot_diff_display", methods=["GET", "POST"])
@login_required
def snapshot_diff_display():
    if request.method == "POST":
        if request.form["snapshot_1"] == request.form["snapshot_2"]:
            flash("Snapshots cannot be the same.", "danger")
            return redirect(url_for("snapshot_diff_choose"))
        if request.form["snapshot_1"] == "" or request.form["snapshot_2"] == "":
            flash("Select a snapshot from each list.", "danger")
            return redirect(url_for("snapshot_diff_choose"))

        html = process_diff(session, request)

        return render_template(
            "snapshot_diff_display.html",
            message=html,
        )
    else:
        file_list = list_user_files(session)
        snapshot_list = list_snapshots(session)
        message, config = generate_config(session)

        return render_template(
            "snapshot_diff_choose.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            message=message,
            username=session["username"],
        )


@app.route("/snapshot_tag_create", methods=["GET", "POST"])
@login_required
def snapshot_tag_create():
    if request.method == "POST":
        logging.info(request.form)

        tag_snapshot(session, request)

        return redirect(url_for("snapshot_tag_create"))

    else:
        file_list = list_user_files(session)
        snapshot_list = list_snapshots(session)
        message, config = generate_config(session)

        return render_template(
            "snapshot_tag_create.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            message=message,
            username=session["username"],
        )


@app.route("/delete_config", methods=["POST"])
@login_required
def delete_config():
    if request.form["delete_config"] == "":
        flash("You must select a config to delete.", "danger")
        return redirect(url_for("index"))

    if "firewall_name" in session:
        if session["firewall_name"] == request.form["delete_config"]:
            session.pop("firewall_name")

    delete_user_data_file(f'{session["data_dir"]}/{request.form["delete_config"]}')
    flash(
        f'Firewall config {request.form["delete_config"]} has been deleted.', "success"
    )

    return redirect(url_for("display_config"))


@app.route("/download_config")
@login_required
def download_config():
    message, config = generate_config(session)

    return message.replace("<br>", "\n")


@app.route("/download_json")
@login_required
def download_json():
    json_data = download_json_data(session)

    return json_data


@app.route("/select_firewall_config", methods=["POST"])
@login_required
def select_firewall_config():
    # If choosing Snapshot Diff
    if request.form["file"] == "Snapshot Diff":
        return redirect(url_for("snapshot_diff_choose"))
    # If selecting a snapshot
    if request.form["file"].__contains__("/"):
        session["firewall_name"] = request.form["file"].split("/")[0]
        snapshot = request.form["file"].split("/")[1]
        if snapshot == "delete":
            snapshot_name = request.form["file"].split("/")[2]
    # Else selecting a firewall config
    else:
        session["firewall_name"] = request.form["file"]
        snapshot = "current"

    # Execute a read to read the "snapshot" version into "current"
    read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', snapshot)

    # If snapshot name is "create", then create a snapshot with date/time stamp
    if snapshot == "create":
        snapshot_name = datetime.now().strftime("%m-%d-%Y %H:%M:%S")

        user_data = read_user_data_file(
            f'{session["data_dir"]}/{session["firewall_name"]}'
        )
        del user_data["tag"]
        write_user_data_file(
            f'{session["data_dir"]}/{session["firewall_name"]}',
            user_data,
            snapshot_name,
        )

    # If snapshot name is "delete" then delete a snapshot
    if snapshot == "delete":
        delete_user_data_file(
            f'{session["data_dir"]}/{session["firewall_name"]}/{snapshot_name}'
        )

    session["hostname"], session["port"] = get_system_name(session)

    return redirect(url_for("display_config"))


@app.route("/upload_json", methods=["POST"])
@login_required
def upload_json():
    process_upload(session, request, app)

    return redirect(url_for("index"))


if __name__ == "__main__":
    # Read version from .version and display
    with open(".version", "r") as f:
        logging.info(f"|---------------- FW-GUI version: {f.read()} ----------------|")
        logging.info(f"|                                                        |")
        logging.info(f"|                                                        |")
        logging.info(f"|            *** v1.4.0+ requires MongoDB ***            |")
        logging.info(f"|                                                        |")
        logging.info(f"|                                                        |")
        logging.info(f"|         See https://github.com/ibehren1/fw-gui         |")
        logging.info(f"|                            or                          |")
        logging.info(f"|        https://hub.docker.com/r/ibehren1/fw-gui        |")
        logging.info(f"|                                                        |")
        logging.info(f"|       for recommended docker-compose.yml updates.      |")
        logging.info(f"|                                                        |")
        logging.info(f"|                                                        |")
        logging.info(f"|--------------------------------------------------------|")

    # Load Environment Vars
    load_dotenv()

    # Initialize Data Directory
    initialize_data_dir()

    # Validate connection to MongoDB and create backup
    if validate_mongodb_connection(os.environ.get("MONGODB_URI")):
        mongo_converter()

    # Convert all .json files to MongoDB

    # If environment is set, run debug, else assume PROD
    if os.environ.get("FLASK_ENV") == "Development":
        # B201:A -- Intentional execution with Debug when env var set.
        # B104 -- Intentional binding to all IPs.
        app.run(debug=True, host="0.0.0.0", port="8080")  # nosec

    # Else, run app in production mode on port 8080.
    else:
        # B104 -- Intentional binding to all IPs.
        serve(app, host="0.0.0.0", port=8080, channel_timeout=120)  # nosec
