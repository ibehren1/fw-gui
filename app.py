"""
FW-GUI for use with VyOS
Copyright © 2023-2026 Isaac Behrens. All rights reserved.

Basic Flask app to present web forms and process posts from them.
Generates VyOS firewall CLI configuration commands to create
the corresponding firewall filters, chains and rules.

Features:
- Web interface for managing VyOS firewall configurations
- User authentication and session management
- Firewall rule creation and management
- Chain and filter management
- Configuration backup and restore
- Direct VyOS device integration
- Diff comparison between configurations

Requirements:
- Python 3.x
- Flask web framework
- SQLAlchemy database
- VyOS compatible device
"""

#
# Library Imports
import logging
import os
import sys
from datetime import datetime, timedelta
from io import BytesIO

import certifi
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
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
from waitress import serve

from package.auth_functions import (
    change_password,
    process_login,
    query_user_by_id,
    register_user,
)
from package.chain_functions import (
    add_chain_to_data,
    add_rule_to_data,
    assemble_detail_list_of_chains,
    assemble_list_of_chains,
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
    list_user_files,
    list_user_keys,
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
    assemble_detail_list_of_filters,
    assemble_list_of_filters,
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
    run_operational_command,
    test_connection,
)
from package.telemetry_functions import telemetry_instance

# Set SSL certificate file path
os.environ["SSL_CERT_FILE"] = certifi.where()
os.environ["REQUESTS_CA_BUNDLE"] = certifi.where()

# Load environment variables from .env file and version from .version file
load_dotenv()

#
# Configure logging handlers for both file and console output
# Create empty list to store handlers
handlers = []
# If log directory exists, create and add file handler
if os.path.exists("data/log"):
    file_handler = logging.FileHandler(filename="data/log/app.log")
    handlers.append(file_handler)
# Create and add stdout handler for console output
stdout_handler = logging.StreamHandler(stream=sys.stdout)
handlers.append(stdout_handler)

# Set logging level from environment variable if it exists and is valid
# Otherwise default to INFO level
if "LOG_LEVEL" in os.environ:
    if os.environ.get("LOG_LEVEL") in logging._nameToLevel:
        log_level = os.environ.get("LOG_LEVEL")
    else:
        log_level = logging.INFO
else:
    log_level = logging.INFO

#
# Initialize logging with handlers and format
logging.basicConfig(
    encoding="utf-8",
    format="%(asctime)s:%(levelname)s:%(funcName)s\t%(message)s",
    handlers=handlers,
    level=log_level,
)
logging.info(f"Logging Level: {log_level}")

#
# Initialize Flask application and database
# Set database location to data/database directory
db_location = os.path.join(os.getcwd(), "data/database")

# Load version from .version file into environment
with open(".version", "r") as f:
    os.environ["FWGUI_VERSION"] = f.read()

# Get session timeout from environment or default to 120 minutes
try:
    session_lifetime = int(os.environ.get("SESSION_TIMEOUT"))
except Exception:
    session_lifetime = 120

# Configure Flask application settings
app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET_KEY")
app.config["VERSION"] = os.environ.get("FWGUI_VERSION")
app.config["UPLOAD_FOLDER"] = "./data/uploads"
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:////{db_location}/auth.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=session_lifetime)

# Initialize database and encryption
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Configure login manager for user authentication
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "user_login"


#
# Database User Table Model
class User(db.Model, UserMixin):
    """
    User model for authentication database.

    This class defines the database schema for storing user account information.
    It inherits from SQLAlchemy's Model class and Flask-Login's UserMixin.

    Attributes:
        id (int): Primary key for uniquely identifying users
        username (str): Unique username, max length 20 characters, required
        email (str): User's email address, max length 40 characters, required
        password (str): Hashed password, max length 80 characters, required
    """

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(40), nullable=False)
    password = db.Column(db.String(80), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    """
    Load a user from the database by their user ID.

    This function is used by Flask-Login to load a user object from the database
    given their user ID. It is required for the login manager to function.

    Args:
        user_id: The ID of the user to load from the database

    Returns:
        User: The User object if found, or None if not found

    Raises:
        NoResultFound: If no user with the given ID exists
    """
    return db.session.execute(
        db.select(User).filter_by(id=user_id)
    ).scalar_one_or_none()


#
# Root
@app.route("/")
@login_required
def index():
    """
    Root endpoint that redirects to the display_config view.

    Returns:
        Response: Redirect to the display_config endpoint
    """
    return redirect(url_for("display_config"))


#
# Administration Settings
@app.route("/admin_settings", methods=["GET", "POST"])
@login_required
def admin_settings():
    """
    Handle administration settings page requests.

    This endpoint allows users to manage backups and view system files.
    Supports both GET and POST methods.

    For POST requests:
    - Handles backup creation (full or user-specific)
    - Retrieves lists of backups, files and snapshots

    For GET requests:
    - Retrieves lists of backups, files and snapshots

    Returns:
        Response: Rendered admin_settings_form.html template with:
            - backup_list: List of user backups
            - file_list: List of user files
            - snapshot_list: List of system snapshots
            - full_backup_list: List of full system backups
            - username: Current user's username
    """
    if request.method == "POST":
        if "backup" in request.form:
            if request.form["backup"] == "full_backup":
                create_backup(session)

        file_list = list_user_files(session)
        full_backup_list = list_full_backups(session)
        snapshot_list = list_snapshots(session)

        return render_template(
            "admin_settings_form.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            full_backup_list=full_backup_list,
            username=session["username"],
        )

    else:
        file_list = list_user_files(session)
        full_backup_list = list_full_backups(session)
        snapshot_list = list_snapshots(session)

        return render_template(
            "admin_settings_form.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            full_backup_list=full_backup_list,
            username=session["username"],
        )


@app.route("/download", methods=["POST"])
@login_required
def download():
    """
    Handle file download requests.

    Endpoint that allows authenticated users to download files. The file path and name
    are provided in the POST request form data.

    Args:
        None

    Returns:
        Response: File download response with the requested file data

    Raises:
        None
    """
    path = request.form["path"]
    filename = request.form["filename"]
    full_path = os.path.realpath(path + filename)

    if not full_path.startswith(os.path.realpath("data/")):
        flash("Invalid file path.", "danger")
        return redirect(url_for("index"))

    with open(full_path, "rb") as f:
        data = f.read()
    return send_file(BytesIO(data), download_name=filename, as_attachment=True)


#
# Sessions
@app.route("/user_change_password", methods=["GET", "POST"])
@login_required
def user_change_password():
    """
    Handle password change requests.

    Endpoint that allows authenticated users to change their password. Supports both
    GET and POST methods.

    For POST requests:
    - Processes the password change request
    - Redirects to index on success, back to change password form on failure

    For GET requests:
    - Displays the password change form with user context

    Args:
        None

    Returns:
        Response: On POST - Redirect to index or password change form
                 On GET - Rendered password change form template

    Raises:
        None
    """
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
    """
    Handle user login requests.

    Endpoint that processes user login attempts. Supports both GET and POST methods.

    For POST requests:
    - Validates login credentials
    - Sets session data on successful login
    - Redirects to index page on success, back to login form on failure

    For GET requests:
    - Displays the login form
    - Shows registration option if enabled in environment settings

    Args:
        None

    Returns:
        Response: On POST - Redirect to index or login form
                 On GET - Rendered login form template with registration status

    Raises:
        None
    """
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
    """
    Handle user logout requests.

    Endpoint that processes user logout. Requires user to be logged in.
    Clears session data and logs the logout event.

    Args:
        None

    Returns:
        Response: Redirect to index page

    Raises:
        None
    """
    logging.info(
        f"{datetime.now()} User <{query_user_by_id(db, User, session['_user_id']).username}> logged out."
    )
    logout_user()
    session.clear()
    return redirect(url_for("index"))


@app.route("/user_registration", methods=["GET", "POST"])
def user_registration():
    """
    Handle user registration requests.

    Endpoint that processes new user registration. Supports both GET and POST methods.
    Registration can be disabled via environment settings.

    For POST requests:
    - Creates new user if registration is enabled
    - Redirects to login page on success
    - Redirects back to registration form on failure

    For GET requests:
    - Displays registration form if enabled
    - Redirects to login if registration is disabled

    Args:
        None

    Returns:
        Response: On POST - Redirect to login or registration form
                 On GET - Registration form template or redirect to login

    Raises:
        None
    """
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
    """
    Handle group addition requests.

    Endpoint that processes group creation. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Adds new group to the data using form input
    - Redirects to group view page

    For GET requests:
    - Displays the group addition form with file and snapshot lists

    Args:
        None

    Returns:
        Response: On POST - Redirect to group view page
                 On GET - Rendered group add form template
    """
    if request.method == "POST":
        logging.debug(request.form)
        if request.form["type"] == "add":
            add_group_to_data(session, request)

        if request.form["type"] == "edit":
            file_list = list_user_files(session)
            snapshot_list = list_snapshots(session)

            return render_template(
                "group_add_form.html",
                file_list=file_list,
                snapshot_list=snapshot_list,
                firewall_name=session["firewall_name"],
                username=session["username"],
                rule_detail=request.form,
            )

        return redirect(url_for("group_view"))

    else:
        file_list = list_user_files(session)
        snapshot_list = list_snapshots(session)
        rule_detail_defaults = {"ip_version": "ipv4", "group_type": "address-group"}

        return render_template(
            "group_add_form.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
            rule_detail=rule_detail_defaults,
        )


@app.route("/group_delete", methods=["POST"])
@login_required
def group_delete():
    """
    Handle group deletion requests.

    Endpoint that processes group deletion. Requires user to be logged in.
    Only accepts POST method.

    Args:
        None

    Returns:
        Response: Redirect to group view page after deletion
    """
    delete_group_from_data(session, request)
    return redirect(url_for("group_view"))


@app.route("/group_view")
@login_required
def group_view():
    """
    Handle group view requests.

    Endpoint that displays list of groups. Requires user to be logged in.
    Retrieves file list, group details and snapshots to display.

    Args:
        None

    Returns:
        Response: Rendered group view template with group details
    """
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
    """
    Handle interface addition requests.

    Endpoint that processes interface creation. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Adds new interface to the data using form input
    - Redirects to interface view page

    For GET requests:
    - Displays the interface addition form with file and snapshot lists

    Args:
        None

    Returns:
        Response: On POST - Redirect to interface view page
                 On GET - Rendered interface add form template
    """
    if request.method == "POST":
        logging.debug(request.form)
        if request.form["type"] == "add":
            add_interface_to_data(session, request)

        if request.form["type"] == "edit":
            file_list = list_user_files(session)
            snapshot_list = list_snapshots(session)

            return render_template(
                "interface_add_form.html",
                file_list=file_list,
                snapshot_list=snapshot_list,
                firewall_name=session["firewall_name"],
                username=session["username"],
                rule_detail=request.form,
            )

        return redirect(url_for("interface_view"))

    else:
        file_list = list_user_files(session)
        snapshot_list = list_snapshots(session)
        rule_detail_defaults = {"interface_name": "", "interface_desc": ""}

        return render_template(
            "interface_add_form.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
            rule_detail=rule_detail_defaults,
        )


@app.route("/interface_delete", methods=["GET", "POST"])
@login_required
def interface_delete():
    """
    Handle interface deletion requests.

    Endpoint that processes interface deletion. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Deletes interface from the data
    - Redirects to interface view page

    For GET requests:
    - Redirects to config display page

    Args:
        None

    Returns:
        Response: On POST - Redirect to interface view page
                 On GET - Redirect to config display page
    """
    if request.method == "POST":
        delete_interface_from_data(session, request)

        return redirect(url_for("interface_view"))

    else:
        return redirect(url_for("display_config"))


@app.route("/interface_view")
@login_required
def interface_view():
    """
    Handle interface view requests.

    Endpoint that displays list of interfaces. Requires user to be logged in.
    Retrieves file list, group details, interface list and snapshots to display.

    Args:
        None

    Returns:
        Response: Rendered interface view template with interface details
    """
    file_list = list_user_files(session)
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
    """
    Handle flowtable addition requests.

    Endpoint that processes flowtable creation. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Logs the form data
    - Adds new flowtable to the data using form input
    - Redirects to flowtable view page

    For GET requests:
    - Displays the flowtable addition form with file, snapshot and interface lists

    Args:
        None

    Returns:
        Response: On POST - Redirect to flowtable view page
                 On GET - Rendered flowtable add form template
    """
    if request.method == "POST":
        logging.debug(request.form)
        if request.form["type"] == "add":
            add_flowtable_to_data(session, request)

        if request.form["type"] == "edit":
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
                flowtable_detail=request.form,
            )

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
            flowtable_detail={},
        )


@app.route("/flowtable_delete", methods=["GET", "POST"])
@login_required
def flowtable_delete():
    """
    Handle flowtable deletion requests.

    Endpoint that processes flowtable deletion. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Deletes flowtable from the data
    - Redirects to flowtable view page

    For GET requests:
    - Redirects to config display page

    Args:
        None

    Returns:
        Response: On POST - Redirect to flowtable view page
                 On GET - Redirect to config display page
    """
    if request.method == "POST":
        delete_flowtable_from_data(session, request)

        return redirect(url_for("flowtable_view"))

    else:
        return redirect(url_for("display_config"))


@app.route("/flowtable_view")
@login_required
def flowtable_view():
    """
    Handle flowtable view requests.

    Endpoint that displays list of flowtables. Requires user to be logged in.
    Retrieves file list, group details, flowtable list and snapshots to display.

    Args:
        None

    Returns:
        Response: Rendered flowtable view template with flowtable details
    """
    file_list = list_user_files(session)
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
    """
    Handle chain addition requests.

    Endpoint that processes chain creation. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Adds new chain to the data using form input
    - Redirects to chain view page

    For GET requests:
    - Displays the chain addition form with file and snapshot lists

    Args:
        None

    Returns:
        Response: On POST - Redirect to chain view page
                 On GET - Rendered chain add form template
    """
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
    """
    Handle chain rule addition requests.

    Endpoint that processes chain rule creation. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - If no chain specified, redirects to chain view
    - Otherwise adds new rule to the chain and redirects to that chain's section

    For GET requests:
    - If no chains exist, redirects to chain creation
    - Displays the rule addition form with chain, file, group and snapshot lists
    - Pre-populates chain name if provided in URL args

    Args:
        None

    Returns:
        Response: On POST - Redirect to chain view page (with optional anchor)
                 On GET - Rendered rule add form template or redirect
    """
    if request.method == "POST":
        logging.debug(request.form)
        if request.form["type"] == "add":
            if request.form["fw_chain"] == "":
                return redirect(url_for("chain_view"))
            else:
                add_rule_to_data(session, request)
                return redirect(
                    url_for("chain_view")
                    + "#"
                    + request.form["fw_chain"].replace(",", "")
                )
        if request.form["type"] == "edit":
            file_list = list_user_files(session)
            chain_list = assemble_list_of_chains(session)
            group_list = assemble_detail_list_of_groups(session)
            snapshot_list = list_snapshots(session)
            if chain_list == []:
                return redirect(url_for("chain_add"))

            return render_template(
                "chain_rule_add_form.html",
                chain_list=chain_list,
                file_list=file_list,
                snapshot_list=snapshot_list,
                group_list=group_list,
                firewall_name=session["firewall_name"],
                username=session["username"],
                rule_detail=request.form,
            )

    else:
        file_list = list_user_files(session)
        chain_list = assemble_list_of_chains(session)
        group_list = assemble_detail_list_of_groups(session)
        snapshot_list = list_snapshots(session)
        if chain_list == []:
            return redirect(url_for("chain_add"))

        rule_detail_defaults = {
            "chain": request.args.get("fw_chain"),
            "action": "accept",
            "protocol": "",
            "dest_address_type": "address",
            "dest_port_type": "port",
            "source_address_type": "address",
            "source_port_type": "port",
        }

        return render_template(
            "chain_rule_add_form.html",
            chain_list=chain_list,
            file_list=file_list,
            snapshot_list=snapshot_list,
            group_list=group_list,
            firewall_name=session["firewall_name"],
            username=session["username"],
            rule_detail=rule_detail_defaults,
        )


@app.route("/chain_rule_delete", methods=["POST"])
@login_required
def chain_rule_delete():
    """
    Handle chain rule deletion requests.

    Endpoint that processes chain rule deletion. Supports POST method only.
    Requires user to be logged in.

    Args:
        None

    Returns:
        Response: Redirect to chain view page
    """
    delete_rule_from_data(session, request)
    return redirect(url_for("chain_view"))


@app.route("/chain_rule_reorder", methods=["GET", "POST"])
@login_required
def chain_rule_reorder():
    """
    Handle chain rule reordering requests.

    Endpoint that processes chain rule reordering. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Reorders the rule and redirects to the chain's section

    For GET requests:
    - Redirects to chain view page

    Args:
        None

    Returns:
        Response: Redirect to chain view page (with optional anchor)
    """
    if request.method == "POST":
        anchor = reorder_chain_rule_in_data(session, request)

        return redirect(url_for("chain_view", _anchor=anchor))
    else:
        return redirect(url_for("chain_view"))


@app.route("/chain_view")
@login_required
def chain_view():
    """
    Handle chain view requests.

    Endpoint that displays list of chains and their rules. Requires user to be logged in.
    If no chains exist, redirects to chain creation page.
    Retrieves file list, chain details and snapshots to display.

    Args:
        None

    Returns:
        Response: Rendered chain view template with chain details or redirect to chain add
    """
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
    """
    Handle filter addition requests.

    Endpoint that processes filter creation. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Adds new filter and redirects to filter view page

    For GET requests:
    - Displays filter creation form with file list, snapshots and flowtables

    Args:
        None

    Returns:
        Response: Redirect to filter view or rendered filter add form template
    """
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
    """
    Handle filter rule addition requests.

    Endpoint that processes filter rule creation. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Adds new filter rule and redirects to filter view page with anchor

    For GET requests:
    - Displays filter rule creation form with chains, files, filters, interfaces etc.
    - Redirects to filter add if no filters exist
    - Shows warning and redirects if no chains or interfaces exist

    Args:
        None

    Returns:
        Response: Redirect to filter view/add or rendered filter rule add form template
    """
    if request.method == "POST":
        logging.debug(request.form)
        if request.form["type"] == "add":
            add_filter_rule_to_data(session, request)

        if request.form["type"] == "edit":
            chain_list = assemble_list_of_chains(session)
            file_list = list_user_files(session)
            filter_list = assemble_list_of_filters(session)
            interface_list = list_interfaces(session)
            snapshot_list = list_snapshots(session)
            flowtable_list = list_flowtables(session)

            filter = request.form["filter"]

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
                rule_detail=request.form,
            )

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
                "Cannot add a filter rule if there are not chains to target.",
                "warning",
            )
            return redirect(url_for("filter_add"))

        if interface_list == []:
            flash(
                "Cannot add a filter rule if there are no interfaces to target.",
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
            rule_detail={},
        )


@app.route("/filter_rule_delete", methods=["POST"])
@login_required
def filter_rule_delete():
    """
    Handle filter rule deletion requests.

    Endpoint that processes filter rule deletion. Supports POST method only.
    Requires user to be logged in.

    Args:
        None

    Returns:
        Response: Redirect to filter view page
    """
    delete_filter_rule_from_data(session, request)
    return redirect(url_for("filter_view"))


@app.route("/filter_rule_reorder", methods=["GET", "POST"])
@login_required
def filter_rule_reorder():
    """
    Handle filter rule reordering requests.

    Endpoint that processes filter rule reordering. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Reorders the rule and redirects to the filter's section

    For GET requests:
    - Redirects to filter view page

    Args:
        None

    Returns:
        Response: Redirect to filter view page (with optional anchor)
    """
    if request.method == "POST":
        anchor = reorder_filter_rule_in_data(session, request)

        return redirect(url_for("filter_view", _anchor=anchor))
    else:
        return redirect(url_for("filter_view"))


@app.route("/filter_view")
@login_required
def filter_view():
    """
    Handle filter view requests.

    Endpoint that displays list of filters and their rules. Requires user to be logged in.
    If no filters exist, redirects to filter creation page.
    Retrieves file list, filter details and snapshots to display.

    Args:
        None

    Returns:
        Response: Rendered filter view template with filter details or redirect to filter add
    """
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
    """
    Handle configuration extra items requests.

    Endpoint that manages extra configuration items. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Logs and adds extra items to configuration
    - Redirects to display config page

    For GET requests:
    - Retrieves file list, extra items and snapshots
    - Renders configuration extra items template

    Args:
        None

    Returns:
        Response: Redirect to display config or rendered extra items template
    """
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
    """
    Handle hostname configuration requests.

    Endpoint that manages firewall hostname configuration. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Adds hostname and port to session
    - Redirects to configuration push page

    For GET requests:
    - Retrieves file list and snapshots
    - Renders hostname configuration template

    Args:
        None

    Returns:
        Response: Redirect to config push or rendered hostname config template
    """
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
    """
    Handle configuration push requests.

    Endpoint that manages pushing configurations to firewall. Supports both GET and POST methods.
    Requires user to be logged in.

    For POST requests:
    - Creates connection string with credentials
    - Generates and writes config file
    - Performs requested action (show usage, view diffs, commit)
    - Renders push template with results

    For GET requests:
    - Checks if hostname is configured
    - Retrieves files, keys and tests connection
    - Renders push template with connection status

    Args:
        None

    Returns:
        Response: Rendered configuration push template or redirect to hostname config
    """
    if request.method == "POST":
        connection_string = {
            "hostname": session["hostname"],
            "username": request.form["username"],
            "password": request.form["password"],
            "port": session["port"],
        }

        if "ssh_key_name" in request.form and request.form["ssh_key_name"]:
            connection_string["ssh_key_name"] = request.form["ssh_key_name"]

        # Cache SSH user/pass to session.
        session["ssh_user"] = request.form["username"]
        session["ssh_pass"] = request.form["password"]
        if "ssh_key_name" in request.form and request.form["ssh_key_name"]:
            session["ssh_keyname"] = request.form["ssh_key_name"].replace(".key", "")

        # Include 'delete firewall' before set commands
        message, config = generate_config(session)
        if "delete_before_set" in request.form:
            write_user_command_conf_file(session, config, delete=True)
        else:
            write_user_command_conf_file(session, config, delete=False)

        if request.form["action"] == "Run Operational Command":
            message = run_operational_command(
                connection_string, session, request.form["op_command"]
            )
        if request.form["action"] == "View Diffs":
            message = get_diffs_from_firewall(connection_string, session)
        if request.form["action"] == "Commit":
            message = commit_to_firewall(connection_string, session)
        file_list = list_user_files(session)
        key_list = list_user_keys(session)
        snapshot_list = list_snapshots(session)
        if "op_command" in request.form:
            op_command = request.form["op_command"]
        else:
            op_command = "show firewall"

        return render_template(
            "configuration_push.html",
            file_list=file_list,
            snapshot_list=snapshot_list,
            firewall_name=session["firewall_name"],
            firewall_hostname=session["hostname"],
            firewall_port=session["port"],
            firewall_reachable=True,
            op_command=op_command,
            ssh_user_name=session["ssh_user"],
            ssh_pass=session["ssh_pass"],
            ssh_keyname=session.get("ssh_keyname", ""),
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
            ssh_user_name=session["ssh_user"],
            ssh_pass=session["ssh_pass"],
            ssh_keyname=session.get("ssh_keyname", ""),
            key_list=key_list,
            message=message,
            username=session["username"],
        )


@app.route("/create_config", methods=["POST"])
@login_required
def create_config():
    """
    Handle configuration creation requests.

    Endpoint that creates new firewall configurations. Supports POST method only.
    Requires user to be logged in.

    Validates config name is not empty, creates new user data file and updates session.

    Args:
        None

    Returns:
        Response: Redirect to index or display config page
    """
    if request.form["config_name"] == "":
        flash("Config name cannot be empty", "danger")
        return redirect(url_for("index"))
    else:
        user_data = {}

        session["firewall_name"] = request.form["config_name"]
        write_user_data_file(
            f"{session['data_dir']}/{request.form['config_name']}", user_data
        )

    return redirect(url_for("display_config"))


@app.route("/display_config")
@login_required
def display_config():
    """
    Handle configuration display requests.

    Endpoint that displays firewall configuration. Supports GET method only.
    Requires user to be logged in.

    Checks if firewall is selected and retrieves configuration details.

    Args:
        None

    Returns:
        Response: Rendered configuration display template with config details or selection message
    """
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
    """
    Display page for selecting snapshots to compare.

    Endpoint that shows interface for choosing two snapshots to diff.
    Requires user to be logged in.

    Returns:
        Response: Rendered template for snapshot selection or message if no firewall selected
    """
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
    """
    Display diff between two snapshots.

    Endpoint that shows differences between two selected snapshots.
    Requires user to be logged in. Validates snapshots are different and selected.

    Returns:
        Response: Rendered template showing diff or redirect back to selection on error
    """
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
    """
    Create tags for snapshots.

    Endpoint that handles creating and applying tags to snapshots.
    Requires user to be logged in.

    Returns:
        Response: Redirect to tag creation page or rendered template for tag creation
    """
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
    """
    Delete a firewall configuration.

    Endpoint that handles deletion of firewall configurations.
    Requires user to be logged in. Validates config is selected.
    Removes config from session if it was selected.

    Returns:
        Response: Redirect to config display page
    """
    if request.form["delete_config"] == "":
        flash("You must select a config to delete.", "danger")
        return redirect(url_for("index"))

    if "firewall_name" in session:
        if session["firewall_name"] == request.form["delete_config"]:
            session.pop("firewall_name")

    delete_user_data_file(f"{session['data_dir']}/{request.form['delete_config']}")
    flash(
        f"Firewall config {request.form['delete_config']} has been deleted.", "success"
    )

    return redirect(url_for("display_config"))


@app.route("/download_config")
@login_required
def download_config():
    """
    Download the current firewall configuration as a text file.

    Returns:
        str: The configuration text with HTML line breaks converted to newlines
    """
    message, config = generate_config(session)

    return message.replace("<br>", "\n")


@app.route("/download_json")
@login_required
def download_json():
    """
    Download the current firewall configuration as a JSON file.

    Returns:
        str: The configuration data in JSON format
    """
    json_data = download_json_data(session)

    return json_data


@app.route("/select_firewall_config", methods=["POST"])
@login_required
def select_firewall_config():
    """
    Handle selection of firewall configurations and snapshots.

    Processes form submissions for:
    - Selecting a firewall configuration
    - Creating snapshots of configurations
    - Deleting snapshots
    - Viewing snapshot diffs

    The function updates the session with the selected firewall name and
    handles reading/writing snapshot data as needed.

    Returns:
        Response: Redirects to either snapshot diff view or config display
    """
    # If choosing Snapshot Diff
    if request.form["file"] == "Snapshot Diff":
        return redirect(url_for("snapshot_diff_choose"))
    # If selecting a snapshot
    if request.form["file"].__contains__("/"):
        parts = request.form["file"].split("/")
        session["firewall_name"] = parts[0]
        snapshot = parts[1]
        if snapshot == "delete":
            if len(parts) < 3:
                flash("Invalid snapshot selection.", "danger")
                return redirect(url_for("display_config"))
            snapshot_name = parts[2]
    # Else selecting a firewall config
    else:
        session["firewall_name"] = request.form["file"]
        snapshot = "current"

    # Execute a read to read the "snapshot" version into "current"
    read_user_data_file(f"{session['data_dir']}/{session['firewall_name']}", snapshot)

    # If snapshot name is "create", then create a snapshot with date/time stamp
    if snapshot == "create":
        snapshot_name = datetime.now().strftime("%m-%d-%Y %H:%M:%S")

        user_data = read_user_data_file(
            f"{session['data_dir']}/{session['firewall_name']}"
        )
        if "tag" in user_data:
            del user_data["tag"]
        write_user_data_file(
            f"{session['data_dir']}/{session['firewall_name']}",
            user_data,
            snapshot_name,
        )

    # If snapshot name is "delete" then delete a snapshot
    if snapshot == "delete":
        delete_user_data_file(
            f"{session['data_dir']}/{session['firewall_name']}/{snapshot_name}"
        )

    # Load firewall values to session
    session["hostname"], session["port"] = get_system_name(session)

    # Clear any previously cached values for SSH
    # B105 -- Intentional hardcoding of password to ""
    session["ssh_user"] = ""
    session["ssh_pass"] = ""  # nosec
    session["ssh_keyname"] = ""

    return redirect(url_for("display_config"))


@app.route("/upload_json", methods=["POST"])
@login_required
def upload_json():
    """
    Handle upload of JSON configuration files.

    Processes the uploaded JSON file and stores it as a new firewall configuration.

    Returns:
        Response: Redirects to index page after processing upload
    """
    process_upload(session, request, app)

    return redirect(url_for("index"))


if __name__ == "__main__":
    # Read version from .version and display
    with open(".version", "r") as f:
        logging.info(
            f"|---------------- FW-GUI version: {f.read().strip()} ----------------|"
        )
        logging.info("|                                                        |")
        logging.info("|                                                        |")
        logging.info("|            *** v1.4.0+ requires MongoDB ***            |")
        logging.info("|                                                        |")
        logging.info("|                                                        |")
        logging.info("|         See https://github.com/ibehren1/fw-gui         |")
        logging.info("|                            or                          |")
        logging.info("|        https://hub.docker.com/r/ibehren1/fw-gui        |")
        logging.info("|                                                        |")
        logging.info("|       for recommended docker-compose.yml updates.      |")
        logging.info("|                                                        |")
        logging.info("|                                                        |")
        logging.info("|--------------------------------------------------------|")

    # Load environment variables from .env file
    load_dotenv()

    # Create and initialize the data directory for storing firewall configurations
    initialize_data_dir()

    # Post instance telemetry
    telemetry_instance()

    # Check if MongoDB connection is valid using URI from environment variables
    # If connection is successful, run converter to migrate data
    if validate_mongodb_connection(os.environ.get("MONGODB_URI")):
        mongo_converter()

    # Convert all existing JSON config files to MongoDB format

    # Check if running in development environment
    if os.environ.get("FLASK_ENV") == "Development":
        # Run Flask app in debug mode if in development
        # B201:A -- Intentional execution with Debug when env var set.
        # B104 -- Intentional binding to all IPs.
        app.run(debug=True, host="0.0.0.0", port="8080")  # nosec

    # Run in production mode if FLASK_ENV not set to Development
    else:
        # Use waitress WSGI server for production
        # B104 -- Intentional binding to all IPs.
        serve(app, host="0.0.0.0", port=8080, channel_timeout=120)  # nosec
