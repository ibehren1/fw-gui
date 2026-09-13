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
- MongoDB
- VyOS compatible device
"""

#
# Library Imports
import logging
import os
import sys
from datetime import datetime, timedelta
from io import BytesIO

import base64
import hashlib
from functools import wraps

import certifi
from cryptography.fernet import Fernet
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
from flask_login import LoginManager, login_required, logout_user
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from waitress import serve

from package.auth_functions import (
    change_password,
    process_login,
    register_user,
)
from package.chain_functions import (
    add_chain_to_data,
    add_rule_to_data,
    assemble_detail_list_of_chains,
    assemble_list_of_chains,
    delete_rule_from_data,
    move_chain_rule_in_data,
    reorder_chain_rule_in_data,
    resequence_chain_rules_in_data,
)
from package.data_file_functions import (
    AUTO_SNAPSHOT_TAG,
    SERVER_SELECTION_TIMEOUT_MS,
    add_extra_items,
    add_hostname,
    create_backup,
    create_snapshot,
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
    restore_snapshot,
    sweep_legacy_user_files,
    tag_snapshot,
    validate_mongodb_connection,
    write_user_data_file,
)
from package.diff_functions import process_diff
from package.filter_functions import (
    add_filter_rule_to_data,
    add_filter_to_data,
    assemble_detail_list_of_filters,
    assemble_list_of_filters,
    delete_filter_rule_from_data,
    move_filter_rule_in_data,
    reorder_filter_rule_in_data,
    resequence_filter_rules_in_data,
)
from package.flowtable_functions import (
    add_flowtable_to_data,
    delete_flowtable_from_data,
    list_flowtables,
)
from package.generate_config import (
    build_merge_config,
    download_json_data,
    generate_config,
)
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
from package.ssh_key_store import migrate_legacy_key_files
from package.telemetry_functions import telemetry_instance
from package.user_migration import migrate_sqlite_users
from package.user_store import get_user_by_session_id, list_usernames
from package.validators import is_safe_name

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
    if os.environ.get("LOG_LEVEL") in logging.getLevelNamesMapping():
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
# Initialize Flask application
# Load version from .version file into environment
try:
    with open(".version", "r") as f:
        os.environ["FWGUI_VERSION"] = f.read()
except OSError:
    logging.warning(".version file not found; defaulting version to 0.0.0.")
    os.environ["FWGUI_VERSION"] = "0.0.0"

# Get session timeout from environment or default to 120 minutes
try:
    session_lifetime = int(os.environ.get("SESSION_TIMEOUT"))
except Exception:
    session_lifetime = 120

# Configure Flask application settings
app = Flask(__name__)
# APP_SECRET_KEY ships with a well-known default (see .env / compose / Helm values)
# for quick start-up. Operators are expected to override it with a unique random
# value before any non-local use; the shipped default must not be trusted.
app.secret_key = os.environ.get("APP_SECRET_KEY")
# Fail loudly at startup rather than erroring on the first session/CSRF use.
# secret_key signs the session id and CSRF tokens and derives the session-secret
# encryption key; it must be set (all shipped configs set it).
if not app.secret_key:
    raise RuntimeError(
        "APP_SECRET_KEY is not set. Set it in the environment / .env before starting."
    )
app.config["VERSION"] = os.environ.get("FWGUI_VERSION")
app.config["UPLOAD_FOLDER"] = "./data/uploads"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=session_lifetime)

# Session cookie hardening. HttpOnly blocks JavaScript from reading the cookie;
# SameSite=Lax limits cross-site sending (defense-in-depth alongside CSRF
# tokens). Secure requires HTTPS, so it is opt-in via env to avoid breaking
# plain-HTTP deployments -- set SESSION_COOKIE_SECURE=True when serving over
# HTTPS (e.g. behind the recommended Nginx Proxy Manager).
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "False").strip().lower() == "true"
)

# Initialize password hashing
bcrypt = Bcrypt(app)

# Enable CSRF protection for all state-changing POST requests. Every rendered
# <form> must include {{ csrf_token() }}; the token is signed with APP_SECRET_KEY.
csrf = CSRFProtect(app)

# Store session data server-side so the browser cookie holds only an opaque,
# signed session id -- cached SSH credentials never travel to (or persist on)
# the client. Backed by the existing MongoDB by default; SESSION_TYPE can be
# overridden (e.g. "filesystem") for offline/test use.
session_type = os.environ.get("SESSION_TYPE", "mongodb")
app.config["SESSION_TYPE"] = session_type
app.config["SESSION_PERMANENT"] = True  # honors PERMANENT_SESSION_LIFETIME
if session_type == "mongodb":
    from pymongo import MongoClient

    # Bounded server selection, not pymongo's 30s default: this client is hit on
    # every single request (including the login page), so an unreachable database
    # would otherwise stall each one for half a minute and exhaust the waitress
    # thread pool.
    app.config["SESSION_MONGODB"] = MongoClient(
        os.environ["MONGODB_URI"],
        serverSelectionTimeoutMS=SERVER_SELECTION_TIMEOUT_MS,
    )
    app.config["SESSION_MONGODB_DB"] = os.environ.get(
        "MONGODB_DATABASE", "fwgui_database"
    )
    app.config["SESSION_MONGODB_COLLECT"] = "sessions"
Session(app)


def _session_fernet():
    """Fernet built from a key derived from APP_SECRET_KEY.

    Used to encrypt the cached SSH secret before it is stored in the
    server-side session, so the value is not readable in the session store
    (e.g. the MongoDB `sessions` collection) at rest.
    """
    secret = app.secret_key or os.environ.get("APP_SECRET_KEY", "")
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(value):
    """Encrypt a cached SSH secret for storage in the session. Empty stays empty."""
    if not value:
        return ""
    return _session_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(token):
    """Decrypt a cached SSH secret read from the session. Returns "" on failure."""
    if not token:
        return ""
    try:
        return _session_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception:
        return ""


def registration_enabled():
    """Whether new-user registration is allowed.

    Registration is enabled unless DISABLE_REGISTRATION is a truthy value.
    Parsing is case-insensitive and tolerant of an unset var (defaults to
    enabled, matching the shipped configuration).
    """
    return os.environ.get("DISABLE_REGISTRATION", "False").strip().lower() not in (
        "true",
        "1",
        "yes",
    )


def requires_firewall(view):
    """Redirect to the config page (with a prompt) when no firewall is selected.

    Routes that operate on the selected config read session["firewall_name"];
    without a selection that would KeyError (500). This guards them uniformly.
    """

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("firewall_name"):
            flash("Select or create a firewall configuration first.", "warning")
            return redirect(url_for("display_config"))
        return view(*args, **kwargs)

    return wrapper

@app.after_request
def set_security_headers(response):
    """Add defense-in-depth security response headers.

    HSTS is only emitted when the app is served over HTTPS (reusing the
    SESSION_COOKIE_SECURE signal) so plain-HTTP deployments are not pinned to
    HTTPS. CSP is intentionally not set here — a strict policy would break the
    inline scripts/handlers in the templates and warrants a separate, tested
    change.
    """
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if app.config.get("SESSION_COOKIE_SECURE"):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


@app.errorhandler(404)
def handle_404(error):
    """Friendly 404 instead of a bare error page."""
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def handle_500(error):
    """Log the exception and show a friendly page instead of a stack trace.

    Safety net for any unguarded session/dict access that would otherwise 500.
    """
    logging.exception("Unhandled server error")
    return (
        render_template(
            "error.html", code=500, message="Something went wrong."
        ),
        500,
    )


# Configure login manager for user authentication
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "user_login"


@login_manager.user_loader
def load_user(user_id):
    """
    Load a user from MongoDB by their Flask-Login session token.

    Runs on every authenticated request. Returns None for an unknown or
    disabled account, so disabling a user takes effect on their next request
    rather than at their next login.

    Args:
        user_id: The "_user_id" value Flask-Login stored in the session,
                 which is "u:<username>" (see user_store.SESSION_ID_PREFIX)

    Returns:
        User: The user_store.User if the account exists and is enabled,
              otherwise None
    """
    return get_user_by_session_id(user_id)


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
        result = change_password(bcrypt, session["username"], request)

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
        login, session["data_dir"], session["username"] = process_login(bcrypt, request)
        if login:
            return redirect(url_for("index"))
        else:
            return redirect(url_for("user_login"))
    else:
        registration = registration_enabled()
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
    username = session.get("username", "Unknown")
    logging.info(f"{datetime.now()} User <{username}> logged out.")
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
        registration = registration_enabled()

        if registration:
            if register_user(bcrypt, request):
                return redirect(url_for("user_login"))
            else:
                return redirect(url_for("user_registration"))
        else:
            return redirect(url_for("user_login"))
    else:
        registration = registration_enabled()

        if registration:
            return render_template("user_registration_form.html")
        else:
            return redirect(url_for("user_login"))


#
# Groups
@app.route("/group_add", methods=["GET", "POST"])
@login_required
@requires_firewall
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
        if request.form["type"] == "add":
            add_group_to_data(session, request)

        elif request.form["type"] == "edit":
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
@requires_firewall
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
@requires_firewall
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
@requires_firewall
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
        if request.form["type"] == "add":
            add_interface_to_data(session, request)

        elif request.form["type"] == "edit":
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
@requires_firewall
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
@requires_firewall
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
@requires_firewall
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
        if request.form["type"] == "add":
            add_flowtable_to_data(session, request)

        elif request.form["type"] == "edit":
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
@requires_firewall
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
@requires_firewall
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
@requires_firewall
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
@requires_firewall
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
        elif request.form["type"] == "edit":
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
@requires_firewall
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
@requires_firewall
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

        if anchor:
            return redirect(url_for("chain_view", _anchor=anchor))

        return redirect(url_for("chain_view"))
    else:
        return redirect(url_for("chain_view"))


@app.route("/chain_rule_move", methods=["POST"])
@login_required
@requires_firewall
def chain_rule_move():
    """
    Handle chain rule move up/down requests.

    Endpoint that swaps a chain rule's number with its neighbor's. Supports POST
    method only. Requires user to be logged in.

    Args:
        None

    Returns:
        Response: Redirect to chain view page (with optional anchor)
    """
    anchor = move_chain_rule_in_data(session, request)

    if anchor:
        return redirect(url_for("chain_view", _anchor=anchor))

    return redirect(url_for("chain_view"))


@app.route("/chain_rules_resequence", methods=["POST"])
@login_required
@requires_firewall
def chain_rules_resequence():
    """
    Handle chain rule resequence requests.

    Endpoint that renumbers all rules in a chain to 10, 20, 30, ... Supports POST
    method only. Requires user to be logged in.

    Args:
        None

    Returns:
        Response: Redirect to chain view page (with optional anchor)
    """
    anchor = resequence_chain_rules_in_data(session, request)

    if anchor:
        return redirect(url_for("chain_view", _anchor=anchor))

    return redirect(url_for("chain_view"))


@app.route("/chain_view")
@login_required
@requires_firewall
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
@requires_firewall
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
@requires_firewall
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
        if request.form["type"] == "add":
            add_filter_rule_to_data(session, request)

        elif request.form["type"] == "edit":
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
@requires_firewall
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
@requires_firewall
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

        if anchor:
            return redirect(url_for("filter_view", _anchor=anchor))

        return redirect(url_for("filter_view"))
    else:
        return redirect(url_for("filter_view"))


@app.route("/filter_rule_move", methods=["POST"])
@login_required
@requires_firewall
def filter_rule_move():
    """
    Handle filter rule move up/down requests.

    Endpoint that swaps a filter rule's number with its neighbor's. Supports POST
    method only. Requires user to be logged in.

    Args:
        None

    Returns:
        Response: Redirect to filter view page (with optional anchor)
    """
    anchor = move_filter_rule_in_data(session, request)

    if anchor:
        return redirect(url_for("filter_view", _anchor=anchor))

    return redirect(url_for("filter_view"))


@app.route("/filter_rules_resequence", methods=["POST"])
@login_required
@requires_firewall
def filter_rules_resequence():
    """
    Handle filter rule resequence requests.

    Endpoint that renumbers all rules in a filter to 10, 20, 30, ... Supports POST
    method only. Requires user to be logged in.

    Args:
        None

    Returns:
        Response: Redirect to filter view page (with optional anchor)
    """
    anchor = resequence_filter_rules_in_data(session, request)

    if anchor:
        return redirect(url_for("filter_view", _anchor=anchor))

    return redirect(url_for("filter_view"))


@app.route("/filter_view")
@login_required
@requires_firewall
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
@requires_firewall
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
@requires_firewall
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
@requires_firewall
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
        # Prefer freshly-typed credentials; otherwise reuse the values cached
        # in the (server-side) session so the secret never has to round-trip
        # through the browser on every submit.
        # The cached password is stored encrypted in the session; decrypt it as
        # the fallback when the form field is left blank.
        username = request.form.get("username") or session.get("ssh_user", "")
        password = request.form.get("password") or decrypt_secret(
            session.get("ssh_pass", "")
        )

        connection_string = {
            "hostname": session["hostname"],
            "username": username,
            "password": password,
            "port": session["port"],
        }

        # Keys are addressed in MongoDB by their bare name (ssh_key_store uses
        # _id = "<user>/<name>"). Pre-2.5.0 the form carried a trailing ".key"
        # because the name was used to build an on-disk path, so strip it here as
        # well as in the template: a browser still holding a cached copy of the
        # old form would otherwise submit a name that cannot resolve. removesuffix
        # rather than replace, so a key legitimately named "my.keyring" survives.
        ssh_key_name = request.form.get("ssh_key_name", "").removesuffix(".key")

        if ssh_key_name:
            connection_string["ssh_key_name"] = ssh_key_name

        # Cache SSH user/pass to the server-side session for this login. The
        # password/Fernet key is encrypted so it is not stored in cleartext in
        # the session store at rest.
        session["ssh_user"] = username
        session["ssh_pass"] = encrypt_secret(password)
        if ssh_key_name:
            session["ssh_keyname"] = ssh_key_name

        # generate_config() also supplies the message rendered when the action is
        # unrecognized, so it stays outside the branches below. build_merge_config
        # optionally includes 'delete firewall' before the set commands; it is
        # pure string work, so computing it up front costs nothing even for the
        # operational-command action that does not use it.
        message, config = generate_config(session)
        merge_config = build_merge_config(
            config, delete="delete_before_set" in request.form
        )

        if request.form["action"] == "Run Operational Command":
            message = run_operational_command(
                connection_string, session, request.form["op_command"]
            )
        elif request.form["action"] == "View Diffs":
            message = get_diffs_from_firewall(connection_string, session, merge_config)
        elif request.form["action"] == "Commit":
            message = commit_to_firewall(connection_string, session, merge_config)
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
            ssh_pass_cached=bool(session.get("ssh_pass")),
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
            ssh_user_name=session.get("ssh_user", ""),
            ssh_pass_cached=bool(session.get("ssh_pass")),
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
    elif not is_safe_name(request.form["config_name"]):
        flash("Invalid config name.", "danger")
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
@requires_firewall
def snapshot_diff_choose():
    """
    Display page for selecting snapshots to compare.

    Endpoint that shows interface for choosing two snapshots to diff.
    Requires user to be logged in and a firewall selected.

    Returns:
        Response: Rendered template for snapshot selection
    """
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


@app.route("/snapshot_diff_display", methods=["GET", "POST"])
@login_required
@requires_firewall
def snapshot_diff_display():
    """
    Display diff between two snapshots.

    Endpoint that shows differences between two selected snapshots.
    Requires user to be logged in and a firewall selected. Validates snapshots
    are different and selected.

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


@app.route("/snapshots")
@login_required
@requires_firewall
def snapshot_manage():
    """
    Manage the selected firewall's snapshots.

    Lists every snapshot with its tag and the actions that apply to it (tag,
    load, diff against the working copy, delete). The load, diff and delete
    actions post to their existing endpoints; only tagging is handled here.

    Returns:
        Response: Rendered snapshot management page
    """
    file_list = list_user_files(session)
    snapshot_list = list_snapshots(session)
    message, config = generate_config(session)

    return render_template(
        "snapshot_manage.html",
        file_list=file_list,
        snapshot_list=snapshot_list,
        firewall_name=session["firewall_name"],
        message=message,
        username=session["username"],
    )


@app.route("/snapshot_tag", methods=["POST"])
@login_required
@requires_firewall
def snapshot_tag():
    """
    Set or clear the tag on one snapshot.

    Returns:
        Response: Redirect back to the snapshot management page
    """
    tag_snapshot(session, request)

    return redirect(url_for("snapshot_manage"))


@app.route("/snapshot_tag_create")
@login_required
def snapshot_tag_create():
    """
    Redirect the old tag-only page to the snapshot management page.

    Kept so links and bookmarks to the previous URL keep working.

    Returns:
        Response: Redirect to snapshot_manage
    """
    return redirect(url_for("snapshot_manage"))


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

    if not is_safe_name(request.form["delete_config"]):
        flash("Invalid config name.", "danger")
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
@requires_firewall
def download_config():
    """
    Download the current firewall configuration as a text file.

    Returns:
        str: The configuration text with HTML line breaks converted to newlines
    """
    message, config = generate_config(session)
    text = message.replace("<br>", "\n")

    return send_file(
        BytesIO(text.encode("utf-8")),
        mimetype="text/plain",
        as_attachment=True,
        download_name=f"{session['firewall_name']}.conf",
    )


@app.route("/download_json")
@login_required
@requires_firewall
def download_json():
    """
    Download the current firewall configuration as a JSON file.

    Returns:
        str: The configuration data in JSON format
    """
    json_data = download_json_data(session)

    return send_file(
        BytesIO(json_data.encode("utf-8")),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"{session['firewall_name']}.json",
    )


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
    if "/" in request.form["file"]:
        parts = request.form["file"].split("/")
        if not is_safe_name(parts[0]):
            flash("Invalid firewall selection.", "danger")
            return redirect(url_for("display_config"))
        session["firewall_name"] = parts[0]
        snapshot = parts[1]
        if snapshot == "delete":
            if len(parts) < 3 or not is_safe_name(parts[2]):
                flash("Invalid snapshot selection.", "danger")
                return redirect(url_for("display_config"))
            snapshot_name = parts[2]
    # Else selecting a firewall config
    else:
        if not is_safe_name(request.form["file"]):
            flash("Invalid firewall selection.", "danger")
            return redirect(url_for("display_config"))
        session["firewall_name"] = request.form["file"]
        snapshot = "current"

    # Restore the selected snapshot into "current" (only for an actual
    # snapshot; current/create/delete are handled below).
    if snapshot not in ("current", "create", "delete"):
        # Safety net: the restore overwrites the working copy, so snapshot the
        # working copy first. Without this, loading a snapshot by mistake
        # discards unsaved work with no way back.
        auto_snapshot_name = create_snapshot(
            f"{session['data_dir']}/{session['firewall_name']}",
            AUTO_SNAPSHOT_TAG,
        )
        if auto_snapshot_name:
            flash(
                f"Working copy saved as snapshot {auto_snapshot_name}.",
                "success",
            )

        restore_snapshot(
            f"{session['data_dir']}/{session['firewall_name']}", snapshot
        )
        flash(f"Loaded snapshot {snapshot}.", "success")

    # If snapshot name is "create", then create a snapshot with date/time stamp
    if snapshot == "create":
        create_snapshot(f"{session['data_dir']}/{session['firewall_name']}")

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
    try:
        with open(".version", "r") as f:
            fwgui_version = f.read().strip()
    except OSError:
        fwgui_version = "unknown"
    logging.info(
        f"|---------------- FW-GUI version: {fwgui_version} ----------------|"
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

    # Check if MongoDB connection is valid using URI from environment variables
    # If connection is successful, run the startup migrations. Users must move
    # first: mongo_converter() gets its user list from the users collection.
    if validate_mongodb_connection(os.environ.get("MONGODB_URI")):
        migrate_sqlite_users()
        # Removes per-user files earlier releases left behind (.conf, .old).
        # Position is deliberate: after migrate_sqlite_users() because
        # list_usernames() needs the accounts in MongoDB -- on a pre-2.5.0
        # upgrade it would otherwise return nothing and sweep nothing -- and
        # before mongo_converter() because that is what creates the .old files,
        # so running it after would delete a file created seconds earlier. It
        # cannot live in initialize_data_dir() above either; that runs before
        # MongoDB is known to be reachable.
        accounts = list_usernames()
        # Adopts pre-2.5.0 data/<user>/*.key files into MongoDB. Same position
        # requirement as the sweep below: it needs the migrated account list.
        migrate_legacy_key_files(accounts)
        sweep_legacy_user_files(accounts)
        mongo_converter()

    # Post instance telemetry. Deliberately after the MongoDB check: the instance
    # id now lives in MongoDB, so running this first would mean waiting on the
    # database before the check that exists to report it is unreachable. The
    # trade-off is that an install which cannot reach MongoDB no longer reports at
    # all -- it used to post here and then exit in the check above.
    telemetry_instance()

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
