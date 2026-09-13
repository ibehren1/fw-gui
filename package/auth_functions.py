"""
Database support functions.
This module provides database operations for user management including:
- Password changes
- Version checking
- User authentication
- User registration
- Database queries
"""

import json
import logging
import os
import re

# B404 -- security implications considered.
from datetime import datetime

import urllib3
from flask import flash
from flask_login import login_user
from packaging.version import Version

from pymongo.errors import DuplicateKeyError

from package import user_store
from package.data_file_functions import write_user_data_file
from package.telemetry_functions import telemetry_instance
from package.validators import is_reserved_username, is_valid_username

# Minimum length for new/changed passwords (enforced on set, not on login).
MIN_PASSWORD_LENGTH = 8
# Basic email sanity check (not full RFC validation).
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _password_matches(bcrypt, user, candidate):
    """Returns True if ``candidate`` matches the stored hash.

    check_password_hash feeds the stored value to bcrypt.hashpw as the salt,
    which raises ValueError on an empty or malformed hash. Treat that as a
    failed login rather than letting it 500 the login page.
    """
    try:
        return bool(bcrypt.check_password_hash(user.password, candidate))
    except ValueError:
        logging.error(
            f"Stored password hash for user <{user.username}> is unusable; "
            "the account cannot log in until its password is reset."
        )
        return False


def change_password(bcrypt, username, request):
    """
    Changes a user's password after validating current and new passwords.

    Args:
        bcrypt: Password hashing utility
        username: Username of user changing password
        request: HTTP request containing form data

    Returns:
        bool: True if password change successful, False otherwise
    """
    # Get Inputs
    cur_password = request.form["current_password"]
    new_password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]

    # Basic Validations
    # B105 -- Not a hardcoded password.
    if new_password == "":  # nosec
        flash("New password cannot be empty.", "danger")
        return False
    if len(new_password) < MIN_PASSWORD_LENGTH:
        flash(
            f"New password must be at least {MIN_PASSWORD_LENGTH} characters.",
            "danger",
        )
        return False
    if new_password == username:
        flash("New password cannot be your username.", "danger")
        return False
    if new_password == cur_password:
        flash("New password cannot be the same as your current password.", "danger")
        return False
    if new_password != confirm_password:
        flash("Passwords do not match.", "warning")
        return False

    # Look the account up. A session can outlive the account it belongs to, so
    # this may legitimately be None rather than a bug.
    result = user_store.get_user_by_username(username)

    if result is None:
        logging.warning(
            f"{datetime.now()} Password change for unknown user <{username}>."
        )
        flash("Current password was incorrect.", "warning")
        return False

    # A disabled account must not be able to rotate its way back in.
    if result.disabled:
        logging.warning(
            f"{datetime.now()} Password change attempted on disabled user <{username}>."
        )
        flash("Current password was incorrect.", "warning")
        return False

    # Check if old password matches
    if _password_matches(bcrypt, result, cur_password):
        # Hash new password. generate_password_hash returns bytes; decode it so
        # the stored value is a str rather than BSON Binary.
        hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")

        if not user_store.set_password(username, hashed_password):
            logging.warning(
                f"{datetime.now()} Password change for <{username}> matched no account."
            )
            flash("Current password was incorrect.", "warning")
            return False

        logging.info(f"{datetime.now()} User <{result.username}> changed password.")
        flash("Password changed.", "success")
        return True

    else:
        flash("Current password was incorrect.", "warning")
        return False


def check_version():
    """
    Checks local version against remote version and displays notification if newer version exists.

    Reads local version from .version file and compares against version from GitHub.
    Displays warning if running development version or if update is available.
    """
    try:
        with open(".version", "r") as f:
            local_version = f.read().replace("v", "")
            logging.debug(f"Local version: {local_version}")
    except OSError:
        local_version = "0.0.0"

    try:
        # Get remote version from https://raw.githubusercontent.com/ibehren1/fw-gui/master/.version
        resp = urllib3.request(
            "GET",
            "https://raw.githubusercontent.com/ibehren1/fw-gui/master/.version",
            timeout=5.0,
        )
        remote_version = resp.data.decode("utf-8").replace("v", "")
        logging.debug(f"Remote version: {remote_version}")

    except Exception:
        logging.info("Unable to check remote version.")
        remote_version = "0.0.0"

    if remote_version != "0.0.0":
        if Version(local_version) < Version(remote_version):
            flash(f"New version v{remote_version} available.", "warning")

        if Version(local_version) > Version(remote_version):
            flash(f"Running development version v{local_version.strip()}.", "warning")

    return


def process_login(bcrypt, request):
    """
    Authenticates user login and sets up user environment.

    Args:
        bcrypt: Password hashing utility
        request: HTTP request containing login form data

    Returns:
        tuple: (success, data_dir, username)
            success (bool): True if login successful
            data_dir (str): User's data directory path
            username (str): Authenticated username
    """
    if request.form["username"] == "":
        return False, None, None

    result = user_store.get_user_by_username(request.form["username"])

    if result is None:
        flash("Login incorrect.", "warning")
        return False, None, None

    elif result.disabled:
        # Deliberately the same message as a bad password: telling the caller an
        # account exists but is disabled hands them account enumeration. The log
        # line is where an operator sees the difference.
        logging.warning(
            f'{datetime.now()} Disabled user <{request.form["username"]}> attempted login.'
        )
        flash("Login incorrect.", "warning")
        return False, None, None

    else:
        if _password_matches(bcrypt, result, request.form["password"]):
            logging.info(
                f'{datetime.now()} User <{request.form["username"]}> logged in.'
            )
            login_user(result)
            telemetry_instance()
            check_version()
            username = f"{result.username}"
            data_dir = f"data/{username}"
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)

                file = "examples/example.json"
                with open(file, "r") as f:
                    data = f.read()
                    user_data = json.loads(data)
                    if "_id" in user_data:
                        del user_data["_id"]
                    filename = file.replace(".json", "")
                    logging.info(f"Loading datafile {filename} into MongoDB.")
                    write_user_data_file(f"{data_dir}/example", user_data)

        else:
            logging.info(
                f'{datetime.now()} User <{request.form["username"]}> attempted login with incorrect password.'
            )
            flash("Login incorrect.", "warning")
            return False, None, None

    return True, data_dir, username


def register_user(bcrypt, request):
    """
    Registers a new user after validating inputs.

    Args:
        bcrypt: Password hashing utility
        request: HTTP request containing registration form data

    Returns:
        bool: True if registration successful, False otherwise
    """
    # Get Inputs
    email = request.form["email"]
    username = request.form["username"]
    password = request.form["password"]
    confirm_password = request.form["confirm_password"]

    # Basic Validations
    if username == "":
        flash("Username cannot be empty.", "danger")
        return False

    # A username is also the name of the user's MongoDB collection, so the
    # collections the application owns cannot be handed out as usernames.
    if is_reserved_username(username):
        flash("That username is reserved.", "danger")
        return False

    # Username becomes a directory name and a MongoDB collection name; hold it
    # to a strict allowlist to prevent path traversal / collection injection.
    if not is_valid_username(username):
        flash(
            "Username may only contain letters, numbers, dashes, underscores, and dots.",
            "danger",
        )
        return False

    if email == "":
        flash("Email cannot be empty.", "danger")
        return False

    if not _EMAIL_RE.match(email):
        flash("Enter a valid email address.", "danger")
        return False

    # B105 -- Not a hardcoded password.
    if password == "":  # nosec
        flash("Password cannot be empty", "danger")
        return False

    if len(password) < MIN_PASSWORD_LENGTH:
        flash(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", "danger"
        )
        return False

    if password != confirm_password:
        flash("Passwords do not match", "danger")
        return False

    # Hash Password and Create User. generate_password_hash returns bytes;
    # decode it so the stored value is a str rather than BSON Binary.
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    # The username is the document _id, so the insert itself is the uniqueness
    # check -- no query-then-insert window in which two registrations of the
    # same name both succeed.
    try:
        user_store.create_user(username, email, hashed_password)
    except DuplicateKeyError:
        flash("Username already exists.", "danger")
        return False

    flash(f"User {username} created successfully.", "success")

    return True
