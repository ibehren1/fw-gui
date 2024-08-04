"""
    Database support functions.
"""

from datetime import datetime
from flask import flash
from flask_login import login_user
from package.data_file_functions import write_user_data_file
from packaging.version import Version
import json
import logging
import os
import urllib3

# B404 -- security implications considered.
import subprocess  # nosec


#
# Change Password
def change_password(bcrypt, db, User, username, request):
    # Get Inputs
    cur_password = request.form["current_password"]
    new_password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]

    # Basic Validations
    # B105 -- Not a hardcoded password.
    if new_password == "":  # nosec
        flash("New password cannot be empty.", "danger")
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

    # Query User table
    result = query_user_by_username(db, User, username)

    # Check if old password matches
    if bcrypt.check_password_hash(result.password, cur_password):
        # Hash new password
        hashed_password = bcrypt.generate_password_hash(new_password)

        # Update User table
        result.password = hashed_password
        db.session.commit()
        logging.info(f"{datetime.now()} User <{result.username}> changed password.")
        flash("Password changed.", "success")
        return True

    else:
        flash("Current password was incorrect.", "warning")
        return False


#
# Check Verion
def check_version():
    with open(".version", "r") as f:
        local_version = f.read().replace("v", "")

    try:
        # Get remote version from https://raw.githubusercontent.com/ibehren1/fw-gui/master/.version
        resp = urllib3.request(
            "GET", "https://raw.githubusercontent.com/ibehren1/fw-gui/master/.version"
        )
        remote_version = resp.data.decode("utf-8").replace("v", "")
        print(f"Remote version: {remote_version}")
    except:
        print("Unable to check remote version.")
        remote_version = "0.0.0"

    if remote_version != "0.0.0":
        if Version(local_version) < Version(remote_version):
            flash(f"New version v{remote_version} available.", "warning")

        if Version(local_version) > Version(remote_version):
            flash("Running dev version.", "warning")
    return


#
# Process login from user/password
def process_login(bcrypt, db, request, User):
    if request.form["username"] == "":
        return False, None, None

    result = query_user_by_username(db, User, request.form["username"])

    if result is None:
        flash("Login incorrect.", "warning")
        return False, None, None

    else:
        if bcrypt.check_password_hash(result.password, request.form["password"]):
            logging.info(
                f'{datetime.now()} User <{request.form["username"]}> logged in.'
            )
            login_user(result)
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


#
# Query User table by id
def query_user_by_id(db, User, id):
    try:
        result = db.session.execute(db.select(User).filter_by(id=id)).scalar_one()
    except:
        result = None
    return result


#
# Query User table by username
def query_user_by_username(db, User, username):
    try:
        result = db.session.execute(
            db.select(User).filter_by(username=username)
        ).scalar_one()
    except:
        result = None
    return result


#
# Register a new user
def register_user(bcrypt, db, request, User):
    # Get Inputs
    email = request.form["email"]
    username = request.form["username"]
    password = request.form["password"]
    confirm_password = request.form["confirm_password"]

    # Basic Validations
    if username == "":
        flash("Username cannot be empty.", "danger")
        return False

    if email == "":
        flash("Email cannot be empty.", "danger")
        return False

    # B105 -- Not a hardcoded password.
    if password == "":  # nosec
        flash("Password cannot be empty", "danger")
        return False
    else:
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return False

    if query_user_by_username(db, User, username) is not None:
        flash("Username already exists.", "danger")
        return False

    # Hash Password and Create User
    hashed_password = bcrypt.generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()

    flash(f"User {username} created successfully.", "success")

    return True
