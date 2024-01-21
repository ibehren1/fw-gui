"""
    Database support functions.
"""
from datetime import datetime
from flask import flash
from flask_login import login_user
import os


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
            print(f'{datetime.now()} User <{request.form["username"]}> logged in.')
            login_user(result)
            username = f"{result.username}"
            data_dir = f"data/{username}"
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)
                os.system(f"cp examples/example.json {data_dir}/example.json")
        else:
            print(
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

    if password == "":
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
