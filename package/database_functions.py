"""
    Database support functions.
"""
from datetime import datetime
from flask import flash
from flask_login import login_user


#
# Process login from user/password
def process_login(bcrypt, db, request, User):
    result = query_user_username(db, User, request.form["username"])

    if result is None:
        flash("Login incorrect.", "warning")
        return False

    else:
        if bcrypt.check_password_hash(result.password, request.form["password"]):
            print(f'{datetime.now()} User <{request.form["username"]}> logged in.')
            login_user(result)
        else:
            print(
                f'{datetime.now()} User <{request.form["username"]}> attempted login with incorrect password.'
            )
            flash("Login incorrect.", "warning")
            return False

    return True


#
# Query User table by username
def query_user_username(db, User, username):
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

    if query_user_username(db, User, username) is not None:
        flash("Username already exists.", "danger")
        return False

    # Hash Password and Create User
    hashed_password = bcrypt.generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()

    flash(f"User {username} created successfully.", "success")

    return True
