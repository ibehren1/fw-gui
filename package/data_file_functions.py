"""
    Data File Support Functions
"""
from flask import app, flash, redirect
from werkzeug.utils import secure_filename
import json
import os


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"json"}


def initialize_data_dir():
    if not os.path.exists("data"):
        os.makedirs("data")
    if not os.path.exists("data/uploads"):
        os.makedirs("data/uploads")
    if not os.path.exists("data/example.json"):
        os.system("cp examples/example.json data/example.json")

    return


def process_upload(session, request, app):
    if "file" not in request.files:
        flash(f"No file upload!", "danger")
        return
    else:
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file", "danger")
            return
        if file and allowed_file(file.filename):
            filename = f'{session["firewall_name"]}.json'
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        else:
            flash("Invalid file type, only .json files allowed.", "danger")

    try:
        with open(f"data/uploads/{filename}", "r") as f:
            data = f.read()
            json.loads(data)
            flash("File is valid JSON", "success")
            os.rename(f"data/uploads/{filename}", f"data/{filename}")
    except:
        flash("File is not valid JSON", "danger")

    return


def read_user_data_file(filename):
    try:
        with open(f"data/{filename}.json", "r") as f:
            data = f.read()
            user_data = json.loads(data)
            return user_data
    except:
        return {}


def write_user_data_file(filename, data):
    with open(f"data/{filename}.json", "w") as f:
        f.write(json.dumps(data, indent=4))
    return
