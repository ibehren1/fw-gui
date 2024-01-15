"""
    Data File Support Functions
"""
from flask import app, flash, redirect
import json
import os


#
# Determine if a file is a JSON file
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"json"}


#
# Initialize the data directory at App start
def initialize_data_dir():
    print("Initializing Data Directory...")

    if not os.path.exists("data"):
        print(" |\n |--> Data directory not found, creating...")
        os.makedirs("data")

    if not os.path.exists("data/database"):
        print(" |\n |--> Database directory not found, creating...")
        os.makedirs("data/database")

    if not os.path.exists("data/uploads"):
        print(" |\n |--> Uploads directory not found, creating...")
        os.makedirs("data/uploads")

    if not os.path.exists("data/example.json"):
        print(" |\n |--> Example data file not found, copying...")
        os.system("cp examples/example.json data/example.json")

    if not os.path.exists("./data/database/auth.db"):
        print(" |\n |--> Auth database not found, creating...")
        from app import app, db

        with app.app_context():
            db.create_all()

    print(" |\n |--> Data directory initialized.\n |")
    return


#
# Return a list of files in the user's data directory
def list_user_files(session):
    file_list = []

    files = os.listdir(f"{session['data_dir']}")

    for file in files:
        file_list.append(file.replace(".json", ""))

    file_list.sort()

    return file_list


#
# Process the uploaded file, validate it, and move it to the user's data directory
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
            filename = f"{file.filename}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        else:
            flash("Invalid file type, only .json files allowed.", "danger")

    try:
        with open(f"data/uploads/{filename}", "r") as f:
            data = f.read()
            json.loads(data)
            flash("File is valid JSON", "success")
            os.rename(f"data/uploads/{filename}", f'{session["data_dir"]}/{filename}')
    except:
        flash("File is not valid JSON", "danger")

    return


#
# Read User Data File
def read_user_data_file(filename):
    try:
        with open(f"{filename}.json", "r") as f:
            data = f.read()
            user_data = json.loads(data)
            return user_data
    except:
        return {}


#
# Write User Data File
def write_user_data_file(filename, data):
    with open(f"{filename}.json", "w") as f:
        f.write(json.dumps(data, indent=4))
    return
