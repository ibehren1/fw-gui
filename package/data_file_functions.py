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
        if ".json" in file:
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
            if "version" not in user_data:
                user_data["version"] = "0"
                user_data = update_schema(user_data)
                write_user_data_file(filename, user_data)
            return user_data
    except:
        return {}


#
# Schema Updater
def update_schema(user_data):
    if user_data["version"] == "0":
        for ip_version in ["ipv4", "ipv6"]:
            # Change "tables" to "chains"
            if ip_version in user_data:
                if "tables" in user_data[ip_version]:
                    user_data[ip_version]["chains"] = user_data[ip_version]["tables"]
                    del user_data[ip_version]["tables"]

            # Change "fw_table" to "fw_chain"
            if ip_version in user_data:
                if "filters" in user_data[ip_version]:
                    for filter in ["input", "forward", "output"]:
                        if filter in user_data[ip_version]["filters"]:
                            if "rule-order" in user_data[ip_version]["filters"][filter]:
                                for rule in user_data[ip_version]["filters"][filter][
                                    "rule-order"
                                ]:
                                    user_data[ip_version]["filters"][filter]["rules"][
                                        rule
                                    ]["fw_chain"] = user_data[ip_version]["filters"][
                                        filter
                                    ][
                                        "rules"
                                    ][
                                        rule
                                    ][
                                        "fw_table"
                                    ]
                                    del user_data[ip_version]["filters"][filter][
                                        "rules"
                                    ][rule]["fw_table"]
    user_data["version"] = "1"

    return user_data


#
# Write User commands.conf file
def write_user_command_conf_file(filename, command_list):
    with open(f"{filename}.conf", "w") as f:
        for line in command_list:
            f.write(f"{line}\n")
    return


#
# Write User Data File
def write_user_data_file(filename, data):
    with open(f"{filename}.json", "w") as f:
        f.write(json.dumps(data, indent=4))
    return
