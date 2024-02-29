"""
    Data File Support Functions
"""

from cryptography.fernet import Fernet
from datetime import datetime
from flask import app, flash, redirect, url_for
import json
import logging
import os
import random
import string

# B404 -- security implications considered.
import subprocess  # nosec


#
# Add extra items
def add_extra_items(session, request):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')
    default_extra_items = [
        "# Enter set commands here, one per line.",
        "# set firewall global-options all-ping 'enable'",
        "# set firewall global-options log-martians 'disable'",
    ]

    extra_items = []

    for item in request.form["extra_items"].split("\r"):
        item = item.strip("\n")
        if item != "":
            extra_items.append(item)

    if extra_items == default_extra_items:
        logging.info("MATCH")
        flash(f"There are no extra configuration items to add.", "warning")
        return
    else:
        user_data["extra-items"] = extra_items
        write_user_data_file(
            f'{session["data_dir"]}/{session["firewall_name"]}', user_data
        )
        flash(f"Extra items added to configuration.", "success")
        return


#
# Add hostname
def add_hostname(session, reqest):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Add hostname and port to user_data
    user_data["system"]["hostname"] = reqest.form["hostname"]
    user_data["system"]["port"] = reqest.form["port"]

    # Write user_data to file
    write_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}', user_data)


#
# Determine if a file is a JSON file
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ["json", "key"]


#
# Create backup of data dir or user dir
def create_backup(session, user=False):
    timestamp = str(datetime.now()).replace(" ", "-")
    if user is False:
        try:
            # B607 -- Cmd is partial executable path for compatibility between OSes.
            subprocess.run(
                [
                    "zip",
                    "-r",
                    f"data/backups/full-backup-{timestamp}.zip",
                    "data/",
                    "-x",
                    "data/backups/*",
                    "-x",
                    "data/tmp/*",
                    "-x",
                    "data/uploads/*",
                ]
            )  # nosec
            logging.info(f'User <{session["username"]}> created a full backup.')
            flash(
                f"Backup created: data/backups/full-backup-{timestamp}.zip", "success"
            )

        except Exception as e:
            logging.info(e)
            flash(f"Backup failed.", "critical")

    else:
        user = session["username"]
        try:
            # B607 -- Cmd is partial executable path for compatibility between OSes.
            subprocess.run(
                [
                    "zip",
                    "-r",
                    f"data/{user}/user-{user}-backup-{timestamp}.zip",
                    f"data/{user}",
                    "-x",
                    f"data/{user}/*.zip",
                ]
            )  # nosec
            logging.info(f'User <{session["username"]}> created a user backup.')
            flash(
                f"Backup created: data/{user}/user-{user}-backup-{timestamp}.zip",
                "success",
            )

        except Exception as e:
            logging.info(e)
            flash(f"Backup failed.", "critical")

    return


#
# Decrypt key file and stage for use
def decrypt_file(filename, key):
    # try:
    # using the key
    fernet = Fernet(key)

    # opening the encrypted file
    with open(filename, "rb") as enc_file:
        encrypted = enc_file.read()

    # decrypting the file
    decrypted = fernet.decrypt(encrypted)

    # B311 -- Use of pseudo-random generator is not for security purposes.
    tmp_file_name = "data/tmp/" + "".join(
        random.choices(string.ascii_uppercase + string.digits, k=6)  # nosec
    )

    # opening the file in write mode and
    # writing the decrypted data
    with open(f"{tmp_file_name}", "wb") as dec_file:
        dec_file.write(decrypted)
        dec_file.close()

    return f"{tmp_file_name}"


#
# Get extra items
def get_extra_items(session):
    # Get user's data
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    # Create list of defined filters
    extra_items = []
    if "extra-items" in user_data:
        for item in user_data["extra-items"]:
            extra_items.append(item)

    # If there are no filters, flash message
    if extra_items == []:
        flash(f"There are no extra configuration items defined.", "warning")
        extra_items = [
            "# Enter set commands here, one per line.",
            "# set firewall global-options all-ping 'enable'",
            "# set firewall global-options log-martians 'disable'",
        ]

    return extra_items


#
# Get system info from data file
def get_system_name(session):
    user_data = read_user_data_file(f'{session["data_dir"]}/{session["firewall_name"]}')

    if "system" in user_data:
        return user_data["system"]["hostname"], user_data["system"]["port"]

    else:
        return None, None


#
# Initialize the data directory at App start
def initialize_data_dir():
    logging.info("Initializing Data Directory...")

    if not os.path.exists("data"):
        logging.info(" |--> Data directory not found, creating...")
        os.makedirs("data")

    if not os.path.exists("data/backups"):
        logging.info(" |--> Backups directory not found, creating...")
        os.makedirs("data/backups")

    if not os.path.exists("data/log"):
        logging.info(" |--> Log directory not found, creating...")
        os.makedirs("data/log")

    if not os.path.exists("data/database"):
        logging.info(" |--> Database directory not found, creating...")
        os.makedirs("data/database")

    if not os.path.exists("data/tmp"):
        logging.info(" |--> Tmp directory not found, creating...")
        os.makedirs("data/tmp")

    if not os.path.exists("data/uploads"):
        logging.info(" |--> Uploads directory not found, creating...")
        os.makedirs("data/uploads")

    if not os.path.exists("data/example.json"):
        logging.info(" |--> Example data file not found, copying...")
        # B603 -- No untrusted input
        # B607 -- Cmd is partial executable path for compatibility between OSes.
        subprocess.run(["cp", "examples/example.json", "data/example.json"])  # nosec

    if not os.path.exists("./data/database/auth.db"):
        logging.info(" |--> Auth database not found, creating...")
        from app import app, db

        with app.app_context():
            db.create_all()

    logging.info(" |--> Data directory initialized.")
    return


#
# Return a list of backups in the user's data directory
def list_full_backups(session):
    full_backup_list = []

    files = os.listdir(f"data/backups")

    for file in files:
        if ".zip" in file:
            full_backup_list.append(file)

    full_backup_list.sort()

    return full_backup_list


#
# Return a list of backups in the user's data directory
def list_user_backups(session):
    backup_list = []

    files = os.listdir(f"{session['data_dir']}")

    for file in files:
        if ".zip" in file:
            backup_list.append(file)

    backup_list.sort()

    return backup_list


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
# Return a list of keys in the user's data directory
def list_user_keys(session):
    key_list = []

    files = os.listdir(f"{session['data_dir']}")

    for file in files:
        if ".key" in file:
            key_list.append(file.replace(".key", ""))

    key_list.sort()

    return key_list


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
        # if file and allowed_file(file.filename):
        filename = f"{file.filename}"
        if filename.rsplit(".", 1)[1].lower() in ["json"]:
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            filetype = "json"
        elif filename.rsplit(".", 1)[1].lower() in ["key"]:
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            filetype = "key"
        else:
            flash("Invalid file type, only .json and .key files are allowed.", "danger")

    if filetype == "json":
        try:
            with open(f"data/uploads/{filename}", "r") as f:
                data = f.read()
                json.loads(data)
                flash("File is valid JSON", "success")
                os.rename(
                    f"data/uploads/{filename}", f'{session["data_dir"]}/{filename}'
                )
        except:
            flash("File is not valid JSON", "danger")

    if filetype == "key":
        try:
            # TODO -- validate key is a valid ssh key
            with open(f"data/uploads/{filename}", "rb") as f:
                data = f.read()

                # Generate a key
                key = Fernet.generate_key()

                # using the generated key
                fernet = Fernet(key)

                # encrypting the file
                encrypted = fernet.encrypt(data)

                # writing the encrypted data
                with open(f'{session["data_dir"]}/{filename}', "wb") as encrypted_file:
                    encrypted_file.write(encrypted)
                    flash(
                        f"Your encryption key for this file is: {key.decode('utf-8')}",
                        "key",
                    )
                os.remove(f"data/uploads/{filename}")
                flash(
                    f"SSH key has been uploaded and encrypted.  To use the SSH Key you will have to provide the encryption key.",
                    "success",
                )
        except:
            flash("File is not valid key", "danger")

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
            if "system" not in user_data:
                user_data["system"] = {
                    "hostname": "None",
                    "port": "None",
                }
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
def write_user_command_conf_file(session, command_list, delete=False):
    with open(f'{session["data_dir"]}/{session["firewall_name"]}.conf', "w") as f:
        if delete is True:
            f.write(
                f"#\n# Delete all firewall before setting new values\ndelete firewall\n"
            )
            for line in command_list:
                f.write(f"{line}\n")
        if delete is False:
            for line in command_list:
                f.write(f"{line}\n")
    return


#
# Write User Data File
def write_user_data_file(filename, data):
    with open(f"{filename}.json", "w") as f:
        f.write(json.dumps(data, indent=4, sort_keys=True))
    return
