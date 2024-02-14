"""
    Data File Support Functions
"""

from cryptography.fernet import Fernet
from flask import app, flash, redirect, url_for
import json
import os
import random
import string


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

    tmp_file_name = "data/tmp/" + "".join(
        random.choices(string.ascii_uppercase + string.digits, k=6)
    )

    # opening the file in write mode and
    # writing the decrypted data
    with open(f"{tmp_file_name}", "wb") as dec_file:
        dec_file.write(decrypted)
        dec_file.close()

    return f"{tmp_file_name}"
    # except Exception as e:
    #     print(f" |--X Error: {e}")
    #     flash("Authentication error.", "danger")
    #     print(" |")
    #     return "Auth Error"


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
    print("Initializing Data Directory...")

    if not os.path.exists("data"):
        print(" |\n |--> Data directory not found, creating...")
        os.makedirs("data")

    if not os.path.exists("data/database"):
        print(" |\n |--> Database directory not found, creating...")
        os.makedirs("data/database")

    if not os.path.exists("data/tmp"):
        print(" |\n |--> Tmp directory not found, creating...")
        os.makedirs("data/tmp")

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
    print(f"Delete_before_set: {delete}")
    with open(f'{session["data_dir"]}/{session["firewall_name"]}.conf', "w") as f:
        if delete == True:
            f.write(
                f"#\n# Delete all firewall before setting new values\ndelete firewall\n"
            )
            for line in command_list:
                f.write(f"{line}\n")
        if delete == False:
            for line in command_list:
                f.write(f"{line}\n")
    return


#
# Write User Data File
def write_user_data_file(filename, data):
    with open(f"{filename}.json", "w") as f:
        f.write(json.dumps(data, indent=4, sort_keys=True))
    return
