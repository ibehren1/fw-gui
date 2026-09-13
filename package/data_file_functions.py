"""
Data File Support Functions

This module provides utility functions for handling data files in a firewall configuration system.
It includes functions for:
- Managing user configuration data (add_extra_items, add_hostname)
- File validation and backup operations (allowed_file, create_backup)
- Encryption/decryption of sensitive files (decrypt_file)
- Database operations for user data (delete_user_data_file)

The module uses MongoDB for data persistence and Fernet for symmetric encryption.
It handles both individual user data and system-wide backups.
"""

import glob
import json
import logging
import os
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta

import boto3
import bson
import pymongo
from cryptography.fernet import Fernet
from flask import flash
from werkzeug.utils import secure_filename

from package.validators import is_safe_name

# Shared MongoDB client — reused across calls to avoid connection leaks.
_mongo_client = None

# Fallback database name, used when MONGODB_DATABASE is unset. Kept in sync with
# the SESSION_MONGODB_DB default in app.py.
DEFAULT_MONGODB_DATABASE = "fwgui_database"

# How long pymongo may spend looking for a reachable server before giving up.
# pymongo's default is 30 seconds, which is not a useful wait: a database on the
# same Docker network either answers in milliseconds or is not coming. Meanwhile
# every stalled request holds a waitress thread (the pool is finite), so a
# handful of retrying browsers during an outage wedges the server instead of
# failing fast. Applied to the shared client here and to the Flask-Session client
# in app.py, which is the one every single request touches.
#
# Deliberately not socketTimeoutMS: that would cap legitimately long queries.
SERVER_SELECTION_TIMEOUT_MS = 5000

# Keys that exist only on snapshot documents. A "current" document must never
# carry them: generate_config walks the document's top-level keys, and a stray
# `tag` string there previously crashed config generation.
_SNAPSHOT_ONLY_KEYS = ("firewall", "snapshot", "tag")

# Snapshot tags are free-text labels; cap them so a pasted config cannot become
# a tag. Mirrored by maxlength on the input in templates/snapshot_manage.html.
_MAX_TAG_LENGTH = 100

# Tag put on the snapshot taken automatically just before a snapshot is
# restored, so the working copy that the restore overwrites is recoverable.
AUTO_SNAPSHOT_TAG = "auto-snapshot before reloading snapshot"

# Snapshot names are timestamps, and the name is the only thing identifying a
# snapshot of a config -- two snapshots taken in the same second would collide,
# and write_user_data_file upserts, so the second would silently overwrite the
# first.
_SNAPSHOT_NAME_FORMAT = "%m-%d-%Y %H:%M:%S"


def _get_mongo_client():
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = pymongo.MongoClient(
            os.environ.get("MONGODB_URI"),
            serverSelectionTimeoutMS=SERVER_SELECTION_TIMEOUT_MS,
        )
    return _mongo_client


def _get_mongo_db():
    """
    Returns the application database handle.

    MONGODB_DATABASE has a default because pymongo raises
    ``TypeError: name must be an instance of str`` on ``client[None]``. User
    accounts live in this database too, so an unset variable would otherwise
    take the login page down rather than just the config routes. The default
    matches the one used for the session store in app.py.
    """
    return _get_mongo_client()[
        os.environ.get("MONGODB_DATABASE", DEFAULT_MONGODB_DATABASE)
    ]


def _unique_snapshot_name(filename):
    """
    Builds a timestamp snapshot name that is not already used by this config.

    Args:
        filename (str): Path in format 'data/<user>/<firewall_name>'

    Returns:
        str: A snapshot name in _SNAPSHOT_NAME_FORMAT

    Names have one-second granularity, so creating a snapshot and then loading
    another one within the same second would otherwise reuse a name and
    overwrite the existing snapshot document. Step forward a second at a time
    until the name is free.
    """
    # filename format:  data/<user>/<firewall_name>
    collection_name = filename.split("/")[1]
    firewall = filename.split("/")[2]

    db = _get_mongo_db()
    collection = db[collection_name]

    timestamp = datetime.now()
    while collection.count_documents(
        {"firewall": firewall, "snapshot": timestamp.strftime(_SNAPSHOT_NAME_FORMAT)},
        limit=1,
    ):
        timestamp += timedelta(seconds=1)

    return timestamp.strftime(_SNAPSHOT_NAME_FORMAT)


def add_extra_items(session, request):
    """
    Adds extra configuration items to a user's firewall configuration file.

    Args:
        session: Session object containing data_dir and firewall_name
        request: Request object containing form data with extra_items field

    The function:
    - Reads the existing user data file
    - Processes extra items from the request form, stripping whitespace
    - If items match the default template, shows warning that no items were added
    - Otherwise saves the new items to the user data file
    - Displays success/warning message via flash

    Returns:
        None
    """
    # Get user's data
    user_data = read_user_data_file(f"{session['data_dir']}/{session['firewall_name']}")
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
        flash("There are no extra configuration items to add.", "warning")
        return
    else:
        user_data["extra-items"] = extra_items
        write_user_data_file(
            f"{session['data_dir']}/{session['firewall_name']}", user_data
        )
        flash("Extra items added to configuration.", "success")
        return


def add_hostname(session, request):
    """
    Adds or updates hostname and port information in a user's firewall configuration file.

    Args:
        session: Session object containing data_dir and firewall_name paths
        reqest: Request object containing form data with hostname and port fields

    The function:
    - Reads the existing user data file
    - Updates the system hostname and port with values from the request form
    - Saves the updated data back to the user's data file

    Returns:
        None
    """
    # Get user's data
    user_data = read_user_data_file(f"{session['data_dir']}/{session['firewall_name']}")

    # Add hostname and port to user_data
    user_data["system"]["hostname"] = request.form["hostname"]
    user_data["system"]["port"] = request.form["port"]

    # Write user_data to file
    write_user_data_file(f"{session['data_dir']}/{session['firewall_name']}", user_data)


def allowed_file(filename):
    """
    Checks if a given filename has an allowed extension.

    Args:
        filename (str): The name of the file to check

    Returns:
        bool: True if the file extension is .json or .key, False otherwise

    The function checks two conditions:
    1. The filename contains a period (.)
    2. The file extension (part after last period) is either 'json' or 'key' (case insensitive)
    """
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ["json", "key"]


def create_backup(session, user=False):
    """
    Creates a backup of either the full data directory or a specific user's directory.

    Args:
        session (dict): Session object containing username and other session data
        user (bool): If False, creates full backup. If True, creates backup of user directory.

    The function:
    1. Generates timestamp for backup filename
    2. For full backup (user=False):
        - Creates MongoDB dump
        - Zips entire data directory excluding backups/tmp/uploads, key files,
          and the retained pre-2.5.0 auth.db*
        - Logs backup creation and shows success message
        - Uploads backup file
    3. For user backup (user=True):
        - Zips user's directory excluding existing zips and key files
        - Logs backup creation and shows success message
        - Uploads backup file
    4. Handles exceptions by logging error and showing failure message

    Returns:
        None
    """
    # TODO -- Remove user backups.
    timestamp = str(datetime.now()).replace(" ", "-")
    if user is False:
        try:
            mongo_dump()
            backup_path = f"data/backups/full-backup-{timestamp}.zip"
            with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk("data/"):
                    if root.startswith(("data/backups", "data/tmp", "data/uploads")):
                        continue
                    for file in files:
                        if file.endswith(".key"):
                            continue
                        # The retained pre-2.5.0 auth database is a full set of
                        # bcrypt hashes that nothing reads any more. Current
                        # accounts are already in the Mongo dump; there is no
                        # reason to ship the legacy copy off the host as well.
                        if file.startswith("auth.db"):
                            continue
                        file_path = os.path.join(root, file)
                        zipf.write(file_path, os.path.relpath(file_path, "data/"))
            logging.info(f"User <{session['username']}> created a full backup.")
            flash(f"Backup created: {backup_path}", "success")
            upload_backup_file(backup_path)
        except Exception as e:
            logging.info(e)
            flash("Backup failed.", "critical")
    else:
        user = session["username"]
        try:
            backup_path = f"data/{user}/user-{user}-backup-{timestamp}.zip"
            with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(f"data/{user}"):
                    for file in files:
                        if file.endswith((".zip", ".key")):
                            continue
                        file_path = os.path.join(root, file)
                        zipf.write(
                            file_path, os.path.relpath(file_path, f"data/{user}")
                        )
            logging.info(f"User <{session['username']}> created a user backup.")
            flash(f"Backup created: {backup_path}", "success")
            upload_backup_file(backup_path)
        except Exception as e:
            logging.info(e)
            flash("Backup failed.", "critical")

    return


def create_snapshot(filename, tag=""):
    """
    Copies the current config of a firewall into a new snapshot document.

    Args:
        filename (str): Path in format 'data/<user>/<firewall_name>'
        tag (str, optional): Tag to put on the new snapshot. Defaults to no tag.

    Returns:
        str: Name of the snapshot created, or None if there was nothing to copy

    The function:
    1. Reads the current config
    2. Picks a timestamp name that no existing snapshot of this config uses
    3. Writes the config as a snapshot document
    4. Tags the new snapshot if a tag was given
    """
    user_data = read_user_data_file(filename)

    # No current document means there is nothing to snapshot; writing anyway
    # would create an empty snapshot that only gets in the way.
    if not user_data:
        return None

    snapshot_name = _unique_snapshot_name(filename)

    # write_user_data_file mutates the dict it is handed (pops _id, sets
    # firewall/snapshot), so it gets the read data last.
    write_user_data_file(filename, user_data, snapshot_name)

    if tag:
        set_snapshot_tag(filename, snapshot_name, tag)

    return snapshot_name


def decrypt_file(filename, key):
    """
    Decrypts an encrypted file using Fernet symmetric encryption and saves to a temporary file.

    Args:
        filename (str): Path to the encrypted file to decrypt
        key (bytes): Encryption key to use for decryption

    Returns:
        str: Path to the temporary decrypted file

    The function:
    1. Creates a Fernet instance with the provided key
    2. Reads and decrypts the encrypted file contents
    3. Generates a random temporary filename
    4. Writes the decrypted data to the temporary file
    5. Returns the path to the temporary decrypted file

    Note: The temporary file is created in data/tmp/ via tempfile.mkstemp,
    which uses a cryptographically-random name and 0o600 (owner-only)
    permissions so the plaintext key is not world-readable.
    """
    # using the key
    fernet = Fernet(key)

    # opening the encrypted file
    with open(filename, "rb") as enc_file:
        encrypted = enc_file.read()

    # decrypting the file
    decrypted = fernet.decrypt(encrypted)

    # Stage the plaintext key in an owner-only temp file with an
    # unpredictable name. mkstemp creates the file with mode 0o600.
    fd, tmp_file_name = tempfile.mkstemp(dir="data/tmp")
    with os.fdopen(fd, "wb") as dec_file:
        dec_file.write(decrypted)
    logging.debug(f" |--> Decrypted key temporarily staged as: {tmp_file_name}")

    return tmp_file_name


def delete_user_data_file(filename):
    """
    Deletes a user data file from MongoDB based on the provided filename path.

    Args:
        filename (str): Path to the file to delete, in format: data/collection/firewall[/snapshot]

    The function:
    1. Parses the filename path to extract:
       - collection_name (2nd segment)
       - firewall name (3rd segment)
       - optional snapshot name (4th segment if present)
    2. Connects to MongoDB using environment variables for URI and database
    3. Builds query based on:
       - For snapshots: Matches firewall and snapshot name
       - For firewalls: Matches firewall _id
    4. Deletes matching document from the collection
    5. Logs debug information about the deletion

    Returns:
        None
    """
    collection_name = filename.split("/")[1]
    firewall = filename.split("/")[2]

    logging.debug("Prepping Mongo query.")
    db = _get_mongo_db()
    collection = db[collection_name]

    if len(filename.split("/")) > 3:
        snapshot_name = filename.split("/")[3]
        query = {"firewall": firewall, "snapshot": snapshot_name}
    else:
        query = {"_id": firewall}

    logging.debug("Deleting data from Mongo.")
    logging.debug(query)
    result = collection.delete_one(query)
    logging.debug(f"{result.deleted_count} documents deleted")

    return


def get_extra_items(session):
    """
    Gets extra configuration items for a firewall from the user's data file.

    Args:
        session (dict): The session dictionary containing data_dir and firewall_name

    Returns:
        list: A list of extra configuration items (commands) for the firewall.
            If no items are defined, returns a list of example commands.

    The function:
    1. Reads the user's data file for the current firewall
    2. Extracts any defined extra-items into a list
    3. If no extra items are found:
       - Displays a warning flash message
       - Returns a list of example configuration commands
    4. Returns the list of extra items
    """
    # Get user's data
    user_data = read_user_data_file(f"{session['data_dir']}/{session['firewall_name']}")

    # Create list of defined filters
    extra_items = []
    if "extra-items" in user_data:
        for item in user_data["extra-items"]:
            extra_items.append(item)

    # If there are no filters, flash message
    if extra_items == []:
        flash("There are no extra configuration items defined.", "warning")
        extra_items = [
            "# Enter set commands here, one per line.",
            "# set firewall global-options all-ping 'enable'",
            "# set firewall global-options log-martians 'disable'",
        ]

    return extra_items


def get_system_name(session):
    """
    Gets the hostname and port from the system configuration in a user's data file.

    Args:
        session (dict): Session dictionary containing data_dir and firewall_name keys

    Returns:
        tuple: A tuple containing:
            - hostname (str): The system hostname from the config, or None if not found
            - port (str): The system port from the config, or None if not found

    The function:
    1. Reads the user's data file for the current firewall
    2. Checks if "system" configuration exists in the data
    3. If system config exists:
       - Returns the hostname and port as a tuple
    4. If no system config exists:
       - Returns (None, None)
    """
    user_data = read_user_data_file(f"{session['data_dir']}/{session['firewall_name']}")

    if "system" in user_data:
        return user_data["system"]["hostname"], user_data["system"]["port"]

    else:
        return None, None


def initialize_data_dir():
    """
    Initializes the application's data directory structure by creating required subdirectories.

    This function:
    1. Creates the main 'data' directory if it doesn't exist
    2. Creates required subdirectories under 'data/':
       - backups/: For storing backup files
       - log/: For application logs
       - mongo_dumps/: For MongoDB database dumps
       - database/: For retained pre-2.5.0 artifacts (the SQLite auth database
         and the telemetry instance id file); nothing current is written here
       - tmp/: For temporary files (contents cleared on startup)
       - uploads/: For user uploaded files
    3. Copies example.json from examples/ if not present

    The function checks for each directory's existence before creating it and logs the initialization
    process using the logging module.

    Returns:
        None
    """
    logging.info("Initializing Data Directory...")

    if not os.path.exists("data"):
        logging.info(" |--> Data directory not found, creating...")
        os.makedirs("data")

    # if not os.path.exists("data/mongodb"):
    #     logging.info(" |--> MongoDB directory not found, creating...")
    #     os.makedirs("data/mongodb")

    if not os.path.exists("data/backups"):
        logging.info(" |--> Backups directory not found, creating...")
        os.makedirs("data/backups")

    if not os.path.exists("data/log"):
        logging.info(" |--> Log directory not found, creating...")
        os.makedirs("data/log")

    if not os.path.exists("data/mongo_dumps"):
        logging.info(" |--> MongoDB directory not found, creating...")
        os.makedirs("data/mongo_dumps")

    # Holds the retained pre-2.5.0 artifacts on an upgraded install
    # (auth.db.migrated, instance.id.migrated). Nothing is written here by
    # current code -- accounts and the telemetry id both live in MongoDB.
    if not os.path.exists("data/database"):
        logging.info(" |--> Database directory not found, creating...")
        os.makedirs("data/database")

    if not os.path.exists("data/tmp"):
        logging.info(" |--> Tmp directory not found, creating...")
        os.makedirs("data/tmp")

    if os.path.exists("data/tmp"):
        logging.info(" |--> Tmp directory found, clearing contents...")
        for file in glob.glob("data/tmp/*"):
            logging.debug(f" |--> Removing file: {file}")
            os.remove(file)

    if not os.path.exists("data/uploads"):
        logging.info(" |--> Uploads directory not found, creating...")
        os.makedirs("data/uploads")

    if not os.path.exists("data/example.json"):
        logging.info(" |--> Example data file not found, copying...")
        shutil.copy("examples/example.json", "data/example.json")

    logging.info(" |--> Data directory initialized.")
    return


def list_full_backups(session):
    """
    Lists all backup files with .zip extension in the data/backups directory.

    Args:
        session (dict): Session dictionary containing user session information
                       (not used in current implementation)

    Returns:
        list: A sorted list of backup filenames (strings) with .zip extension
              found in the data/backups directory

    The function:
    1. Creates an empty list to store backup filenames
    2. Lists all files in the data/backups directory
    3. Filters for files containing .zip extension
    4. Sorts the list alphabetically
    5. Returns the sorted list of backup filenames
    """
    full_backup_list = []

    files = os.listdir("data/backups")

    for file in files:
        if ".zip" in file:
            full_backup_list.append(file)

    full_backup_list.sort()

    return full_backup_list


def list_snapshots(session):
    """
    Retrieves a list of snapshots for the currently selected firewall from MongoDB.

    Args:
        session (dict): Session dictionary containing user session information including:
                       - username: The current user's username
                       - firewall_name: Name of the currently selected firewall

    Returns:
        list: A list of dictionaries containing snapshot information, where each dictionary has:
              - name: Name/timestamp of the snapshot
              - id: ID of the firewall the snapshot belongs to
              - tag: Optional tag associated with the snapshot (empty string if no tag)

    The function:
    1. Creates an empty list to store snapshots
    2. Checks if a firewall is currently selected in the session
    3. Connects to MongoDB using environment variables for connection details
    4. Queries the user's collection for documents containing snapshots of the selected firewall
    5. Sorts results oldest first, by _id (creation order). Snapshot names are
       formatted MM-DD-YYYY HH:MM:SS, which does not sort lexicographically, so
       the name is not usable as a sort key.
    6. Extracts snapshot details and optional tags into formatted dictionaries
    7. Returns the list of snapshot dictionaries
    """
    snapshot_list = []

    if "firewall_name" in session:
        collection_name = f"{session['username']}"

        logging.debug("Prepping Mongo query.")
        db = _get_mongo_db()
        collection = db[collection_name]
        query = {"firewall": session["firewall_name"], "snapshot": {"$exists": True}}

        logging.debug("Reading data from Mongo.")
        # Project just the three fields used below; this runs on nearly every
        # page render, and the documents hold entire firewall configurations.
        projection = {"snapshot": 1, "firewall": 1, "tag": 1}
        for doc in collection.find(query, projection).sort("_id", pymongo.ASCENDING):
            snapshot_list.append(
                {
                    "name": doc["snapshot"],
                    "id": doc["firewall"],
                    "tag": doc.get("tag", ""),
                }
            )

    logging.debug("Snapshot List: " + str(snapshot_list))

    return snapshot_list


def list_user_backups(session):
    """
    Lists all backup files with .zip extension in the user's data directory.

    Args:
        session (dict): Session dictionary containing user session information including:
                       - data_dir: Path to the user's data directory

    Returns:
        list: A sorted list of backup filenames (strings) with .zip extension
              found in the user's data directory

    The function:
    1. Creates an empty list to store backup filenames
    2. Lists all files in the user's data directory specified in session['data_dir']
    3. Filters for files containing .zip extension
    4. Sorts the list alphabetically
    5. Returns the sorted list of backup filenames
    """
    # TODO -- remove
    backup_list = []

    files = os.listdir(f"{session['data_dir']}")

    for file in files:
        if ".zip" in file:
            backup_list.append(file)

    backup_list.sort()

    return backup_list


def list_user_files(session):
    """
    Returns a list of firewall configuration filenames from the user's MongoDB collection.

    Args:
        session (dict): Session dictionary containing user session information including:
                       - username: The current user's username

    Returns:
        list: A sorted list of firewall configuration filenames (strings) stored in MongoDB,
              excluding snapshots and documents with 'firewall' field

    The function:
    1. Creates an empty list to store filenames
    2. Connects to MongoDB using environment variables for connection details
    3. Queries the user's collection for documents that don't have 'firewall' or 'snapshot' fields
    4. Extracts the '_id' field from each document as the filename
    5. Sorts the list alphabetically
    6. Returns the sorted list of filenames
    """
    file_list = []
    collection_name = f"{session['username']}"

    logging.debug("Prepping Mongo query.")
    db = _get_mongo_db()
    collection = db[collection_name]
    query = {"firewall": {"$exists": False}, "snapshot": {"$exists": False}}

    logging.debug("Reading data from Mongo.")
    for doc in collection.find(query):
        file_list.append(doc["_id"])

    file_list.sort()
    return file_list


def list_user_keys(session):
    """
    Lists all SSH key files in the user's data directory, removing the .key extension.

    Args:
        session (dict): Session dictionary containing user session information including:
                       - data_dir: Path to the user's data directory

    Returns:
        list: A sorted list of key filenames (strings) with .key extension removed,
              found in the user's data directory

    The function:
    1. Creates an empty list to store key filenames
    2. Lists all files in the user's data directory specified in session['data_dir']
    3. Filters for files containing .key extension
    4. Removes the .key extension from the filenames
    5. Sorts the list alphabetically
    6. Returns the sorted list of key filenames
    """
    key_list = []

    files = os.listdir(f"{session['data_dir']}")

    for file in files:
        if ".key" in file:
            key_list.append(file.replace(".key", ""))

    key_list.sort()

    return key_list


def mongo_dump():
    """
    Creates a backup dump of all collections in the MongoDB database.

    The function:
    1. Creates a timestamped directory under data/mongo_dumps to store the backup
    2. Connects to MongoDB using environment variable MONGODB_URI
    3. Gets the database name from environment variable MONGODB_DATABASE
    4. For each collection in the database:
       - Creates a .bson file named after the collection
       - Writes all documents from that collection to the .bson file
       - Uses BSON encoding to preserve MongoDB document structure

    The backup files are stored in:
    data/mongo_dumps/<timestamp>/<database_name>/<collection>.bson

    No parameters or return values.
    """
    logging.info("Dumping MongoDB Backup")

    timestamp = str(datetime.now()).replace(" ", "-")
    db = _get_mongo_db()
    mongo_dump_path = f"data/mongo_dumps/{timestamp}/{db.name}"

    if not os.path.exists(mongo_dump_path):
        os.makedirs(mongo_dump_path)

    collist = db.list_collection_names()
    for coll in collist:
        with open(os.path.join(mongo_dump_path, f"{coll}.bson"), "wb+") as f:
            for doc in db[coll].find():
                f.write(bson.BSON.encode(doc))


def process_upload(session, request, app):
    """
    Process uploaded files, validate them, and store them in the user's data directory.

    Handles two types of files:
    1. JSON files:
       - Validates JSON format
       - Removes _id field if present
       - Saves processed data using write_user_data_file()

    2. SSH Key files:
       - Encrypts the key using Fernet symmetric encryption
       - Generates and returns an encryption key to the user
       - Saves the encrypted key file

    Args:
        session (dict): User session data containing data_dir path
        request (Request): Flask request object containing the uploaded file
        app (Flask): Flask application instance with config

    Returns:
        None

    Side effects:
        - Saves valid files to user's data directory
        - Removes uploaded files after processing
        - Flashes status messages to the user
        - For key files, generates and displays encryption key
    """
    if "file" not in request.files:
        flash("No file upload!", "danger")
        return
    else:
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file", "danger")
            return
        # if file and allowed_file(file.filename):
        # Sanitize the client-supplied filename to strip any path components
        # (e.g. "../../etc/x") before it is used to build a save path.
        filename = secure_filename(file.filename)
        if filename == "":
            flash("Invalid file name.", "danger")
            return
        if not allowed_file(filename):
            flash("Invalid file type, only .json and .key files are allowed.", "danger")
            return
        filetype = filename.rsplit(".", 1)[1].lower()
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

    if filetype == "json":
        try:
            with open(f"data/uploads/{filename}", "r") as f:
                data = f.read()
                user_data = json.loads(data)
                flash("File is valid JSON", "success")
                # os.rename(
                #     f"data/uploads/{filename}", f'{session["data_dir"]}/{filename}'
                # )
                if "_id" in user_data:
                    del user_data["_id"]
                filename = filename.replace(".json", "")
                write_user_data_file(f"{session['data_dir']}/{filename}", user_data)
                os.remove(f"data/uploads/{filename}.json")
        except Exception:
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
                with open(f"{session['data_dir']}/{filename}", "wb") as encrypted_file:
                    encrypted_file.write(encrypted)
                    flash(
                        f"Your encryption key for this file is: {key.decode('utf-8')}",
                        "key",
                    )
                os.remove(f"data/uploads/{filename}")
                flash(
                    "SSH key has been uploaded and encrypted.  To use the SSH Key you will have to provide the encryption key.",
                    "success",
                )
        except Exception:
            flash("File is not valid key", "danger")

    return


def read_user_data_file(filename, snapshot="current", diff=False):
    """
    Read user data from MongoDB for a given firewall configuration.

    Args:
        filename (str): Path to the user data file in format 'data/<user>/<firewall_name>'
        snapshot (str, optional): Name of snapshot to read. Defaults to 'current'.
        diff (bool, optional): Whether this is for a diff operation. Defaults to False.

    Returns:
        dict: User data containing firewall configuration, or empty dict if error occurs

    The function:
    1. Extracts collection name and firewall name from filename
    2. Connects to MongoDB using environment variables
    3. Queries for either current data (_id=firewall) or snapshot data
    4. Performs schema updates if needed:
       - Sets version if missing
       - Adds system config if missing
    5. For non-current snapshots, overwrites current data unless diff=True
    """
    # filename format:  data/<user>/<firewall_name>
    try:
        collection_name = filename.split("/")[1]
        firewall = filename.split("/")[2]

        logging.debug("Prepping Mongo query.")
        db = _get_mongo_db()
        collection = db[collection_name]

        if snapshot == "current":
            query = {"_id": firewall}
        else:
            query = {"firewall": firewall, "snapshot": snapshot}

        logging.debug("Reading data from Mongo.")
        for data in collection.find(query):
            user_data = data
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

    except pymongo.errors.PyMongoError as e:
        # Do NOT return {} on a DB error: callers treat {} as "empty config"
        # and can overwrite real data. Fail loud instead, and let non-DB
        # exceptions (real bugs) propagate rather than being swallowed.
        logging.error(f"MongoDB read failed for {filename}: {e}")
        raise


def restore_snapshot(filename, snapshot):
    """Overwrite the current config with the named snapshot's data.

    This is the explicit, destructive counterpart to read_user_data_file:
    it reads the snapshot (without side effects), deletes the current
    document, and writes the snapshot's data back as current.

    Args:
        filename (str): 'data/<user>/<firewall_name>'
        snapshot (str): snapshot name to restore

    Returns:
        dict: the restored data, or {} if the snapshot was not found
    """
    user_data = read_user_data_file(filename, snapshot, diff=True)
    if user_data:
        delete_user_data_file(filename)
        write_user_data_file(filename, user_data)
    return user_data or {}


def set_snapshot_tag(filename, snapshot, tag):
    """
    Sets or clears the tag on a single snapshot document.

    Only the `tag` field is touched -- the configuration data is neither read
    nor rewritten, so tagging cannot disturb the config (and cannot create a
    document: there is deliberately no upsert here, so a name that does not
    resolve is a no-op rather than a ghost snapshot).

    Args:
        filename (str): Path in format 'data/<user>/<firewall_name>'
        snapshot (str): Name of the snapshot to tag
        tag (str): Tag value; an empty value removes the field entirely

    Returns:
        bool: True if the snapshot document existed, False otherwise
    """
    # filename format:  data/<user>/<firewall_name>
    collection_name = filename.split("/")[1]
    firewall = filename.split("/")[2]

    logging.debug("Prepping Mongo query.")
    db = _get_mongo_db()
    collection = db[collection_name]

    query = {"firewall": firewall, "snapshot": snapshot}
    # An empty tag means "untagged", which is the absence of the key. Storing ""
    # instead would make "never tagged" and "tag cleared" indistinguishable.
    if tag:
        update = {"$set": {"tag": tag}}
    else:
        update = {"$unset": {"tag": ""}}

    logging.debug("Writing snapshot tag to Mongo.")
    result = collection.update_one(query, update)

    return result.matched_count == 1


def tag_snapshot(session, request):
    """
    Updates the tag for a firewall configuration snapshot from a form post.

    Args:
        session: The current user session containing data_dir and other data
        request: The HTTP request containing form data with:
            - firewall_name: Name of the firewall configuration
            - snapshot_name: Name of the snapshot to tag
            - snapshot_tag: Tag value to apply (empty clears the tag)

    The function:
    1. Extracts firewall name, snapshot name and tag from the request form
    2. Validates the names, which address a MongoDB document
    3. Trims the tag and truncates it to _MAX_TAG_LENGTH
    4. Writes just the tag field to the snapshot document
    5. Displays a success or failure message

    Returns:
        bool: True if the tag was written, False if the request was rejected
    """
    firewall_name = request.form.get("firewall_name", "")
    snapshot_name = request.form.get("snapshot_name", "")
    snapshot_tag = request.form.get("snapshot_tag", "").strip()[:_MAX_TAG_LENGTH]

    # Both names address a MongoDB document and are supplied by the client.
    if not is_safe_name(firewall_name) or not is_safe_name(snapshot_name):
        flash("Invalid snapshot selection.", "danger")
        return False

    if not set_snapshot_tag(
        f"{session['data_dir']}/{firewall_name}", snapshot_name, snapshot_tag
    ):
        flash(f"Snapshot {snapshot_name} not found.", "danger")
        return False

    if snapshot_tag:
        flash(f"Tag updated for snapshot {snapshot_name}.", "success")
    else:
        flash(f"Tag cleared for snapshot {snapshot_name}.", "success")

    return True


def update_schema(user_data):
    """
    Updates the schema of a firewall configuration from version 0 to version 1.

    Args:
        user_data (dict): Dictionary containing firewall configuration data

    Returns:
        dict: Updated user_data with version 1 schema

    The function performs the following schema updates:
    1. For both IPv4 and IPv6 configurations:
        - Renames "tables" key to "chains"
        - Renames "fw_table" to "fw_chain" in all filter rules
    2. Sets version to "1" after updates are complete

    Example user_data structure:
    {
        "version": "0",
        "ipv4": {
            "tables": {...},  # Renamed to "chains"
            "filters": {
                "input": {
                    "rule-order": [...],
                    "rules": {
                        "rule1": {
                            "fw_table": "..."  # Renamed to "fw_chain"
                        }
                    }
                }
            }
        }
    }
    """
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
                                    ]["rules"][rule]["fw_table"]
                                    del user_data[ip_version]["filters"][filter][
                                        "rules"
                                    ][rule]["fw_table"]
    user_data["version"] = "1"

    return user_data


def upload_backup_file(backup_file):
    """
    Uploads a backup file to an S3 bucket.

    Args:
        backup_file (str): Path to the backup file to upload

    The function:
    1. Gets S3 bucket name and AWS credentials from environment variables
    2. Processes the backup file path to create the S3 key:
       - Removes "data/backups/" and "data/" prefixes
       - Prepends "fw-gui/backups/" to create final key
    3. Uploads the file to S3 using boto3
    4. Displays success message if upload succeeds
    5. Logs error if upload fails
    6. Logs message if bucket/credentials not configured

    Environment variables used:
        BUCKET_NAME: Name of S3 bucket
        AWS_ACCESS_KEY_ID: AWS access key
        AWS_SECRET_ACCESS_KEY: AWS secret key

    Returns:
        None
    """

    logging.debug("Retrieving bucket name and credentials from environment variables")

    bucket_name = os.environ.get("BUCKET_NAME")

    if bucket_name is not None:
        logging.debug(f"Bucket name: {bucket_name}")
        aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
        aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

        try:
            # Remove prefixes and create key
            remote_file = backup_file.replace("data/backups/", "")
            remote_file = remote_file.replace("data/", "")
            key = f"fw-gui/backups/{remote_file}"
            logging.debug(f"Key: {key}")

            # Upload file to S3
            s3 = boto3.client(
                "s3",
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
            )
            s3.upload_file(backup_file, bucket_name, key)

            flash("Backup file uploaded to S3.", "success")
            logging.info("Backup file uploaded to S3.")

            return

        except Exception as e:
            logging.error(f"Error uploading backup file to S3: {e}")
            return

    else:
        logging.info("Variables for bucket and credentials not provided.")


def validate_mongodb_connection(mongodb_uri):
    """
    Validates that a MongoDB connection can be established.

    Args:
        mongodb_uri (str): MongoDB connection URI string to test

    Returns:
        bool: True if connection succeeds

    Raises:
        SystemExit: If connection fails

    The function:
    1. Attempts to connect to MongoDB using the provided URI
    2. Allows SERVER_SELECTION_TIMEOUT_MS for a server to be found
    3. Tests the connection by requesting server info
    4. Logs success/failure message
    5. Closes the connection if successful
    6. Returns True on success, exits program on failure

    The timeout used to be 1ms, which is shorter than a real connection takes: a
    mongod that is up but still starting -- the normal case behind Compose's
    `depends_on`, which has no healthcheck -- could fail this probe and exit the
    app into a restart loop. Sharing the runtime bound keeps one number to reason
    about and costs at most a few seconds on a genuinely unreachable database.
    """
    client = None
    try:
        client = pymongo.MongoClient(
            mongodb_uri, serverSelectionTimeoutMS=SERVER_SELECTION_TIMEOUT_MS
        )
        client.server_info()
        logging.info("  |--> MongoDB connection successful.")
        return True
    except Exception:
        logging.error("  |--> MongoDB connection failed!")
        sys.exit()
    finally:
        if client is not None:
            client.close()


def write_user_command_conf_file(session, command_list, delete=False):
    """
    Writes firewall commands to a configuration file.

    Args:
        session (dict): Session dictionary containing data_dir and firewall_name
        command_list (list): List of firewall commands to write to file
        delete (bool): If True, adds command to delete existing firewall first

    The function:
    1. Opens a .conf file using the firewall name from the session
    2. If delete=True:
        - Writes a comment and delete command at the start
        - Writes all commands from command_list
    3. If delete=False:
        - Only writes the commands from command_list
    4. File is written in the data_dir specified in session

    Returns:
        None
    """
    with open(f"{session['data_dir']}/{session['firewall_name']}.conf", "w") as f:
        if delete is True:
            f.write(
                "#\n# Delete all firewall before setting new values\ndelete firewall\n"
            )
            for line in command_list:
                f.write(f"{line}\n")
        if delete is False:
            for line in command_list:
                f.write(f"{line}\n")
    return


def write_user_data_file(filename, data, snapshot="current"):
    """
    Writes firewall configuration data to MongoDB.

    Args:
        filename (str): Path in format 'data/<user>/<firewall_name>' containing user and firewall info
        data (dict): Dictionary containing firewall configuration data to write
        snapshot (str, optional): Name of snapshot to write. Defaults to "current"

    The function:
    1. Extracts collection name (user) and firewall name from filename path
    2. Connects to MongoDB using environment variables for URI and database name
    3. For current snapshots:
        - Removes _id and the snapshot-only fields (firewall, snapshot, tag)
          from data, and $unsets them on the stored document
        - Uses firewall name as document _id
    4. For named snapshots:
        - Removes _id field
        - Adds firewall name and snapshot name to data
        - Uses firewall and snapshot names to identify document
    5. Updates or inserts document in MongoDB collection

    Environment variables used:
        MONGODB_URI: MongoDB connection string
        MONGODB_DATABASE: Name of MongoDB database

    Returns:
        None
    """
    # filename format:  data/<user>/<firewall_name>
    collection_name = filename.split("/")[1]
    firewall = filename.split("/")[2]

    logging.debug("Prepping Mongo query.")
    db = _get_mongo_db()
    collection = db[collection_name]

    if snapshot == "current":
        # Remove items that should not be in a "current" config. Dropping them
        # from `data` is not enough: $set leaves anything already stored in
        # place, so a document that picked up a snapshot-only key (restoring a
        # tagged snapshot used to leak `tag`) would keep it forever. $unset
        # clears it. Safe to combine with $set because the keys are popped
        # first, so no field appears in both operators.
        data.pop("_id", None)
        for key in _SNAPSHOT_ONLY_KEYS:
            data.pop(key, None)
        query = {"_id": firewall}
        values = {
            "$set": data,
            "$unset": {key: "" for key in _SNAPSHOT_ONLY_KEYS},
        }
    else:
        data.pop("_id", None)
        # Add snapshot and firewall to the data.
        data["firewall"] = firewall
        data["snapshot"] = snapshot
        query = {"firewall": firewall, "snapshot": snapshot}
        values = {"$set": data}

    logging.debug("Writing data to Mongo.")
    logging.debug(query)
    result = collection.update_one(query, values, upsert=True)
    logging.debug(f"{result.modified_count} documents updated")

    return
