"""
    MongoDB Converter

    This script converts user data files from JSON format to MongoDB.
    It reads the user list from the MongoDB users collection and processes JSON
    files in user directories to load them into MongoDB.
"""

import json
import logging
import os

from package.data_file_functions import write_user_data_file
from package.user_store import list_usernames


def mongo_converter():
    """
    Main function to convert JSON files to MongoDB entries.

    Steps:
    1. Gets the list of usernames from MongoDB
    2. Finds all JSON files in user directories
    3. Loads JSON data into MongoDB
    4. Renames processed files with .old extension

    Must run after migrate_sqlite_users() on an install upgrading from
    pre-3.0.0, since that is what puts the accounts in MongoDB.
    """
    logging.info("*** Starting MongoDB Converter ***")

    # Get the list of users. Disabled accounts are included on purpose: their
    # leftover JSON should still be imported rather than silently skipped.
    userlist = list_usernames()

    # Find all JSON files in user directories
    file_list = []
    for user in userlist:
        try:
            files = os.listdir(f"data/{user}")
            for file in files:
                if ".json" in file:
                    file_list.append(f"data/{user}/{file}")
        except Exception:
            logging.info(f"No data for {user}.")

    file_list.sort()

    # Process each JSON file and load into MongoDB
    for file in file_list:
        with open(file, "r") as f:
            data = f.read()
            user_data = json.loads(data)
            # Remove MongoDB _id field if present
            if "_id" in user_data:
                del user_data["_id"]
            filename = file.replace(".json", "")
            logging.info(f"Loading datafile {filename} into MongoDB.")
            write_user_data_file(filename, user_data)

            # Rename processed file with .old extension
            os.rename(file, f"{filename}.old")
