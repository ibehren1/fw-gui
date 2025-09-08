"""
    MongoDB Converter
    
    This script converts user data files from JSON format to MongoDB.
    It reads user information from a SQLite database and processes JSON files
    in user directories to load them into MongoDB.
"""

import json
import logging
import os
import sqlite3

from package.data_file_functions import write_user_data_file


def mongo_converter():
    """
    Main function to convert JSON files to MongoDB entries.

    Steps:
    1. Connects to SQLite DB and gets list of usernames
    2. Finds all JSON files in user directories
    3. Loads JSON data into MongoDB
    4. Renames processed files with .old extension
    """
    logging.info("*** Starting MongoDB Converter ***")

    # Connect to SQLite database and get list of users
    con = sqlite3.connect("data/database/auth.db")
    cur = con.cursor()
    res = cur.execute("SELECT username FROM User")

    # Convert query results to list of usernames
    userlist = []
    usertuples = res.fetchall()
    for user in usertuples:
        userlist.append(user[0])

    # Close database connections
    cur.close()
    con.close()

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
