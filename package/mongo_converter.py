"""
    MongoDB Converter
"""

from package.data_file_functions import write_user_data_file
import json
import logging
import os
import sqlite3


def mongo_converter():
    logging.info("*** Starting MongoDB Converter ***")
    # Connect to the SQLite database
    con = sqlite3.connect("data/database/auth.db")

    # Create cursor and execute select
    cur = con.cursor()
    res = cur.execute("SELECT username FROM User")

    # Dump result to a list
    userlist = []
    usertuples = res.fetchall()
    for user in usertuples:
        userlist.append(user[0])

    # Close the connection
    cur.close()
    con.close()

    # Step through user directories finding json files
    file_list = []
    for user in userlist:
        try:
            files = os.listdir(f"data/{user}")
            for file in files:
                if ".json" in file:
                    file_list.append(f"data/{user}/{file}")
        except:
            logging.info(f"No data for {user}.")

    file_list.sort()

    print(file_list)

    # Step through file list and load into MongoDB
    for file in file_list:
        with open(file, "r") as f:
            data = f.read()
            user_data = json.loads(data)
            if "_id" in user_data:
                del user_data["_id"]
            filename = file.replace(".json", "")
            logging.info(f"Loading datafile {filename} into MongoDB.")
            write_user_data_file(filename, user_data)

            os.rename(file, f"{filename}.old")
