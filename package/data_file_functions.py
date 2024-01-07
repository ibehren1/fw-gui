"""
    Data File Support Functions
"""
import json


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
