"""
    Session Support Functions
"""
from flask import redirect, url_for, session


def logged_in():
    if "firewall_name" not in session:
        print("fuck")
        return redirect(url_for("login"))
        # return redirect(url_for("display_config"))
    else:
        return True
