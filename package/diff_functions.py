"""
Diff related functions for comparing configuration snapshots and generating HTML diff views.
Contains functions for processing configuration lists and creating styled HTML diff output.
"""

import difflib

from package.generate_config import generate_config


def fix_list(list):
    """
    Processes a list of configuration lines to handle newlines.

    Args:
        list: List of configuration lines

    Returns:
        new_list: Processed list with newlines split into separate items
    """
    new_list = []

    # Go line by line and split based on \n and add to list as separate list items
    for line in list:
        # print("Line:")
        # print(line)
        segments = line.split("\n")
        for segment in segments:
            new_list.append(f" {segment}")

    return new_list


def process_diff(session, request):
    """
    Generates an HTML diff view comparing two configuration snapshots.

    Args:
        session: The current session object
        request: The HTTP request containing snapshot IDs

    Returns:
        html: String containing styled HTML diff output
    """
    # Get snapshot IDs from the request
    snapshot_1 = request.form["snapshot_1"]
    snapshot_2 = request.form["snapshot_2"]

    # Generate and process config lists for both snapshots
    snapshot_1_list = fix_list(
        generate_config(session, snapshot=snapshot_1, diff=True)[1]
    )
    snapshot_2_list = fix_list(
        generate_config(session, snapshot=snapshot_2, diff=True)[1]
    )

    # Create Diff and return html page as string
    diff = difflib.HtmlDiff()
    html = diff.make_file(
        snapshot_1_list,
        snapshot_2_list,
        fromdesc=f"Snapshot: {snapshot_1}",
        todesc=f"Snapshot: {snapshot_2}",
        context=False,
    )

    return html
