"""
Diff related functions for comparing configuration snapshots and generating HTML diff views.
Contains functions for processing configuration lists and creating styled HTML diff output.
"""

import difflib
import re

from package.generate_config import generate_config

# difflib puts its navigation links in an unlabeled column and writes them as
# bare single letters -- "f" (first change), "n" (next change), "t" (top) --
# which are easy to miss in a long config diff. Spell the links out and give
# the column a heading. difflib's own legend explaining "(f)irst change" is
# dropped (see _LabeledHtmlDiff._legend); snapshot_diff_display.html carries a
# legend that matches these labels.
_NAV_LABELS = {"f": "First change", "n": "Next change", "t": "Back to top"}
_NAV_LINK_RE = re.compile(r'(<a href="#difflib_chg_[^"]+">)([fnt])(</a>)')
_BLANK_NAV_HEADER = '<th class="diff_next"><br /></th>'
_NAV_HEADER = '<th class="diff_next">Jump</th>'


class _LabeledHtmlDiff(difflib.HtmlDiff):
    """HtmlDiff whose change-navigation links are worded, not single letters."""

    # Suppress difflib's built-in legend; it documents the "f"/"n"/"t" wording.
    _legend = ""

    def _convert_flags(self, *args, **kwargs):
        """Relabel the next/first/top anchors difflib builds for each row."""
        fromlist, tolist, flaglist, next_href, next_id = super()._convert_flags(
            *args, **kwargs
        )
        next_href = [
            _NAV_LINK_RE.sub(lambda m: f"{m[1]}{_NAV_LABELS[m[2]]}{m[3]}", href)
            for href in next_href
        ]

        return fromlist, tolist, flaglist, next_href, next_id


def fix_list(config_lines):
    """
    Processes a list of configuration lines to handle newlines.

    Args:
        config_lines: List of configuration lines

    Returns:
        new_list: Processed list with newlines split into separate items
    """
    new_list = []

    # Go line by line and split based on \n and add to list as separate list items
    for line in config_lines:
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
    diff = _LabeledHtmlDiff()
    html = diff.make_file(
        snapshot_1_list,
        snapshot_2_list,
        fromdesc=f"Snapshot: {snapshot_1}",
        todesc=f"Snapshot: {snapshot_2}",
        context=False,
    )

    # Label the two navigation columns; difflib leaves their headers blank.
    html = html.replace(_BLANK_NAV_HEADER, _NAV_HEADER)

    return html
