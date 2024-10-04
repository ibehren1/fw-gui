"""
    Diff related functions.
"""

from package.generate_config import generate_config
import difflib


def fix_list(list):

    new_list = []

    # Go line by line and split based on \n and add to list as separate list items
    for line in list:
        segments = line.split("\n")
        for segment in segments:
            new_list.append(f" {segment}")

    return new_list


def process_diff(session, request):

    snapshot_1 = request.form["snapshot_1"]
    snapshot_2 = request.form["snapshot_2"]

    snapshot_1_list = fix_list(generate_config(session, snapshot=snapshot_1, diff=True))
    snapshot_2_list = fix_list(generate_config(session, snapshot=snapshot_2, diff=True))

    # Create Diff and return html page as string
    diff = difflib.HtmlDiff()
    html = diff.make_file(
        snapshot_1_list,
        snapshot_2_list,
        fromdesc=f"Snapshot: {snapshot_1}",
        todesc=f"Snapshot: {snapshot_2}",
        context=False,
    )

    #
    # Alter the html to make it fit FW-GUI style
    #

    html = html.replace(
        'type="text/css">',
        """
        type="text/css">
                body {
                    font-family: Roboto, sans-serif;
                    font-weight: 400;
                    max-width: 100vw;
                    overflow-x: hidden;
                }
                .page_background { 
                    background-color: #606263;
                    color: aliceblue; }
                header { 
                    margin: auto;
                    text-align: center;
                    padding: .1px;
                    align-content: center;
                    color: #323231;
                    background: #ffbf12;
                }
                h1 {
                    font-variant: small-caps;
                }
                .h4_dark {
                    font-weight: bold;
                    font-variant:
                    small-caps;
                    color: #323231;
                }
        """,
    )

    html = html.replace(
        "<body>",
        """
        <header>
            <table width="100%">
                <tr>
                    <td align="center" style="width: 25%;">
                        <img src="static/fw-gui.png">
                    </td>
                    <td align="center" style="width: 50%;">
                        <h1>Firewall GUI</h1>
                        <p class="h4_dark">for use with VyOS</p>
                    </td>
                    <td style="width: 25%;">
                    </td>
                </tr>
            </table>
        </header>

        <body class="page_background">
        <br><br>
        """,
    )

    html = html.replace("<body>", '<body class="page_background">')

    html = html.replace(
        '<table class="diff" id="difflib_chg_to0__top"',
        '<table class="diff" width="100%" id="difflib_chg_to0__top"',
    )

    html = html.replace(
        ".diff_header {background-color:#e0e0e0}",
        ".diff_header {background-color:#e0e0e0; color: #0800ff; font-weight: bold;}",
    )

    html = html.replace(
        ".diff_add {background-color:#aaffaa}",
        ".diff_add {background-color:#1dbd42; color: aliceblue}",
    )
    html = html.replace(
        ".diff_chg {background-color:#ffff77}",
        ".diff_chg {background-color:#ffbf12}",
    )
    html = html.replace(
        ".diff_sub {background-color:#ffaaaa}",
        ".diff_sub {background-color:#dc2232; color: aliceblue}",
    )

    return html
