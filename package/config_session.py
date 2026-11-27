"""
    VyOS configuration sessions over a plain SSH channel.

    Builds the vbash script that View Diffs and Commit run on the firewall, and
    reads its output. The script uses VyOS's script-template, so `configure`,
    `set`, `compare`, `commit` and `save` behave as at the CLI. Pure functions:
    the SSH side is napalm_ssh_functions.

    Measured on VyOS (2025.01 rolling), which shapes the design:

    - Every command's exit status is 0, even a rejected `set`, so errors are
      read from the output: "Set failed", "Delete failed", "Comment failed",
      "Commit failed", "[[firewall]] failed", "... is not valid",
      "Invalid command: [x]". "Nothing to delete" is not an error.
    - Path errors go to stderr and value errors to stdout, so the script
      merges stderr into stdout (`exec 2>&1`) to keep them in order.
    - Each line's output is collected in a log file between numbered markers,
      so the script itself can refuse to commit when any line failed, and
      Python can say which line it was.

    The lines come from build_merge_config, which includes the user's extra
    items, and they are run as shell input exactly as typing them at the VyOS
    CLI would be. A line is refused before connecting if it could escape its
    per-line redirection: unbalanced quotes, a trailing backslash, an unquoted
    comment, a shell operator (; & | < > ( ) `), or a brace word.
"""

import re
import secrets

# One pattern for the shell gate (grep -E) and for Python: a line or a commit
# failed. Keep the two uses identical, so the script never commits a session
# that the parser would report as failed.
ERROR_PATTERN = "failed|is not valid|Invalid command"
_ERROR = re.compile(ERROR_PATTERN)
_NO_CHANGES = "No changes between working and active configurations"
# Printed by `exit discard` in script mode; noise, not a result.
_NOISE = ("calling discardChanges() without config session",)
_OPERATORS = set(";&|<>()`")


def unsafe_reason(line):
    """
    Why a command line cannot be sent, or None if it can.

    Scans as bash would: inside single quotes nothing is special; inside
    double quotes only a backslash escapes; outside quotes an operator, a
    word-initial "#" or a "{" / "}" word could break out of the line's
    redirection.
    """
    if "\x00" in line or "\r" in line or "\n" in line:
        return "contains a control character"
    quote = None
    escaped = False
    word_start = True
    words = []
    word = ""
    for ch in line:
        if escaped:
            escaped = False
            word += ch
            word_start = False
            continue
        if quote == "'":
            if ch == "'":
                quote = None
            word += ch
            continue
        if quote == '"':
            if ch == "\\":
                escaped = True
            elif ch == '"':
                quote = None
            word += ch
            continue
        if ch == "\\":
            escaped = True
            word += ch
            word_start = False
        elif ch in "'\"":
            quote = ch
            word += ch
            word_start = False
        elif ch in " \t":
            if word:
                words.append(word)
            word = ""
            word_start = True
        elif ch in _OPERATORS:
            return f"contains the shell operator {ch!r} outside quotes"
        elif ch == "#" and word_start:
            return "contains a comment"
        else:
            word += ch
            word_start = False
    if quote:
        return "has an unterminated quote"
    if escaped:
        return "ends with a backslash"
    if word:
        words.append(word)
    if "{" in words or "}" in words:
        return "contains a brace word"
    return None


def command_lines(merge_config):
    """The non-blank lines of a merge config, in order."""
    return [line for line in merge_config.split("\n") if line.strip()]


def new_marker():
    """A per-run marker no device output will contain."""
    return f"@@FWGUI-{secrets.token_hex(8)}"


def build_script(lines, marker, commit):
    """
    The vbash script for one session.

    Diff: configure, the lines, compare, exit discard.
    Commit: the same, then commit and save only if no line failed and there
    are changes; a failed commit is discarded, never saved.
    """
    script = [
        "exec 2>&1",
        "source /opt/vyatta/etc/functions/script-template",
        # A private directory, not files directly in sticky /tmp: during a real
        # commit vyos-configd (root) reopens the session's stdout, and the
        # kernel's protected_regular refuses root opening another user's file
        # in a sticky directory -- configd crashes and the commit hangs.
        "fwgui_dir=$(mktemp -d)",
        'fwgui_log="$fwgui_dir/log"',
        'fwgui_out="$fwgui_dir/out"',
        "configure",
    ]
    for number, line in enumerate(lines, start=1):
        script += [
            f'echo "{marker} L {number}" >>"$fwgui_log"',
            "{",
            line,
            '} >>"$fwgui_log" 2>&1',
        ]
    script += [
        'cat "$fwgui_log"',
        f'echo "{marker} COMPARE"',
        'compare >"$fwgui_out" 2>&1',
        'cat "$fwgui_out"',
    ]
    if commit:
        script += [
            f"if grep -qE '{ERROR_PATTERN}' \"$fwgui_log\"; then",
            f'  echo "{marker} ABORT"',
            "  exit discard",
            f"elif grep -q '{_NO_CHANGES}' \"$fwgui_out\"; then",
            f'  echo "{marker} NO_CHANGES"',
            "  exit discard",
            "else",
            f'  echo "{marker} COMMIT"',
            '  commit >"$fwgui_out" 2>&1',
            '  cat "$fwgui_out"',
            # A commit counts only if it reported no error AND nothing is left
            # uncommitted: a commit refused for another reason (e.g. a commit
            # lock) need not print an error string.
            f'  echo "{marker} VERIFY"',
            '  compare >"$fwgui_dir/after" 2>&1',
            f"  if grep -qE '{ERROR_PATTERN}' \"$fwgui_out\" || "
            f"! grep -q '{_NO_CHANGES}' \"$fwgui_dir/after\"; then",
            f'    echo "{marker} COMMIT_FAILED"',
            "    exit discard",
            "  else",
            f'    echo "{marker} SAVE"',
            "    save",
            "    exit",
            "  fi",
            "fi",
        ]
    else:
        script += [f'echo "{marker} DISCARD"', "exit discard"]
    script += [
        'rm -rf "$fwgui_dir"',
        f'echo "{marker} END"',
    ]
    return "\n".join(script) + "\n"


def _segments(output, marker):
    segments = {}
    current = "PRELUDE"
    segments[current] = []
    prefix = marker + " "
    for raw in output.splitlines():
        if raw.startswith(prefix):
            current = raw[len(prefix):].strip()
            segments[current] = []
        elif raw.strip() and raw.strip() not in _NOISE:
            segments[current].append(raw.rstrip())
    return {key: "\n".join(value) for key, value in segments.items()}


def _clean(text):
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def parse_output(output, marker, lines):
    """
    Reads a session's output.

    Returns:
        dict: errors -- [(line number, line, device message)] for rejected
                  lines; diff -- the compare output, "" when unchanged;
              committed -- True once commit and save ran; commit_error --
                  the device's message for a failed commit, else None;
              complete -- False when the session ended before its last marker.
    """
    segments = _segments(output, marker)
    errors = []
    for number, line in enumerate(lines, start=1):
        text = segments.get(f"L {number}", "")
        if _ERROR.search(text):
            errors.append((number, line, _clean(text)))

    diff = segments.get("COMPARE", "").strip("\n")
    if _NO_CHANGES in diff:
        diff = ""

    commit_error = None
    if "COMMIT_FAILED" in segments:
        commit_error = _clean(segments.get("COMMIT", "")) or (
            "The firewall still had uncommitted changes after the commit."
        )

    return {
        "errors": errors,
        "diff": diff,
        "committed": "SAVE" in segments,
        "commit_error": commit_error,
        "complete": "END" in segments,
    }


def describe_errors(errors):
    """The rejected lines, for the push page."""
    parts = []
    for number, line, message in errors:
        parts.append(f"Line {number}: {line}\n" + "\n".join(
            f"    {m}" for m in message.splitlines()
        ))
    return "\n\n".join(parts)
