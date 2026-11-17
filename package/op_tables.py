"""
Split VyOS operational command output into text and table segments.

VyOS op-mode commands print their tables with Python's tabulate "simple"
format: a header line, a line of dash runs (one run per column, separated by
spaces), then one line per row. The dash runs give each column's start, so a
row is sliced at those offsets; the last column runs to the end of the line
because free text (firewall conditions, descriptions) lives there.

A row whose first column is blank continues the row above it -- show
interfaces prints extra addresses that way and show nat prints the sport/dport
line that way -- so its cells are appended to the previous row's, one value
per line.

Anything that is not a table is kept as a text segment, in order, so a caller
can render the whole output without losing a line. Parsing never raises: the
worst case is that everything is one text segment and the page shows the raw
output, as before.
"""

import re

_RULE_LINE = re.compile(r"^\s*-+(\s+-+)+\s*$")
_DASH_RUN = re.compile(r"-+")
_INTEGER = re.compile(r"^-?\d+$")


def _column_starts(rule_line):
    return [m.start() for m in _DASH_RUN.finditer(rule_line)]


def _slice(line, starts):
    cells = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else None
        cells.append(line[start:end].strip())
    return cells


def _numeric_columns(rows, count):
    """A column is numeric when every non-empty single-line cell is an integer."""
    numeric = []
    for i in range(count):
        values = [row[i] for row in rows if row[i]]
        numeric.append(bool(values) and all(_INTEGER.match(v) for v in values))
    return numeric


def parse_segments(text):
    """
    Split ``text`` into an ordered list of segments.

    Returns:
        list[dict]: each either ``{"kind": "text", "text": str}`` or
        ``{"kind": "table", "columns": [str], "numeric": [bool],
        "rows": [[str]]}``. A multi-line cell holds its lines joined by
        ``"\\n"``. Returns ``[]`` for empty input.
    """
    if not isinstance(text, str) or not text.strip():
        return []

    lines = text.replace("\r\n", "\n").split("\n")
    segments = []
    pending = []

    def flush_text():
        if pending and any(line.strip() for line in pending):
            segments.append({"kind": "text", "text": "\n".join(pending)})
        pending.clear()

    i = 0
    while i < len(lines):
        line = lines[i]
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if line.strip() and _RULE_LINE.match(nxt):
            starts = _column_starts(nxt)
            columns = _slice(line, starts)
            rows = []
            j = i + 2
            while j < len(lines) and lines[j].strip():
                cells = _slice(lines[j], starts)
                if rows and not cells[0]:
                    prev = rows[-1]
                    for k, cell in enumerate(cells):
                        if cell:
                            prev[k] = f"{prev[k]}\n{cell}" if prev[k] else cell
                else:
                    rows.append(cells)
                j += 1
            flush_text()
            segments.append(
                {
                    "kind": "table",
                    "columns": columns,
                    "numeric": _numeric_columns(rows, len(columns)),
                    "rows": rows,
                }
            )
            i = j
            continue
        pending.append(line)
        i += 1

    flush_text()
    return segments


def has_tables(segments):
    """True if any segment is a table."""
    return any(segment["kind"] == "table" for segment in segments)
