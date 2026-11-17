"""
Build the push page's view of an operational command's output.

The raw output is always kept and shown on request; this only decides
whether there is something richer to show alongside it. ``None`` means "show
the raw text", which is also what happens for any output this module does not
recognise, so a new or unusual command never renders worse than before.
"""

from package.op_tables import has_tables, parse_segments


def build_op_view(output):
    """
    Return the structured view of ``output``, or None to show it raw.

    Returns:
        dict | None: ``{"kind": "tables", "segments": [...],
        "table_count": int}`` when the output contains at least one table.
    """
    segments = parse_segments(output)
    if not has_tables(segments):
        return None
    return {
        "kind": "tables",
        "segments": segments,
        "table_count": sum(1 for s in segments if s["kind"] == "table"),
    }
