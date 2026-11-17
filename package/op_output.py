"""
Build the push page's view of an operational command's output.

The raw output is always kept and shown on request; this only decides
whether there is something richer to show alongside it. ``None`` means "show
the raw text", which is also what happens for any output this module does not
recognise, so a new or unusual command never renders worse than before.
"""

from package import op_firewall
from package.op_tables import has_tables, parse_segments


def build_op_view(output, user_data=None):
    """
    Return the structured view of ``output``, or None to show it raw.

    Args:
        output (str): the device's output.
        user_data (dict | None): the selected FW-GUI config, used to add
            descriptions to ``show firewall`` rulesets.

    Returns:
        dict | None: ``{"kind": "firewall", "chains": [...], "stats": {...},
        "table_count": int}`` for ``show firewall`` output,
        ``{"kind": "tables", "segments": [...], "table_count": int}`` for
        other output with at least one table, else None.
    """
    segments = parse_segments(output)
    if not has_tables(segments):
        return None
    table_count = sum(1 for s in segments if s["kind"] == "table")

    chains = op_firewall.parse_firewall(segments)
    if chains:
        op_firewall.enrich(chains, user_data)
        return {
            "kind": "firewall",
            "chains": chains,
            "stats": op_firewall.stats(chains),
            "table_count": table_count,
        }

    return {"kind": "tables", "segments": segments, "table_count": table_count}
