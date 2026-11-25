"""
Build the push page's view of an operational command's output.

The raw output is always kept and shown on request; this only decides
whether there is something richer to show alongside it. ``None`` means "show
the raw text", which is also what happens for any output this module does not
recognise, so a new or unusual command never renders worse than before.
"""

from package import op_firewall
from package.op_tables import has_tables, parse_segments


def build_op_view(output, user_data=None, previous=None):
    """
    Return the structured view of ``output``, or None to show it raw.

    Args:
        output (str): the device's output.
        user_data (dict | None): the selected FW-GUI config, used to add
            descriptions to ``show firewall`` rulesets.
        previous (dict | None): the counters saved from the last run of the
            same command (``counters`` of that run's view), for deltas.

    Returns:
        dict | None: ``{"kind": "firewall", "chains": [...], "stats": {...},
        "table_count": int, "counters": {...}, "has_previous": bool,
        "has_last_used": bool}`` for ``show firewall`` output (table or
        ``detail`` form),
        ``{"kind": "tables", "segments": [...], "table_count": int}`` for
        other output with at least one table, else None.
    """
    # "show firewall ... detail" prints key/value blocks, not tables.
    chains = op_firewall.parse_firewall_detail(output)
    if chains:
        return _firewall_view(chains, len(chains), user_data, previous)

    segments = parse_segments(output)
    if not has_tables(segments):
        return None
    table_count = sum(1 for s in segments if s["kind"] == "table")

    chains = op_firewall.parse_firewall(segments)
    if chains:
        return _firewall_view(chains, table_count, user_data, previous)

    return {"kind": "tables", "segments": segments, "table_count": table_count}


def _firewall_view(chains, table_count, user_data, previous):
    op_firewall.enrich(chains, user_data)
    op_firewall.apply_deltas(chains, previous)
    return {
        "kind": "firewall",
        "chains": chains,
        "stats": op_firewall.stats(chains),
        "table_count": table_count,
        "counters": op_firewall.counter_snapshot(chains),
        "has_previous": bool(previous),
        "has_last_used": op_firewall.has_last_used(chains),
    }


# Saved firewall counters kept per session, one entry per (config, command).
# A handful is plenty for comparing runs; the oldest entries are dropped so
# the server-side session cannot grow without bound.
COUNTER_HISTORY_LIMIT = 8


def counter_history_key(firewall_name, command):
    """Key for a command's saved counters; whitespace differences ignored."""
    return f"{firewall_name}|{' '.join(str(command).split())}"


def remember_counters(history, key, counters, ran_at):
    """
    Return ``history`` with ``counters`` saved under ``key`` as the newest
    entry, trimmed to COUNTER_HISTORY_LIMIT entries (oldest dropped first).
    """
    history = {k: v for k, v in (history or {}).items() if k != key}
    history[key] = {"at": ran_at, "counters": counters}
    while len(history) > COUNTER_HISTORY_LIMIT:
        history.pop(next(iter(history)))
    return history
