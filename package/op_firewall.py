"""
The firewall view of ``show firewall`` output.

``show firewall`` prints one tabulate table per ruleset, each preceded by a
title such as ``ipv4 Firewall "name wan_local"`` or ``ipv6 Firewall "forward
filter"``. This module turns those tables into chains with numeric counters,
condenses each rule's nftables conditions into display parts, and matches
every ruleset and rule against the selected FW-GUI configuration by IP
version, chain/filter name and rule number to add its description.

Only tables with exactly the ``show firewall`` columns and a recognised title
are used; anything else is ignored here and left to the generic table view.

``show firewall <family> <name X | hook filter> detail`` prints each rule as
a vertical key/value block instead (``parse_firewall_detail``). That is the
only output carrying the "Last Used" field of rules with ``last-used`` set
(VyOS rolling Aug 2026+); the plain table strips it from the conditions.
"""

import re

FIREWALL_COLUMNS = ["Rule", "Action", "Protocol", "Packets", "Bytes", "Conditions"]

_TITLE = re.compile(r'^(ipv4|ipv6) Firewall "(?:name (\S+)|(\S+) filter)"$')

# nftables set names VyOS gives firewall groups: A_ address, N_ network,
# P_ port, M_ MAC, D_ domain, I_ interface; a 6 marks the IPv6 address and
# network groups.
_GROUP_TYPES = {
    "A": "address-group",
    "N": "network-group",
    "P": "port-group",
    "M": "mac-group",
    "D": "domain-group",
    "I": "interface-group",
}
_STATE_NAMES = {"established": "EST", "related": "REL", "new": "NEW", "invalid": "INV"}

_TOKEN = re.compile(
    r"ct state \{ (?P<states>[a-z, ]+) \}"
    r"|ct state (?P<state>[a-z]+)"
    r"|@(?P<prefix>[ANPMDI]6?)_(?P<group>[\w.-]+)"
)
_LOG_PREFIX = re.compile(r'\s*prefix "\[[^"]*"')
_COMMENT = re.compile(r'\s*comment "[^"]*"')
_JUMP = re.compile(r"\s*jump NAME6?_(\S+)")
_VERDICT = re.compile(r"\s*\b(accept|drop|reject|return|continue)\s*$")

# One line of a detail block (tabulate "presto" with no header): " Key | value",
# or "     | more" continuing the previous value.
_DETAIL_LINE = re.compile(r"^ (?P<key>[A-Za-z][A-Za-z -]*?)?\s*\|(?: (?P<value>.*))?$")
# nftables duration, e.g. "2h3m4s174ms".
_DURATION = re.compile(r"(\d+)(ms|d|h|m|s)")
_DURATION_MS = {"d": 86_400_000, "h": 3_600_000, "m": 60_000, "s": 1_000, "ms": 1}


def human_count(n):
    """1234 -> '1,234'; 12345 -> '12.3k'; 1234567 -> '1.23M'."""
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.2f}G"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 10_000:
        return f"{n / 1_000:.1f}k"
    return f"{n:,}"


def human_bytes(n):
    """Binary units: 1536 -> '1.50 KiB'."""
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    value = float(n)
    i = 0
    while value >= 1024 and i < len(units) - 1:
        value /= 1024
        i += 1
    if i == 0:
        return f"{n} B"
    return f"{value:.2f} {units[i]}" if value < 10 else f"{value:.1f} {units[i]}"


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def condition_parts(raw):
    """
    Condense a rule's nftables conditions for display.

    The verdict is dropped (it is the Action column), the log prefix becomes
    a flag, the default-action comment is dropped, a jump becomes its target
    chain, ``ct state`` becomes state abbreviations and ``@A_name`` style sets
    become group references.

    Returns:
        tuple: (parts, log, jump). ``parts`` is a list of
        ``{"t": "text", "v": str}``, ``{"t": "state", "v": "EST"}`` or
        ``{"t": "group", "type": "address-group", "name": str,
        "ip_version": "ipv4"|"ipv6"}``. ``log`` is a bool; ``jump`` is the
        target chain name or None.
    """
    log = bool(_LOG_PREFIX.search(raw))
    text = _COMMENT.sub("", _LOG_PREFIX.sub("", raw))
    jump = None
    match = _JUMP.search(text)
    if match:
        jump = match.group(1)
        text = text[: match.start()] + text[match.end():]
    text = _VERDICT.sub("", text).strip()
    if text in ("accept", "drop", "reject", "return", "continue"):
        text = ""

    parts = []

    def add_text(value):
        value = " ".join(value.split())
        if value:
            parts.append({"t": "text", "v": value})

    pos = 0
    for m in _TOKEN.finditer(text):
        add_text(text[pos:m.start()])
        if m.group("prefix"):
            prefix = m.group("prefix")
            parts.append(
                {
                    "t": "group",
                    "type": _GROUP_TYPES[prefix[0]],
                    "name": m.group("group"),
                    "ip_version": "ipv6" if prefix.endswith("6") else "ipv4",
                }
            )
        else:
            states = m.group("states") or m.group("state")
            for state in states.split(","):
                state = state.strip()
                parts.append({"t": "state", "v": _STATE_NAMES.get(state, state.upper())})
        pos = m.end()
    add_text(text[pos:])
    return parts, log, jump


def parse_firewall(segments):
    """
    Extract ``show firewall`` rulesets from parsed segments.

    Returns:
        list[dict]: one per ruleset, in output order; empty if none. Each is
        ``{"family", "kind": "name"|"filter", "name", "label", "rules",
        "default_action", "packets"}`` and each rule ``{"number",
        "is_default", "action", "protocol", "packets", "bytes",
        "conditions", "parts", "log", "jump"}``.
    """
    chains = []
    for i, segment in enumerate(segments):
        if segment["kind"] != "table" or segment["columns"] != FIREWALL_COLUMNS:
            continue
        if i == 0 or segments[i - 1]["kind"] != "text":
            continue
        title_lines = [l.strip() for l in segments[i - 1]["text"].split("\n") if l.strip()]
        match = _TITLE.match(title_lines[-1]) if title_lines else None
        if not match:
            continue
        rules = [_rule(*row) for row in segment["rows"]]
        chains.append(_chain(match, rules))
    return chains


def _rule(number, action, protocol, packets, byte_count, conditions, last_used=None):
    parts, log, jump = condition_parts(conditions)
    return {
        "number": number,
        "is_default": number == "default",
        "action": action,
        "protocol": protocol,
        "packets": _int(packets),
        "bytes": _int(byte_count),
        "conditions": conditions,
        "parts": parts,
        "log": log,
        "jump": jump,
        "last_used": last_used,
    }


def _chain(title_match, rules):
    family, chain_name, hook = title_match.groups()
    default_action = next((r["action"] for r in rules if r["is_default"]), None)
    return {
        "family": family,
        "kind": "name" if chain_name else "filter",
        "name": chain_name or hook,
        "label": chain_name or f"{hook} filter",
        "rules": rules,
        "default_action": default_action,
        "packets": sum(r["packets"] for r in rules),
    }


def _detail_rule(record):
    if not record.get("Rule"):
        return None
    return _rule(
        record["Rule"],
        record.get("Action", ""),
        record.get("Protocol") or "all",
        record.get("Packets"),
        record.get("Bytes"),
        record.get("Conditions", ""),
        record.get("Last Used"),
    )


def parse_firewall_detail(output):
    """
    Extract rulesets from ``show firewall ... detail`` output.

    Each ruleset is a title line followed by one key/value block per rule,
    blocks separated by blank lines, long values wrapped onto lines with an
    empty key. Returns the same structure as ``parse_firewall`` (each rule's
    ``last_used`` is the device's "Last Used" text, or None if the output has
    no such field); empty when the output is not detail output.
    """
    chains = []
    title = None
    rules = []
    record = {}
    key = None

    def end_record():
        nonlocal record, key
        rule = _detail_rule(record)
        if rule is not None and title is not None:
            rules.append(rule)
        record, key = {}, None

    def end_ruleset():
        nonlocal rules
        end_record()
        if title is not None and rules:
            chains.append(_chain(title, rules))
        rules = []

    for line in str(output).splitlines():
        stripped = line.strip()
        match = _TITLE.match(stripped)
        if match:
            end_ruleset()
            title = match
            continue
        detail = _DETAIL_LINE.match(line.rstrip())
        if detail and title is not None:
            value = (detail.group("value") or "").strip()
            if detail.group("key"):
                key = detail.group("key").strip()
                record[key] = value
            elif key and value:
                record[key] = f"{record[key]} {value}".strip()
            continue
        end_record()
        if stripped.startswith("---"):
            end_ruleset()
            title = None
    end_ruleset()
    return chains


def last_used_age_ms(value):
    """
    Sort key for a "Last Used" value: elapsed milliseconds, a huge number for
    "never" (least recently used of all) and -1 when not tracked or unknown.
    """
    text = (value or "").strip().lower()
    if text == "never":
        return 10**15
    matches = _DURATION.findall(text)
    if not matches or _DURATION.sub("", text):
        return -1
    return sum(int(n) * _DURATION_MS[unit] for n, unit in matches)


def _config_ruleset(user_data, chain):
    """The config's chain or filter for a device ruleset, and its rules."""
    version = (user_data or {}).get(chain["family"]) or {}
    if chain["kind"] == "name":
        cfg = (version.get("chains") or {}).get(chain["name"])
        if not isinstance(cfg, dict):
            return None, None, {}
        description = (cfg.get("default") or {}).get("description")
        return cfg, description, cfg
    cfg = (version.get("filters") or {}).get(chain["name"])
    if not isinstance(cfg, dict):
        return None, None, {}
    return cfg, cfg.get("description"), cfg.get("rules") or {}


def enrich(chains, user_data):
    """
    Add config descriptions and display fields to parsed rulesets, in place.

    Per ruleset: ``description`` and ``in_config``. Per rule:
    ``description`` (None when the rule is not in the config), counts as
    ``packets_h``/``bytes_h``, ``zero`` and the packet ``share`` of the
    ruleset (``bar`` is the width relative to its busiest rule).
    """
    for chain in chains:
        cfg, description, rule_cfg = _config_ruleset(user_data, chain)
        chain["in_config"] = cfg is not None
        chain["description"] = description or ""
        chain["packets_h"] = human_count(chain["packets"])
        busiest = max([r["packets"] for r in chain["rules"]] + [1])
        for rule in chain["rules"]:
            detail = None if rule["is_default"] else rule_cfg.get(str(rule["number"]))
            rule["description"] = (
                detail.get("description", "") if isinstance(detail, dict) else None
            )
            rule["packets_h"] = human_count(rule["packets"])
            rule["bytes_h"] = human_bytes(rule["bytes"])
            rule["last_used_ms"] = last_used_age_ms(rule.get("last_used"))
            rule["zero"] = rule["packets"] == 0
            rule["bar"] = round(rule["packets"] / busiest * 100, 1)
            if not chain["packets"] or not rule["packets"]:
                rule["share"] = "0%"
            else:
                share = rule["packets"] / chain["packets"] * 100
                rule["share"] = "<1%" if share < 1 else f"{share:.0f}%"
    return chains


def has_last_used(chains):
    """True when the output carried a Last Used field (detail output)."""
    return any(r.get("last_used") is not None for c in chains for r in c["rules"])


def stats(chains):
    """Summary tiles: rulesets, rules, rules never hit, packets dropped."""
    rules = [r for c in chains for r in c["rules"] if not r["is_default"]]
    dropped = sum(r["packets"] for c in chains for r in c["rules"] if r["action"] == "drop")
    return {
        "chains": len(chains),
        "rules": len(rules),
        "never_hit": sum(1 for r in rules if r["packets"] == 0),
        "dropped": dropped,
        "dropped_h": human_count(dropped),
    }


def counter_key(chain, rule):
    return f'{chain["family"]}|{chain["kind"]}|{chain["name"]}|{rule["number"]}'


def counter_snapshot(chains):
    """Packet counters by ruleset and rule, for the next run's deltas."""
    return {counter_key(c, r): r["packets"] for c in chains for r in c["rules"]}


def apply_deltas(chains, previous):
    """
    Set each rule's ``delta`` (packets since ``previous``), in place.

    ``delta`` is None for a rule not in ``previous`` (new since then, or no
    previous run) and for a counter that went down (reset or rule replaced),
    where a negative change would be misleading. ``delta_h`` is its display
    form.
    """
    previous = previous or {}
    for chain in chains:
        for rule in chain["rules"]:
            before = previous.get(counter_key(chain, rule))
            if isinstance(before, int) and rule["packets"] >= before:
                rule["delta"] = rule["packets"] - before
                rule["delta_h"] = human_count(rule["delta"])
            else:
                rule["delta"] = None
                rule["delta_h"] = ""
    return chains
