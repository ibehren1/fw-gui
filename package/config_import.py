"""
    Import a running VyOS firewall configuration.

    Converts the output of `show configuration json` (the whole config, or only
    its `firewall` subtree) into an FW-GUI configuration document.

    What the document can hold -- groups, named chains, the input/forward/output
    base filters, software flowtables -- is mapped into its fields. Every other
    `set firewall ...` path (global-options, zones, a rule's icmp type or tcp
    flags, a second match on one side of a rule, ...) is kept verbatim as an
    extra-items line, so a push reproduces the device's configuration.

    The full configuration carries secrets (WireGuard private keys, password
    hashes). Only the `firewall` subtree and the interface names and
    descriptions are kept; nothing from the raw output is stored or logged.

    Pure functions only: no database, session or network access.
"""

import json
import re
import shlex

from package.generate_config import _vq, render_config
from package.release_features import FEATURES, set_release

# Pasted / uploaded / fetched output larger than this is refused.
MAX_IMPORT_BYTES = 5 * 1024 * 1024

# Top-level keys of the `firewall` subtree, used to recognise a pasted subtree.
_FIREWALL_KEYS = {"global-options", "group", "ipv4", "ipv6", "bridge", "flowtable", "zone"}

# VyOS group type -> the leaf holding its values (inverse of generate_config).
_GROUP_VALUE_KEY = {
    "address-group": "address",
    "domain-group": "address",
    "interface-group": "interface",
    "mac-group": "mac-address",
    "network-group": "network",
    "port-group": "port",
}
# IPv6 group types, stored under ipv6.groups without the prefix.
_IPV6_GROUPS = {
    "ipv6-address-group": "address-group",
    "ipv6-network-group": "network-group",
}
# Rule match group type -> stored *_address_type.
_ADDRESS_GROUP_TYPES = (
    ("address-group", "address_group"),
    ("network-group", "network_group"),
    ("domain-group", "domain_group"),
    ("mac-group", "mac_group"),
)
_STATES = {
    "established": "state_est",
    "invalid": "state_inv",
    "new": "state_new",
    "related": "state_rel",
}
# Chain rule actions the chain rule form offers.
_UI_CHAIN_ACTIONS = {"accept", "drop", "reject", "continue"}
_HOOKS = ("input", "forward", "output")
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,15}$")
_RULE_NUMBER = re.compile(r"^[0-9]{1,6}$")


class ConfigImportError(ValueError):
    """The input could not be read as a VyOS firewall configuration."""


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------


def extract_trees(raw_text):
    """
    Finds the configuration JSON in device output or pasted text.

    Args:
        raw_text (str): `show configuration json` output, the full config or
            only its `firewall` subtree. Text before the first "{" (a banner,
            a prompt) is skipped.

    Returns:
        tuple: (firewall_tree, interfaces_tree or None). Nothing else from the
            input is kept.

    Raises:
        ConfigImportError: No JSON object, or no firewall configuration in it.
    """
    start = raw_text.find("{")
    if start < 0:
        raise ConfigImportError("No JSON configuration found in the input.")
    try:
        data, _ = json.JSONDecoder().raw_decode(raw_text[start:])
    except json.JSONDecodeError:
        raise ConfigImportError("The input is not valid JSON.") from None
    if not isinstance(data, dict):
        raise ConfigImportError("The input is not a VyOS configuration object.")

    if "firewall" in data:
        firewall, interfaces = data["firewall"], data.get("interfaces")
    elif _FIREWALL_KEYS & set(data):
        firewall, interfaces = data, None
    else:
        raise ConfigImportError("No firewall configuration found in the input.")

    if not isinstance(firewall, dict) or not firewall:
        raise ConfigImportError("The firewall configuration is empty.")
    return firewall, interfaces if isinstance(interfaces, dict) else None


def flatten(tree, prefix=("firewall",)):
    """
    Turns a VyOS JSON tree into its set-command leaves.

    An empty dict is a valueless node (`log`, `last-used`), a list is a
    multi-value node, and a scalar is a value.

    Returns:
        list: (path tuple, value or None) in tree order.
    """
    leaves = []

    def walk(node, path):
        if isinstance(node, dict):
            if not node:
                leaves.append((path, None))
            for key, child in node.items():
                walk(child, path + (str(key),))
        elif isinstance(node, list):
            for item in node:
                leaves.append((path, str(item)))
        else:
            leaves.append((path, str(node)))

    walk(tree, tuple(prefix))
    return leaves


def set_line(path, value):
    """Renders one leaf as a `set` command, quoting the value."""
    line = "set " + " ".join(path)
    return line if value is None else f"{line} {_vq(value)}"


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------


def _as_list(value):
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, dict):
        return []
    return [str(value)]


def _text(value):
    return value if isinstance(value, str) else None


class _Builder:
    """Builds the document, recording every leaf it maps."""

    def __init__(self, firewall):
        self.fw = firewall
        self.consumed = set()
        self.warnings = []
        self.last_used_seen = False
        self.doc = {"version": "1", "origin": "import",
                    "system": {"hostname": "None", "port": "None"}}

    def take(self, path, value=None):
        self.consumed.add((tuple(path), value))

    def flag(self, node, key, path):
        """True and consumed if `key` is a valueless node of `node`."""
        if node.get(key) == {}:
            self.take(path + (key,))
            return True
        return False

    def section(self, ip_version, key):
        return self.doc.setdefault(ip_version, {}).setdefault(key, {})

    # -- groups ------------------------------------------------------------

    def groups(self):
        for vyos_type, groups in (self.fw.get("group") or {}).items():
            if vyos_type in _GROUP_VALUE_KEY:
                ip_version, stored_type = "ipv4", vyos_type
            elif vyos_type in _IPV6_GROUPS:
                ip_version, stored_type = "ipv6", _IPV6_GROUPS[vyos_type]
            else:
                continue  # dynamic-group, remote-group, ...: extra-items
            if not isinstance(groups, dict):
                continue
            value_key = _GROUP_VALUE_KEY[stored_type]
            for name, cfg in groups.items():
                if not isinstance(cfg, dict):
                    continue
                stored = self.section(ip_version, "groups")
                if name in stored:
                    self.warnings.append(
                        f"{ip_version} {vyos_type} {name}: another group already "
                        "uses this name, kept in extra items."
                    )
                    continue
                base = ("firewall", "group", vyos_type, name)
                description = _text(cfg.get("description")) or ""
                if "description" in cfg and description:
                    self.take(base + ("description",), description)
                values = _as_list(cfg.get(value_key, []))
                for value in values:
                    self.take(base + (value_key,), value)
                stored[name] = {
                    "group_desc": description,
                    "group_type": stored_type,
                    "group_value": values,
                }

    # -- chains ------------------------------------------------------------

    def chains(self, ip_version):
        names = ((self.fw.get(ip_version) or {}).get("name")) or {}
        for name, cfg in names.items():
            if not isinstance(cfg, dict):
                continue
            base = ("firewall", ip_version, "name", name)
            description = _text(cfg.get("description"))
            if description is not None:
                self.take(base + ("description",), description)
            else:
                description = ""
            default_action = _text(cfg.get("default-action"))
            if default_action is not None:
                self.take(base + ("default-action",), default_action)
            else:
                # VyOS's implicit default for a named chain.
                default_action = "drop"
                self.warnings.append(
                    f"{ip_version} chain {name}: no default action on the device; "
                    "stored as its implicit default, drop."
                )
            chain = {
                "rule-order": [],
                "default": {
                    "description": description,
                    "default_action": default_action,
                    "default_logging": self.flag(cfg, "default-log", base),
                },
            }
            for number, rule in (cfg.get("rule") or {}).items():
                if not _RULE_NUMBER.match(str(number)) or not isinstance(rule, dict):
                    continue
                chain[number] = self.chain_rule(
                    ip_version, name, number, rule, base + ("rule", number)
                )
                chain["rule-order"].append(number)
            chain["rule-order"].sort(key=int)
            self.section(ip_version, "chains")[name] = chain

    def chain_rule(self, ip_version, chain, number, rule, path):
        stored = {
            "description": "",
            "action": "",
            "dest_address": "",
            "dest_address_type": "address",
            "dest_port": "",
            "dest_port_type": "port",
            "source_address": "",
            "source_address_type": "address",
            "source_port": "",
            "source_port_type": "port",
            "protocol": "",
        }
        description = _text(rule.get("description"))
        if description is not None:
            stored["description"] = description
            self.take(path + ("description",), description)

        action = _text(rule.get("action"))
        if action is not None:
            stored["action"] = action
            self.take(path + ("action",), action)
            if action not in _UI_CHAIN_ACTIONS:
                self.warnings.append(
                    f"{ip_version} chain {chain} rule {number}: action '{action}' "
                    "is kept, but the rule form cannot edit it."
                )
        else:
            self.warnings.append(
                f"{ip_version} chain {chain} rule {number}: no action on the device."
            )

        if self.flag(rule, "disable", path):
            stored["rule_disable"] = True
        if self.flag(rule, "log", path):
            stored["logging"] = True
        if self.flag(rule, "last-used", path):
            stored["last_used"] = True
            self.last_used_seen = True

        for state in _as_list(rule.get("state", [])):
            if state in _STATES:
                stored[_STATES[state]] = True
                self.take(path + ("state",), state)

        protocol = _text(rule.get("protocol"))
        # generate_config rewrites an IPv6 "icmp" to "ipv6-icmp"; leave that one
        # in extra items so the push sends what the device has.
        if protocol is not None and not (ip_version == "ipv6" and protocol == "icmp"):
            stored["protocol"] = protocol
            self.take(path + ("protocol",), protocol)

        for side, prefix in (("destination", "dest"), ("source", "source")):
            match = rule.get(side)
            if isinstance(match, dict):
                self.match(match, path + (side,), stored, prefix)
        return stored

    def match(self, match, path, stored, prefix):
        """One address (or address-like group) and one port (or port group)."""
        groups = match.get("group") if isinstance(match.get("group"), dict) else {}

        address = _text(match.get("address"))
        if address is not None:
            stored[f"{prefix}_address"] = address
            stored[f"{prefix}_address_type"] = "address"
            self.take(path + ("address",), address)
        else:
            for vyos_type, stored_type in _ADDRESS_GROUP_TYPES:
                group = _text(groups.get(vyos_type))
                if group is not None:
                    stored[f"{prefix}_address"] = group
                    stored[f"{prefix}_address_type"] = stored_type
                    self.take(path + ("group", vyos_type), group)
                    break

        port = _text(match.get("port"))
        if port is not None:
            stored[f"{prefix}_port"] = port
            stored[f"{prefix}_port_type"] = "port"
            self.take(path + ("port",), port)
        elif _text(groups.get("port-group")) is not None:
            stored[f"{prefix}_port"] = groups["port-group"]
            stored[f"{prefix}_port_type"] = "port_group"
            self.take(path + ("group", "port-group"), groups["port-group"])

    # -- filters -----------------------------------------------------------

    def filters(self, ip_version):
        for hook in _HOOKS:
            cfg = ((self.fw.get(ip_version) or {}).get(hook) or {}).get("filter")
            if not isinstance(cfg, dict):
                continue
            base = ("firewall", ip_version, hook, "filter")
            description = _text(cfg.get("description"))
            if description is not None:
                self.take(base + ("description",), description)
            else:
                description = ""
            default_action = _text(cfg.get("default-action"))
            if default_action is not None:
                self.take(base + ("default-action",), default_action)
            else:
                # VyOS's implicit default for a base filter.
                default_action = "accept"
            # generate_config emits the pre-1.4 spelling, enable-default-log;
            # a device's default-log is left in extra items.
            log = "True" if self.flag(cfg, "enable-default-log", base) else False
            stored = {
                "rule-order": [],
                "description": description,
                "default-action": default_action,
                "log": log,
                "rules": {},
            }
            for number, rule in (cfg.get("rule") or {}).items():
                if not _RULE_NUMBER.match(str(number)) or not isinstance(rule, dict):
                    continue
                stored["rules"][number] = self.filter_rule(
                    ip_version, hook, number, rule, base + ("rule", number)
                )
                stored["rule-order"].append(number)
            stored["rule-order"].sort(key=int)
            self.section(ip_version, "filters")[hook] = stored

    def filter_rule(self, ip_version, hook, number, rule, path):
        action = _text(rule.get("action")) or ""
        stored = {
            "ip_version": ip_version,
            "filter": hook,
            "description": "",
            "action": action,
            "fw_chain": "",
            "interface": "",
            "direction": "",
        }
        if action:
            self.take(path + ("action",), action)
        description = _text(rule.get("description"))
        if description is not None:
            stored["description"] = description
            self.take(path + ("description",), description)

        if action == "jump":
            target = _text(rule.get("jump-target"))
            if target is not None:
                stored["fw_chain"] = target
                self.take(path + ("jump-target",), target)
            for direction in ("inbound", "outbound"):
                iface = rule.get(f"{direction}-interface")
                name = _text(iface.get("name")) if isinstance(iface, dict) else None
                if name is not None:
                    stored["interface"] = name
                    stored["direction"] = direction
                    self.take(path + (f"{direction}-interface", "name"), name)
                    break
        elif action == "offload":
            target = _text(rule.get("offload-target"))
            if target is not None:
                stored["fw_chain"] = target
                self.take(path + ("offload-target",), target)
        else:
            self.warnings.append(
                f"{ip_version} {hook} filter rule {number}: action '{action}' is "
                "kept, but the filter rule form only edits jump and offload."
            )

        if self.flag(rule, "disable", path):
            stored["rule_disable"] = True
        if self.flag(rule, "log", path):
            stored["log"] = True
        if self.flag(rule, "last-used", path):
            stored["last_used"] = True
            self.last_used_seen = True
        return stored

    # -- flowtables --------------------------------------------------------

    def flowtables(self):
        for name, cfg in (self.fw.get("flowtable") or {}).items():
            if not isinstance(cfg, dict):
                continue
            description = _text(cfg.get("description"))
            # generate_config always emits a description and "offload software".
            if cfg.get("offload") != "software" or description is None:
                self.warnings.append(
                    f"flowtable {name}: kept in extra items (only software "
                    "offload with a description is modelled)."
                )
                continue
            base = ("firewall", "flowtable", name)
            interfaces = _as_list(cfg.get("interface", []))
            for iface in interfaces:
                self.take(base + ("interface",), iface)
            self.take(base + ("description",), description)
            self.take(base + ("offload",), "software")
            self.doc.setdefault("flowtables", []).append(
                {"name": name, "description": description, "interfaces": interfaces}
            )

    # -- interfaces --------------------------------------------------------

    def interfaces(self, tree):
        found = {}

        def add(name, cfg):
            if _INTERFACE_NAME.match(name) and name not in found:
                desc = _text(cfg.get("description")) if isinstance(cfg, dict) else None
                found[name] = desc or ""

        for itype, ifaces in (tree or {}).items():
            if itype == "loopback" or not isinstance(ifaces, dict):
                continue
            for name, cfg in ifaces.items():
                cfg = cfg if isinstance(cfg, dict) else {}
                add(name, cfg)
                for vid, vcfg in (cfg.get("vif") or {}).items():
                    add(f"{name}.{vid}", vcfg)
                for svid, scfg in (cfg.get("vif-s") or {}).items():
                    add(f"{name}.{svid}", scfg)
                    for cvid, ccfg in ((scfg or {}).get("vif-c") or {}).items():
                        add(f"{name}.{svid}.{cvid}", ccfg)

        # Names the rules and flowtables use but the tree lacks (or no tree).
        for version in ("ipv4", "ipv6"):
            for filt in (self.doc.get(version, {}).get("filters") or {}).values():
                for rule in filt["rules"].values():
                    if rule["interface"]:
                        add(rule["interface"], {})
        for flowtable in self.doc.get("flowtables", []):
            for iface in flowtable["interfaces"]:
                add(iface, {})

        if found:
            self.doc["interfaces"] = [
                {"name": name, "description": desc} for name, desc in found.items()
            ]

    # -- all ---------------------------------------------------------------

    def build(self, interfaces_tree):
        self.groups()
        for ip_version in ("ipv4", "ipv6"):
            self.filters(ip_version)
            self.chains(ip_version)
        self.flowtables()
        self.interfaces(interfaces_tree)

        extra = [
            set_line(path, value)
            for path, value in flatten(self.fw)
            if (path, value) not in self.consumed
        ]
        if extra:
            self.doc["extra-items"] = extra

        if self.last_used_seen:
            set_release(self.doc, rolling=True, milestone=FEATURES["last_used"]["since"])
        return self.doc


# ---------------------------------------------------------------------------
# Self-check and entry point
# ---------------------------------------------------------------------------


def _command_set(lines):
    commands = set()
    for line in "\n".join(lines).split("\n"):
        line = line.strip()
        if not line.startswith("set "):
            continue
        commands.add(tuple(shlex.split(line)[1:]))
    return commands


def self_check(doc, firewall_tree):
    """
    Compares what a push of `doc` would send with the device's configuration.

    Returns:
        dict: "not_on_device" -- lines the push would add; "missing" -- device
            lines the push would not send. Both empty for a faithful import.
    """
    device = {
        path + ((value,) if value is not None else ())
        for path, value in flatten(firewall_tree)
    }
    generated = _command_set(render_config(doc))

    def lines(commands):
        return sorted("set " + shlex.join(c) for c in commands)

    return {"not_on_device": lines(generated - device), "missing": lines(device - generated)}


def _counts(doc):
    counts = {"groups": 0, "chains": 0, "chain_rules": 0, "filters": 0,
              "filter_rules": 0}
    for version in ("ipv4", "ipv6"):
        section = doc.get(version, {})
        counts["groups"] += len(section.get("groups", {}))
        for chain in section.get("chains", {}).values():
            counts["chains"] += 1
            counts["chain_rules"] += len(chain["rule-order"])
        for filt in section.get("filters", {}).values():
            counts["filters"] += 1
            counts["filter_rules"] += len(filt["rule-order"])
    counts["flowtables"] = len(doc.get("flowtables", []))
    counts["interfaces"] = len(doc.get("interfaces", []))
    counts["extra_items"] = len(doc.get("extra-items", []))
    return counts


def import_config(raw_text):
    """
    Converts VyOS `show configuration json` output into a document.

    Args:
        raw_text (str): Device output or pasted / uploaded JSON.

    Returns:
        tuple: (document, report). The document has no _id; the caller names
            it and fills system.hostname / port / host_key. The report has
            counts, the extra-items lines, warnings, "interfaces_from"
            ("device" or "rules") and the self-check divergence.

    Raises:
        ConfigImportError: The input holds no usable firewall configuration.
    """
    firewall, interfaces = extract_trees(raw_text)
    builder = _Builder(firewall)
    doc = builder.build(interfaces)
    report = {
        "counts": _counts(doc),
        "extra_items": list(doc.get("extra-items", [])),
        "warnings": builder.warnings,
        "interfaces_from": "device" if interfaces else "rules",
        "rolling_release": builder.last_used_seen,
        "divergence": self_check(doc, firewall),
    }
    return doc, report
