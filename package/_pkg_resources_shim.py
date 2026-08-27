"""Minimal ``pkg_resources`` shim backed by the standard library.

setuptools 81+ no longer bundles ``pkg_resources`` (it is slated for removal),
but ``napalm-vyos`` still does a bare ``import pkg_resources`` (only to read its
own version string), which raises ``ModuleNotFoundError`` and breaks the VyOS
driver used by View Diffs / Commit.

Rather than pin setuptools below 81 (which we keep current for security fixes),
this module provides the small ``pkg_resources`` surface those callers use,
implemented on top of ``importlib.metadata`` / ``importlib.resources``. It is
installed into ``sys.modules['pkg_resources']`` by ``package/__init__.py`` only
when the real ``pkg_resources`` is unavailable, so a future setuptools that
still ships it (or a pin below 81) transparently wins.

Only the surface observed in this project's dependency tree is implemented
(napalm-vyos: get_distribution/DistributionNotFound; pytz: resource_stream;
werkzeug testapp: working_set; _pytest.monkeypatch: fixup_namespace_packages /
_namespace_packages). Add to it if a new consumer needs more.
"""

import re as _re
from importlib import metadata as _md
from importlib import resources as _res


class DistributionNotFound(Exception):
    """Raised when a requested distribution is not installed."""


class Distribution:
    def __init__(self, project_name, version):
        self.project_name = project_name
        self.version = version


def _bare_name(requirement):
    """Strip version specifiers / extras from a requirement string."""
    return _re.split(r"[<>=!~;\[ ]", requirement, 1)[0].strip()


def get_distribution(dist):
    name = _bare_name(dist) if isinstance(dist, str) else dist
    try:
        return Distribution(name, _md.version(name))
    except _md.PackageNotFoundError as exc:  # pragma: no cover - defensive
        raise DistributionNotFound(name) from exc


def require(*requirements):
    return [get_distribution(r) for r in requirements]


# --- namespace-package no-ops (referenced by _pytest.monkeypatch) ---
_namespace_packages = {}


def declare_namespace(name):  # pragma: no cover - no-op compatibility
    return None


def fixup_namespace_packages(path, parent=None):  # pragma: no cover
    return None


# --- entry points (backed by importlib.metadata) ---
class _EntryPoint:
    def __init__(self, ep):
        self._ep = ep
        self.name = ep.name

    def load(self):
        return self._ep.load()


def iter_entry_points(group, name=None):
    try:
        eps = _md.entry_points(group=group)
    except TypeError:  # pragma: no cover - older importlib.metadata
        eps = _md.entry_points().get(group, [])
    for ep in eps:
        if name is None or ep.name == name:
            yield _EntryPoint(ep)


def load_entry_point(dist, group, name):
    for ep in iter_entry_points(group, name):
        return ep.load()
    raise ImportError(f"Entry point {group!r}:{name!r} not found")


# --- resource access (backed by importlib.resources) ---
def resource_stream(package, resource):
    return (_res.files(package) / resource).open("rb")


def resource_string(package, resource):
    return (_res.files(package) / resource).read_bytes()


def resource_filename(package, resource):
    return str(_res.files(package) / resource)


# --- misc attributes some callers reference ---
working_set = []
