"""FW-GUI package.

Importing any ``package.*`` module first runs this file. We use that as a hook
to install a minimal ``pkg_resources`` shim when setuptools (81+) no longer
provides one, so ``napalm-vyos`` (which imports pkg_resources at module load)
keeps working. If the real ``pkg_resources`` is available, it is left untouched.
See ``package/_pkg_resources_shim.py``.
"""

import sys as _sys

try:  # real pkg_resources present (setuptools < 81, or a future re-add)
    import pkg_resources  # noqa: F401
except ModuleNotFoundError:
    from package import _pkg_resources_shim as _shim

    _sys.modules["pkg_resources"] = _shim
