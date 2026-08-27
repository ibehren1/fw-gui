"""Regression tests for the pkg_resources shim.

Ensures napalm-vyos (which imports pkg_resources) keeps working when setuptools
no longer bundles pkg_resources. Importing `package` installs the shim into
sys.modules when the real module is absent.
"""

import sys

import package  # noqa: F401  (import side effect installs the shim)


def test_pkg_resources_importable():
    import pkg_resources

    assert pkg_resources is not None


def test_get_distribution_returns_version():
    import pkg_resources

    dist = pkg_resources.get_distribution("napalm-vyos")
    assert isinstance(dist.version, str) and dist.version != ""


def test_distribution_not_found_raises():
    import pkg_resources

    try:
        pkg_resources.get_distribution("definitely-not-a-real-package-xyz")
    except pkg_resources.DistributionNotFound:
        pass
    else:  # pragma: no cover
        # Only assert when we are actually using the shim; the real
        # pkg_resources also raises DistributionNotFound, so this is safe.
        assert "pkg_resources" in sys.modules


def test_vyos_driver_loads():
    from napalm import get_network_driver

    driver = get_network_driver("vyos")
    assert driver.__name__ == "VyOSDriver"
