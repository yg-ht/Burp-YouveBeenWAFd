"""Regression tests for the legacy Burp/Jython extension entry point."""

import importlib
import sys
import types
import unittest
from unittest import mock


INTERFACE_NAMES = (
    "IBurpExtender",
    "IHttpListener",
    "IScannerCheck",
    "IContextMenuFactory",
    "ITab",
)

INTERFACE_METHODS = {
    "IBurpExtender": ("registerExtenderCallbacks",),
    "IHttpListener": ("processHttpMessage",),
    "IScannerCheck": (
        "doPassiveScan",
        "doActiveScan",
        "consolidateDuplicateIssues",
    ),
    "IContextMenuFactory": ("createMenuItems",),
    "ITab": ("getTabCaption", "getUiComponent"),
}


class BurpEntryPointTests(unittest.TestCase):
    """Verify that Burp receives an object implementing every registered API."""

    def test_exported_class_implements_legacy_burp_interfaces(self):
        # The test environment does not include Burp's Java classes.  Distinct
        # stand-ins let CPython exercise the same inheritance contract without
        # weakening the production entry point with non-Burp fallbacks.
        burp_module = types.ModuleType("burp")
        interfaces = {}
        for interface_name in INTERFACE_NAMES:
            interface = type(interface_name, (object,), {})
            interfaces[interface_name] = interface
            setattr(burp_module, interface_name, interface)

        # Force a fresh import so the module resolves the stand-in interfaces
        # exactly as Jython resolves the real interfaces inside Burp.
        sys.modules.pop("BurpExtender", None)
        try:
            with mock.patch.dict(sys.modules, {"burp": burp_module}):
                entry_module = importlib.import_module("BurpExtender")

            extender_class = entry_module.BurpExtender
            for interface_name, interface in interfaces.items():
                self.assertTrue(
                    issubclass(extender_class, interface),
                    "BurpExtender does not implement %s" % interface_name,
                )

            # Jython's Java proxy does not satisfy abstract interface methods
            # from a later Python mixin.  Every method must therefore be
            # declared directly on the class exported to Burp.
            for interface_name, method_names in INTERFACE_METHODS.items():
                for method_name in method_names:
                    self.assertIn(
                        method_name,
                        extender_class.__dict__,
                        "%s method %s is inherited rather than explicit"
                        % (interface_name, method_name),
                    )
        finally:
            sys.modules.pop("BurpExtender", None)


if __name__ == "__main__":
    unittest.main()
