"""Burp entry point for the WAF detection extension."""

from burp import (IBurpExtender, IContextMenuFactory, IHttpListener,
                  IScannerCheck, ITab)

from wafd.extension import WafExtension


class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck,
                   IContextMenuFactory, ITab, WafExtension):
    """Expose the extension through every legacy Burp API it registers."""

    def __init__(self):
        # Burp's Java interfaces appear first so Jython exports an object that
        # Java recognises for each callback registration.  Initialise the final
        # Python mixin explicitly because interface-first method resolution
        # must not bypass the extension's state initialisation.
        WafExtension.__init__(self)

    def registerExtenderCallbacks(self, callbacks):
        """Delegate Burp's required bootstrap method to the reusable adapter."""
        # Keep this method directly on the exported class.  Burp validates the
        # IBurpExtender contract before invoking any listener registrations.
        return WafExtension.registerExtenderCallbacks(self, callbacks)
