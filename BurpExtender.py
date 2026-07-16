"""Burp entry point for the WAF detection extension."""

from burp import (IBurpExtender, IContextMenuFactory, IExtensionStateListener,
                  IHttpListener, IScannerCheck, ITab)

from wafd.extension import WafExtension


class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck,
                   IContextMenuFactory, IExtensionStateListener, ITab,
                   WafExtension):
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

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Delegate ``IHttpListener`` traffic notifications."""
        return WafExtension.processHttpMessage(
            self, toolFlag, messageIsRequest, messageInfo)

    def doPassiveScan(self, baseRequestResponse):
        """Delegate ``IScannerCheck`` passive analysis."""
        return WafExtension.doPassiveScan(self, baseRequestResponse)

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Delegate ``IScannerCheck`` active analysis."""
        return WafExtension.doActiveScan(
            self, baseRequestResponse, insertionPoint)

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Delegate ``IScannerCheck`` duplicate consolidation."""
        return WafExtension.consolidateDuplicateIssues(
            self, existingIssue, newIssue)

    def createMenuItems(self, invocation):
        """Delegate ``IContextMenuFactory`` menu construction."""
        return WafExtension.createMenuItems(self, invocation)

    def extensionUnloaded(self):
        """Delegate Burp's extension lifecycle notification."""
        return WafExtension.extensionUnloaded(self)

    def getTabCaption(self):
        """Delegate the ``ITab`` caption requested by Burp."""
        return WafExtension.getTabCaption(self)

    def getUiComponent(self):
        """Delegate the ``ITab`` Swing component requested by Burp."""
        return WafExtension.getUiComponent(self)
