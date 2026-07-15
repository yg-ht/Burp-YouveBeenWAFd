"""Burp entry point for the WAF detection extension."""

from wafd.extension import WafExtension


class BurpExtender(WafExtension):
    """Expose the extension through Burp's legacy Python API."""

    pass
