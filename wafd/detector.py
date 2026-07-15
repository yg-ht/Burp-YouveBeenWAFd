"""Burp-independent response matching."""

from .models import Evidence


class ResponseDetector(object):
    """Apply catalogue matchers to normalised response dictionaries."""

    def __init__(self, catalogue):
        self.catalogue = catalogue

    def detect(self, origin, response, source="passive", baseline=None):
        """Return distinct evidence for one response.

        ``response`` has ``status``, ``headers`` and ``body`` fields. Bodies
        are expected to be bounded by the adapter before matching.
        """
        found = []
        headers = dict((str(key).lower(), str(value))
                       for key, value in response.get("headers", {}).items())
        body = str(response.get("body", "")).lower()
        status = int(response.get("status", 0) or 0)
        for rule in self.catalogue.enabled():
            matcher = rule.matcher
            kind = matcher.get("kind")
            matched = False
            detail = ""
            if kind == "status":
                matched = status in [int(value) for value in matcher.get("values", [])]
                detail = "HTTP status %d" % status
            elif kind == "header":
                name = str(matcher.get("name", "")).lower()
                value = headers.get(name)
                expected = str(matcher.get("contains", "")).lower()
                matched = value is not None and expected in value.lower()
                detail = "%s header present" % name
            elif kind == "body_terms":
                term = next((term for term in matcher.get("values", [])
                             if str(term).lower() in body), None)
                matched = term is not None
                detail = "response contains %s" % term if term else ""
            elif kind == "active_differential" and baseline is not None:
                matched = (int(baseline.get("status", 0) or 0) != status or
                           str(baseline.get("body", ""))[:512] != str(response.get("body", ""))[:512])
                detail = "probe response differs from baseline"
            if matched:
                product = next((tag for tag in rule.tags if tag != "generic" and tag != "product"), "")
                found.append(Evidence(rule.rule_id, origin, detail, product, source))
        return found
