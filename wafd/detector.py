"""Burp-independent response matching."""

from .models import Evidence
from difflib import SequenceMatcher
import re


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
            elif kind == "status_transition" and baseline is not None:
                blocked = [int(value) for value in matcher.get("blocked", [])]
                before = int(baseline.get("status", 0) or 0)
                matched = before not in blocked and status in blocked
                detail = "baseline HTTP %d changed to blocked HTTP %d" % (before, status)
            elif kind == "body_similarity_drop" and baseline is not None:
                before = str(baseline.get("body", ""))[:4096]
                similarity = SequenceMatcher(None, before, str(response.get("body", ""))[:4096]).ratio()
                matched = similarity < float(matcher.get("below", 0.5))
                detail = "probe body similarity fell to %.0f%%" % (similarity * 100)
            elif kind == "header_delta" and baseline is not None:
                before = set(str(key).lower() for key in baseline.get("headers", {}))
                added = set(headers) - before
                matched = len(added) >= int(matcher.get("minimum", 1))
                detail = "probe added response headers: %s" % ", ".join(sorted(added))
            elif kind == "body_hash_change" and baseline is not None:
                matched = (baseline.get("body_hash") and response.get("body_hash") and
                           baseline.get("body_hash") != response.get("body_hash"))
                detail = "probe changed the response body hash"
            elif kind == "cookie_delta" and baseline is not None:
                added = set(response.get("cookies", [])) - set(baseline.get("cookies", []))
                matched = len(added) >= int(matcher.get("minimum", 1))
                detail = "probe added response cookies: %s" % ", ".join(sorted(added))
            elif kind == "http_version_change" and baseline is not None:
                matched = (baseline.get("http_version") and response.get("http_version") and
                           baseline.get("http_version") != response.get("http_version"))
                detail = "probe changed HTTP version from %s to %s" % (
                    baseline.get("http_version"), response.get("http_version"))
            elif kind == "connection_state":
                matched = response.get("connection_state") in matcher.get("values", [])
                detail = "transport ended with %s" % response.get("connection_state")
            elif kind == "challenge_transition" and baseline is not None:
                challenge_terms = [str(term).lower() for term in matcher.get("terms", [])]
                before_body = str(baseline.get("body", "")).lower()
                challenge_body = any(term in body and term not in before_body for term in challenge_terms)
                challenge_status = (status in [int(value) for value in matcher.get("statuses", [])]
                                    and int(baseline.get("status", 0) or 0) not in
                                    [int(value) for value in matcher.get("statuses", [])])
                matched = challenge_body or challenge_status
                detail = "probe triggered a challenge or verification response"
            elif kind == "strong_header":
                expected = str(matcher.get("contains", "")).lower()
                value = headers.get(str(matcher.get("name", "")).lower(), "")
                matched = expected in value.lower()
                detail = "%s: %s" % (matcher.get("name"), value)
            elif kind == "header_body":
                value = headers.get(str(matcher.get("header", "")).lower(), "")
                header_match = str(matcher.get("header_contains", "")).lower() in value.lower()
                body_match = all(str(term).lower() in body for term in matcher.get("body_terms", []))
                regex = matcher.get("body_regex")
                regex_match = bool(re.search(regex, body, re.I | re.S)) if regex else True
                matched = header_match and body_match and regex_match
                detail = "vendor response marker and behavioural block content matched"
            elif kind == "body_regex":
                matched = bool(re.search(str(matcher.get("pattern", "")), body, re.I | re.S))
                detail = "response body matched a vendor block template"
            if matched:
                product = next((tag for tag in rule.tags if tag != "generic" and tag != "product"), "")
                action = next((tag for tag in rule.tags if tag in
                               ("block", "challenge", "captcha", "rate_limit", "reset")), "")
                found.append(Evidence(rule.rule_id, origin, detail, product, source, action))
        return found
