"""Bounded, privacy-conscious HTTP response fingerprints."""

import hashlib
import re


def build_fingerprint(status, headers, body, http_version="", connection_state="complete", elapsed_ms=None):
    """Return stable comparison fields without retaining the complete body."""
    # Replacement decoding makes malformed response bytes observable without
    # allowing one invalid sequence to abort passive traffic processing.
    if not isinstance(body, str):
        body = body.decode("utf-8", "replace")
    body_bytes = body.encode("utf-8")
    normalised_headers = dict((str(key).lower(), str(value)) for key, value in headers.items())
    set_cookie = normalised_headers.get("set-cookie", "")
    cookie_names = []
    cookie_fingerprints = {}
    # Retain names rather than values: mitigation-cookie changes are useful
    # evidence, whereas values may contain session material and are not needed.
    for cookie in set_cookie.splitlines() or [set_cookie]:
        for item in cookie.split(","):
            match = re.match(r"\s*([^=;\s]+)=", item.split(";", 1)[0])
            if match:
                name = match.group(1)
                cookie_names.append(name)
                value_match = re.match(r"\s*[^=;\s]+=([^;]*)", item)
                if value_match:
                    # Hash values so rotations remain comparable without
                    # retaining session or mitigation tokens in assessments.
                    cookie_fingerprints[name] = hashlib.sha256(
                        value_match.group(1).encode("utf-8")).hexdigest()
    cookie_names = sorted(set(cookie_names))
    if set_cookie:
        # Header matchers need cookie names (for example BIG-IP routing
        # cookies), not their sensitive values. Replace values after parsing
        # so the complete fingerprint is safe to retain and display.
        normalised_headers["set-cookie"] = "\n".join(
            "%s=<redacted>" % name for name in cookie_names)
    return {
        "status": int(status or 0),
        "headers": normalised_headers,
        "cookies": cookie_names,
        "cookie_fingerprints": cookie_fingerprints,
        "body_length": len(body_bytes),
        "body_hash": hashlib.sha256(body_bytes).hexdigest(),
        # Matching receives only a bounded sample. The hash and original byte
        # length still allow active baseline comparisons without storing the
        # complete response in the assessment model.
        "body": body[:4096],
        "http_version": str(http_version or ""),
        "connection_state": str(connection_state or "complete"),
        "elapsed_ms": elapsed_ms,
    }
