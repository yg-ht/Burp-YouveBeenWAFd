"""Bounded, privacy-conscious HTTP response fingerprints."""

import hashlib
import re


def build_fingerprint(status, headers, body, http_version="", connection_state="complete", elapsed_ms=None):
    """Return stable comparison fields without retaining the complete body."""
    if not isinstance(body, str):
        body = body.decode("utf-8", "replace")
    body_bytes = body.encode("utf-8")
    normalised_headers = dict((str(key).lower(), str(value)) for key, value in headers.items())
    set_cookie = normalised_headers.get("set-cookie", "")
    cookie_names = []
    for cookie in set_cookie.splitlines() or [set_cookie]:
        for item in cookie.split(","):
            match = re.match(r"\s*([^=;\s]+)=", item.split(";", 1)[0])
            if match:
                cookie_names.append(match.group(1))
    cookie_names = sorted(set(cookie_names))
    return {
        "status": int(status or 0),
        "headers": normalised_headers,
        "cookies": cookie_names,
        "body_length": len(body_bytes),
        "body_hash": hashlib.sha256(body_bytes).hexdigest(),
        "body": body[:4096],
        "http_version": str(http_version or ""),
        "connection_state": str(connection_state or "complete"),
        "elapsed_ms": elapsed_ms,
    }
