"""Safe active probe planning, independent of Burp request objects."""


class ProbePlanner(object):
    """Plan bounded marker payloads without executing them."""

    DEFAULT_PAYLOADS = (
        "wafd-probe-quote-'",
        "wafd-probe-angle-<>",
        "wafd-probe-path-..%2f..%2f",
    )

    def __init__(self, max_probes=3, allow_non_idempotent=False):
        self.max_probes = max(0, min(int(max_probes), 20))
        self.allow_non_idempotent = bool(allow_non_idempotent)

    def plan(self, method, insertion_point_name=""):
        """Return payloads, refusing unsafe methods by default."""
        method = str(method).upper()
        if method not in ("GET", "HEAD", "OPTIONS") and not self.allow_non_idempotent:
            return []
        # Avoid putting probes into cookies, authentication and headers unless
        # the user explicitly enables broader scanning in a later setting.
        name = str(insertion_point_name).lower()
        if any(term in name for term in ("cookie", "authorization", "header")):
            return []
        return list(self.DEFAULT_PAYLOADS[:self.max_probes])
