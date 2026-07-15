"""Versioned, dependency-free extension configuration."""

import json


class Configuration(object):
    """Validate settings before they reach detection or probing code."""

    VERSION = 1

    def __init__(self, threshold=0.60, in_scope_only=True, max_probes=None,
                 enabled=True, non_get_target="root", body_test_threshold=8192,
                 header_test_threshold=4096, header_count_test_threshold=64,
                 inspection_boundary=8192, size_hard_max=262144):
        # Reject an invalid threshold rather than silently changing the point
        # at which Burp reports that a WAF is suspected.
        self.threshold = self._threshold(threshold)
        self.in_scope_only = bool(in_scope_only)
        # No implicit cap is applied: every individually enabled and
        # method-compatible probe is eligible by default. A configured numeric
        # limit remains bounded to keep malformed saved settings manageable.
        self.max_probes = self._max_probes(max_probes)
        self.enabled = bool(enabled)
        # Non-GET probes can either use a neutral root request or preserve the
        # explicitly selected resource. Arbitrary paths are not accepted in
        # the saved configuration.
        if non_get_target not in ("root", "selected"):
            raise ValueError("non_get_target must be root or selected")
        self.non_get_target = non_get_target
        # Size probes use user-configured research thresholds rather than
        # assuming a vendor limit. The hard maximum bounds every generated
        # request even if a saved threshold is unexpectedly large.
        self.size_hard_max = self._positive_int(size_hard_max, "size_hard_max", 1024, 1048576)
        self.body_test_threshold = self._threshold_size(
            body_test_threshold, "body_test_threshold")
        self.header_test_threshold = self._threshold_size(
            header_test_threshold, "header_test_threshold")
        self.header_count_test_threshold = self._positive_int(
            header_count_test_threshold, "header_count_test_threshold", 1, 500)
        self.inspection_boundary = self._threshold_size(
            inspection_boundary, "inspection_boundary")
        if self.body_test_threshold >= self.size_hard_max:
            raise ValueError("body_test_threshold must be below size_hard_max")
        if self.header_test_threshold >= self.size_hard_max:
            raise ValueError("header_test_threshold must be below size_hard_max")
        if self.inspection_boundary >= self.size_hard_max:
            raise ValueError("inspection_boundary must be below size_hard_max")

    @staticmethod
    def _threshold(value):
        value = float(value)
        if not 0 <= value <= 1:
            raise ValueError("threshold must be between 0 and 1")
        return value

    @staticmethod
    def _max_probes(value):
        """Return an optional bound on transmitted probe requests."""
        if value is None:
            return None
        return max(0, min(int(value), 1000))

    @staticmethod
    def _positive_int(value, name, minimum, maximum):
        value = int(value)
        if value < minimum or value > maximum:
            raise ValueError("%s must be between %d and %d" % (name, minimum, maximum))
        return value

    def _threshold_size(self, value, name):
        return self._positive_int(value, name, 1, self.size_hard_max)

    def to_json(self):
        return json.dumps({"schema_version": self.VERSION, "threshold": self.threshold,
                           "in_scope_only": self.in_scope_only, "max_probes": self.max_probes,
                           "enabled": self.enabled, "non_get_target": self.non_get_target,
                           "body_test_threshold": self.body_test_threshold,
                           "header_test_threshold": self.header_test_threshold,
                           "header_count_test_threshold": self.header_count_test_threshold,
                           "inspection_boundary": self.inspection_boundary,
                           "size_hard_max": self.size_hard_max}, sort_keys=True)

    @classmethod
    def from_json(cls, text):
        value = json.loads(text)
        # A schema marker prevents a future configuration shape from being
        # interpreted using today's defaults and validation rules.
        if not isinstance(value, dict) or value.get("schema_version") != cls.VERSION:
            raise ValueError("unsupported configuration schema")
        return cls(value.get("threshold", .60), value.get("in_scope_only", True),
                   value.get("max_probes"), value.get("enabled", True),
                   value.get("non_get_target", "root"),
                   value.get("body_test_threshold", 8192),
                   value.get("header_test_threshold", 4096),
                   value.get("header_count_test_threshold", 64),
                   value.get("inspection_boundary", 8192),
                   value.get("size_hard_max", 262144))
