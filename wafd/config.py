"""Versioned, dependency-free extension configuration."""

import json


class Configuration(object):
    """Validate settings before they reach detection or probing code."""

    VERSION = 1

    def __init__(self, threshold=0.60, in_scope_only=True, max_probes=3,
                 enabled=True):
        self.threshold = self._threshold(threshold)
        self.in_scope_only = bool(in_scope_only)
        self.max_probes = max(0, min(int(max_probes), 20))
        self.enabled = bool(enabled)

    @staticmethod
    def _threshold(value):
        value = float(value)
        if not 0 <= value <= 1:
            raise ValueError("threshold must be between 0 and 1")
        return value

    def to_json(self):
        return json.dumps({"schema_version": self.VERSION, "threshold": self.threshold,
                           "in_scope_only": self.in_scope_only, "max_probes": self.max_probes,
                           "enabled": self.enabled}, sort_keys=True)

    @classmethod
    def from_json(cls, text):
        value = json.loads(text)
        if not isinstance(value, dict) or value.get("schema_version") != cls.VERSION:
            raise ValueError("unsupported configuration schema")
        return cls(value.get("threshold", .60), value.get("in_scope_only", True),
                   value.get("max_probes", 3), value.get("enabled", True))
