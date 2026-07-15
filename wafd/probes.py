"""Load and safely plan data-driven active WAF probes."""

import json
import os


class Probe(object):
    """A raw insertion-point value and its expected WAF behaviours."""

    def __init__(self, value, providers, actions, probe_id, name, enabled=True,
                 control_required=True, safe_methods=None, repeat=1):
        self.value = value
        self.providers = tuple(providers)
        self.actions = tuple(actions)
        self.probe_id = probe_id
        self.name = name
        self.enabled = bool(enabled)
        self.control_required = bool(control_required)
        self.safe_methods = tuple(safe_methods or ("GET", "HEAD", "OPTIONS"))
        self.repeat = max(1, min(int(repeat), 10))


class ProbeCatalogue(object):
    """Validate a JSON probe catalogue without executing configuration code."""

    SCHEMA_VERSION = 1

    def __init__(self, probes):
        self.probes = list(probes)
        ids = [probe.probe_id for probe in self.probes]
        if len(ids) != len(set(ids)):
            raise ValueError("probe ids must be unique")

    @classmethod
    def from_json(cls, text):
        document = json.loads(text)
        if document.get("schema_version") != cls.SCHEMA_VERSION:
            raise ValueError("unsupported probe catalogue schema")
        probes = []
        for item in document.get("probes", []):
            if not isinstance(item, dict) or not item.get("id") or not item.get("value"):
                raise ValueError("probe requires id and value")
            value = item["value"]
            if not isinstance(value, str) or len(value) > 4096:
                raise ValueError("probe value must be a bounded string")
            probes.append(Probe(value, item.get("providers", []), item.get("actions", []),
                                item["id"], item.get("name", item["id"]), item.get("enabled", True),
                                item.get("control_required", True), item.get("safe_methods"),
                                item.get("repeat", 1)))
        return cls(probes)

    @classmethod
    def bundled(cls):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "probes.json")
        with open(path, "r") as source:
            return cls.from_json(source.read())


class ProbePlanner(object):
    """Plan bounded marker payloads, refusing unsafe methods and locations."""

    def __init__(self, max_probes=3, allow_non_idempotent=False, catalogue=None):
        self.max_probes = max(0, min(int(max_probes), 20))
        self.allow_non_idempotent = bool(allow_non_idempotent)
        self.catalogue = catalogue or ProbeCatalogue.bundled()

    def plan(self, method, insertion_point_name="", providers=None):
        """Return raw values; Burp insertion points perform URL/body encoding."""
        method = str(method).upper()
        if method not in ("GET", "HEAD", "OPTIONS") and not self.allow_non_idempotent:
            return []
        name = str(insertion_point_name).lower()
        if any(term in name for term in ("cookie", "authorization", "header")):
            return []
        provider_filter = set(providers or [])
        selected = []
        for probe in self.catalogue.probes:
            if not probe.enabled:
                continue
            if method not in probe.safe_methods and not self.allow_non_idempotent:
                continue
            if provider_filter and not provider_filter.intersection(probe.providers):
                continue
            for _ in range(probe.repeat):
                selected.append(probe.value)
                if len(selected) >= self.max_probes:
                    return selected
        return selected
