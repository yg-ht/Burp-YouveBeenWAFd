"""Load and safely plan data-driven active WAF probes."""

import json
import os

# Jython 2.7's JSON decoder returns ``unicode`` for catalogue text.  Use the
# common Python 2 string base while retaining an ordinary ``str`` alias under
# the Python 3 test environment.
try:
    string_types = (basestring,)
except NameError:  # Python 3 test environment.
    string_types = (str,)


class Probe(object):
    """A raw insertion-point value and its expected WAF behaviours."""

    def __init__(self, value, providers, actions, probe_id, name, enabled=True,
                 control_required=True, safe_methods=None, repeat=1, profile=None):
        self.value = value
        self.providers = tuple(providers)
        self.actions = tuple(actions)
        self.probe_id = probe_id
        self.name = name
        self.enabled = bool(enabled)
        self.control_required = bool(control_required)
        # Method eligibility belongs to each probe. A missing allowlist uses
        # the legacy idempotent-method default; there is no global bypass.
        self.safe_methods = tuple(safe_methods or ("GET", "HEAD", "OPTIONS"))
        # Repetition supports bounded behavioural checks such as rate-limit
        # transitions without allowing an untrusted catalogue to create an
        # unbounded request loop.
        self.repeat = max(1, min(int(repeat), 10))
        # Profiles combine request-construction fields with research and
        # expected-response metadata. The request builder consumes declared
        # placements; expected-response fields remain descriptive.
        self.profile = profile or {}


class ProbeCatalogue(object):
    """Validate a JSON probe catalogue without executing configuration code."""

    SCHEMA_VERSION = 2
    SUPPORTED_SCHEMA_VERSIONS = (1, 2)

    def __init__(self, probes):
        self.probes = list(probes)
        ids = [probe.probe_id for probe in self.probes]
        if len(ids) != len(set(ids)):
            raise ValueError("probe ids must be unique")

    @classmethod
    def from_json(cls, text):
        document = json.loads(text)
        # Probes are data rather than executable configuration. Validate the
        # schema and bound payload size before any entry reaches the adapter.
        if document.get("schema_version") not in cls.SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError("unsupported probe catalogue schema")
        probes = []
        for item in document.get("probes", []):
            probes.append(cls._probe_from_item(item))
        for matrix in document.get("matrices", []):
            probes.extend(cls._expand_matrix(matrix))
        return cls(probes)

    @staticmethod
    def _probe_from_item(item):
        if not isinstance(item, dict) or not item.get("id") or "value" not in item:
            raise ValueError("probe requires id and value")
        value = item["value"]
        # Accept both byte and Unicode strings under Jython.  The payload stays
        # bounded before it can be expanded into active requests.
        if not isinstance(value, string_types) or len(value) > 4096:
            raise ValueError("probe value must be a bounded string")
        return Probe(value, item.get("providers", []), item.get("actions", []),
                     item["id"], item.get("name", item["id"]), item.get("enabled", True),
                     item.get("control_required", True), item.get("safe_methods"),
                     item.get("repeat", 1), item.get("profile"))

    @classmethod
    def _expand_matrix(cls, matrix):
        """Expand compact value-by-placement data into ordinary Probe objects."""
        if not isinstance(matrix, dict) or not matrix.get("id"):
            raise ValueError("probe matrix requires an id")
        values = matrix.get("values")
        placements = matrix.get("placements")
        if not isinstance(values, list) or not values or not isinstance(placements, list) or not placements:
            raise ValueError("probe matrix requires values and placements")
        expanded = []
        for value in values:
            if not isinstance(value, dict) or not value.get("id") or "value" not in value:
                raise ValueError("matrix value requires id and value")
            for placement in placements:
                if not isinstance(placement, dict) or not placement.get("id"):
                    raise ValueError("matrix placement requires an id")
                profile = dict(matrix.get("profile", {}))
                profile.update(dict((key, item) for key, item in placement.items()
                                    if key not in ("id", "name", "safe_methods")))
                item = {
                    "id": "%s.%s.%s" % (matrix["id"], value["id"], placement["id"]),
                    "name": "%s - %s - %s" % (
                        matrix.get("name", matrix["id"]), value.get("name", value["id"]),
                        placement.get("name", placement["id"])),
                    "value": value["value"],
                    "providers": matrix.get("providers", []),
                    "actions": matrix.get("actions", []),
                    "enabled": matrix.get("enabled", True),
                    "control_required": matrix.get("control_required", True),
                    "safe_methods": placement.get("safe_methods", matrix.get("safe_methods")),
                    "repeat": placement.get("repeat", matrix.get("repeat", 1)),
                    "profile": profile,
                }
                expanded.append(cls._probe_from_item(item))
        return expanded

    @classmethod
    def bundled(cls):
        # Resolve relative to the installed package rather than Burp's process
        # directory, which is not stable across launch methods.
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "probes.json")
        with open(path, "r") as source:
            return cls.from_json(source.read())


class ProbePlanner(object):
    """Plan enabled marker payloads for compatible methods and locations."""

    def __init__(self, max_probes=None, catalogue=None):
        # ``None`` means all eligible catalogue entries. Numeric limits count
        # expanded repeat runs rather than logical entries, making the setting
        # match the number of probe requests the adapter will transmit.
        self.max_probes = (None if max_probes is None else
                           max(0, min(int(max_probes), 1000)))
        self.catalogue = catalogue or ProbeCatalogue.bundled()

    def plan(self, method, insertion_point_name="", providers=None):
        """Return raw values; Burp insertion points perform URL/body encoding."""
        method = str(method).upper()
        name = str(insertion_point_name).lower()
        # Authentication, header and cookie insertion points are skipped here
        # because buildRequest could overwrite credentials or session state.
        if any(term in name for term in ("cookie", "authorization", "header")):
            return []
        return [probe.value for probe in
                self.plan_entries(method, insertion_point_name, providers)]

    def plan_entries(self, method, insertion_point_name="", providers=None):
        """Return catalogue entries so adapters can apply profile metadata."""
        method = str(method).upper()
        name = str(insertion_point_name).lower()
        # Apply the same trust-boundary check as plan(); callers requesting
        # complete entries must not gain a less restrictive route.
        if any(term in name for term in ("cookie", "authorization", "header")):
            return []
        provider_filter = set(providers or [])
        selected = []
        if self.max_probes == 0:
            return selected
        for probe in self.catalogue.probes:
            if not probe.enabled:
                continue
            # Method eligibility is configured per probe. There is no global
            # override which could accidentally send a GET-only payload in a
            # POST, PUT, PATCH or DELETE request.
            # Constructed profiles may deliberately use a method different
            # from the selected base request. In that case safe_methods
            # authorises the outgoing method, not the triggering request.
            outgoing_method = str(probe.profile.get("method", method)).upper()
            if outgoing_method not in probe.safe_methods:
                continue
            if provider_filter and not provider_filter.intersection(probe.providers):
                continue
            # Repetition is expanded here because the Burp adapter consumes
            # complete entries rather than the raw-value plan() helper.
            for _ in range(probe.repeat):
                selected.append(probe)
                if self.max_probes is not None and len(selected) >= self.max_probes:
                    return selected
        return selected
