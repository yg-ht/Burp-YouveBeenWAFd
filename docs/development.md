# Architecture, testing, and limitations

## Module boundaries

| Path | Responsibility |
| --- | --- |
| `BurpExtender.py` | Minimal legacy Burp entry point. |
| `wafd/extension.py` | Burp callbacks, Swing UI, passive listener, active adapter, context menu, and issues. |
| `wafd/burp_issue.py` | Legacy `IScanIssue`-compatible concern and audit object. |
| `wafd/config.py` | Versioned extension settings and size/request validation. |
| `wafd/overrides.py` | Versioned persistent rule/probe enablement overrides. |
| `wafd/probes.py` | Schema-version-1/2 loading, matrix expansion, and request selection. |
| `wafd/request_builder.py` | Burp-independent specialist HTTP request construction. |
| `wafd/rules.py` | Rule catalogue validation. |
| `wafd/detector.py` | Burp-independent response matcher execution. |
| `wafd/fingerprint.py` | Bounded response fields, hashes, redaction, and cookie fingerprints. |
| `wafd/confidence.py` | Independent evidence-group scoring. |
| `wafd/assessment.py` | Timestamped quality reconciliation, bounded recovery state, and escaped issue HTML. |
| `wafd/models.py` | CPython dataclasses and Jython fallback models. |
| `data/default_rules.json` | Shared passive/active rules. |
| `data/probes.json` | Base probes, matrices, profiles, and research metadata. |

Burp objects stop at the adapter boundary. Rules, fingerprints, confidence,
matrix expansion, overrides, and specialised request construction use plain
objects so they can be tested under CPython.

## Data flow

### Passive

```text
Burp HTTP response
  -> enabled/source/scope checks
  -> bounded and redacted fingerprint
  -> enabled response rules
  -> per-origin evidence
  -> one threshold-triggered concern per origin
```

### Active

```text
Scanner insertion point or context-menu action
  -> enabled concrete probes and outgoing-method allowlists
  -> legacy insertion request or specialist request builder
  -> same-shape control where required
  -> probe/repeat transmissions
  -> bounded fingerprints or classified transport failure
  -> zero-weight outcome plus differential/vendor rules
  -> transactional evidence keyed by rule and concrete probe
  -> one immutable probe determination plus an optional first concern
```

## Trust boundaries and defensive behaviour

- Saved configuration and overrides are parsed as versioned JSON.
- Rules/probes are declarative data and are never evaluated as Python code.
- Rule IDs are unique and weights are bounded to 0–100.
- Probe IDs are unique after matrix expansion; raw values are at most 4,096
  characters and repetitions are bounded to 1–10.
- A user request limit is bounded to 0–1,000 probe transmissions; blank means
  unlimited. Control requests are additional.
- Generated bodies/headers use configurable thresholds and an absolute hard
  maximum no greater than 1 MiB.
- Header names, cookie names, XML element names, multipart names/filenames, and
  header values are validated for their wire context.
- Header placements reject CR/LF. Deliberate CRLF-shaped query input remains
  percent-encoded catalogue data.
- `Content-Length` is removed so Burp recalculates constructed-body length.
- Multipart filenames are never passed to filesystem APIs.
- GraphQL queries are fixed, shallow, and non-recursive.
- XML text is escaped; the entity probe has no external/file/network entity.
- Response bodies are bounded before regex/similarity operations.
- Raw cookie values are replaced with `<redacted>`; only names and SHA-256
  fingerprints remain for detection.
- Response-derived issue values are HTML escaped.
- One invalid profile is skipped without cancelling the complete active batch.
- Passive failures and active transport/profile failures are reported through
  Burp output without logging request secrets.

Catalogue regexes and explicit `request_headers` remain trusted local input.
An inefficient regex can still consume CPU within the bounded body sample.

## Automated tests

The standard-library suite covers:

- extension configuration and size bounds;
- override capture, validation, persistence shape, and stale IDs;
- probe schema compatibility, matrix expansion, uniqueness, provider filters,
  method allowlists, repetitions, and limits;
- construction of every bundled specialist probe and control;
- query, form, JSON, GraphQL, XML, SOAP, header, cookie, multipart, method,
  size, and inspection-boundary edge cases;
- request-line construction for context probes;
- a fake Burp adapter path covering root targeting, controls, repeats,
  response version/timing, consolidated issues, and transport failures;
- all response matcher families, status transitions, vendor signatures, and
  zero-weight outcome identity;
- confidence grouping and thresholds;
- body/cookie hashing, cookie redaction/rotation, protocol, and transport state;
  and
- issue states, evidence classification, deduplication, and HTML escaping.

Run:

```bash
python3 -m unittest discover -s tests -q
python3 -m py_compile BurpExtender.py wafd/*.py
python3 -m json.tool data/default_rules.json >/dev/null
python3 -m json.tool data/probes.json >/dev/null
```

If a project virtual environment containing pytest is available, this is also
valid:

```bash
.venv/bin/pytest -q
```

The repository does not currently contain `.venv/bin/pytest`.

## Manual Burp validation

The fake adapter does not instantiate Burp's Java interfaces or Swing runtime.
Before release, manually verify:

1. Jython loads the entry point and all Python modules.
2. Settings, rule overrides, and probe overrides persist across reload.
3. All three UI tabs render and remain responsive with 213 probe controls;
   settings and checkbox rows retain natural font-relative heights, and tab
   contents remain centred within their documented 1,260-pixel width cap.
4. Rule/provider and probe/function groups start collapsed; expand/collapse-all
   controls, filter-driven expansion, and hiding empty groups behave correctly.
5. Rule and probe filters match documented metadata, update matched counts,
   and limit bulk enable/disable actions to matching rows.
6. The two non-GET path labels show the documented explanation and persist as
   `root` or `selected` across reload.
7. Passive in-scope/out-of-scope behaviour matches the checkbox.
8. Scanner and context-menu requests appear correctly in Burp's extension
   traffic view.
9. Constructed non-GET requests use `/` or the selected target as configured.
10. Content types, multipart boundaries, duplicate parameters/cookies, and
   `Content-Length` are correct on the wire.
11. HTTP/1.1 and HTTP/2 responses retain a usable version field.
12. Timeout/reset behaviour is represented as Burp exposes it on the platform.
13. One determination contains the complete successful batch message set, and
    at most one concern exists for the origin.
14. A failed active transport does not clear response-based qualities that
    could not be re-evaluated, while connection-state qualities still update.
15. Passive responses below threshold do not raise issues; an inclusive
    threshold match raises exactly one concern.

## Known limitations

- Rule weights and the default 60% threshold require validation against
  confirmed customer deployments; the tracked TODO defines the test programme.
- The project uses the legacy Extender API and Jython 2.7 rather than Montoya.
- Assessment metadata is recovered from the newest valid bounded state marker
  in a per-origin passive-state setting, determination, concern, or legacy
  current-assessment issue after reload. Passive settings are created only
  after a concern exists. HTTP message objects are attached to determinations
  but are not serialised inside the marker; the next observation supplies the
  current representative.
- Provider filtering exists in the planner API; the UI exposes provider data
  through its general catalogue text filter rather than a dedicated dropdown.
- Expected-response fields in probe profiles are documentation; shared rules,
  not profile-specific expressions, classify responses.
- External responses cannot prove whether a WAF parsed, plain-text scanned,
  ignored, or permitted an input when no observable differential exists.
- Google Cloud Armor policy outcomes, generic CRS matches, and several other
  products require server-side logs for authoritative attribution.
- Fingerprint length/hash cover at most the first 1 MiB of a larger response.
- Repeated response headers are joined into one normalised value rather than
  retained as an ordered list.
- Timeout/reset/network-error classification relies on callback result and
  exception text because the legacy API does not provide one portable typed
  transport outcome.
- A user-set maximum counts probe transmissions, not their control requests.
- Running all 213 enabled probes can produce hundreds of HTTP requests and a
  large issue detail. Configure the active set for the engagement.
- The Swing UI and actual Burp/Jython adapter still require manual end-to-end
  validation; automated tests use CPython fakes.
- `/` is a targeting default, not a guarantee that an application endpoint is
  inert or free of state changes.

## Compatibility and rollback

Files imported by Burp must retain Python-2/Jython-compatible syntax. Probe
schema version 2 remains backwards-compatible with version 1; extension and
override settings each currently use schema version 1.

Functional changes are separated into commits for planner/context handling,
request matrices, UI persistence, and documentation. Each milestone can be
reverted independently. A future Montoya migration should be planned as a
separate public-interface change.
