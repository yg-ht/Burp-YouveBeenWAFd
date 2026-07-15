# Architecture, testing, and limitations

## Module boundaries

| Path | Responsibility |
| --- | --- |
| `BurpExtender.py` | Minimal Burp entry point. |
| `wafd/extension.py` | Legacy Burp adapter, Swing tab, listeners, scanner check, context menu, and issues. |
| `wafd/config.py` | Versioned persisted configuration and validation. |
| `wafd/probes.py` | Probe catalogue validation and bounded selection. |
| `wafd/rules.py` | Rule catalogue validation. |
| `wafd/detector.py` | Burp-independent matcher execution. |
| `wafd/fingerprint.py` | Bounded response normalisation and hashing. |
| `wafd/confidence.py` | Evidence-group confidence calculation. |
| `wafd/assessment.py` | Per-origin evidence storage and escaped issue HTML. |
| `wafd/models.py` | CPython dataclasses and Jython-compatible fallback models. |
| `data/default_rules.json` | Shared passive/active rule catalogue. |
| `data/probes.json` | Active probe catalogue and research metadata. |

The core deliberately accepts plain dictionaries and model objects rather than
Burp interfaces. This keeps response matching and confidence calculation
testable without launching Burp.

## Data flow

### Passive

```text
Burp HTTP response
  -> scope and source checks
  -> bounded response fingerprint
  -> enabled response rules
  -> deduplicated per-origin evidence
  -> current-assessment Scanner issue
```

### Active

```text
Scanner insertion point or context-menu request
  -> method-eligible catalogue selection
  -> control request/response
  -> capped probe requests
  -> response fingerprints or no-response state
  -> differential and standalone rules
  -> deduplicated per-origin evidence
  -> current-assessment Scanner issue
```

## Error handling and trust boundaries

- Saved configuration is parsed as JSON and schema checked.
- Rules and probes are parsed as data; catalogue content is never evaluated as
  Python code.
- Rule IDs are unique, rule weights are bounded to 0–100, probe values are
  bounded to 4,096 characters, repeats to 1–10, and active operations to 0–20
  selected entries.
- Response matching operates on a bounded body sample.
- Cookie values are not retained in fingerprints.
- Response-derived issue details are HTML escaped before Burp renders them.
- Passive-processing exceptions and active-scan exceptions are sent to Burp's
  error output.

The catalogue files are trusted local input. In particular, regular
expressions can still be inefficient even though response bodies are bounded.

## Tests

The suite covers the Burp-independent core:

- configuration round trips and bounds;
- probe schema, ordering, repetition, provider filtering, sensitive insertion
  points, method allowlists, and bundled profile metadata;
- rule validation and weight bounds;
- header, status, transition, behavioural, challenge, CRS, and vendor matcher
  behaviour;
- confidence grouping and inclusive threshold handling;
- response fingerprint hashing, cookies, protocol, and transport state; and
- assessment states and HTML escaping.

Run it with:

```bash
.venv/bin/pytest -q
```

If the environment has no project virtual environment, the standard-library
test suite can be run with:

```bash
python3 -m unittest discover -s tests -q
```

Validate syntax and catalogue JSON with:

```bash
python3 -m py_compile BurpExtender.py wafd/*.py
python3 -m json.tool data/default_rules.json >/dev/null
python3 -m json.tool data/probes.json >/dev/null
```

## Current test gaps

The automated suite does not instantiate Burp's Java interfaces. It therefore
does not provide end-to-end coverage of:

- callback registration and Scanner issue construction;
- Swing event handling and persistence through Burp;
- root-targeted non-GET request construction;
- context-menu request-line manipulation;
- live HTTP/2 response representation in Burp/Jython; or
- actual transport reset classification by Burp.

Manual validation in a controlled Burp project remains necessary before a
release.

## Known functional limitations

- The extension tab edits only passive enablement, threshold, and session-only
  rule states. It does not expose the remaining configuration or per-probe
  controls.
- Rule checkbox choices are not persisted across extension reloads.
- Probe profile metadata is mostly descriptive; only `accept` and
  `request_headers` are applied.
- `repeat` is not honoured by the adapter because it calls `plan_entries()`.
- Selection by provider exists in the planner but is not exposed by the Burp
  adapter.
- The default cap and file ordering mean most enabled probes are not selected
  in a single operation.
- Structured-body, multipart, cookie, header, filename, upload, size-boundary,
  method-matrix, and content-type-matrix builders are not implemented.
- The context-menu builder appends its query marker to the complete request
  line. This can put the marker after the HTTP version and yield a malformed
  request; use Scanner insertion points until target-aware construction is
  implemented and covered by an adapter regression test.
- Response-header normalisation stores one value per lower-case header name;
  repeated headers may therefore be collapsed before matching.
- Fingerprints hash at most the first 1 MiB provided by the adapter rather than
  every byte of a larger response.
- Connection resets are represented only when the active request yields no
  response; the adapter labels this `no-response` rather than distinguishing
  reset, timeout, and other network failures.
- Elapsed time exists in the fingerprint schema but is not measured.
- Assessments are in-memory and are not recovered after reload.
- There is no automated Burp-adapter test harness.

## Compatibility and rollback

The production adapter is written for Jython 2.7 syntax and Burp's legacy
Extender API. Avoid Python-3-only syntax in files imported by Burp. PortSwigger
now recommends Montoya for new Java extensions, so a future migration would be
an interface change and should be planned separately rather than mixed with
rule or probe work.

Documentation and comment-only changes can be rolled back without migrating
saved settings or catalogue files. Functional catalogue changes should remain
separate commits because they alter confidence or outgoing requests.
