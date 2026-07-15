# Configuration reference

Configuration is split between:

- versioned extension settings persisted by Burp;
- versioned rule/probe enablement overrides persisted by Burp; and
- the bundled rule and probe JSON catalogues.

The **WAF Detector** suite tab exposes **Settings**, **Detection Rules**, and
**Active Probes**. Saving validates the complete settings object before any
live state is changed. Their custom tab headers retain natural title widths,
bounded from 90 to 180 pixels, instead of stretching across the full tab bar.

Settings are grouped into **Detection**, **Active probing**, and **Size and
inspection limits**. GridBag constraints allow horizontal growth but prohibit
vertical fill, so controls retain their look-and-feel font height even when
Burp gives the tab substantial vertical space.

Detection rules are divided into generic and provider sections. Active probes
are divided into SQL injection, cross-site scripting, path/inclusion/SSRF,
command/template/runtime, structured-parser/content-type, HTTP/protocol,
multipart/cookie/header, size/boundary, and provider-profile sections. Sections
start collapsed and expose **Expand all** and **Collapse all** controls.

Both catalogue tabs provide a text filter, a matched/total count, **Show all**,
and **Enable matches**/**Disable matches** actions. Press Enter in the filter or
select **Apply** to update the list. Matching sections expand automatically and
sections without matches are hidden. Space-separated terms are combined: every
term must occur in the row's searchable metadata. Rule searches include name,
ID, evidence group, and tags. Probe searches include name, ID, provider, action,
method, placement, content type, and classification.

Filtering, expansion, and bulk selection are local UI operations. Checkbox
changes are not persisted and do not alter live detector state until **Save
settings** is used.

## Extension settings

The extension configuration schema is version 1.

| Option | Type | Default | Validation/UI meaning |
| --- | --- | --- | --- |
| `threshold` | Number | `0.60` | Inclusive range 0–1. |
| `in_scope_only` | Boolean | `true` | Restrict passive monitoring to Burp scope. |
| `max_probes` | Integer or null | `null` | Blank/null means unlimited; otherwise clamped to 0–1,000. Zero sends none. |
| `enabled` | Boolean | `true` | Enables passive response monitoring. |
| `non_get_target` | String | `root` | `root` sends constructed non-GET probes to `/`; `selected` preserves the actively selected request path. |
| `body_test_threshold` | Integer | `8192` | Body-size research threshold in bytes. |
| `header_test_threshold` | Integer | `4096` | Single/total-header research threshold in bytes. |
| `header_count_test_threshold` | Integer | `64` | Header-count research threshold, range 1–500. |
| `inspection_boundary` | Integer | `8192` | Body inspection-boundary position in bytes. |
| `size_hard_max` | Integer | `262144` | Absolute generated-size limit, range 1,024–1,048,576. |

Body, header, and inspection thresholds must be positive and strictly below
`size_hard_max`. Size probes use gradual 50% and 75% requests plus immediately
below/above variants. The hard maximum is enforced by the builder even when a
catalogue profile asks for a larger request.

The **Path for constructed non-GET probes** dropdown displays **Root path (/)**
for the persisted `root` value and **Selected request path** for `selected`.
Its tooltip repeats the targeting behaviour. Display labels are never written
to saved configuration, preserving schema-version-1 compatibility.

The adapter stores the following shape under Burp's extension-setting key
`configuration`:

```json
{
  "body_test_threshold": 8192,
  "enabled": true,
  "header_count_test_threshold": 64,
  "header_test_threshold": 4096,
  "in_scope_only": true,
  "inspection_boundary": 8192,
  "max_probes": null,
  "non_get_target": "root",
  "schema_version": 1,
  "size_hard_max": 262144,
  "threshold": 0.6
}
```

An invalid saved schema/value is ignored at load time. The extension continues
with validated defaults and reports the problem in Burp output.

## Detection-rule catalogue

Rules live in `data/default_rules.json`. There are currently 41, all enabled
by the bundled catalogue. The loader validates the `rules` array but does not
currently enforce the document's top-level `schema_version`.

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Unique non-empty identifier, at most 100 characters. |
| `name` | Yes | UI display name. |
| `evidence_group` | Yes | Correlation group; only its strongest match scores. |
| `weight` | Yes | Numeric weight from 0 to 100. |
| `tags` | No | Generic, provider, product, and/or action labels. |
| `matcher` | No | Declarative matcher interpreted by `ResponseDetector`. |
| `enabled` | No | Defaults to `true`. |

Example:

```json
{
  "id": "cloudflare.challenge",
  "name": "Cloudflare challenge action",
  "evidence_group": "action-challenge-cloudflare",
  "weight": 100,
  "tags": [
    "cloudflare",
    "product",
    "challenge"
  ],
  "matcher": {
    "kind": "strong_header",
    "name": "cf-mitigated",
    "contains": "challenge"
  }
}
```

Supported matcher kinds:

- `active_differential`
- `active_outcome`
- `body_hash_change`
- `body_regex`
- `body_similarity_drop`
- `body_terms`
- `challenge_transition`
- `connection_state`
- `cookie_delta`
- `cookie_value_delta`
- `header`
- `header_body`
- `header_delta`
- `http_version_change`
- `status`
- `status_transition`
- `strong_header`

Unknown matcher kinds do not match and are not rejected at load time. Regexes
are trusted local catalogue input and run against a bounded body sample.

## Probe catalogue

Probes live in `data/probes.json`. The bundled document uses schema version 2;
the loader also accepts existing version-1 documents.

### Ordinary probe entries

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `id` | Yes | — | Unique concrete identifier. |
| `name` | No | Probe ID | Human-readable name. |
| `value` | Yes | — | Raw string marker, at most 4,096 characters; empty is allowed. |
| `providers` | No | Empty list | Associated provider labels. |
| `actions` | No | Empty list | Expected action labels. |
| `enabled` | No | `true` | Initial eligibility. |
| `control_required` | No | `true` | Whether a constructed profile sends a control. |
| `safe_methods` | No | GET, HEAD, OPTIONS | Allowed outgoing methods. |
| `repeat` | No | `1` | Transmission count, clamped to 1–10 and honoured by the adapter. |
| `profile` | No | Empty object | Request construction plus descriptive research metadata. |

### Matrix entries

Schema version 2 adds a top-level `matrices` array. Each matrix declares:

- unique `id` and display `name`;
- one or more `{id, name, value}` objects;
- one or more placement objects;
- shared providers, actions, profile fields, enabled state, and repeat count.

The loader expands every value/placement combination into a concrete probe ID:

```text
<matrix-id>.<value-id>.<placement-id>
```

Example:

```json
{
  "id": "matrix.example",
  "name": "Example matrix",
  "values": [
    {
      "id": "marker",
      "name": "Marker",
      "value": "WAFTEST"
    }
  ],
  "placements": [
    {
      "id": "json",
      "name": "JSON string",
      "placement": "json",
      "parameter": "value",
      "method": "POST",
      "safe_methods": [
        "POST"
      ]
    }
  ],
  "providers": [],
  "actions": [
    "block"
  ],
  "profile": {
    "control_value": "ordinary"
  },
  "enabled": true
}
```

Matrix and ordinary IDs share one uniqueness check after expansion.

### Executed profile fields

| Field | Behaviour |
| --- | --- |
| `placement` | Selects query, form, structured body, header, cookie, multipart, size, or boundary construction. |
| `method` | Overrides the selected method; must be present in `safe_methods`. |
| `endpoint` | Explicit request target; otherwise normal target policy applies. |
| `parameter` | Query/form/JSON/XML/GraphQL field name. |
| `parameters` | Ordered query pairs, including duplicates and `$value` substitution. |
| `encoding` | `url` (default) or deliberate `raw` query/cookie input. |
| `content_type` | Whole-body media type. |
| `header` / `cookie` / `field` / `filename` | Explicit target name. |
| `part_content_type` | Multipart part media type. |
| `control_value` | Logical value used for the same-shape control. |
| `control_profile` | Control-only boundary/size overrides. |
| `request_headers` / `accept` | Explicit request-header additions/replacements. |
| Threshold factors/offsets | Derive bounded sizes from UI configuration. |
| `marker_position` | Beginning, before/after boundary, or end. |
| `classification` | Labels outcomes such as `malformed-request`. |

Expected response headers/statuses/body terms, notes, provider associations,
actions, and safety descriptions are research metadata. Shared detection rules
interpret responses; these fields do not execute match expressions.

## Enablement overrides

Every loaded rule and concrete probe has a checkbox. Saving captures their
complete Boolean state under Burp's `catalogue_overrides` key using schema
version 1:

```json
{
  "probes": {
    "matrix.xss.script.query": true
  },
  "rules": {
    "cloudflare.challenge": true
  },
  "schema_version": 1
}
```

Overrides do not modify the bundled files. Known IDs are applied at extension
load; stale IDs from older catalogues are ignored, and newly added IDs retain
their bundled default. Invalid override documents are ignored with a Burp
error message.

Disabling a rule or probe removes its existing evidence from in-memory current
assessments when settings are saved.

## Selection and request limits

All enabled method-compatible probes are selected by default. A numeric
`max_probes` limits expanded probe transmissions, including `repeat` runs, in
catalogue order. It does not count same-shape control requests, so total HTTP
traffic may be roughly twice that number for specialist profiles.

The planner core supports provider filtering for programmatic callers. The
Burp UI's text filter also matches provider metadata, allowing a provider's
visible probes to be reviewed or changed together without introducing a
separate saved filter setting.

## Reload and rollback

Bundled JSON changes are loaded when the extension registers. Reload after
editing either catalogue. Burp-persisted UI overrides may supersede a changed
bundled `enabled` value for an existing ID; clear or change its checkbox when
testing catalogue defaults. Use Git to keep catalogue changes reviewable and
reversible.
