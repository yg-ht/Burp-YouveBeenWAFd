# Configuration reference

Configuration is split between Burp-persisted extension settings, session-only
rule choices, and the two JSON catalogues.

## Extension settings

The configuration schema is version 1.

| Option | Type | Default | Validation | Extension-tab control |
| --- | --- | --- | --- | --- |
| `threshold` | Number | `0.60` | Inclusive range 0 to 1 | Yes |
| `in_scope_only` | Boolean | `true` | Boolean conversion | No |
| `max_probes` | Integer | `3` | Clamped to 0–20 | No |
| `enabled` | Boolean | `true` | Boolean conversion | Yes, labelled Passive monitoring |
| `non_get_target` | String | `root` | `root` or `selected` | No |

The adapter serialises these settings as JSON under Burp's extension-setting
key `configuration`:

```json
{
  "enabled": true,
  "in_scope_only": true,
  "max_probes": 3,
  "non_get_target": "root",
  "schema_version": 1,
  "threshold": 0.6
}
```

Only `enabled` and `threshold` are currently editable in the extension tab.
The other values are implemented configuration fields but do not yet have a
supported user-facing editor. Do not assume that changing an example file will
alter them; no standalone extension configuration file is loaded.

An invalid saved schema or value is ignored at load time, and the extension
continues with validated defaults while reporting an error in Burp output.

## Detection-rule configuration

Rules live in `data/default_rules.json`. The top-level document contains
`schema_version` and a `rules` array. The current loader validates the `rules`
array but does not enforce the top-level schema version.

Each rule supports:

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Unique, non-empty identifier of at most 100 characters. |
| `name` | Yes | Display name shown in the extension tab. |
| `evidence_group` | Yes | Correlation group; only its strongest matched rule contributes. |
| `weight` | Yes | Numeric evidence weight from 0 to 100. |
| `tags` | No | Generic, provider, product, or action labels. |
| `matcher` | No | Declarative matcher object interpreted by `ResponseDetector`. |
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

The tab exposes a checkbox for every loaded rule. Checkbox changes take effect
for the current extension load but are not included in saved configuration.
For persistent enablement, set `enabled` in the JSON catalogue and reload.

Supported matcher kinds are:

- `status`
- `header`
- `body_terms`
- `active_differential`
- `status_transition`
- `body_similarity_drop`
- `header_delta`
- `body_hash_change`
- `cookie_delta`
- `http_version_change`
- `connection_state`
- `challenge_transition`
- `strong_header`
- `header_body`
- `body_regex`

Unknown matcher kinds do not match and are not rejected during catalogue load.
Regex patterns are trusted local catalogue input and are evaluated against a
bounded body sample.

## Probe configuration

Probes live in `data/probes.json`, using schema version 1.

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `id` | Yes | — | Unique probe identifier. |
| `name` | No | Probe ID | Human-readable catalogue name. |
| `value` | Yes | — | Raw string payload, limited to 4,096 characters. |
| `providers` | No | Empty list | Associated provider research labels. |
| `actions` | No | Empty list | Expected action labels. |
| `enabled` | No | `true` | Whether the planner may select the entry. |
| `control_required` | No | `true` | Descriptive flag; the adapter does not branch on it. |
| `safe_methods` | No | GET, HEAD, OPTIONS | Per-probe method allowlist. |
| `repeat` | No | `1` | Clamped to 1–10; honoured by `plan()`, not by the adapter's `plan_entries()` route. |
| `profile` | No | Empty object | Request and research metadata; only selected fields execute. |

Example:

```json
{
  "id": "generic.xss-script",
  "name": "XSS-shaped script tag",
  "value": "<script>alert(1)</script>",
  "providers": [
    "cloudflare",
    "aws-waf",
    "azure-waf"
  ],
  "actions": [
    "block",
    "challenge",
    "captcha"
  ],
  "enabled": true
}
```

### Enabling and ordering probes

There is no per-probe UI. Edit each entry's `enabled` value and reload the
extension. Eligible probes are selected in file order until `max_probes` is
reached, so ordering determines which probes run under the default cap.

`safe_methods` is always enforced. There is no sweeping non-idempotent-method
override. To permit a probe for POST, add `POST` to that specific entry. The
current bundled catalogue contains GET/HEAD/OPTIONS entries and five POST-only
entries; it does not contain PUT, PATCH, DELETE, TRACE, or custom-method
allowlists.

### Provider associations

The planner core can filter probes by provider, but the current Burp adapter
does not pass a provider filter. Provider lists therefore document association
and support programmatic use; they do not alter normal extension selection.

### Profile support

Only `profile.accept` and `profile.request_headers` change an outgoing request.
All other current profile keys are descriptive. See
[Features and behaviour](features.md#executed-profile-fields) for the exact
runtime boundary.

## Reload and rollback

Catalogue changes are picked up only when the extension registers. Before
editing, retain the previous JSON or use Git so a malformed or overly broad
catalogue can be reverted. No migration runs against catalogue files or saved
settings.
