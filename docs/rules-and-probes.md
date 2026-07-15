# Rules, probes, and confidence

Passive and active observations use one rule catalogue. Active request values,
placements, methods, and provider associations live separately in the probe
catalogue, preventing probe routines from duplicating detection logic.

## Catalogue summary

| Item | Count | Bundled state |
| --- | ---: | --- |
| Detection rules | 41 | All enabled |
| Base probe definitions | 49 | All enabled |
| Compact matrices | 17 | All enabled |
| Matrix-expanded probes | 164 | All enabled |
| Concrete probes exposed to the planner/UI | 213 | All enabled |

`repeat` can create more transmissions than concrete IDs. Conversely, a user
limit, disabled checkbox, or incompatible legacy insertion-point method can
reduce an operation.

## Detection coverage

### Generic evidence

Generic rules cover:

- weak standalone error/block statuses and challenge terminology;
- benign-to-blocked, rate-limited, concealed-denial, and request-policy
  transitions, including 400, 403, 404, 413, 429, 431, 502, and 503 cases;
- challenge status/body transitions;
- body similarity and body-hash changes;
- response-header additions;
- mitigation-cookie additions and hashed cookie-value rotations;
- HTTP-version changes;
- reset, timeout, no-response, and other network errors;
- broad active response divergence; and
- zero-weight per-probe outcome records.

Generic statuses and edge headers remain intentionally low confidence. A
status transition, body replacement, or explicit vendor action carries more
weight. Network failure remains weak because origin and transport faults can
look like WAF intervention.

### Provider and product evidence

| Provider/product | Implemented signals |
| --- | --- |
| Cloudflare | Low-weight `server`/`cf-ray` edge markers and high-weight `cf-mitigated: challenge`. |
| AWS WAF | Low-weight AWS edge marker and high-weight challenge/CAPTCHA action headers. |
| Azure WAF | Front Door reference, block text plus reference, and Application Gateway block template. |
| Google Cloud Armor | Low-weight Google edge marker; external response alone cannot prove policy denial. |
| ModSecurity / OWASP CRS | Weak terminology and high-weight visible CRS rule-ID pattern. |
| F5 BIG-IP Advanced WAF/ASM | Weak BIG-IP cookie name and strong rejection/support-ID template. |
| Akamai | Weak edge header and 50-point edge-denial reference template; WAF causation remains uncertain. |
| Imperva | Weak proxy marker and strong Imperva/Incapsula incident template. |
| FortiWeb | Weak header marker and low-weight reset/no-response association. |
| Barracuda | Low-weight header marker. |
| Radware | Low-weight header marker. |
| Sucuri | Low-weight header marker. |
| Fastly | Low-weight edge header marker. |

Provider tags do not replace action tags. Supported action conclusions are
`block`, `challenge`, `captcha`, `rate_limit`, and `reset`.

## Confidence model

The 41 bundled rules occupy 40 evidence groups. One group is the zero-weight
active audit record. Positive weights are confidence points on a 0–100 scale.

Confidence is:

```text
min(100, sum(strongest matched positive rule in each evidence group))
```

Consequences:

- A weight-100 rule produces 100% confidence by itself.
- An 85-point explicit block template produces 85% confidence.
- Independent behavioural signals such as 35 + 22 + 14 produce 71%.
- Correlated rules in one evidence group cannot stack.
- Repeating one rule across many concrete probes adds issue detail but not
  repeated confidence weight.
- The zero-weight outcome record never increases confidence.
- Disabling rules removes their possible contribution.
- Adding unrelated provider rules does not dilute existing evidence.
- The default 60% threshold is inclusive.

Provider scores independently add provider-tagged confidence points and cap at
100%.

## Probe values

The catalogue includes the explicitly requested inert/attack-shaped markers.

### SQL injection shapes

- `1'-- `
- `1' OR '1'='1`
- `1 OR 1=1`
- `1 UNION SELECT NULL`
- `ASCII(SUBSTRING(name,1,1))`

These are expanded across query, URL-encoded form, JSON, GraphQL variables,
XML, SOAP, cookies, and request headers.

### XSS shapes

- `<script>alert(1)</script>`
- `<h1>WAFTEST</h1>`
- `<img src=x onerror=alert(1)>`
- `javascript:alert(1)`
- `<svg onload=alert(1)>`

These are expanded across query, form, JSON, headers, cookies, XML, SOAP,
GraphQL variables, multipart fields, filenames, and uploaded text content.
The extension does not render returned payloads in its issue HTML; all dynamic
details are escaped.

### Other families

- Unix/Windows traversal, absolute `/etc/passwd`, and null-byte-shaped LFI.
- Reserved `example.invalid` and TEST-NET `192.0.2.1` RFI/SSRF shapes.
- Three command-injection markers.
- `{{7*7}}` and `${7*7}` expression markers.
- PHP filter and PHP-code-shaped text.
- Printable, non-executable Java serialisation marker.
- Safe internal XML entity declaration with no external entity.
- CRLF, null-byte, invalid-percent, empty-value, repeated-delimiter, and
  empty-name forms.
- GraphQL variables and direct queries without recursion or deep nesting.
- Parameter-name and parameter-pollution comparisons.
- HTTP method and method-override profiles.
- Multipart and cookie/session profiles.
- Request-size, header-size/count, and inspection-boundary profiles.
- Vendor-associated challenge, denial, reference, incident, and reset profiles.

The endpoint receives these as HTTP data. The extension does not access target
files, fetch URLs, invoke PHP, deserialize Java data, execute shell commands,
or render responses. It cannot guarantee that the target application also
treats the values as inert.

## Placement and control semantics

Each matrix value/placement pair becomes a concrete probe with its own ID and
UI checkbox. Ordinary named query profiles replace the first existing
parameter of that name, avoiding accidental parameter pollution. Only the HPP
profiles deliberately create duplicates and preserve their declared order.

Structured controls use the same method, target, headers, content type, field,
and serialization as the probe. XML and SOAP values are escaped as text;
GraphQL values use JSON string escaping. Multipart filenames are escaped for
the wire representation and are never used locally.

Size controls normally use the same configured size with an ordinary marker.
Immediately-above probes declare a control-side immediately-below offset.
Every generated size is checked against `size_hard_max`.

## Active outcome interpretation

Every completed active probe creates a zero-weight outcome such as:

```text
control HTTP 200; probe HTTP 403
```

Additional rules can then record status transitions, body/header/cookie
differences, protocol changes, or provider signatures under the same concrete
probe ID. Malformed-input profiles are explicitly labelled.

An unchanged external response cannot prove whether a WAF structurally parsed,
plain-text scanned, ignored, or permitted the value. Similarly, an external
404 or reset may have non-WAF causes. Where authoritative vendor logs are
available, correlate the recorded probe ID and response with those logs.

## Adding a rule

1. Choose a stable unique ID.
2. Decide whether evidence is generic, provider-specific, action-specific, or
   a combination.
3. Put correlated observations in one evidence group.
4. Keep ambient headers and generic statuses low weight.
5. Prefer control/probe transitions or explicit action signatures.
6. Add loader, detector, confidence, and output-escaping tests.
7. Recalculate achievable additive confidence combinations and review threshold effects.

## Adding a probe or matrix

1. Keep every ID stable and unique after matrix expansion.
2. Bound raw marker values to 4,096 characters.
3. Declare each outgoing method in that profile's `safe_methods`.
4. Associate providers/actions without claiming exclusivity.
5. Supply a benign control value and an explicit placement.
6. Add request-builder tests for both probe and control.
7. Review total request volume; `repeat` and same-shape controls add traffic.
8. Reload the extension and review persisted overrides for existing IDs.
