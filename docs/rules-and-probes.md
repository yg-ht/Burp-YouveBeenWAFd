# Rules, probes, and confidence

The extension keeps detection logic in `data/default_rules.json` and active
input in `data/probes.json`. Passive and active observations therefore share
one rule catalogue rather than maintaining separate provider fingerprints.

## Catalogue summary

The bundled data currently contains:

| Catalogue | Entries | Enabled by default |
| --- | ---: | ---: |
| Detection rules | 38 | 38 |
| Active probes | 49 | 49 |

An enabled catalogue entry is merely eligible. The default active cap of three
means a normal operation does not transmit all 49 probes.

## Detection-rule coverage

### Generic passive and behavioural rules

The generic rules cover:

- weak standalone block/error statuses;
- weak challenge/body terminology;
- benign-to-blocked, rate-limited, and concealed-denial transitions;
- size rejection;
- newly introduced challenge terms or challenge statuses;
- body similarity, body hash, header, cookie, and HTTP-version changes;
- transport reset or no-response outcomes; and
- a broad active-response differential.

Standalone status and visible-edge headers carry weights from 1 to 5. Stronger
behavioural comparisons carry weights from 8 to 35. A reset is intentionally a
low-confidence signal because network and origin failures can look identical.

### Provider and product rules

| Provider/product | Signals represented |
| --- | --- |
| Cloudflare | Low-weight `server`/`cf-ray` edge markers and high-weight `cf-mitigated: challenge`. |
| AWS WAF | Low-weight AWS edge marker and high-weight challenge/CAPTCHA action headers. |
| Azure WAF | Low-weight Front Door reference, Front Door block text plus reference, and Application Gateway block template. |
| Google Cloud Armor | Low-weight Google edge marker; external responses cannot authoritatively prove policy denial. |
| ModSecurity / OWASP CRS | Weak product terminology and high-weight visible CRS rule-ID pattern. |
| F5 BIG-IP Advanced WAF/ASM | Weak BIG-IP cookie marker and strong rejection/support-ID template. |
| Akamai | Weak Akamai edge header and stronger edge-denial reference template; this does not prove App & API Protector caused it. |
| Imperva | Weak proxy marker and strong Imperva/Incapsula incident template. |
| FortiWeb | Weak header marker and low-weight reset/no-response association. |
| Barracuda | Low-weight header marker. |
| Radware | Low-weight header marker. |
| Sucuri | Low-weight header marker. |
| Fastly | Low-weight edge header marker. |

Provider tags identify observed infrastructure or templates. Action tags are
limited to `block`, `challenge`, `captcha`, `rate_limit`, and `reset` and are
reported separately.

## Confidence model

The 38 bundled rules occupy 37 evidence groups with a maximum combined weight
of 1,067. Confidence is not a rule weight divided by 100. It is:

```text
sum(strongest matched rule in each evidence group)
--------------------------------------------------
sum(strongest enabled rule in each evidence group)
```

Consequences:

- A weight-100 rule is very strong relative evidence, but by itself does not
  produce 100% overall confidence.
- Multiple aliases in one evidence group cannot be stacked.
- Disabling a rule can change both the numerator and denominator.
- Adding a new independent evidence group changes the confidence scale.
- The configured 60% threshold is inclusive.

This behaviour makes distinct characteristics important, but catalogue changes
must be reviewed as scoring-model changes rather than isolated signatures.

## Probe families

The 49 definitions cover the following catalogue families.

### Generic attack-shaped values

- XSS: script, ordinary HTML, attribute/event handler, JavaScript URI, SVG,
  encoded angle brackets, and encoded script forms.
- SQL injection: quoted and unquoted booleans, quote/comment, comment,
  UNION-shaped, and expression/function syntax.
- Traversal/LFI: Unix and Windows traversal, absolute Unix path, encoded
  traversal, and null-byte-shaped filename.
- RFI/SSRF: reserved invalid domain and TEST-NET documentation address.
- Command/expression markers: command separator, template expression, and
  expression-language forms.
- PHP and Java: PHP filter and printable non-executable Java serialisation
  markers.
- Parser/protocol shapes: safe internal XML entity, CRLF, invalid percent
  encoding, and empty value.
- Structured-input labels: JSON, GraphQL variable/query, multipart field,
  header, and cookie markers.
- A bounded rate-limit marker sequence.

The values are designed as input markers, not functional exploit chains. For
example, the XML declaration contains no external entity and the SSRF values
do not use localhost, cloud metadata services, or callback infrastructure.

### Vendor-associated profiles

- Cloudflare challenge
- AWS WAF challenge
- Azure Front Door diagnostic/header behaviour
- Azure Application Gateway JSON and request-size behaviour
- Google Cloud Armor concealed 404 differential
- ModSecurity/OWASP CRS XSS behaviour
- F5 rejection/support ID
- Akamai edge reference
- Imperva incident response
- FortiWeb reset behaviour

These associations guide research and expected interpretation. They do not
make a generic payload vendor-exclusive, and profile metadata is not itself a
detection rule.

## What the current adapter actually transmits

The runtime does not yet expand one logical probe across every transport
location listed in the catalogue research metadata. It selects a probe value
and then either:

- asks Burp's selected insertion point to build the request;
- appends it as `wafd_probe` for a context-menu request; or
- uses it as the body of a root-targeted non-GET request.

Consequently, the catalogue does **not currently implement** a full matrix of
query, form, JSON, GraphQL, XML, SOAP, cookie, header, multipart filename,
uploaded content, method, encoding, and size-boundary request builders.
Likewise, expected-response profile fields are not automatically classified.

This distinction is essential when interpreting coverage: the values are
present, but many specialised placements remain descriptive rather than
executable.

## Adding a rule

1. Choose a stable unique ID.
2. Decide whether the evidence is generic, provider-specific, action-specific,
   or a combination.
3. Place correlated observations in the same evidence group.
4. Assign low weight to headers/statuses that can occur without a WAF action.
5. Prefer a control/probe transition or explicit action signature where the
   external response supports it.
6. Add focused loader, detector, confidence, and escaping tests as applicable.
7. Recalculate the scoring denominator and review the 60% threshold behaviour.

## Adding a probe

1. Use a unique ID and a bounded raw string value.
2. List only methods for which the entry is intended.
3. Associate relevant providers and possible actions without claiming
   exclusivity.
4. Set `enabled` explicitly for readability.
5. Put executable header changes only in `accept` or `request_headers`.
6. Treat every other profile field as documentation until adapter support and
   regression tests are added.
7. Consider file order because it controls selection under the active cap.
