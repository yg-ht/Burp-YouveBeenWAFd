# Burp WAF Detector

Burp WAF Detector is a Python/Jython Burp Suite extension that maintains a
current, evidence-weighted assessment of whether an HTTP origin is protected
by a web application firewall (WAF).

It combines:

- **Passive detection**, which examines eligible responses already passing
  through Burp without sending additional traffic.
- **Active detection**, which sends explicitly requested, data-driven control
  and probe requests through Burp Scanner or **Probe for WAF**.

The extension reports generic WAF behaviour separately from provider and
security-action signals. Seeing `cf-ray`, for example, supports Cloudflare edge
attribution but does not by itself claim that Cloudflare WAF blocked a request.

> **Development status:** this project is intended for GitHub/manual
> installation and internal evaluation. It has not yet been submitted to the
> BApp Store.

## Headline features

- Continuous passive analysis, restricted to Burp scope by default.
- Explicit Scanner and context-menu active probing.
- Same-shape controls for constructed specialist requests.
- SQL injection and XSS matrices across query, form, JSON, GraphQL, XML, SOAP,
  headers, cookies, multipart fields, filenames, and uploaded text.
- Content-type, HTTP-method, parameter-pollution, malformed-input, multipart,
  cookie, size-limit, and inspection-boundary matrices.
- 41 shared passive/active detection rules.
- 49 base probe definitions plus 17 compact matrices, expanding to 213
  concrete user-configurable probes.
- Provider coverage for Cloudflare, AWS WAF, Azure WAF, Google Cloud Armor,
  ModSecurity/OWASP CRS, F5, Akamai, Imperva, FortiWeb, Barracuda, Radware,
  Sucuri, and Fastly.
- Confidence scoring based on distinct evidence groups rather than repeated
  aliases for one header or response template.
- Separate action labels for block, challenge, CAPTCHA, rate limit, and reset.
- One **WAF Detector: WAF suspected** High-severity concern per origin, raised
  only when the inclusive configured threshold is reached.
- One informational **probe determination** audit issue per completed active
  batch, with request/response messages and timestamped tested, matched, and
  cleared qualities.
- Font-height settings plus searchable, collapsible rule/probe groups with
  matched-only bulk enablement and persistent state.
- No third-party Python runtime dependencies.

## Quick start

1. Configure Burp Suite with a Jython standalone JAR.
2. In **Extensions > Installed**, add a Python extension and select
   `BurpExtender.py` from the repository root.
3. Confirm that Burp output reports 41 loaded rules.
4. Open **WAF Detector > Settings** and review the active request volume and
   configured size thresholds before probing.
5. Browse an in-scope target for passive analysis.
6. Start active probing from a Scanner insertion point or **Probe for WAF**
   only when the additional requests are intended.

See [Installation](docs/installation.md) for complete instructions.

## Documentation

- [Features and behaviour](docs/features.md)
- [Configuration reference](docs/configuration.md)
- [Rules, probes, and confidence](docs/rules-and-probes.md)
- [Architecture, testing, and limitations](docs/development.md)

## Active request volume

There is no implicit three-probe cap. By default, every enabled probe whose
outgoing method is authorised by its own `safe_methods` is eligible. Constructed
specialist probes normally send one control and one probe request, while
`repeat` entries send every configured repetition. A user-set maximum limits
probe transmissions but does not include their control requests.

The bundled catalogue is intentionally broad, so a complete operation can send
hundreds of requests. Use the **Active Probes** tab to select the required
coverage or set a maximum under **Settings**.

## Targeting and operational assumptions

Constructed non-GET requests use `/` by default. The `selected` policy preserves
the chosen path instead. In the UI these policies are labelled **Root path
(/)** and **Selected request path**. GET-like placements preserve the selected
target unless a profile declares an explicit endpoint.

The extension cannot determine whether `/` is inert and does not enforce an
application-specific safety contract. Probe values are attack-shaped text, not
functional exploit chains, but they are real HTTP input and may trigger WAF,
proxy, server, or application behaviour. Use the extension within the agreed
scope and testing conditions.

## Runtime compatibility

The extension uses Burp's legacy Extender API because Python extensions run
through Jython. Core modules retain Jython 2.7-compatible models and syntax.
PortSwigger recommends Montoya for new Java extensions, but migration would be
a separate interface change.

## Licence

No licence file is currently included. Do not assume permission to redistribute
or modify the project outside the rights granted by its owner.
