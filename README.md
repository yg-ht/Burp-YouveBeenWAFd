# Burp WAF Detector

Burp WAF Detector is a Python/Jython Burp Suite extension that maintains a
current, evidence-weighted assessment of whether an HTTP origin is protected
by a web application firewall (WAF).

It combines two forms of observation:

- **Passive detection** examines eligible responses as they pass through Burp.
- **Active detection** compares a control response with responses to
  attack-shaped probe values when a scan or context-menu action requests it.

The extension reports generic WAF behaviour separately from provider and
security-action signals. A Cloudflare edge header, for example, can identify
edge infrastructure without claiming that a managed WAF rule caused a block.

> **Development status:** this project is intended for GitHub/manual
> installation and internal evaluation. It has not yet been submitted to the
> BApp Store.

## Headline features

- Continuous passive response analysis, optionally restricted to Burp scope.
- Explicit active checks through Burp Scanner, plus a **Probe for WAF** context
  action whose current request-line defect is documented under limitations.
- A control/probe comparison covering status, bounded body content, body hash,
  cookie names, response headers, HTTP version, and no-response behaviour.
- Confidence scoring based on distinct evidence groups, preventing correlated
  aliases from being counted repeatedly.
- One replaceable **WAF Detector: current assessment** issue per observed
  origin, including a no-indicators state after the first eligible response.
- Separate provider and action tags such as `cloudflare`, `aws-waf`, `block`,
  `challenge`, `captcha`, `rate_limit`, and `reset`.
- External JSON catalogues containing 38 detection rules and 49 enabled probe
  definitions.
- Per-rule enablement in the extension tab and per-probe enablement/method
  allowlists in `data/probes.json`.
- Dependency-free detection code that can be tested outside Burp.

## Quick start

1. Configure Burp Suite to use a Jython standalone JAR.
2. In **Extensions > Installed**, add a Python extension and select
   `BurpExtender.py` from the repository root.
3. Confirm that Burp's extension output reports the number of loaded rules.
4. Open the **WAF Detector** tab to review passive monitoring, the confidence
   threshold, and enabled detection rules.
5. Browse an in-scope target for passive analysis. Use an active scan insertion
   point when active requests are intended. The context-menu request builder
   has a known request-line limitation described in
   [Architecture, testing, and limitations](docs/development.md#known-functional-limitations).

See [Installation](docs/installation.md) for complete instructions and
troubleshooting.

## Documentation

- [Features and behaviour](docs/features.md)
- [Configuration reference](docs/configuration.md)
- [Rules, probes, and confidence](docs/rules-and-probes.md)
- [Architecture, testing, and limitations](docs/development.md)

## Important operational notes

All 49 bundled probes are enabled in the catalogue, but one active operation
selects only the first eligible entries up to the configured cap (three by
default). Probe values include SQL-injection-, XSS-, traversal-, command-,
parser-, GraphQL-, XML-, and vendor-specific shapes. They are not exploits, but
they are real HTTP input and may trigger application or infrastructure policy.

For non-GET active scans, `/` is the default target unless the configuration is
changed to preserve the selected path. This reduces the chance of replaying a
selected application action, but it cannot guarantee that the target treats
the request as inert. Use the extension only within the agreed scope and
testing conditions.

## Runtime compatibility

The extension uses Burp's legacy Extender API because Burp Python extensions
run through Jython. The core modules retain Jython 2.7-compatible fallback
models and avoid third-party runtime dependencies. PortSwigger recommends the
Montoya API for new Java extensions, but this project currently remains a
Python extension.

## Licence

No licence file is currently included. Do not assume permission to redistribute
or modify the project outside the rights granted by its owner.
