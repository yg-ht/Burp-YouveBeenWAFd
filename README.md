# Burp WAF Detector

Burp WAF Detector is a Python/Jython Burp Suite extension that combines passive
traffic analysis with explicitly initiated active control and probe requests to
maintain an evidence-weighted WAF assessment for each HTTP origin.

It separates generic WAF behaviour, provider/edge attribution, and observed
security actions. A header such as `cf-ray` can identify Cloudflare edge
infrastructure without proving that Cloudflare WAF blocked the request.

> **Development status:** this legacy Extender API/Jython 2.7 project is
> distributed for manual installation and internal evaluation. It is not in
> the BApp Store, and its confidence weights still require customer validation.

## Safety notice

Active probes send real, attack-shaped HTTP input. A full run can send hundreds
of requests; controls are additional to the configured probe maximum, and
constructed non-GET probes target `/` unless **Selected request path** is set.
Confirm authorization, scope, target paths, size limits, request volume, and
the engagement's WAF-testing policy before probing. The extension cannot know
whether an endpoint is inert.

## How it works

```text
Passive response -> evidence and confidence -> concern at threshold
Active batch -> controls and probes -> determination -> optional concern
```

Burp receives two deliberately different issue types:

- **WAF Detector: probe determination** is an immutable Information audit
  record for every completed active batch, including outcomes, matched and
  cleared qualities, and successful request/response messages.
- **WAF Detector: WAF suspected** is a High concern raised once per origin when
  the inclusive threshold is reached.

A later clean determination records cleared qualities but does not delete the
original concern; the legacy API has no reliable general issue-removal method.

## Capabilities

- In-scope passive monitoring and explicit Scanner/context-menu probing.
- Same-shape controls and evidence-group confidence scoring.
- Query, form, JSON, GraphQL, XML, SOAP, header, cookie, multipart, upload,
  raw-body, endpoint, protocol, size, and inspection-boundary coverage.
- Provider signals for Cloudflare, AWS, Azure, Google Cloud Armor, ModSecurity,
  F5, Akamai, Imperva, FortiWeb, Barracuda, Radware, Sucuri, and Fastly.
- Separate block, challenge, CAPTCHA, rate-limit, and reset actions.
- Searchable rule/probe configuration and recoverable per-origin state.
- No third-party Python runtime dependencies.

The validated catalogues contain 41 shared rules, 49 base probes, and 17
matrices that expand to 213 concrete user-configurable probes.

## Requirements and quick start

Requirements are Burp Suite with legacy Python-extension support, a configured
Jython standalone JAR, and a complete checkout keeping `BurpExtender.py`,
`wafd/`, and `data/` together.

1. Configure Burp with a trusted Jython standalone JAR.
2. Add `BurpExtender.py` as a Python extension under **Extensions > Installed**.
3. Confirm output includes `WAF Detector loaded with 41 rules`.
4. Review threshold, request maximum, size limits, and non-GET targeting.
5. Browse an in-scope target for passive analysis.
6. Start Scanner probing or **Probe for WAF** only when traffic is intended.

See [Installation and troubleshooting](docs/installation.md) for full setup.

## Interpreting results

The default inclusive threshold is 60%. Confidence adds the strongest enabled
rule weight in each distinct evidence group and caps the result at 100%, so
aliases for one response signature do not stack.

Burp confidence and severity have different roles. Determinations stay
Information even when their historical result was WAF suspected; the separate
High concern represents the testing-policy condition. An old concern can
therefore coexist correctly with a newer clean determination. Provider signals
also do not prove a particular enforcement action: inspect rule/probe IDs,
control outcomes, attached messages, and server-side logs where available.

## Request volume and targeting

There is no implicit three-probe cap. Every enabled and method-authorized probe
is eligible by default; specialist controls and configured repetitions add
requests. A maximum limits probe transmissions, not controls. Enable only the
coverage required for the engagement.

Constructed non-GET requests use **Root path (/)** by default;
**Selected request path** preserves the chosen target. GET-like placements
normally preserve the target unless a profile declares an endpoint.

## Configuration

The extension tab provides **Settings**, **Detection Rules**, and **Active
Probes**. Filtering and checkbox changes do not affect live behaviour until
**Save settings** is selected. See the
[configuration reference](docs/configuration.md) for all fields and schemas.

## Documentation

- [Installation and troubleshooting](docs/installation.md)
- [Features and issue behaviour](docs/features.md)
- [Configuration and catalogue schemas](docs/configuration.md)
- [Rules, probes, and confidence](docs/rules-and-probes.md)
- [Architecture, testing, and limitations](docs/development.md)
- [Calibration and remaining work](TODO.md)

## Development and compatibility

Runtime modules retain Python 2/Jython 2.7-compatible syntax. The current
CPython suite contains 146 automated tests for models, catalogues, requests,
adapter behaviour, recovery, and compatibility:

```bash
python -m unittest discover -q
```

Real Burp/Swing and Jython integration still requires manual validation.
PortSwigger recommends Montoya for new Java extensions; migration would be a
separate public-interface change.

## Known limitations

- Confidence weights and the default threshold are not yet calibrated against
  representative confirmed deployments.
- HTTP responses cannot authoritatively identify every provider or policy.
- Full runs can generate substantial traffic and issue data.
- Legacy API limitations prevent reliable deletion of an existing concern.
- The real Burp/Jython adapter requires manual end-to-end validation.

See [Architecture, testing, and limitations](docs/development.md) for details.

## Licence

No licence file is included. Do not assume permission to redistribute or
modify the project outside the rights granted by its owner.
