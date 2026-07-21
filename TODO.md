# TODO

- [x] Separate active-probe audit records from actionable WAF concerns.
  - Return active issues through Burp's scanner-check contract and retain one
    immutable probe determination for every completed batch.
  - Raise one High-severity concern per origin only when the inclusive
    configured threshold is reached.
  - Attach the selected, control, and successful probe request/response
    messages to each determination without duplicating shared controls.
  - Recover the newest valid state from determinations, concerns, legacy
    issues, or post-concern passive-state settings.
  - Preserve later passive evidence across reloads without creating another
    visible issue, and do not infer a previously reported concern merely by
    rescoring historical evidence after a threshold change.
  - Cover legacy migration, invalid-state fallback, context-menu submission,
    concern deduplication, threshold changes, and Jython compatibility in the
    automated suite.

- [ ] Review and validate the additive WAF confidence model against customer
  systems before treating the default weights and 60% threshold as calibrated.
  - Exercise confirmed deployments for every supported provider and record
    which passive and active evidence groups match.
  - Include applications with no WAF, CDN-only deployments, load balancers,
    bot management, rate limiting, origin-generated denial pages, and unstable
    upstream connections to measure false positives.
  - Compare generic confidence, provider confidence, and reported actions with
    authoritative customer-side WAF/security logs where available.
  - Review whether 100-point challenge signatures and 85–90-point vendor block
    templates remain appropriate across customised responses.
  - Specifically validate the 50-point Akamai edge-reference weight so an edge
    denial alone remains below the WAF threshold without corroboration.
  - Reassess the default 60% threshold using anonymised results, documenting
    provider-specific blind spots or weight changes before release.
  - Add sanitised regression fixtures for confirmed true-positive,
    false-positive, ambiguous, and no-WAF outcomes.
