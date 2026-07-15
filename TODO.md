# TODO

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
