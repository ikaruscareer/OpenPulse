# Methodology — sources, evidence, confidence, limitations (Phase 0)

## Sources (v0.1)
Upstream: GitHub releases, official blogs/changelogs. Security: OSV.dev, NVD, MITRE CVE, CISA KEV, GitHub Advisories, Exploit-DB (link only). Lifecycle: endoflife.date. Ecosystems: Maven, npm, PyPI, Docker/OCI (initial).

## Confidence
- CONFIRMED: official announcement (vendor blog, repo release, EOL page).
- CORROBORATED: 2+ independent sources.
- EMERGING: single credible secondary.
- UNVERIFIED: weak/rumor — never triggers ACTION alone.

## Impact
INFORMATIONAL < WATCH < REVIEW < ACTION < CRITICAL. MVP shows facets (activity/security/lifecycle/support/license/distribution/popularity) with 🟢🟠🔴 each — no opaque single score.

## Limitations
- No auto-remediation, no SAST/SCA duplication, English sources first, OCI tags are mutable — always record digest when possible.
