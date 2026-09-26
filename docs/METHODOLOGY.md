# Methodology — how OpenPulse knows what it claims (schema v0.3.0)

## Sources

Upstream: GitHub releases + repo metadata, official blogs/changelogs.
Security: OSV.dev, NVD, MITRE CVE, CISA KEV, GitHub Advisories,
Exploit-DB (link only). Lifecycle: endoflife.date. Ecosystems: Maven,
npm, PyPI, Docker/OCI (initial).

## Identity hierarchy

`docker.io/redis` ≠ `docker.io/bitnami/redis`, always. Resolution
order: curated overrides → catalog aliases → Bitnami-namespace rule →
normalized fallback (`core/entities/resolve.py`). Typed identity refs
(`core/entities/identity.py`: project, package, artifact, repository,
registry_artifact, purl, cpe) record *why* two names were treated as
the same thing. Same identity evidence = same thing; same name is
never enough.

## Vulnerability correlation methodology

NVD `keywordSearch` is **discovery**, never applicability. Findings
carry `relationship` + `match_method` + `identity_evidence`:

- `osv_package` — OSV query scope (package/ecosystem identity).
- `osv_package+version_range` / `cpe_version_range` — plus an evaluated
  version range → `AFFECTS_VERSION`.
- `cpe_vendor_product` — normalized exact product equality only.
  Token overlap (`spring` vs `spring-shell`) is NOT identity.
- `keyword_only` — capped at `REVIEW`, never `AFFECTS_VERSION/_ARTIFACT`.
- KEV `exact`/`strong` sets `in_kev`; `weak` never does. KEV +
  uncertain applicability → `REVIEW`, never `CRITICAL`.

## Version applicability

`core/versions.py` evaluates OSV events
(introduced/fixed/last_affected) and NVD CPE range attributes
(versionStart/EndIncluding/Excluding) plus exact versions. Result is
`True`/`False`/`None` — `None` (unknown version, exotic scheme) keeps
the ceiling at `AFFECTS_PACKAGE` or `RELATED`. Uncertainty never
strengthens a conclusion.

## Evidence, claims, independence

Every claim names supporting evidence (`Claim.evidence_refs`); an
official-but-unrelated source never satisfies a claim. Corroboration
counts independent families, folding `derived_from` chains.
Contradicting evidence stays visible (`⚠️ CONTRADICTS`); unresolved
conflict blocks `ACTION`/`CRITICAL`. High-impact conclusions require
official/primary authority or hashed provenance.

## Confidence

- CONFIRMED: official announcement (vendor blog, repo release, EOL page).
- CORROBORATED: 2+ independent sources.
- EMERGING: single credible secondary.
- UNVERIFIED: weak/rumor — never triggers ACTION alone.

Official evidence proves the statement *from that source*; it does not
automatically prove the user's dependency is affected. Impact coupling
is enforced by the gate.

## Impact

INFORMATIONAL < WATCH < REVIEW < ACTION < CRITICAL. Findings also
carry severity (CVSS band), urgency, and recommended_action. No opaque
single score — facets stay separate.

## Registry observations

What the registry exposed at time T: repository state, tag→digest
map, content hash (`core/observations/`). Tags are mutable pointers,
never identities. First sighting is a baseline; changes derive only
from observation diffs. History lives in git-ignored local JSON —
portable, no server.

## Uncertainty handling

Unknown version → no version claim. Unknown identity → RELATED, not
AFFECTS. Unknown applicability + KEV → REVIEW, not CRITICAL.
Conflicting evidence → visible + blocking for strong actions.

## Limitations — what OpenPulse does not know

- No auto-remediation; not a SAST/SCA replacement.
- English sources first; no private-registry visibility.
- Version comparison is best-effort numeric (exotic schemes → unknown).
- CPE data depends on NVD configuration quality.
- Popularity facet is informational (no methodology yet).
- `latest` moves constantly — pin digests in production.
