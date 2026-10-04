# Methodology — how OpenPulse knows what it claims (schema v0.4.0)

## Sources

Upstream: GitHub releases + repo metadata, official blogs/changelogs.
Security: OSV.dev, NVD, MITRE CVE, CISA KEV, GitHub Advisories,
Exploit-DB (link only). Lifecycle: endoflife.date. Ecosystems: Maven,
npm, PyPI, Docker/OCI (initial).

## Source authority tiers

Sources are not equal. Tiers, strongest first:

- **official** — the vendor/project itself (announcement, changelog,
  advisory, repo). Alone sufficient for CONFIRMED.
- **primary** — lifecycle databases (endoflife.date), registries
  serving protocol truth (tag lists, digests). Strong but narrow:
  endoflife.date proves dates, never distribution intent.
- **secondary** — reputable press, mirrors, aggregators. Corroborates;
  never confirms alone.
- **tertiary** — rumors, single discussions. Context at most.

endoflife.date is a primary lifecycle source — one input among many,
not the definition of OpenPulse. A lifecycle database answers "when
does software reach EOL"; OpenPulse answers "what is changing upstream,
and does it affect what I depend on".

## Identity hierarchy

`docker.io/redis` ≠ `docker.io/bitnami/redis`, always. Resolution
order: curated overrides → catalog aliases → Bitnami-namespace rule →
normalized fallback (`core/entities/resolve.py`). Typed identity refs
(`core/entities/identity.py`: project, package, artifact, repository,
registry_artifact, purl, cpe) record *why* two names were treated as
the same thing. Same identity evidence = same thing; same name is
never enough.

Every resolution carries an identity status: VERIFIED (curated
mappings and self-identity), REVIEW_REQUIRED (heuristic rules or
flagged catalog entries, e.g. broad aliases), UNVERIFIED
(explicitly distrusted). Catalog entries that need it declare an
`identity:` block (status, source, reviewed_at, maintainer,
confidence, note) — never mechanically, only where ambiguity lives
(aliases, forks, renames, distributions, namespace collisions).
Affected verdicts that rely on REVIEW_REQUIRED/UNVERIFIED mappings
are capped at EMERGING confidence: unverified identity can never
silently elevate impact. Exact artifact equality needs no mapping
and is never capped.

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
counts independent families, folding `derived_from` chains — and the
monthly report counts families, not labels: NVD + OSV share the
vuln-data family, and OpenPulse's own correlation never counts as an
independent source (`source_family_count`,
`corroborating_family_count`). Contradicting evidence stays visible
(`⚠️ CONTRADICTS`); unresolved conflict blocks `ACTION`/`CRITICAL`.
High-impact conclusions require official/primary authority or hashed
provenance.

## Confidence

- CONFIRMED: official announcement (vendor blog, repo release, EOL page).
- CORROBORATED: 2+ independent sources.
- EMERGING: single credible secondary.
- UNVERIFIED: weak/rumor — never triggers ACTION alone.

Match strength and evidence strength are separate axes
(`core/risk/check.py`): an exact artifact match answers *what
matches*; the event's evidence answers *how trustworthy the claim
is*. Final verdict confidence is the conservative minimum of the
two — a precise match on a weak claim stays weak. Official evidence
proves the statement *from that source*; it does not automatically
prove the user's dependency is affected. Impact coupling is enforced
by the gate.

Finding confidence follows the same ladder at analyst level
(`AFFECTS_*` from ≥2 sources → CORROBORATED, else EMERGING;
`RELATED` → UNVERIFIED unless KEV-confirmed-exploited → EMERGING).
Weakly established findings (EMERGING/UNVERIFIED) cap at REVIEW:
weak evidence never enters an ACTION-level channel (`check --strict`
fires only on ACTION/CRITICAL causes).

## Popularity

GitHub stars inform reach, never risk: ≥50k very high, ≥10k high,
≥1k medium, else low, unknown → unranked. The facet stays
informational (always 🟢) — popularity never promotes an impact.

## Impact

INFORMATIONAL < WATCH < REVIEW < ACTION < CRITICAL. Findings also
carry severity (CVSS band), urgency, and recommended_action. No opaque
single score — facets stay separate.

## Intelligence semantics

An analyst `impact` is a proposal, not a conclusion. Reports place
findings through impact eligibility (`core/risk/impact.py`):

- `PROJECT_SIGNAL` — something exists (unscoped, unconfirmed).
- `PROJECT_CHANGE` — scoped ecosystem change (what changed, with
  versions/artifacts/dates). Never customer impact.
- `AFFECTS_DEPENDENCY` — a linked inventory entry matches.
- `ACTION_REQUIRED` — affected + effective + strong confidence. Only
  here does EOL (or any change) become action for *your* software.

Eligibility ladder for public reports: scoped effective EOL and
distribution model changes may be ACTION-framed (with disclaimer);
archived upstreams, vanished repositories/tags, and support ends are
REVIEW at most; upcoming EOL and routine registry churn are WATCH.
EOL detected never equals ACTION_REQUIRED — that needs inventory.

## Lead time

Upcoming changes carry their warning in days: effective −
first_detected_at, per finding (`core/leadtime.py`). First detection
is the first trustworthy OpenPulse detection of the change —
re-observations never stand in, and an unknown first detection means
no lead-time claim (never estimated). Unknown or already-past
effective dates print nothing — silence, not a number. Temporal
roles are never conflated: published/announcement (source claims),
first detection (our discovery), last observation (confirmation),
effective (applies). Lead times are never averaged, ranked, or
marketed: the metric stays instrumented but unclaimed until
independently measured incidents exist.

### Durable detection ledger

Sweep findings derive first detection from observation history, but
lifecycle and security findings had no persisted history — warning
windows died with the process. Watchlist runs (`openpulse check`)
now record durable first detections under `.openpulse/detections/`
(`core/detections/ledger.py`): one JSON entry per fact, keyed by
stable identity — (project, class, subject, scope) where lifecycle
facts use (project, `EOL`/`EOS`/`DEPRECATION`, sorted cycle versions)
and security facts use (project, CVE id). The store reuses the
observation-history trust model: atomic writes (temp + rename),
per-project locks with stale reclaim, and content hashes over the
fact identity. No hash chain: an entry is a standalone
earliest-witness record, so its own content hash meets the
integrity need, and absence — deleted or never written — is
indistinguishable from never-detected, which is exactly the
"unknown means unknown" rule. Earliest evidence wins, including
under clock skew: a later stamp never overwrites, an earlier
trustworthy stamp is taken (correcting it would be an estimate).
Deleting the ledger degrades to per-run behavior — no claims, never
invented dates.

## Research window and freshness

OpenPulse researches the last 12 months (`core/freshness.py`).
Freshness derives from the effective date, never the observation
date: a 2024 EOL re-observed today is background knowledge
(`BACKGROUND`), not news. Findings effective over a year ago sink in
rankings and carry the background label, but stay narrated with full
evidence — freshness demotes and labels, never deletes. Unknown
effective dates are `UNKNOWN` freshness, never assumed old.
Reports segment background explicitly so monthly briefings cannot
present last year's changes as this month's.

## Date semantics

Five temporal roles, never substituted for one another
(`core/freshness.py:_finding_dates`, `core/leadtime.py`):

- Announced — when the upstream project publicly communicated the
  change. Used only with provenance: `official` (NVD/CVE
  publication, OSV publication, KEV catalog addition, GitHub release
  publication) or `unknown`. Inferred dates are marked inferred with
  their provenance retained; without a trustworthy date the report
  shows "Announcement: Unknown" — dates are never fabricated from
  file times, commit dates, scan dates, or report generation dates.
- Effective — when the change takes (or took) effect.
- First detected — when OpenPulse first observed sufficient
  evidence. Re-observations never stand in.
- Last verified — when OpenPulse most recently confirmed the
  evidence (`last_observed_at`, else `observed_at`).
- Reported — the reporting period that included the finding.

## Freshness policy (`core/freshness.py`)

Event-temporal classification is deterministic date arithmetic —
no LLM, no heuristics beyond the documented rules:

- `UPCOMING` — effective date in the future. Announcement age never
  hides a future consequence.
- `NEW` — announced within the recency window and not yet past effect.
- `RECENTLY_UPDATED` — old announcement with a recent first
  detection or verification: the update is treated as new intelligence.
- `ACTIVE` — ongoing dateless conditions, recently verified.
- `EXPIRED` — effective date past with no recent update; moves to
  the Historical appendix, never deleted.
- `UNKNOWN_DATE` — no dates at all; narrates only when
  REVIEW/ACTION-eligible.

The recency window defaults to 90 days (`OPENPULSE_REPORT_FRESHNESS_DAYS`
overrides): three monthly reporting cycles, matching typical OSS
disclosure-to-impact spans. Effective-date rules always take
precedence over the window; a 365-day research window backstops
unknown-announcement cases.

## Public/internal/debug information boundary

Monthly Markdown reports are website-facing. Every report field is
classified:

| Class | Content | Examples |
|---|---|---|
| PUBLIC | Evidence, sources, dates with provenance, scope, assessment vocabulary, confidence | finding titles, summaries, references, observation/content/chain hashes, `Announced/Effective/First detected/Last verified/Status` lines |
| INTERNAL | Trust machinery legible only with codebase context | analyst names, impact proposals, parser versions, match methods, `_refs`, evidence-link internals, lifecycle states, store paths |
| DEBUG | Diagnostics, never rendered | tracebacks, raw payloads, lock files, credentials (never collected) |

`tests/test_public_report.py` enforces the boundary by token scan.
Assessment and eligibility labels (`PROJECT_CHANGE`, `ACTION`,
`REVIEW`, `WATCH`) are PUBLIC domain vocabulary, defined in the
report Methodology section — not cryptic codes.

## Registry observations

What the registry exposed at time T: repository state, tag→digest
map, content hash (`core/observations/`). Tags are mutable pointers,
never identities. First sighting is a baseline; changes derive only
from observation diffs. History lives in git-ignored local JSON —
portable, no server.

Observations are tamper-evident: every persisted record carries a
chain hash `H[n] = SHA256(canonical_fields(n) + H[n-1])` over
observation id, source, entity, timestamps, content hash, parser
version, and predecessor link; the first record links to an explicit
`genesis` marker. Histories verify VALID / BROKEN / UNKNOWN —
a broken chain is never diffed against (no findings, no append;
the corrupt predecessor stays on disk as evidence). Sealed records
are frozen; concurrent writers serialize on a per-repository lock
with atomic writes, and history is ordered by chain links, never
filenames. Threat model: the chain defeats silent corruption,
partial edits, and rollback/fork anomalies — not an adversary who
recomputes the whole suffix (no secrets in a local-first store).

Every registry-derived finding retains first-class observation
evidence (`observation_evidence`: observation ids, hashes, chain
links, timestamps, the exact diff fact). The public Hub URL is
reader context; the observation identity is the machine evidence.
Diffs are candidate changes with explicit evidence strength
(observed fact: moderate; namespace heuristic: weak) — weak
evidence caps report placement at REVIEW and can never become
ACTION_REQUIRED, however precise the dependency match.

## Uncertainty handling

Unknown version → no version claim. Unknown identity → RELATED, not
AFFECTS. Unknown applicability + KEV → REVIEW, not CRITICAL.
Conflicting evidence → visible + blocking for strong actions.

## Limitations — what OpenPulse does not know

- No auto-remediation; not a SAST/SCA replacement.
- English sources first; no private-registry visibility.
- Version comparison is best-effort numeric (exotic schemes → unknown).
- CPE data depends on NVD configuration quality.
- Popularity informs reach, never risk (stars bands, always 🟢).
- `latest` moves constantly — pin digests in production.
- License/support-model changes are curated events for now (Bitnami,
  iText fixtures): no automated license collector exists yet, so the
  pipeline cannot *discover* them — only validate, gate, and match
  them once recorded with evidence.

## Core distinctions (design principles)

- RELATED ≠ AFFECTED — association is not impact.
- AFFECTS_PROJECT ≠ AFFECTS_VERSION — project ties are contextual.
- UNKNOWN ≠ NOT_AFFECTED — unevaluated is not cleared.
- OBSERVATION ≠ CLAIM ≠ EVENT — facts, assertions, and gated
  intelligence are separate layers.
- Detection (what was observed) ≠ assessment (what evidence
  establishes) ≠ recommendation (what to investigate). Recommendations
  never feed back into impact calculations.
- SOURCE SIGNAL ≠ CHANGE ≠ AFFECTED DEPENDENCY ≠ ACTIONABLE
  INTELLIGENCE. A lifecycle date is a signal; a scoped, dated change
  is intelligence; impact requires a dependency.
- Public intelligence (what changed in OSS) ≠ customer intelligence
  (does it affect my software). Public reports never assert the second.
- MATCH STRENGTH ≠ EVIDENCE STRENGTH — precise identity answers
  "what matches", never "how trustworthy is the claim".
- HEURISTIC DETECTION ≠ AUTHORITATIVE EVIDENCE — discovery leads
  stay capped until confirmed.
- OBSERVED DATE ≠ FIRST DETECTED DATE — re-observation is
  confirmation, not discovery.

## Webhook security boundary (`core/notify.py`)

Digest webhooks POST to operator-supplied URLs, but OpenPulse runs
automated — so delivery enforces an SSRF policy: https by default
(http needs `--webhook-allow-http` opt-in), no credentials in URLs,
every resolved IP checked (loopback, link-local incl. the cloud
metadata range, RFC1918/ULA, CGNAT, multicast, reserved, and named
metadata endpoints all rejected — one blocked address refuses the
whole delivery), redirects never followed, short timeout, bounded
response body, failures never log secrets. Known limitation: DNS is
resolved before connecting, so a hostile resolver could race the
check; short timeouts and no-redirects bound the blast radius.

## Verdict decision matrix (`core/risk/check.py`)

AFFECTS_ARTIFACT > AFFECTS_VERSION > AFFECTS_PACKAGE >
NOT_AFFECTED > RELATED > AFFECTS_PROJECT > UNKNOWN.
`affected` is True only for ARTIFACT/VERSION/PACKAGE. A stronger
negative (evaluated version outside the range) beats RELATED/UNKNOWN;
no weaker match overrides it. The match implies a confidence *ceiling*
(ARTIFACT → CONFIRMED, VERSION/NOT_AFFECTED → CORROBORATED, PACKAGE →
EMERGING, project/related → EMERGING/UNVERIFIED, unknown →
UNVERIFIED); the verdict takes the minimum of that ceiling and the
evidence behind the event. NOT_AFFECTED carries the explicit
NOT_AFFECTED assessment (informational/cleared) — a negative is never
combinable with an AFFECTS_* assessment.
