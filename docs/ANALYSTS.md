# Analysts — pure functions, deterministic, no network

Four analysts, kept separate on purpose. Each consumes raw collector
dicts or findings and returns plain data. Only the gate
(`core/evidence/policy.py`) can promote a proposal to an OSSEvent.

## Change Analyst (`analyzers/change_analyst.py`)

Rules today:

- endoflife.date cycle with EOL date in the past (or `eol: true`) →
  `EOL` / `ACTION`. Within 180 days → `EOL` / `REVIEW`.
- endoflife.date active-support date in the past → `EOS` / `REVIEW`.
- Registry probes showing Bitnami mainline latest-only + legacy holding
  versioned tags → `DISTRIBUTION_CHANGE` / `ACTION`.
- Any repo serving latest-only tags → `DISTRIBUTION_CHANGE` / `WATCH`.
  "Latest-only" is version-aware (`parse_tags`): a mainline whose
  every tag is `latest` or distribution machinery (`sha256-*` digest
  tags, `*.sig`/`*.att`/`-metadata` sidecars) is latest-only; any
  version-like tag disqualifies it. So a digest-tagged mainline
  next to a legacy namespace holding the versioned tags fires the
  split rule above — the Bitnami scenario is now derived, not just
  recorded.
- Missing repo → `REGISTRY_CHANGE` / `REVIEW`.
- Archived GitHub repo (via `fetch_repo_meta`) → `PROJECT_ARCHIVED` / `ACTION`.
- Repository ownership drift: API `full_name` owner differs from the
  queried path → `OWNERSHIP_CHANGE` / `REVIEW` (moderate). Same-owner
  renames stay silent; archived repos still fire independently.
- Observation diffs (`analyze_diffs`): `tag_disappeared` → `REVIEW`,
  `tag_appeared`/`tag_digest_changed`/`latest_moved` → `WATCH`,
  `repo_missing` → `REVIEW`, `repo_restored` → `INFORMATIONAL`.

Every lifecycle and distribution finding is machine-scoped and dated:
`scope` (`kind` + `versions`/`artifacts` — see Finding scope below),
`lifecycle_state` (`EFFECTIVE`/`UPCOMING`), `effective_at`,
`observed_at`, and — for registry findings — `significance`
(low/medium/high) assessed from the observation itself, never from
assumed customer usage (`analyzers/change_analyst.py`).

Registry findings label `detection_method`: `registry_observation`
for direct probe/diff facts, `namespace_heuristic` for the
legacy-namespace pattern rule (discovery aid, never authoritative
evidence). `official_distribution_announcement` is reserved for
curated official findings. Every diff finding also carries
`evidence_strength` (`moderate` for observed facts, `weak` for
heuristics) and `observation_evidence` — the immutable observation
identity (ids, content/chain hashes, timestamps, exact diff fact)
behind the claim. Weak evidence caps report placement at REVIEW and
can never become ACTION_REQUIRED, however precise the match.

## Finding scope (`scope.kind` + id lists)

Analysts narrow applicability beyond "the project" with a
machine-readable `scope` block (`analyzers/change_analyst.py`,
`analyzers/lifecycle_events.py:_scope`):

- `kind: "version"` + `versions` — specific release cycles (EOL/EOS
  findings from `analyze_endoflife`).
- `kind: "artifact"` + `artifacts` — concrete references such as
  `docker.io/ns/repo:tag` (registry observations from
  `analyze_registries`/`analyze_diffs`).
- `kind: "project"` + empty `versions` — project-wide, nothing more
  specific claimed (archive findings, distribution-model moves).
- `kind: "package"` / `kind: "registry"` — accepted by the
  normalizer in `analyzers/lifecycle_events.py` (packages and
  registries lists) for producers that narrow to those levels.

`core/risk/impact.py:_scoped` counts a finding as scoped only for
`kind` in (version, artifact, package, registry) with a non-empty id
list — a `kind: "project"` scope never counts as scoped. Report
renderers show the scope lists verbatim
(`analyzers/report_analyst.py`).

## Lifecycle states and per-field timestamps

Temporal roles are never conflated (`core/leadtime.py`):

- `effective_at` (or `event_date`) — when the change applies. EOL
  findings set it from the endoflife.date date; diff findings use the
  observation time (`analyzers/change_analyst.py`).
- `first_detected_at` — our first trustworthy detection. Inherited
  from the predecessor observation by `core/observations/base.py`
  and resolved by `core/observations/sweep.py:first_detected_at_for`;
  re-observations never stand in for discovery. Lifecycle and
  security findings have no observation history, so watchlist runs
  persist them in the durable detection ledger
  (`core/detections/ledger.py`, `.openpulse/detections/`) — the
  earliest detection survives the process, and a missing entry
  still means no claim (never estimated).
- `observed_at` — when the analyst ran (analysis time).

`lifecycle_state` (`STATE_EFFECTIVE`/`STATE_UPCOMING`,
`analyzers/change_analyst.py`): EFFECTIVE means already applies —
past EOL dates, ended support, observations; UPCOMING means announced
but not yet effective — EOL within `EOL_WARN_DAYS` (180). Impact
eligibility branches on it: an EFFECTIVE + scoped EOL may be
ACTION-framed, an UPCOMING EOL is WATCH, and one with no usable
scope/state stays REVIEW at most (`core/risk/impact.py:_public_change`).

## Significance levels

Registry findings carry `significance` — low/medium/high — assessed
from the observation itself (`DIFF_RULES` and `analyze_registries` in
`analyzers/change_analyst.py`): a moved `latest` digest or an
appeared tag is routine churn (low); a vanished versioned tag is a
high-significance candidate that still needs usage context; a
vanished repository is also high (impact stays REVIEW — never
automatic action). Significance measures how much the
distribution changed, never whether a deployment is affected — only
high significance plus `distribution_model_change` opens ACTION
framing in `core/risk/impact.py:_public_change`.

## Assessment vocabulary and eligibility (`core/risk/impact.py`)

An analyst `impact` is a proposal made without customer context.
`evaluate_impact` decides what a finding *is eligible for* in a
report — assessment (what kind of claim) and eligibility (where it
may appear) are decided together; a proposal never travels straight
to placement:

- `PROJECT_SIGNAL` — something exists; unscoped or unconfirmed.
  Example: a security finding without established dependency impact,
  or an unclassified change (`_public_security`, `_public_change`).
- `PROJECT_CHANGE` — a scoped ecosystem change: what changed, with
  versions/artifacts/dates. Never customer impact. Example: an EOL
  effective for scoped versions, an archived upstream, a registry
  disappearance (`_public_change`).
- `AFFECTS_DEPENDENCY` — a linked inventory entry matches. Only
  produced on the dependency path (`_with_context`), when a
  correlation verdict in AFFECTS_ARTIFACT/VERSION/PACKAGE is
  established for a dependency in scope.
- `ACTION_REQUIRED` — affected + effective + strong confidence
  (CONFIRMED/CORROBORATED). Only here does EOL (or any change) become
  action for *your* software (`_with_context`).

Eligibility ladder for report placement: `INFORMATIONAL < WATCH <
REVIEW < ACTION` (`_ELIGIBILITY`). Central rule: `EOL detected` never
equals ACTION_REQUIRED — without a dependency inventory, lifecycle
findings are at most PROJECT_CHANGE (`evaluate_impact`).

## Report eligibility (`reports/generate.py`)

The monthly report computes public-context eligibility fresh for
every finding — it is never stored on the finding
(`reports/generate.py:_eligibility` -> `evaluate_impact`). Narrative
content includes findings whose eligibility is above INFORMATIONAL;
"Changes Requiring Attention" lists ACTION-eligible findings only
(`build_report`). Finding cards show assessment and scope, never the
raw analyst `impact` proposal. The lifecycle posture view
(`reports/lifecycle.py`) applies its own status ladder (EOL / UPCOMING /
SUPPORT-ENDED / OK / NO-DATA) rather than reusing `finding_to_event`;
both keep analyst proposals out of placement decisions. Analysts propose;
`core/risk/impact.py` disposes.

## Security Analyst (`analyzers/security_analyst.py`)

Merges OSV + NVD + CVE + KEV entries by CVE ID: source list, max CVSS,
KEV flag, reference union — plus `relationship`, `match_method`,
`identity_evidence`, severity, urgency, and recommended_action:

- `AFFECTS_VERSION` — version evaluated inside a range (OSV events or
  NVD CPE range attributes) via `core/versions.py`.
- `AFFECTS_PACKAGE` — identity evidence exists (OSV query scope,
  normalized-exact CPE/CNA product match) but version unproven.
- `RELATED` — the CVE exists but nothing ties it to this project
  (keyword-only NVD hits land here and cap at `REVIEW`).
- `UNKNOWN` — no score and no identity signal.

Live `analyze` queries OSV for catalog entries that declare an `osv`
`(package, ecosystem)` mapping (`data/canonical_projects.yaml`). OSV
records are keyed by their CVE alias (`GHSA-*`/`PYSEC-*` primary ids
carry `aliases`); records without a CVE alias cannot merge into the
CVE-keyed slots and are ignored by correlation.

CPE matching is normalized-exact only: token overlap (`spring` vs
`spring-shell`) is never identity. Impact: KEV + AFFECTS →
`CRITICAL`; KEV alone → `REVIEW`; AFFECTS_VERSION ≥ 7 / AFFECTS_PACKAGE
≥ 9 → `ACTION`. Weak KEV matches never set `in_kev`. Findings name
their match method (`osv_package[+version_range]`, `cpe_version_range`,
`cpe_vendor_product`, `keyword_only`); `keyword_only` never yields
`AFFECTS_VERSION`/`AFFECTS_ARTIFACT`.

Findings also carry `confidence` (CORROBORATED for ≥2 sources, else
EMERGING for AFFECTS_*, UNVERIFIED for RELATED/UNKNOWN) and cap at
REVIEW on weak evidence. `check --strict` fires only on affected
verdicts carried by ACTION/CRITICAL causes.

## Evidence Analyst (`analyzers/evidence_analyst.py`)

`assess_confidence`: official source → `CONFIRMED`; ≥2 independent
sources → `CORROBORATED`; single secondary → `EMERGING`; else
`UNVERIFIED`. `assemble_event` builds the OSSEvent (claims included)
and returns `(event, gate_violations)` — callers must handle
violations. Claims (`core/claims.py`) name supporting source names;
contradictions surface as `⚠️ CONTRADICTS` and unresolved conflict
blocks strong actions.

## OSS Pulse (`core/pulse.py`)

`compute_pulse` maps findings + events to 7 facets (activity, security,
lifecycle, support, licence, distribution, popularity). Worst impact
wins per facet; the strongest title is kept as the reason, so every
dot traces to a finding. Activity derives from repo metadata + release
recency (archived → action, >365d stale → review); popularity uses
documented stars bands (reach only, never risk). Rendered by
`openpulse pulse --project <slug> [--raw-bundle file]`.

## Report Analyst (`analyzers/report_analyst.py`)

`render_event_md`, `render_finding_md`, `render_digest`. Every claim
traces to an evidence URL or named collector output.

## Monthly report (`reports/generate.py`)

`collect_project` turns one raw bundle into pulse + findings;
`build_report` ranks them into a decision-support briefing —
Executive Summary, Top Changes (deterministic evidence-aware rank:
non-lifecycle first, then actionability, confidence, freshness
status, upcoming dates; findings effective over 12 months ago sink
as labeled background, never deleted), Discovery of the Month,
Changes Requiring Attention, Upcoming Changes (detection lead times
from first trustworthy detection only), Changes by Category,
Evidence Quality, What OpenPulse Watches, Methodology, What OpenPulse
Added This Month, For Your Environment, and an Appendix (Historical
first, then every current finding, sources, gaps). Finding cards show
category, evidence confidence (`finding_confidence`: declared
finding confidence, else strong→CONFIRMED, weak→UNVERIFIED, else
EMERGING), assessment, scope, announcement (with provenance),
effective, first-detected and last-verified dates, freshness status,
a conditional recommended investigation, and evidence refs — never
`_analyst` or raw impact proposals. Security findings carry
`announced_at` (earliest authoritative publication date across
merged entries) with `official` provenance; lifecycle and registry
findings honestly report announcement Unknown. Placement follows the
freshness taxonomy (`core/freshness.py:classify`: NEW / UPCOMING /
ACTIVE / RECENTLY_UPDATED stay in the main narrative; EXPIRED moves
to Historical). Recency (`--since`) and relationship
(`--include-related`) filters keep the monthly narrative honest.
`openpulse report --month YYYY-MM` runs the catalog live or from
`--raw-bundle-dir` offline bundles. `--with-sweep` feeds live
registry diffs into the ranking, the reference story, and the
appendix — the first report content no lifecycle database could
provide. `## What OpenPulse Added This Month` is the demonstrated-value section: upstream detection per present category, dependency
attribution with scope-kind examples (plus the Bitnami namespace
distinction when bitnami evidence is present), evidence-backed
counts, early-warning maxima, a six-stage reference case built
solely from the reference finding's data, and the public-to-early-
warning progression. Empty dimensions are omitted, never padded.

## Lifecycle posture report (`reports/lifecycle.py`)

`collect_lifecycle_status` turns one raw bundle's endoflife.date
entries into structured posture (effective EOL, upcoming deadlines
with trustworthy dates, ended support, or explicit NO-DATA);
`build_lifecycle_report` renders the planning view — Executive
Summary, Upcoming Deadlines (soonest first, dated only), Recently
Ended (last year, capped, overflow noted), Coverage Gaps grouped by
reason, Top Planning Items (soonest deadlines, then recent ends,
then confirmed EOL by version count), and the full matrix as an
appendix. NO-DATA is a coverage limitation, never an OK state.
`openpulse lifecycle-report --month YYYY-MM` runs endoflife.date
live or from `--raw-bundle-dir` offline bundles. Day counts derive
from an explicit `today`, so renders stay deterministic.

## Distribution discovery (`core/observations/sweep.py`)

`sweep_targets` lists every probeable catalog image (registry/namespace/
repo triples only — bare namespaces are skipped, never guessed).
`sweep_catalog` probes (injected function, offline-testable), persists
sealed observations, diffs against history, pairs cross-namespace
appear/disappear tags into migration stories (`split_moves` — one
move, not two findings), emits distribution findings, and aggregates
same-repo/same-direction diffs into one story
(`aggregate_distribution` — one pruning event, one card).
Probes paginate the Hub tag set (`page_size=100`, up to 30 pages);
when the walk stops short — Hub's anonymous offset wall (issue #36)
or the page cap — the registry v2 protocol supplies the complete
tag-name list (`auth.docker.io` pull token -> `registry-1.docker.io`
`/v2/<repo>/tags/list`, one response, no pagination). Rescued names
carry no digests, so the probe is `digests_partial` (names complete,
digests window-only) and digest-change diffs are withheld; if the v2
path is unavailable the probe stays `truncated` and all diffs
against it are withheld. A stored history from older probe semantics
is re-baselined,
never diffed (parser-version guard). First sightings are baselines.
`openpulse sweep` wires the live Docker Hub probe with `--projects`
filter and `--out` findings. Discovery acceptance ledger:
`docs/DISCOVERIES.md`.

## Golden scenarios (`tests/test_golden.py`)

Bitnami, iText, minio-archived, Django EOL versions — each asserting
the five product questions. New golden cases go here, not scattered
across suites.

## Try it

```bash
openpulse analyze --project redis
openpulse analyze --project bitnami
openpulse demo-bitnami
openpulse check --watchlist data/fixtures/watchlist_sample.yaml --event data/fixtures/bitnami/event.json
openpulse sweep --projects bitnami,redis
```

## Verdicts (`core/risk/check.py`)

`check_dependency` keeps event-based and correlation causes separate
(`upstream_change` vs `security_vulnerability`) and combines them with
the matrix in METHODOLOGY. AFFECTS_PROJECT never means affected;
NOT_AFFECTED beats RELATED/UNKNOWN; findings and recommendations stay
in their lanes (detection ≠ assessment ≠ recommendation).
