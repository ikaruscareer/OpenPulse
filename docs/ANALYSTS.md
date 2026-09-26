# Analysts — Phase 2 (pure functions, deterministic, no network)

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
- Missing repo → `REGISTRY_CHANGE` / `REVIEW`.
- Archived GitHub repo (via `fetch_repo_meta`) → `PROJECT_ARCHIVED` / `ACTION`.
- Observation diffs (`analyze_diffs`): `tag_disappeared` → `REVIEW`,
  `tag_appeared`/`tag_digest_changed`/`latest_moved` → `WATCH`,
  `repo_missing` → `ACTION`, `repo_restored` → `INFORMATIONAL`.

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

CPE matching is normalized-exact only: token overlap (`spring` vs
`spring-shell`) is never identity. Impact: KEV + AFFECTS →
`CRITICAL`; KEV alone → `REVIEW`; AFFECTS_VERSION ≥ 7 / AFFECTS_PACKAGE
≥ 9 → `ACTION`. Weak KEV matches never set `in_kev`. Findings name
their match method (`osv_package[+version_range]`, `cpe_version_range`,
`cpe_vendor_product`, `keyword_only`); `keyword_only` never yields
`AFFECTS_VERSION`/`AFFECTS_ARTIFACT`.

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
recency (archived → action, >365d stale → review); popularity stays
informational until a real methodology lands. Rendered by
`openpulse pulse --project <slug> [--raw-bundle file]`.

## Report Analyst (`analyzers/report_analyst.py`)

`render_event_md`, `render_finding_md`, `render_digest`. Every claim
traces to an evidence URL or named collector output.

## Try it

```bash
openpulse analyze --project redis
openpulse analyze --project bitnami
openpulse demo-bitnami
```
