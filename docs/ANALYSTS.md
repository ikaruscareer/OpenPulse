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
KEV flag, reference union — plus a `relationship` label:

- `AFFECTS_PACKAGE` — identity evidence exists (OSV query scope, NVD CPE
  vendor/product match, or CNA affected-product match).
- `RELATED` — the CVE exists but nothing ties it to this project
  (keyword-only NVD hits land here and cap at `REVIEW`).
- `UNKNOWN` — no score and no identity signal.

Impact: KEV exact/strong + identity → `CRITICAL`; KEV alone →
`REVIEW` (exploited, relation unconfirmed); identity + score ≥ 9 →
`ACTION`; ≥ 7 → `REVIEW`; else `WATCH`. Weak KEV matches never set
`in_kev`.

## Evidence Analyst (`analyzers/evidence_analyst.py`)

`assess_confidence`: official source → `CONFIRMED`; ≥2 distinct
sources → `CORROBORATED`; single secondary → `EMERGING`; else
`UNVERIFIED`. `assemble_event` builds the OSSEvent and returns
`(event, gate_violations)` — callers must handle violations.

## Report Analyst (`analyzers/report_analyst.py`)

`render_event_md`, `render_finding_md`, `render_digest`. Every claim
traces to an evidence URL or named collector output.

## Try it

```bash
openpulse analyze --project redis
openpulse analyze --project bitnami
openpulse demo-bitnami
```
