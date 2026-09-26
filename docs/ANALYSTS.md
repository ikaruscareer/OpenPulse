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

Not yet: `PROJECT_ARCHIVED` needs repo metadata (add a repo-meta
collector input before claiming it).

## Security Analyst (`analyzers/security_analyst.py`)

Merges OSV + NVD + CVE + KEV entries by CVE ID: source list, max CVSS,
KEV flag, reference union. Impact: KEV → `CRITICAL`; score ≥ 9 →
`ACTION`; ≥ 7 → `REVIEW`; else `WATCH`.

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
