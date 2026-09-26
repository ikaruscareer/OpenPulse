# OpenPulse — OSS Change Intelligence

[![ci](https://github.com/ikaruscareer/OpenPulse/actions/workflows/ci.yml/badge.svg)](https://github.com/ikaruscareer/OpenPulse/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![python](https://img.shields.io/badge/python-%3E%3D3.10-blue.svg)

> Your SCA tells you about CVEs. **Who tells you the registry your production images come from is being deleted?**

OpenPulse tracks the critical open-source changes that vulnerability scanners miss — end-of-life, license shifts, distribution and support-model changes, ownership moves — and turns them into **evidence-backed events** mapped to the dependencies you actually run.

## The problem we solve

In July 2025, Bitnami announced that effective **28 August 2025** its public `docker.io/bitnami` catalog would stop publishing versioned images: existing tags move to an unmaintained `bitnamilegacy` archive, the mainline goes `latest`-only community tier, and production use requires a Bitnami Secure Images subscription. Miss that one announcement and CI/CD pipelines, Helm releases, and production pulls break — with no CVE ever filed, so no scanner fires.

Bitnami is the pattern, not the exception:

| Signal | Example | Covered by traditional SCA? |
|---|---|---|
| CVE | Critical vulnerability | ✅ |
| EOL / EOS | `Node.js 18` unmaintained, support window ends | ⚠️ partial |
| License change | OSS → restrictive/commercial | ⚠️ partial |
| Distribution change | Registry/image deleted, tags moved | ❌ |
| Support change | Community → paid subscription | ❌ |
| Ownership / maintainer change | Project acquired, maintainer leaves | ❌ |
| Repo health collapse | Activity dies, releases stop | ⚠️ partial |
| Breaking roadmap | Major incompatible release | ⚠️ partial |
| AI selection risk | Coding agent picks an obsolete package | ❌ |

Every row above is a production incident waiting for a team that only watches CVEs.

## What OpenPulse does

```
Upstream world                      OpenPulse engine                    You
GitHub releases ─┐                    ┌───────────────┐
OSV / NVD / CVE ─┼─ collectors ─────▶ │ Change Analyst │── findings ──┐
CISA KEV ────────┤   (7 sources)      │ Security Analyst│             ▼
endoflife.date ──┤                    │ Evidence Analyst│── gate ─▶ OSSEvent ─▶ are YOU affected?
Docker Hub ──────┘                    │ Report Analyst │   (confidence + impact + evidence)
                                      └───────────────┘
```

Principles that make it different:

- **Evidence-first.** Every event carries source URLs, announcement/effective dates, and a confidence level (`CONFIRMED` / `CORROBORATED` / `EMERGING` / `UNVERIFIED`). No black boxes.
- **No mystery scores.** Instead of `Risk: 72`, you see per-facet signals — activity, security, lifecycle, support, license, distribution, popularity.
- **Impact attribution.** `docker.io/bitnami/redis` and `docker.io/redis` resolve to *different* canonical projects, so a Bitnami distribution event alerts Bitnami users without false-alarming upstream Redis users.
- **Analysts, not one giant agent.** Four small, deterministic, testable analysts. The evidence gate has veto power.

## Who it's for — and what you get

- **Software security teams / AppSec** — extend vulnerability management beyond CVEs: EOL software, exploited-in-the-wild (CISA KEV) correlation, license and support-model drift, with evidence you can paste into a risk register.
- **Platform / DevOps engineers** — early warning before registry deletions, tag removals, and chart breakages hit pipelines. The Bitnami case is the reference implementation.
- **Engineering leaders** — a monthly intelligence report over the projects you depend on, ranked by action-worthiness instead of CVE counts.
- **Contributors** — a clean, typed Python codebase where every collector and analyst is a pure, tested function. See [Contributing](#contributing).

## Status — working today

- **7 collectors**: GitHub releases, OSV, NVD, MITRE CVE, CISA KEV, endoflife.date, Docker Hub registries. All degrade gracefully (errors become data, never crashes).
- **4 analysts**: Change, Security, Evidence, Report — plus an evidence gate (`UNVERIFIED` can never emit `ACTION`).
- **Entity resolution**: canonical catalog with PURL builders and Bitnami-namespace rules.
- **CLI**: validate events, run analysts live or offline, and replay the Bitnami case end to end.
- **30+ tests**, `ruff` clean, CI green.

## Quickstart

```bash
pip install -e ".[dev]"

# 1. Validate the Bitnami reference event (CONFIRMED/ACTION, 3 official evidences)
openpulse validate --event data/fixtures/bitnami/event.json --strict

# 2. Replay the north-star scenario offline:
#    Bitnami event -> evidence gate -> which sample dependencies are affected -> report
openpulse demo-bitnami

# 3. Run live analysts against a real project (network; degrades gracefully)
openpulse analyze --project redis
openpulse analyze --project bitnami

# 4. Run the test suite
pytest -q
```

Expected `demo-bitnami` result: 🚨 on every `bitnami*` ref, ✅ on upstream `redis` / `postgres` / `nginx` — the distinction traditional tooling doesn't make.

## Repo layout

```
core/schema/        # v0.1.0 Intelligence Schema — the source of truth
core/entities/      # catalog + resolve() — canonical Project <-> Package/Artifact
core/evidence/      # policy.py — the gate with veto power
core/risk/          # match.py — event-vs-dependency impact matching
collectors/         # github, osv, nvd, cve, kev, endoflife, registries (+base)
analyzers/          # change_analyst, security_analyst, evidence_analyst, report_analyst
cli/                # openpulse CLI (validate, pulse, analyze, demo-bitnami)
data/               # canonical_projects.yaml, openpulse100 seed, bitnami fixture
docs/               # METHODOLOGY, ROADMAP, ANALYSTS, BITNAMI_VALIDATION
tests/              # 30+ offline tests (no network in CI)
```

The commercial SaaS layer (`openpulse-saas/`) is intentionally **not** in this repo — the OSS intelligence core stays independent.

## Docs

| Doc | Content |
|---|---|
| `docs/METHODOLOGY.md` | Sources, evidence rules, confidence levels, limitations |
| `docs/ROADMAP.md` | 12-week MVP: v0.1 → v0.4 milestones |
| `docs/ANALYSTS.md` | The four analysts and their rules |
| `docs/BITNAMI_VALIDATION.md` | The Phase-3 acceptance gate |

## Roadmap

- **v0.1 Intelligence Core** ✅ — schema, 7 collectors, entity resolution, evidence model
- **v0.2 OSS Pulse** 🔨 in progress — analysts, confidence, Bitnami validation, CLI
- **v0.3 OpenPulse 100** — curated watchlist, history, monthly reports
- **v0.4 Early Warning** — customer watchlist, impact engine, alerts, weekly digest

Deliberately *not* in the MVP: full SAST/SCA duplication, auto-remediation, CI/CD apps, SSO/RBAC, mobile. They don't prove the core hypothesis.

## Contributing

Evidence-first means contributions are easy to review:

1. **Add a collector** — subclass `collectors/base.py:9`, add `parse_*` pure functions, offline fixture tests. Network failures must return `error` dicts, never raise.
2. **Add an analyst rule** — extend the relevant `analyzers/*_analyst.py`, document the rule in `docs/ANALYSTS.md`, cover it with tests.
3. **Add a project** — append to `data/canonical_projects.yaml` (lowercase, tag-free aliases; tests enforce hygiene).
4. Every event needs: source URL + fetch date + confidence. `UNVERIFIED` can never be `ACTION`.

```bash
ruff check .   # must pass
pytest -q      # must pass (offline)
```

## License

Apache-2.0 — see [LICENSE](LICENSE). Commercial use, modification, and distribution are welcome; the SaaS service layer lives outside this repo.
