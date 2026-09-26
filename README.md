# OpenPulse — OSS Dependency Intelligence

[![ci](https://github.com/ikaruscareer/OpenPulse/actions/workflows/ci.yml/badge.svg)](https://github.com/ikaruscareer/OpenPulse/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![python](https://img.shields.io/badge/python-%3E%3D3.10-blue.svg)

> **Watch what can change underneath your software.**
>
> OpenPulse is OSS Dependency Intelligence that detects upstream changes and warns you before they become problems for your software.
>
> From *"What is happening in open source?"* to *"What is happening to MY software?"*

Most security tools tell you when your dependencies have a vulnerability.
OpenPulse watches for something different: **what can change underneath your software.**
We monitor the open-source ecosystem for end-of-life, support and license changes, registry and distribution changes, ownership changes, breaking changes and other supply-chain signals — then map those changes to the dependencies you actually use.
So instead of another giant list of things happening in open source, OpenPulse answers:

> *"Something changed upstream. Does it affect us?"* — with evidence.

## Know Your Agent. Know Your Dependencies.

OpenPulse is part of an AI-era security story by [Ikarus Career](https://github.com/ikaruscareer):

| Question | Project | Answer |
|---|---|---|
| What can this AI agent do? | [SafeAI](https://github.com/ikaruscareer/SafeAI) — **KYA, Know Your Agent** | Agent capabilities, prompt risks, tool permissions |
| What does the software it creates depend on? | **OpenPulse — KYD, Know Your Dependencies** | Upstream change intelligence mapped to your dependencies |

AI can introduce dependencies faster than humans can review them. OpenPulse helps you understand what those dependencies depend on — and what happens when the ecosystem underneath them changes. **AI writes code fast. OpenPulse watches what that code depends on.**

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

## Intelligence, not aggregation

A report item should demonstrate intelligence, not repeat news. Not:

> Redis — EOL approaching.

But:

> **Redis 7.x — support lifecycle change detected**
> Evidence: official lifecycle information ·
> Potential impact: organisations running affected versions ·
> Recommended attention: migration planning

That is the bar for every OpenPulse event: **what changed, the evidence, who may be affected, and what to investigate.**

## One product, progressively more personal

| Level | Customer question | OpenPulse answer | Status |
|---|---|---|---|
| Free | "What is happening in OSS?" | Monthly OSS Dependency Risk Report over the 100 open-source projects we believe matter most to modern software supply chains | Planned |
| Intelligence | "What is changing in the OSS projects I care about?" | OSS Dependency Intelligence — this repo | 🔨 Building now |
| Early Warning | "What is changing in MY dependencies?" | Dependency Early Warning — watchlist + impact matching | Early preview (`demo-bitnami`) |
| AI-native | "What dependencies is AI introducing?" | AI Supply Chain Governance — Know Your Dependencies | Direction |

## The metric that matters: Early Warning Lead Time

Repositories monitored is a vanity metric. The commercially meaningful one is:

> **Early Warning Lead Time** — time between OpenPulse detecting a material upstream change and that change producing an observable impact on the customer's environment.

The goal: *"We identified an upstream change 47 days before it affected the customer's pipeline."* We will not publish an average until independently measured customer incidents make it defensible — until then, verified case studies (Bitnami first).

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
- **Engineering leaders** — useful lead time before an upstream change becomes a production problem, ranked by action-worthiness instead of CVE counts.
- **Contributors** — a clean, typed Python codebase where every collector and analyst is a pure, tested function. See [Contributing](#contributing).

## Status — working today

- **7 collectors**: GitHub releases, OSV, NVD, MITRE CVE, CISA KEV, endoflife.date, Docker Hub registries. All degrade gracefully (errors become data, never crashes).
- **4 analysts**: Change, Security, Evidence, Report — plus an evidence gate (`UNVERIFIED` can never emit `ACTION`).
- **Change engine**: digest-aware registry observations, local history, observation diffs (`openpulse observe`).
- **Entity resolution**: canonical catalog with PURL builders and Bitnami-namespace rules.
- **CLI**: validate events, run analysts live or offline, observe registries, render per-project Pulse, and replay the Bitnami case end to end.
- **70+ tests**, `ruff` clean, CI green (incl. CodeQL + pip-audit).

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

# 4. Record a registry observation and diff it against history
openpulse observe --namespace bitnami --repo redis

# 5. Run the test suite
pytest -q
```

Expected `demo-bitnami` result: 🚨 on every `bitnami*` ref, ✅ on upstream `redis` / `postgres` / `nginx` — the distinction traditional tooling doesn't make.

## Repo layout

```
core/schema/        # v0.2.0 Intelligence Schema — the source of truth
core/entities/      # catalog + resolve() — canonical Project <-> Package/Artifact
core/evidence/      # policy + provenance + independence — the gate with veto power
core/observations/  # RegistryObservation + local history store + diffs
core/risk/          # match.py — event-vs-dependency impact matching
core/pulse.py       # compute_pulse() — findings/events to 7 facets
collectors/         # github, osv, nvd, cve, kev, endoflife, registries (+base)
analyzers/          # change_analyst, security_analyst, evidence_analyst, report_analyst
cli/                # openpulse CLI (validate, pulse, analyze, observe, demo-bitnami)
data/               # canonical_projects.yaml, openpulse100 seed, bitnami fixture
docs/               # METHODOLOGY, ROADMAP, ANALYSTS, ARCHITECTURE_REVIEW, ...
tests/              # 70+ offline tests (no network in CI)
```

The commercial SaaS layer (`openpulse-saas/`) is intentionally **not** in this repo — the OSS intelligence core stays independent.

## Docs

| Doc | Content |
|---|---|
| `docs/METHODOLOGY.md` | Sources, evidence rules, confidence levels, limitations |
| `docs/ROADMAP.md` | 12-week MVP: v0.1 → v0.4 milestones |
| `docs/ANALYSTS.md` | The four analysts and their rules |
| `docs/ARCHITECTURE_REVIEW.md` | Architecture & security assessment, finding matrix, migration plan |
| `docs/BITNAMI_VALIDATION.md` | The Phase-3 acceptance gate |

## Roadmap

- **v0.1 Intelligence Core** ✅ — schema (now 0.2.0), 7 collectors, entity resolution, evidence model
- **v0.2 OSS Pulse** ✅ — analysts, confidence, Bitnami validation, CLI, and computed Pulse facets (`openpulse pulse` renders worst-wins status + reason per facet)
- **v0.3 OpenPulse 100** 🔨 in progress — seed at 20, catalog at 22 (growth in [#9](https://github.com/ikaruscareer/OpenPulse/issues/9)); next: the monthly report pipeline (`reports/` is still empty)
- **v0.4 Early Warning** — customer watchlist, impact engine, alerts, weekly digest (only matching preview exists)

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

Good first issues are labeled [`good first issue`](https://github.com/ikaruscareer/OpenPulse/labels/good%20first%20issue).

## License

Apache-2.0 — see [LICENSE](LICENSE). Commercial use, modification, and distribution are welcome; the SaaS service layer lives outside this repo.
