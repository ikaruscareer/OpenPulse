# OpenPulse — OSS Dependency Intelligence

[![ci](https://github.com/ikaruscareer/OpenPulse/actions/workflows/ci.yml/badge.svg)](https://github.com/ikaruscareer/OpenPulse/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![python](https://img.shields.io/badge/python-%3E%3D3.10-blue.svg)

> **Watch what can change underneath your software.**
>
> OpenPulse is OSS Dependency Intelligence that detects upstream changes and warns you before they become problems for your software.
>
> From *"What is happening in open source?"* to *"What is happening to MY software?"*

<img width="1024" height="1024" alt="OpenPulse" src="https://github.com/user-attachments/assets/f7e4b9c9-6f7c-49fa-8950-a5d1594829b7" />

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

<img width="1024" height="1024" alt="The problem we solve 2" src="https://github.com/user-attachments/assets/be884e68-0482-4954-aba1-907286d258c6" />

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

<img width="1024" height="1024" alt="What is changing in MY dependencies2" src="https://github.com/user-attachments/assets/c2930ba2-0866-4de4-b6b5-b028014b8026" />


| Level | Customer question | OpenPulse answer | Status |
|---|---|---|---|
| Free | "What is happening in OSS?" | Monthly OSS Dependency Risk Report — first edition: [September 2026](reports/2026-09-openpulse.md) (100 projects, every item sourced) | ✅ Shipped |
| Intelligence | "What is changing in the OSS projects I care about?" | OSS Dependency Intelligence — this repo | 🔨 Building now |
| Early Warning | "What is changing in MY dependencies?" | Dependency Early Warning — watchlist + impact matching (`openpulse check`, [scheduled runs](docs/SCHEDULED_CHECKS.md)) | Early preview |
| AI-native | "What dependencies is AI introducing?" | AI Supply Chain Governance — Know Your Dependencies | Direction |

## The metric that matters: Early Warning Lead Time

Repositories monitored is a vanity metric. The commercially meaningful one is:

> **Early Warning Lead Time** — time between OpenPulse detecting a material upstream change and that change producing an observable impact on the customer's environment.

"Detecting" means first trustworthy detection (`first_detected_at`), never the latest re-observation; unknown first detection means no lead-time claim. The goal: *"We identified an upstream change 47 days before it affected the customer's pipeline."* We will not publish an average until independently measured customer incidents make it defensible — until then, verified case studies (Bitnami first).

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

<img width="1024" height="1024" alt="EarlyWarningLeadTime1" src="https://github.com/user-attachments/assets/04ebb832-2ae7-4e59-8e34-dba9ec0552dd" />

Principles that make it different:

- **Evidence-first.** Every event carries source URLs, announcement/effective dates, and a confidence level (`CONFIRMED` / `CORROBORATED` / `EMERGING` / `UNVERIFIED`). No black boxes.
- **No mystery scores.** Instead of `Risk: 72`, you see per-facet signals — activity, security, lifecycle, support, license, distribution, popularity.
- **Impact attribution.** `docker.io/bitnami/redis` and `docker.io/redis` resolve to *different* canonical projects, so a Bitnami distribution event alerts Bitnami users without false-alarming upstream Redis users.
- **Honest verdicts.** `RELATED ≠ AFFECTED`, `AFFECTS_PROJECT ≠ AFFECTS_VERSION`, `UNKNOWN ≠ NOT_AFFECTED` — same project never means affected, and cleared dependencies say `NOT_AFFECTED`, not "no match".
- **Analysts, not one giant agent.** Four small, deterministic, testable analysts. The evidence gate has veto power.

## What OpenPulse is not

| Existing category | Asks | OpenPulse instead asks |
|---|---|---|
| Lifecycle database (endoflife.date) | When does software reach EOL? | What is changing upstream, and does it affect what I depend on? |
| Vulnerability database (OSV/NVD) | Is this package vulnerable? | Same question, plus: is the match identity-strong or keyword-only? |
| SCA / scanners | What dependency risks exist in my code? | What changed upstream since we last looked? |
| Dependency updater | Should I upgrade? | What breaks if I don't — and by when? |

endoflife.date is one of our sources, not our definition: lifecycle data
enters as raw signals, gets correlated into stories, and is gated like
everything else. We do not compete on EOL record counts.

## Who it's for — and what you get

- **Software security teams / AppSec** — extend vulnerability management beyond CVEs: EOL software, exploited-in-the-wild (CISA KEV) correlation, license and support-model drift, with evidence you can paste into a risk register.
- **Platform / DevOps engineers** — early warning before registry deletions, tag removals, and chart breakages hit pipelines. The Bitnami case is the reference implementation.
- **Engineering leaders** — useful lead time before an upstream change becomes a production problem, ranked by action-worthiness instead of CVE counts.
- **Contributors** — a clean, typed Python codebase where every collector and analyst is a pure, tested function. See [Contributing](#contributing).

## Status — working today

- **7 collectors**: GitHub releases, OSV, NVD, MITRE CVE, CISA KEV, endoflife.date, Docker Hub registries. All degrade gracefully (errors become data, never crashes).
- **4 analysts**: Change, Security, Evidence, Report — plus an evidence gate (`UNVERIFIED` can never emit `ACTION`).
- **Change engine**: tamper-evident digest-aware registry observations
  (hash-chained local history, frozen sealed records, per-repo locks),
  observation diffs (`openpulse observe`), catalog sweep with
  first-detection tracking (`openpulse sweep`, `report --with-sweep`).
- **Entity resolution**: canonical catalog with PURL builders,
  Bitnami-namespace rules, and identity trust (VERIFIED /
  REVIEW_REQUIRED / UNVERIFIED — untrusted mappings cap verdicts at
  EMERGING).
- **CLI**: validate events, run analysts live or offline, observe registries, sweep the catalog, render per-project Pulse, generate monthly reports, check watchlists and CycloneDX SBOMs (digest + webhook), and replay the Bitnami case end to end. Webhook delivery enforces an SSRF policy (https by default; `--webhook-allow-http` opts in).
- **290+ tests**, `ruff` clean, CI green (Linux + Windows, incl. CodeQL + pip-audit, lock-drift check, deterministic SBOM, secret tripwire).

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

# 5. Generate the monthly report (offline bundles or live collectors)
openpulse report --month 2026-09 --raw-bundle-dir path/to/bundles

# 6. Check your watchlist against an event (Early Warning preview)
openpulse check --watchlist data/fixtures/watchlist_sample.yaml --event data/fixtures/bitnami/event.json

   # or feed a CycloneDX SBOM (composable with a watchlist)
openpulse check --sbom data/fixtures/sbom/cyclonedx.json --event data/fixtures/bitnami/event.json

# 7. Run the test suite
pytest -q
```

Expected `demo-bitnami` result: 🚨 on every `bitnami*` ref, ✅ on upstream `redis` / `postgres` / `nginx` — the distinction traditional tooling doesn't make.

## Outputs — what you get

Every month OpenPulse produces two decision-support briefings (see
`reports/` for real examples). They read like security intelligence,
not database exports: ranked findings with evidence confidence,
scope, timing, and a recommended investigation — never raw CVE/EOL
dumps, never claims about your environment without a watchlist.

![October 2026 monthly intelligence briefing]
<img width="1552" height="832" alt="OpenPulse_Report_Summary" src="https://github.com/user-attachments/assets/a1bcbf0d-c842-4c84-9060-5e4095fb2ba5" />

**Monthly intelligence** (`openpulse report --month YYYY-MM [--with-sweep]`):

- Executive Summary — material changes, attention items, upcoming
  warnings, non-lifecycle discoveries, evidence confidence, data gaps.
- Top Changes — deterministic evidence-aware ranking (non-lifecycle
  first, never raw counts). Every card shows announcement, effective,
  first-detected and last-verified dates, freshness status, evidence
  confidence, scope, and a recommended investigation.
- Discovery of the Month — the strongest non-lifecycle story, broken
  out as WHAT / WHY / HOW DETECTED / AFFECTED / NOT AFFECTED /
  EVIDENCE / ANNOUNCED / DETECTION / WARNING WINDOW.
- Changes Requiring Attention, Upcoming Changes (detection lead
  times from first trustworthy detection only), Changes by Category,
  Evidence Quality, What OpenPulse Watches, Methodology.
- What OpenPulse Added This Month — value demonstrated from the
  report's own data, ending in the public → watchlist → impact →
  warning progression.
- For Your Environment (public/customer boundary) and an appendix
  with historical findings, every current finding, sources, and gaps.
- Machine-readable companion: `report --metadata-out` writes a
  `.meta.json` sidecar (report ID, period, version, freshness policy,
  coverage, status/category counts) for web frontends.

**Lifecycle posture** (`openpulse lifecycle-report --month YYYY-MM`):

- Executive Summary, Upcoming Deadlines table (soonest first),
  Recently Ended, Coverage Gaps (NO-DATA is a limitation, never OK),
  Top Planning Items, and the full coverage matrix as an appendix.

## Repo layout

```
core/schema/        # v0.4.0 Intelligence Schema — the source of truth
core/entities/      # catalog + resolve() — canonical Project <-> Package/Artifact
core/evidence/      # policy + provenance + independence — the gate with veto power
core/observations/  # RegistryObservation + local history store + diffs
core/risk/          # match.py — event-vs-dependency impact matching
core/pulse.py       # compute_pulse() — findings/events to 7 facets
collectors/         # github, osv, nvd, cve, kev, endoflife, registries (+base)
analyzers/          # change_analyst, security_analyst, evidence_analyst, report_analyst
cli/                # openpulse CLI (validate, pulse, analyze, observe, report, check, demo-bitnami)
reports/            # generate.py — monthly ranked markdown reports
data/               # canonical_projects.yaml, openpulse100 seed, bitnami fixture
docs/               # METHODOLOGY, ROADMAP, ANALYSTS, ARCHITECTURE_REVIEW, ...
tests/              # 330+ offline tests (no network in CI)
```

The commercial SaaS layer (`openpulse-saas/`) is intentionally **not** in this repo — the OSS intelligence core stays independent.

## Docs

| Doc | Content |
|---|---|
| `docs/METHODOLOGY.md` | Sources, evidence rules, confidence levels, limitations |
| `docs/ROADMAP.md` | M1–M8 milestones, principles, metrics, Next 90 Days |
| `docs/ANALYSTS.md` | The four analysts and their rules |
| `docs/ARCHITECTURE_REVIEW.md` | Architecture & security assessment, finding matrix, migration plan |
| `docs/BITNAMI_VALIDATION.md` | The Phase-3 acceptance gate |

## Roadmap

M1 Trusted Intelligence Engine ✅ done (now maintenance) → M2 Real
Upstream Change Discovery 🔨 active / highest priority → M3 Report
Product ✅ briefing format live → M4 Intelligence Benchmark 🔨 4 of
12+ scenarios formalized → M5 Customer Dependency Intelligence (next
major milestone; watchlist CLI is the preview) → M6 Early Warning
SaaS → M7 Intelligence Network → M8 AI Dependency Intelligence
(futures). Full sequence, principles, and metrics: [`docs/ROADMAP.md`](docs/ROADMAP.md)
(reset 2026-10-02; the old v0.x phase plan is retired).

Deliberately *not* on the roadmap: becoming an EOL database, another
generic SCA, collector-count vanity, AI reasoning in the trusted
decision path. They don't prove the core hypothesis.

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

## Contributors

Thank you to everyone moving OpenPulse forward:

- **[@wufangyong973](https://github.com/wufangyong973)** — grew the canonical project catalog toward OpenPulse 100 (Airflow, Spark, MinIO, Celery, ZooKeeper) in [#11](https://github.com/ikaruscareer/OpenPulse/pull/11). First of many.
- **[@DYNOSuprovo](https://github.com/DYNOSuprovo)** — ASCII-marker fallback for `openpulse check` on non-UTF-8 consoles in [#14](https://github.com/ikaruscareer/OpenPulse/pull/14) (merged via [#17](https://github.com/ikaruscareer/OpenPulse/pull/17)).
- **[@choksi2212](https://github.com/choksi2212)** — six good-first-issue contributions: Unicode fallback for every CLI command ([#21](https://github.com/ikaruscareer/OpenPulse/pull/21)), OSV live wiring ([#22](https://github.com/ikaruscareer/OpenPulse/pull/22)), catalog identity metadata for forks/renames/ecosystem mappings ([#23](https://github.com/ikaruscareer/OpenPulse/pull/23)), intelligence-semantics documentation ([#24](https://github.com/ikaruscareer/OpenPulse/pull/24)), SBOM artifact upload ([#25](https://github.com/ikaruscareer/OpenPulse/pull/25)), and the Windows CI runner ([#26](https://github.com/ikaruscareer/OpenPulse/pull/26)).

## License

Apache-2.0 — see [LICENSE](LICENSE). Commercial use, modification, and distribution are welcome; the SaaS service layer lives outside this repo.
