# Roadmap — 12-week MVP (distilled from proposal)

Status as of the security re-implementation: schema 0.3.0,
86 tests, claims + version applicability + observation core landed.

## Done

- [x] **Phase 0 (W1) — Schema freeze.** `core/schema/` v0.3.0 (was v0.1.0;
  additive provenance/independence/relation fields). Event taxonomy,
  confidence, impact levels frozen.
- [x] **Phase 1 (W2–4) — Collectors.** All 7: github (+repo metadata),
  osv, nvd (+CPE criteria), cve, kev (+match strength), endoflife.date,
  registries (+digests). Structured `CollectorError`s, graceful degrade.
- [x] **Phase 2 (W3–5) — Analysts.** Change, Security, Evidence, Report
  as pure functions + evidence gate with veto power. No giant agent.
- [x] **Phase 3 (W5) — Bitnami validation.** Reference event
  (`CONFIRMED`/`ACTION`, 3 official evidences), `demo-bitnami`
  rehearsal, permanent acceptance test (`tests/test_acceptance.py`).
  Gate passed — SaaS track unblocked in principle, not started.
- [x] **Phase 4 (W5–7) — OSS Pulse facets.** `core/pulse.py` maps
  findings+events to 7 facets (worst-wins + reason); `pulse` CLI
  renders computed status live or from offline bundles.
- [x] **Trust hardening (arch review).** Provenance fields, independent
  corroboration, NVD relationships + caps, KEV strength, observation
  history + diffs, `CollectorError` redaction, CLI input bounds,
  `PROJECT_ARCHIVED`, CI (least privilege, CodeQL, pip-audit),
  Dependabot.
- [x] **Security re-implementation.** Conservative CPE identity,
  explicit version applicability (`core/versions.py`), claim objects +
  support/conflict gate rules, generalized observations, typed identity
  refs, `AFFECTS_ARTIFACT` matching, explainable security rendering,
  SHA-pinned actions, `requirements.lock`, 10-test boundary contract.
  See `IMPLEMENTATION_PLAN.md` / `IMPLEMENTATION_SUMMARY.md`.

## In progress

- [ ] **Phase 5 remainder — OpenPulse 100 seed.** Catalog at 22 entries
  (was 10). Growth toward 100 continues in #9.
- [ ] **Phase 6 (W7–8) — Monthly report pipeline.** `reports/` is empty.

## Not started

- **Phase 7–10 (W8–12)** — website, follows/newsletter, customer
  watchlist, impact engine (only `core/risk/match.py` preview exists).

## Non-goals W1–12 (unchanged)

Full SAST/SCA duplication, auto-remediation, CI/CD apps, SSO/RBAC,
mobile, opaque risk scores. They don't prove the core hypothesis.

## Next phase — v0.3: monthly report pipeline (recommended)

Goal: the first real "OSS Dependency Risk Report" artifact — the Free
level of the README product ladder.

1. **Report generator** (`reports/`, pure + offline tests): seed +
   facets + top findings → ranked markdown (action-worthy / watch /
   informational, every item with evidence). Reuse `report_analyst`
   rendering; golden test on frozen bundles.
2. **Seed growth** (#9, contributor-friendly): 22 → 40 entries so the
   first report has breadth beyond databases/messaging.
3. **Popularity methodology**: replace the informational placeholder
   with a documented rule (e.g. catalog tier + repo stars bands) before
   the report leans on it.

Then **v0.4**: customer watchlist file format + `openpulse check`
(generalizing `demo-bitnami`'s hardcoded list) toward Dependency
Early Warning.
