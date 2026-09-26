# Bitnami validation — Phase 3 gate (do not skip to SaaS if this fails)
Flow: announcement -> collector -> Change Analyst -> Distribution/Support event -> Evidence Analyst -> OSSEvent -> Pulse -> alert/report.
Required output for `data/fixtures/bitnami/event.json` (replace placeholders with real sources):
- announcement_date, effective_date, affected artifacts (e.g. docker.io/bitnami/*, bitnamicharts/*), affected versions
- source URLs, excerpts, confidence (CONFIRMED needs official Bitnami/Broadcom URL), recommended investigation
Run: `openpulse validate --event data/fixtures/bitnami/event.json`
Acceptance: validates against core/schema v0.2.0 + 2 evidences, one official.
