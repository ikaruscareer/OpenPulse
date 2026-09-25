# OpenPulse — OSS Change Intelligence

> Track critical OSS announcements you would otherwise miss: EOL, license, distribution, support, ownership, and security-policy changes — with evidence.

**North-star test (MVP):** *“Bitnami made a significant upstream announcement. Did OpenPulse discover it, understand what changed, establish credible evidence, identify affected artifacts/versions, and warn a company that actually depends on them?”*

Traditional SCA covers CVEs. OpenPulse covers the other 12 failure modes:

| Signal | Example | Traditional SCA? |
|---|---|---|
| CVE | Critical vuln | ✅ |
| EOL / EOS | v1.x unmaintained | ⚠️ |
| Abandonment | Maintainer disappears | ⚠️ |
| License change | OSS → restrictive | ⚠️ |
| Distribution change | Registry/image gone | ❌/⚠️ |
| Support change | Community → paid | ❌ |
| Breaking roadmap | Major incompatible | ⚠️ |
| Ownership / Maintainer change | Acquired / leaves | ❌ |
| Repo health collapse | Activity dies | ⚠️ |
| Security-policy change | New disclosure model | ⚠️ |
| AI selection risk | Agent picks obsolete pkg | ❌ |

## Repo layout (OSS core, SaaS stays separate)

```
core/schema/       # v0.1.0 Intelligence Schema (source of truth)
core/events/       # event taxonomy + validation
core/entities/     # canonical Project <-> Package/Artifact resolution
core/evidence/     # evidence graph, confidence
core/risk/         # impact levels (no opaque single score in MVP)
collectors/        # github, osv, nvd, cve, kev, endoflife, registries
analyzers/         # security, lifecycle, license, distribution, support, activity
cli/               # `openpulse` CLI
reports/           # monthly report pipeline
data/              # openpulse100 seed + fixtures (bitnami validation)
docs/              # methodology, architecture, roadmap
```

## Quickstart (v0.1 — Intelligence Core)

```bash
pip install -e ".[dev]"
openpulse validate --event data/fixtures/bitnami/event.json
openpulse pulse --project bitnami --show-signals
pytest -q
```

## Releases

- **v0.1 Intelligence Core:** schema + GitHub/OSV/NVD/CVE/endoflife.date + entity resolution + evidence model
- **v0.2 OSS Pulse:** analysts + confidence + Bitnami validation + CLI/API
- **v0.3 OpenPulse 100:** top-100 watchlist + history + monthly reports
- **v0.4 Early Warning:** customer watchlist + impact engine + email/weekly digest

See `docs/ROADMAP.md` and `docs/METHODOLOGY.md`. SaaS (`openpulse-saas/`) is intentionally **not** in this repo.

## Contributing

Evidence-first: every event needs source URL + fetched date + confidence. See `docs/METHODOLOGY.md`.
License: Apache-2.0.
