# OpenPulse — Architecture & Security Review (2026-09-26)

Evaluation of the implementation at `f5f5c70` against the 2026-09
Architecture & Security Re-Evaluation. Each finding was validated
against the actual code before any remediation was chosen. Only
remediations that preserve simplicity, determinism, and
offline-testability were implemented.

## A. Executive assessment

1. **Is the current architecture sound enough to continue? Yes.**
   Layering (collectors → analysts → evidence gate → events → reports/CLI),
   pure-function analysts, offline fixture tests (31 passing), and the
   Bitnami identity-separation regression test are the right foundation.
   The gaps are trust-depth gaps (provenance, independence, correlation
   strength, observation history), not structural mistakes.
2. **Top 5 architectural risks:**
   - Keyword-only NVD correlation can assert ACTION on unrelated CVEs (§6).
   - No observation history — every "change" is a snapshot heuristic (§8–10, §17).
   - Tags treated as identities; no digest persistence (§9).
   - Corroboration counts names, not independence (§3).
   - Raw exception strings flow through collector outputs (§13).
3. **Must fix before production-grade:** 2, 3 (above) + KEV weak-match
   promotion (§7) + claim/evidence linkage (§4) + CLI input bounds (§16)
   + supply-chain minimum (permissions, audit, updates) (§14–15).
4. **Can safely wait:** impact-field split (§11 — impact+confidence+advice
   already separate concerns), AI governance layer (§18), SQLite/server
   history (§17 — JSON store suffices), full identity graph with forks/CPE
   catalog (§5 — namespace rule + regression test hold the line).

## B. Finding matrix

| Finding | Status | Sev | Evidence | Remediation (implemented) | Release |
|---|---|---|---|---|---|
| P0 Source integrity & provenance | CONFIRMED | P0 | `Source` has name/url/authority/fetched_at only; no content hash, parser version, acquisition method (`core/schema/models.py:14`) | Optional `family`, `derived_from`, `acquisition_method`, `parser_version`, `content_hash` on `Source`; `relation` on `Evidence`; `hash_content()` helper; schema → 0.2.0 | next |
| P0 Evidence independence | CONFIRMED | P0 | `assess_confidence` counts distinct names; Bitnami fixture's 3 sources span 2 same-org families (`analyzers/evidence_analyst.py:26`) | `independent_count()` excludes `derived_from` chains, groups by family; gate keeps name rule (backward compatible), family count reported | next |
| P0 Claim→Evidence | CONFIRMED | P0 | `gate()` checks existence/authority/counts, never support linkage (`core/evidence/policy.py:30`) | `Evidence.relation` (`supports`\|`context`\|`contradicts`); gate rejects `contradicts`-only support; findings carry claim text into `assemble_event` | next |
| P0 Entity identity | PARTIALLY ADDRESSED | P0 | Catalog + namespace rule + `docker.io/redis` ≠ `docker.io/bitnami/redis` regression test exist; no forks/renames/CPE | Keep; NVD CPE vendor/product now feeds correlation instead of a CPE catalog | next |
| P0 NVD accuracy | CONFIRMED | P0 | `parse_cves` drops `configurations`; keyword-only; score ≥ 9 → ACTION (`collectors/nvd/collector.py:38`, `analyzers/security_analyst.py:76`) | Parse CPE criteria; `relationship` per CVE (`AFFECTS_*` vs `RELATED`); keyword-only caps at REVIEW | next |
| P0 KEV matching | PARTIALLY ADDRESSED | P0 | Merge-by-CVE-ID is exact (sound); `filter_catalog` substring is broad (`collectors/kev/collector.py:25`) | Token-set matching + `match_strength` (exact/strong/weak); weak never sets `in_kev` | next |
| P0 Registry intel | CONFIRMED | P0 | `collect("bitnami")` special-case; snapshot heuristics (`collectors/registries/docker.py:56`, `analyzers/change_analyst.py`) | Generic `RegistryObservation` + JSON history store + `diff_observations`; Bitnami kept as fixture/test | next |
| P0 Tag mutability | CONFIRMED | P0 | No digest captured or persisted | Capture per-tag digests from Hub API; store tag→digest; `latest_moved`/`tag_digest_changed` diffs | next |
| P1 Change intel | CONFIRMED | P1 | Snapshot interpretation, no previous-observation compare | Diff-driven findings (`tag_appeared/disappeared`, `digest_changed`, `repo_missing`) feed the Change Analyst | next |
| P1 Impact semantics | PARTIALLY ADDRESSED | P1 | `impact` + `confidence` separate; `ADVICE` mapping in report analyst | No model split (deferred — current split + advice is the explainable answer) | later |
| P1 Lifecycle | PARTIALLY ADDRESSED | P1 | EOL/EOS + 3 dates good; `PROJECT_ARCHIVED` admitted incomplete (`docs/ANALYSTS.md`) | GitHub repo metadata (`archived`, `pushed_at`) → `PROJECT_ARCHIVED` rule | next |
| P1 Error leakage | CONFIRMED | P1 | `str(e)` in 7 collectors (e.g. `collectors/nvd/collector.py:84`) | `CollectorError` struct (category/retryable/status/safe_message); raw detail stays local-only | next |
| P1 Deps/build | CONFIRMED | P1 | `pydantic>=2.0` etc., no audit/updates (`pyproject.toml:12`) | `pip-audit` CI job + Dependabot (pip + actions); lockfile deferred | next |
| P1 CI/CD | PARTIALLY ADDRESSED | P1 | Green but root permissions, floating tags, no scanning (`.github/workflows/ci.yml`) | `permissions: contents: read`, CodeQL job, `pip-audit` job | next |
| P1 CLI input | CONFIRMED | P1 | Bare `open()`/`json.load`, raw tracebacks (`cli/main.py:21`) | 1 MiB size guard, clean JSON/schema error messages + exit codes, bounded counts | next |
| P1 History | NOT PRESENT | P1 | No store exists | `.openpulse/observations/*.json` local-first store (no server/DB) | next |
| AI governance (§18) | NOT APPLICABLE | P3 | — | Prerequisites (identity + observations) already underway; no layer built | later |
| OSS/SaaS boundary (§19) | SOUND | — | `openpulse-saas/` excluded; README states it | Unchanged | — |

## C. Target architecture

```
Sources (GitHub, OSV, NVD, CVE, KEV, endoflife.date, registries)
  ↓ Acquisition (collectors; CollectorError on failure, never raise)
Observations (immutable, hashed: RegistryObservation, RepoObservation, …)
  ↓ Normalization (parsers with parser_version recorded)
Identity (catalog + resolve(): slug for every ref; bitnami/* stays separate)
  ↓ Diff (observation vs previous observation → Change list)
Claims (finding text: what changed, where)
  ↓ Evidence correlation (sources + families + derived_from; independent count)
Policy (gate: confidence/impact coupling, support linkage, artifacts, dates)
  ↓ Intelligence (OSSEvent 0.2.0 with provenance + relation fields)
Reports / CLI / CI
```

Layers: acquisition never interprets; observations are content-hashed
facts; identity precedes correlation; diffs precede impact; policy
vetoes; reports render only what evidence supports.

## D. Data-model changes (this release, all backward compatible)

- `Source` += `family`, `derived_from`, `acquisition_method`,
  `parser_version`, `content_hash` (all optional).
- `Evidence` += `relation` (`supports` default, `context`, `contradicts`).
- New: `CollectorError{source, category, retryable, status_code, safe_message}`,
  `RegistryObservation{registry, namespace, repository, observed_at, tags{tag: digest}, tag_count, content_hash, parser_version}`,
  `Change{type, repository, tag, previous, current, observed_at}`.
- `SCHEMA_VERSION` 0.1.0 → 0.2.0 (additive only).

Deferred: impact split, knowledge graph, SQLite, CPE catalog.

## E. Migration plan (implemented as: Trust → Correlation → Change → Hygiene)

- **Trust Foundation** (this release): `collectors/errors.py`; provenance
  fields + `hash_content`; independence counting; CLI guards.
  Tests: error shape, hash stability, derived-source counting, malformed/
  oversized CLI input. Accept: ruff + pytest green, no `str(e)` leaks.
- **Security correlation** (this release): NVD CPE parse + relationship +
  cap; KEV token matching + strength. Tests: false-positive fixtures
  (keyword hit without CPE → RELATED/≤REVIEW; exact CVE KEV → CRITICAL).
  Accept: Bitnami non-security behavior unchanged.
- **Change Engine** (this release): observation store + diff + digests +
  `observe` CLI + diff-driven analyst rules. Tests: tag appeared/
  disappeared/digest-changed/latest-moved fixtures. Accept: Bitnami
  snapshot rule still passes; diffs reproduce from fixtures.
- **Product integration** (this release): `PROJECT_ARCHIVED` rule,
  acceptance test (`tests/test_acceptance.py` answering the §23
  questionnaire), CI permissions + CodeQL + pip-audit + Dependabot.
  Accept: CI green; demo-bitnami output unchanged.

## Risks introduced by this plan

- Schema 0.2.0 requires consumers to tolerate new optional fields
  (mitigated: additions are optional with defaults, so old documents
  still validate and old readers ignore unknown fields).
- KEV/NVD behavior changes could surprise: mitigated by explicit
  `relationship`/`match_strength` labels in every finding.
- Local observation store creates files under `.openpulse/` (git-ignored,
  documented).

## Build next (≤5 initiatives)

1. **Trust Foundation** — structured errors, provenance fields, independent
   corroboration, CLI input bounds.
2. **Security correlation correctness** — CPE-aware NVD relationships with
   caps; exact/strong/weak KEV matching.
3. **Registry Change Engine** — generic observations, digest-aware diffs,
   local history, `observe` CLI.
4. **Claim linkage + lifecycle completion** — evidence relations,
   `PROJECT_ARCHIVED`, §23 acceptance test as permanent regression.
5. **Supply-chain hygiene** — CI least privilege, CodeQL, pip-audit,
   Dependabot.
