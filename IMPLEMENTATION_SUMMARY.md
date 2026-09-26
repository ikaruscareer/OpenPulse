# IMPLEMENTATION_SUMMARY — Security Architecture Re-Implementation

## Files changed

- New: `core/versions.py`, `core/claims.py`, `core/entities/identity.py`,
  `core/observations/base.py`, `collectors/errors.py`,
  `collectors/registries/reference.py`, `tests/test_versions.py`,
  `tests/test_boundary.py`, `requirements.lock`,
  `IMPLEMENTATION_PLAN.md`, this file.
- Extended: `analyzers/security_analyst.py` (relationships, versions,
  KEV chain, severity/urgency/actions), `analyzers/report_analyst.py`
  (security block, contradicts marking), `analyzers/evidence_analyst.py`
  (claims passthrough), `analyzers/change_analyst.py` (archived rule
  kept, Bitnami documented as reference), `core/schema/models.py`
  (0.3.0: claims, attribution), `core/evidence/policy.py`
  (claim/conflict/provenance rules), `core/observations/registry.py`
  (base class, observation hashes), `core/observations/store.py`
  (`first_observed`), `core/risk/match.py` (relationship labels),
  collectors (structured errors, OSV ranges, NVD range attrs, digests,
  generic acquisition), `cli/main.py` (`--version`, `observe`),
  `.github/workflows/ci.yml` (SHA pins), docs (see below).

## Architectural decisions

- Token overlap is never identity: normalized-exact product equality.
- Version truth values are tri-state (`True`/`False`/`None`); `None`
  caps conclusions instead of strengthening them.
- Claims are flat per-event objects, not a graph; contradicting
  evidence is stored, rendered, and blocking for strong actions.
- Observations share one metadata envelope; Bitnami probes moved out
  of generic acquisition into a named reference module.
- No new runtime dependencies; no database; no LLM; no risk score.

## Security improvements

Conservative CPE/CNA identity, explicit version applicability,
match_method audit trail, KEV decision chain (exact→applicability→
urgency), claim↔evidence gate linkage, conflict blocking, provenance
requirements for strong impacts, redacted collector errors, bounded
CLI input, pinned actions, lockfile, 10-test boundary contract.

## Tests added

`test_versions.py` (4), `test_boundary.py` (12: the 10 spec tests +
Django range + identity separation), plus extended analyst coverage.
31 → 86 total, all offline.

## Known limitations

- Version comparison is numeric best-effort (exotic schemes → unknown).
- Popularity facet still informational; OSV live wiring stays with
  contributor issue #10; no CPE catalog (parsed, not curated).
- `requirements.lock` is dev/test reproducibility, not pip hash-locking.

## Verification commands

```
ruff check .            # All checks passed
ruff format --check .   # clean
pytest -q               # 86 passed
openpulse validate --event data/fixtures/bitnami/event.json --strict  # gate: PASS
openpulse demo-bitnami  # exit 0; 3x 🚨 bitnami*, 3x ✅ upstream/other
```
