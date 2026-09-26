# IMPLEMENTATION_PLAN — Security Architecture Re-Implementation

## Current architecture (at `0f8717e`, 70 tests green)

Collectors (7, structured errors) → pure-function analysts (Change,
Security, Evidence, Report) → evidence gate (veto) → OSSEvent 0.2.0 →
CLI (validate, pulse, analyze, observe, demo-bitnami). Plus: catalog +
namespace-aware resolution, CPE extraction, KEV match strength,
digest-aware RegistryObservation + JSON history + diffs, archived-repo
detection, bounded CLI input, Pulse facets, CodeQL + pip-audit +
Dependabot.

## Confirmed weaknesses (validated against code, not assumed)

1. CPE matching is token-overlap (`tokens & hay`) — `spring` matches
   `spring-shell` (`analyzers/security_analyst.py`).
2. No version applicability: OSV ranges dropped by `parse_vulns`, NVD
   `versionStart/End*` dropped, no `AFFECTS_VERSION` path exists.
3. No claim objects; gate checks evidence *existence*, not
   claim↔evidence support; no conflict state (only contradicts-only
   rejection).
4. Registry `collect("bitnami")` special-case lives in generic
   acquisition; `Change` lacks observation linkage.
5. `match_artifact` has no relationship label; no `AFFECTS_ARTIFACT`
   relationship anywhere.
6. Security findings lack severity/urgency/recommended-action and
   `match_method`/`identity_evidence` records.
7. No lockfile; actions float on tags.

## Proposed model changes (all additive/backward compatible)

- `core/versions.py` (new): version parse/compare + OSV-event and
  CPE-range applicability → `bool | None`.
- OSV parse keeps `affected[]` (package, ecosystem, ranges, fixed).
  NVD parse keeps `versionStart/End*` per CPE.
- Findings gain `relationship`, `match_method`, `identity_evidence`,
  `severity`, `urgency`, `recommended_action`, `affected_package`,
  `affected_version`, `fixed_version`, `kev_match`.
- `core/claims.py` (new): `Claim{id, type, subject, statement,
  evidence_refs}` + `claims_from_finding()`. `OSSEvent.claims: []` and
  `OSSEvent.attribution` (project/package/artifact/version, optional).
  Schema 0.2.0 → 0.3.0.
- Gate gains: claim-support rule, UNRESOLVED-conflict blocks
  ACTION/CRITICAL, high-impact provenance rule.
- `core/observations/base.py`: shared metadata; `Change` gains
  `previous_hash`/`current_hash`; GitHub/Lifecycle observation models.
- `core/entities/identity.py`: typed `IdentityRef`s; match results gain
  `relationship` (`AFFECTS_ARTIFACT` on triple equality).
- `requirements.lock`; actions pinned to SHAs.

## Migration strategy (§27 order)

Phase 1 correlation → Phase 2 claims/gate → Phase 3 identity →
Phase 4 observations → Phase 5 hardening. Existing tests updated only
where semantics intentionally tighten (documented); new behavior lands
in `test_versions.py`, `test_boundary.py` (the 10 spec tests), plus
extensions to trust/analyst suites.

## Compatibility risks

- `correlate()` gains optional `project` keys (`version`, `package`,
  `ecosystem`); old calls behave as before except CPE matching, which
  intentionally tightens (token overlap no longer sufficient).
- OSSEvent 0.3.0 adds optional fields only; 0.2.0 documents validate.
- `RegistryCollector.collect()` becomes fully generic; Bitnami probes
  move to `reference_bitnami_distribution()` used by the CLI.
