"""Evidence independence — 2 sources != 2 independent sources.

A republished announcement (Source B quoting Source A) must not count
as corroboration. Groups evidences by source family, folding
`derived_from` chains into the group they derive from:

    independent_count() = distinct groups, not distinct names.

Callers pass evidence dicts (raw) or Evidence/Source models — both
shapes are read defensively.
"""

from __future__ import annotations

from typing import Any


def _source_of(evidence: Any) -> dict[str, Any]:
    if isinstance(evidence, dict):
        source = evidence.get("source", {})
        return source if isinstance(source, dict) else {}
    source = getattr(evidence, "source", None)
    if source is None:
        return {}
    if isinstance(source, dict):
        return source
    return {
        "name": getattr(source, "name", None),
        "family": getattr(source, "family", None),
        "derived_from": getattr(source, "derived_from", None),
    }


def _field(source: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = source.get(key)
        if value:
            return value
    return None


def independent_count(evidences: list[Any]) -> int:
    """Distinct independent groups after folding derived_from chains."""
    keys = [_field(_source_of(e), "family", "name") or "?" for e in evidences]
    by_name = {}
    for e, key in zip(evidences, keys):
        name = _field(_source_of(e), "name")
        if name:
            by_name.setdefault(str(name), key)
    groups = set()
    for e, key in zip(evidences, keys):
        derived = _field(_source_of(e), "derived_from")
        if derived and str(derived) in by_name:
            groups.add(by_name[str(derived)])
        else:
            groups.add(key)
    return len(groups)
