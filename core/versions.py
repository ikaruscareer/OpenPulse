"""Version applicability — explicit, conservative, dependency-free.

Evaluates OSV range events (introduced/fixed/last_affected) and NVD
CPE range attributes (versionStart/EndIncluding/Excluding) plus exact
versions. Returns True/False, or None when applicability cannot be
determined — uncertainty never becomes a stronger claim.

Not a universal solver: numeric-core comparison with documented
best-effort prerelease handling. Ecosystems with exotic schemes fall
back to None rather than a guessed answer.
"""

from __future__ import annotations

import re
from typing import Any

_PRE = {
    "dev": -4,
    "a": -3,
    "alpha": -3,
    "b": -2,
    "beta": -2,
    "rc": -1,
    "c": -1,
    "pre": -1,
    "preview": -1,
}


def _key(version: str) -> tuple[tuple[int, ...], int] | None:
    """(numeric core, prerelease rank); None when no digits at all."""
    tokens = re.findall(r"\d+|[a-z]+", str(version).lower())
    nums: list[int] = []
    for token in tokens:
        if token.isdigit():
            nums.append(int(token))
        else:
            break
    if not nums:
        return None
    rank = 0
    for token in tokens[len(nums) :]:
        if not token.isdigit() and token in _PRE:
            rank = _PRE[token]
            break
    return (tuple(nums), rank)


def compare(a: str, b: str) -> int | None:
    """-1/0/1, or None when either side is unparseable."""
    ka, kb = _key(a), _key(b)
    if ka is None or kb is None:
        return None
    (na, ra), (nb, rb) = ka, kb
    length = max(len(na), len(nb))
    na += (0,) * (length - len(na))
    nb += (0,) * (length - len(nb))
    if na != nb:
        return -1 if na < nb else 1
    if ra != rb:
        return -1 if ra < rb else 1
    return 0


def satisfies(version: str, constraint: dict[str, Any]) -> bool | None:
    """One range constraint (OSV or CPE style) against a version."""
    if not constraint:
        return None
    lower: list[tuple[str, bool]] = []  # (bound, inclusive)
    upper: list[tuple[str, bool]] = []
    if "introduced" in constraint:
        introduced = constraint["introduced"]
        if introduced not in ("0", "0.0", ""):
            lower.append((introduced, True))
    if "versionStartIncluding" in constraint:
        lower.append((constraint["versionStartIncluding"], True))
    if "versionStartExcluding" in constraint:
        lower.append((constraint["versionStartExcluding"], False))
    if "fixed" in constraint:
        upper.append((constraint["fixed"], False))
    if "last_affected" in constraint:
        upper.append((constraint["last_affected"], True))
    if "versionEndIncluding" in constraint:
        upper.append((constraint["versionEndIncluding"], True))
    if "versionEndExcluding" in constraint:
        upper.append((constraint["versionEndExcluding"], False))
    if "exact" in constraint:
        result = compare(version, constraint["exact"])
        return result == 0 if result is not None else None
    if not lower and not upper:
        return None
    for bound, inclusive in lower:
        result = compare(version, bound)
        if result is None:
            return None
        if result < 0 or (result == 0 and not inclusive):
            return False
    for bound, inclusive in upper:
        result = compare(version, bound)
        if result is None:
            return None
        if result > 0 or (result == 0 and not inclusive):
            return False
    return True


def osv_applicable(version: str | None, affected: dict[str, Any]) -> bool | None:
    """OSV affected entry vs a deployed version."""
    if not version:
        return None
    for known in affected.get("versions", []) or []:
        if compare(version, str(known)) == 0:
            return True
    ranges = affected.get("ranges", []) or []
    if not ranges:
        return None
    undecided = False
    for rng in ranges:
        constraint: dict[str, Any] = {}
        for event in rng.get("events", []) or []:
            for key, value in event.items():
                if key == "introduced" and value in ("0", "0.0", ""):
                    continue
                constraint[key] = value
        result = satisfies(version, constraint)
        if result is True:
            return True
        if result is None:
            undecided = True
    return None if undecided else False


def cpe_applicable(version: str | None, cpe: dict[str, Any]) -> bool | None:
    """NVD CPE match entry vs a deployed version."""
    if cpe.get("vulnerable") is False:
        return False
    if not version:
        return None
    constraint = {
        k: cpe[k]
        for k in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
        if k in cpe
    }
    if constraint:
        return satisfies(version, constraint)
    exact = _cpe_version(cpe.get("criteria", ""))
    if exact and exact not in ("*", "-"):
        result = compare(version, exact)
        return result == 0 if result is not None else None
    return None


def _cpe_version(criteria: str) -> str:
    parts = str(criteria).split(":")
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[5]
    return ""
