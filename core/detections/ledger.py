"""Local-first detection ledger - durable per-entity first-detection history.

The ledger closes the gap issue #41 names: sweep findings carry
``first_detected_at`` (diffed against observation history), but
lifecycle and security findings detected in a fresh run have no
persistent memory - a second run cannot tell "detected 90 days ago"
from "seen first now", so warning windows died with the process.

Model (deliberately the same trust treatment as
``core.observations.store`` - atomic writes, per-key locking,
content hashes - NOT a second storage model):

- Layout: ``{root}/{project}/{key}.json`` - one file per detected
  fact, keyed by stable entity identity (project slug + finding
  class + subject + scope), value = earliest detection timestamp +
  content hash of the fact identity.
- Earliest evidence wins: a re-detection never moves ``first_seen``
  later. Clock skew is absorbed the same way: a skewed-later stamp
  cannot overwrite an earlier one; a skewed-earlier stamp IS taken
  (it is indistinguishable from a truthful earlier detection, and
  inventing a correction would violate the "never estimated" rule).
- Writes are atomic (temp file + ``os.replace``) under a per-project
  lock (``O_CREAT|O_EXCL``, stale reclaim after 120s) borrowed from
  the observation store so two simultaneous ``openpulse check`` runs
  cannot interleave half-written ledgers.
- Git-ignored under ``.openpulse/``; safe to delete. A missing or
  corrupt entry means *unknown*, never a fabricated date: deletion
  degrades to current per-run behavior, never to invented dates.

Hash-chain decision: observations chain because each record derives
meaning from its position in history (diffs read the predecessor);
a ledger entry is a standalone earliest-witness record whose
integrity need is met by its own content hash. Chaining would add
verification machinery without changing any decision this system
makes. Absence (or deletion) of entries is indistinguishable from
never-detected, and both mean "no claim" - the tripwire an
observation chain provides has no decision to protect here.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: Same staleness policy as the observation store: a crashed lock
#: holder must not block automation forever.
_LOCK_STALE_SECONDS = 120.0
_LOCK_WAIT_SECONDS = 30.0

#: Finding classes with durable, re-detectable identity. Both
#: lifecycle (endoflife-derived) and security (CVE) findings are
#: covered - per issue #41 each has a stable subject.
LIFECYCLE = "lifecycle"
SECURITY = "security"


def _safe(part: str) -> str:
    """Filesystem-safe path segment. Dots alone (`..`) never survive:
    traversal segments collapse to `_`, hostile values stay inside
    the ledger root."""
    cleaned = "".join(c if c.isalnum() or c in (".", "-", "_") else "_" for c in str(part))
    if cleaned.strip(".") == "":
        return "_"
    return cleaned


def now_iso() -> str:
    """Current UTC time, ISO-8601 with offset. One clock read per call."""
    return datetime.now(timezone.utc).isoformat()


def _project_dir(root: str | Path, project: str) -> Path:
    return Path(root) / _safe(project)


def _key_file(directory: Path, key: str) -> Path:
    return directory / f"{key}.json"


def _lock_path(directory: Path) -> Path:
    return directory / ".ledger-lock"


def fact_content_hash(project: str, finding_class: str, subject: str, scope: list[str]) -> str:
    """SHA-256 over the canonical identity of one detected fact.

    Independent of timestamps and formatting so the same fact from
    different runs (or sources) hashes identically.
    """
    material = json.dumps(
        [str(project), str(finding_class), str(subject), sorted(str(s) for s in scope)],
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def fact_key(project: str, finding_class: str, subject: str, scope: list[str]) -> str:
    """Stable ledger key for one detected fact.

    SHA-256 over the normalized identity terms so the key doubles as
    the (content-derived) filename - a hostile subject string cannot
    forge path segments, and two sources reporting the same CVE or
    lifecycle cycle produce the same key, so a re-report cannot
    split the history.
    """
    terms = [str(project), str(finding_class), str(subject)]
    terms += sorted(str(s).strip().lower() for s in scope)
    return hashlib.sha256("|".join(terms).encode("utf-8")).hexdigest()


@contextlib.contextmanager
def ledger_lock(
    root: str | Path, project: str, wait_seconds: float = _LOCK_WAIT_SECONDS
) -> Iterator[None]:
    """Per-project exclusive lock across load-merge-save.

    Same mechanics as ``core.observations.store.repo_lock``: atomic
    O_CREAT|O_EXCL creation, stale reclaim, TimeoutError (never
    proceed unlocked). Lock files live in the project directory so
    concurrent runs on different projects never serialize.
    """
    directory = _project_dir(root, project)
    directory.mkdir(parents=True, exist_ok=True)
    lock = _lock_path(directory)
    deadline = time.monotonic() + wait_seconds
    fd: int | None = None
    while fd is None:
        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                age = time.time() - lock.stat().st_mtime
            except OSError:
                age = 0.0
            if age > _LOCK_STALE_SECONDS:
                with contextlib.suppress(OSError):
                    lock.unlink()
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError(f"ledger lock busy: {lock}")
            time.sleep(0.05)
    try:
        os.write(fd, f"{os.getpid()}".encode("ascii"))
        yield
    finally:
        os.close(fd)
        with contextlib.suppress(OSError):
            lock.unlink()


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Temp file + os.replace: readers never see a partial entry."""
    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _try_load(path: Path) -> dict[str, Any] | None:
    """One file -> dict, or None when missing/corrupt (never raises)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _parse_moment(value: Any) -> datetime | None:
    """ISO timestamp -> aware datetime; garbage -> None (never estimated)."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def record_detection(
    project: str,
    finding_class: str,
    subject: str,
    scope: list[str] | None = None,
    detected_at: str | None = None,
    root: str | Path = ".openpulse/detections",
) -> dict[str, Any]:
    """Record one detection; return the ledger entry after merge.

    Earliest-wins merge: a re-detection refreshes ``last_seen`` but
    never moves ``first_seen`` later. ``recorded_now`` tells the
    caller whether this call created the entry (first detection).
    """
    scope = list(scope or [])
    stamp = detected_at or now_iso()
    directory = _project_dir(root, project)
    key = fact_key(project, finding_class, subject, scope)
    path = _key_file(directory, key)
    with ledger_lock(root, project):
        existing = _try_load(path)
        if existing is None:
            entry = {
                "project": str(project),
                "finding_class": str(finding_class),
                "subject": str(subject),
                "scope": sorted(str(s) for s in scope),
                "first_seen": stamp,
                "last_seen": stamp,
                "content_hash": fact_content_hash(project, finding_class, subject, scope),
            }
            _write_atomic(path, entry)
            return {**entry, "recorded_now": True}
        first_prev = _parse_moment(existing.get("first_seen"))
        incoming = _parse_moment(stamp)
        if first_prev is None:
            first_seen = stamp if incoming is not None else str(existing.get("first_seen") or stamp)
        elif incoming is not None and incoming < first_prev:
            # Strictly earlier trustworthy stamp wins - includes the
            # clock-skew case; never corrected, never estimated.
            first_seen = stamp
        else:
            first_seen = str(existing.get("first_seen") or stamp)
        last_prev = _parse_moment(existing.get("last_seen"))
        last_seen = str(existing.get("last_seen") or stamp)
        if last_prev is None or (incoming is not None and incoming > last_prev):
            last_seen = stamp
        entry = {
            "project": str(project),
            "finding_class": str(finding_class),
            "subject": str(subject),
            "scope": sorted(str(s) for s in scope),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "content_hash": fact_content_hash(project, finding_class, subject, scope),
        }
        _write_atomic(path, entry)
    return {**entry, "recorded_now": False}


def first_seen(
    project: str,
    finding_class: str,
    subject: str,
    scope: list[str] | None = None,
    root: str | Path = ".openpulse/detections",
) -> str | None:
    """Earliest recorded detection of one fact, or None (never a guess)."""
    directory = _project_dir(root, project)
    path = _key_file(directory, fact_key(project, finding_class, subject, list(scope or [])))
    entry = _try_load(path)
    if entry is None:
        return None
    value = entry.get("first_seen")
    return str(value) if value else None
