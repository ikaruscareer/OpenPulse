"""Local-first observation history — portable JSON, no server or database.

Layout: {root}/{registry}/{namespace}/{repository}/{timestamp}.json
Filenames sort chronologically, so "previous observation" is the
latest file before the current run. The store directory
(`.openpulse/`) is git-ignored and safe to delete: history rebuilds
from new observations (first sighting after a wipe is a baseline).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def _safe(part: str) -> str:
    return "".join(c if c.isalnum() or c in (".", "-", "_") else "_" for c in part)


def repo_dir(root: str | Path, registry: str, namespace: str, repository: str) -> Path:
    return Path(root) / _safe(registry) / _safe(namespace) / _safe(repository)


def save_observation(obs: dict[str, Any], root: str | Path = ".openpulse/observations") -> Path:
    """Persist one observation dict. Returns the file path."""
    observed = obs.get("observed_at") or datetime.now().isoformat()
    stamp = str(observed).replace(":", "").replace("-", "").replace("+0000", "Z")
    stamp = "".join(c if c.isalnum() or c in ("T", "Z", ".") else "" for c in stamp)
    directory = repo_dir(
        root,
        str(obs.get("registry", "?")),
        str(obs.get("namespace", "?")),
        str(obs.get("repository", "?")),
    )
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{stamp}.json"
    path.write_text(json.dumps(obs, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path


def list_observations(
    registry: str, namespace: str, repository: str, root: str | Path = ".openpulse/observations"
) -> list[Path]:
    directory = repo_dir(root, registry, namespace, repository)
    if not directory.is_dir():
        return []
    return sorted(directory.glob("*.json"))


def load_previous(
    registry: str, namespace: str, repository: str, root: str | Path = ".openpulse/observations"
) -> dict[str, Any] | None:
    """Latest stored observation, if any."""
    files = list_observations(registry, namespace, repository, root)
    if not files:
        return None
    return json.loads(files[-1].read_text(encoding="utf-8"))


def first_observed(
    registry: str, namespace: str, repository: str, root: str | Path = ".openpulse/observations"
) -> dict[str, Any] | None:
    """Earliest stored observation, if any."""
    files = list_observations(registry, namespace, repository, root)
    if not files:
        return None
    return json.loads(files[0].read_text(encoding="utf-8"))
