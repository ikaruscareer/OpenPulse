"""Provenance helpers — content hashing for reproducible evidence.

Parser changes must not silently make historical evidence
incomparable: every parser output that gets persisted (observations,
normalized records) carries `parser_version` + `content_hash`.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

PARSER_VERSION = "openpulse-parsers/0.2.0"


def hash_content(payload: Any) -> str:
    """Stable sha256 over canonical JSON. `sha256:<hex>`."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
