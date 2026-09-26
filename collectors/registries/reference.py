"""Reference probe sets — named, documented cases demonstrating the generic engine.

The generic acquisition path (`RegistryCollector.collect`) knows
nothing about Bitnami. This module keeps the Bitnami distribution
probe set as an explicit *reference rule input*: same generic
`check_image` calls, curated list, used by the CLI and the acceptance
tests to rehearse the north-star scenario.
"""

from __future__ import annotations

from typing import Any

BITNAMI_DISTRIBUTION_PROBES = [
    ("bitnami", "redis"),
    ("bitnamilegacy", "redis"),
    ("bitnamisecure", "redis"),
]


def bitnami_distribution_probes(collector: Any) -> list[dict[str, Any]]:
    """Three generic probes that together reveal the Bitnami pattern."""
    return [
        collector.check_image(namespace, repo) for namespace, repo in BITNAMI_DISTRIBUTION_PROBES
    ]
