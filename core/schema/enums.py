"""OpenPulse Intelligence Schema v0.3.0 — enums (frozen since Phase 0)."""

from enum import Enum


class EventType(str, Enum):
    SECURITY = "SECURITY"
    EOL = "EOL"
    EOS = "EOS"
    LICENSE_CHANGE = "LICENSE_CHANGE"
    SUPPORT_CHANGE = "SUPPORT_CHANGE"
    DISTRIBUTION_CHANGE = "DISTRIBUTION_CHANGE"
    REGISTRY_CHANGE = "REGISTRY_CHANGE"
    OWNERSHIP_CHANGE = "OWNERSHIP_CHANGE"
    MAINTAINER_CHANGE = "MAINTAINER_CHANGE"
    DEPRECATION = "DEPRECATION"
    BREAKING_CHANGE = "BREAKING_CHANGE"
    MAJOR_RELEASE = "MAJOR_RELEASE"
    PROJECT_ARCHIVED = "PROJECT_ARCHIVED"
    OTHER_CRITICAL = "OTHER_CRITICAL"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"  # official source, e.g. vendor announcement
    CORROBORATED = "CORROBORATED"  # 2+ independent sources
    EMERGING = "EMERGING"  # single credible secondary source
    UNVERIFIED = "UNVERIFIED"  # single weak source / rumor


class Impact(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    WATCH = "WATCH"
    REVIEW = "REVIEW"
    ACTION = "ACTION"
    CRITICAL = "CRITICAL"


# Pulse signal facets — never collapse to a single opaque score in MVP.
PULSE_FACETS = [
    "activity",
    "security",
    "lifecycle",
    "support",
    "license",
    "distribution",
    "popularity",
]
