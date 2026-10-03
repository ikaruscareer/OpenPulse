"""CycloneDX SBOM reader — SBOM components become checkable dependencies.

Feeds the existing watchlist path (`core.risk.check.check_dependency`)
without touching matching semantics: components normalize into the
same dep shapes the watchlist uses (`{kind: image, ref}` for
`pkg:docker/...`, `{kind: package, package, ecosystem, version}` for
the four purl types with an unambiguous mapping). Everything else is
skipped and recorded — never guessed.

CycloneDX JSON, spec 1.4/1.5 `components[]` only. No new
dependencies; no network.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

#: purl type -> OSV ecosystem (the casing `analyzers.security_analyst`
#: and the fixtures already use). Only unambiguous mappings live here;
#: an unknown type is a skip-and-record, never a guess.
_PURL_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
}


def _split_purl(purl: str) -> dict[str, str] | None:
    """Parse `pkg:type/namespace/name@version` into parts, or None.

    Follows the Package-URL spec for the segments we need: type,
    namespace (joined when nested), name, version. Qualifiers and
    subpath are ignored — they carry no identity for version checks.
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[len("pkg:") :]
    for sep in ("?", "#"):
        body = body.split(sep, 1)[0]
    if "@" in body:
        body, version = body.rsplit("@", 1)
        if not version:
            return None
    else:
        version = ""
    parts = [p for p in body.split("/") if p]
    if len(parts) < 2:
        return None
    purl_type = parts[0].lower()
    name = parts[-1]
    namespace = "/".join(parts[1:-1])
    if not name:
        return None
    return {"type": purl_type, "namespace": namespace, "name": name, "version": version}


def _dep_from_purl(purl: str) -> tuple[dict[str, Any] | None, str | None]:
    """One purl -> (dep shape, skip reason). Both None = mapped."""
    parts = _split_purl(purl)
    if parts is None:
        return None, f"purl `{purl}` is not a parseable package URL"
    purl_type = parts["type"]
    namespace = urllib.parse.unquote(parts["namespace"])
    name = urllib.parse.unquote(parts["name"])
    if purl_type == "docker":
        # Rebuild the image ref exactly as `docker pull` spells it; a
        # bare name is the Docker Hub `library/` convention. The purl
        # version IS the tag (split_image_ref strips it for artifact
        # equality, version scopes still read it via tag_of).
        ref = f"{namespace}/{name}" if namespace else name
        if parts["version"]:
            # Per purl-spec a docker version is a tag OR a digest. A
            # digest carries a colon and attaches with `@` — spelling
            # it `name:sha256:...` would corrupt tag_of().
            joiner = "@" if ":" in parts["version"] else ":"
            ref = f"{ref}{joiner}{parts['version']}"
        return {"kind": "image", "ref": ref}, None
    ecosystem = _PURL_ECOSYSTEMS.get(purl_type)
    if ecosystem is None:
        return None, f"purl type `{purl_type}` has no unambiguous ecosystem mapping"
    package = f"{namespace}/{name}" if namespace else name
    dep: dict[str, Any] = {"kind": "package", "package": package, "ecosystem": ecosystem}
    if parts["version"]:
        dep["version"] = parts["version"]
    return dep, None


def load_sbom_doc(doc: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate a parsed CycloneDX document into normalized dep entries.

    Returns (dependencies, skipped) — `skipped` records one line per
    component we refused to guess about, with its purl and reason.
    """
    if not isinstance(doc, dict):
        raise ValueError("sbom must be a mapping")
    components = doc.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("sbom needs a non-empty `components` list")
    if not isinstance(doc.get("specVersion"), str) or not doc["specVersion"]:
        raise ValueError("sbom needs a string `specVersion`")
    deps: list[dict[str, Any]] = []
    skipped: list[str] = []
    for i, component in enumerate(components):
        if not isinstance(component, dict):
            skipped.append(f"component #{i}: not a mapping")
            continue
        purl = component.get("purl")
        name = component.get("name")
        label = str(purl if purl is not None else name if name is not None else i)
        if purl is None:
            skipped.append(f"component `{label}`: no purl; name/version fields alone are ambiguous")
            continue
        dep, reason = _dep_from_purl(str(purl))
        if dep is None:
            skipped.append(f"component `{label}`: {reason}")
            continue
        deps.append(dep)
    return deps, skipped


def read_sbom(path: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Load + validate a CycloneDX JSON file from disk."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    return load_sbom_doc(doc)
