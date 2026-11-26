"""CycloneDX 1.6 JSON bill of materials for one stored package archive."""

from __future__ import annotations

from pathlib import Path
import uuid

from .bundle import read_package
from .fetch import CATALOGUE
from .model import DEFAULT_NAMESPACE, PackageRef, canonical, digest, guarded, package_url, parse_package

SPEC_VERSION = "1.6"
SERIAL_NAMESPACE = uuid.UUID("6f1c0a52-3e7d-5b8a-9c41-0d2e8f7a6b13")
# GitHub owners of namespaces other than io.github.<owner>.
NAMESPACE_OWNERS = {DEFAULT_NAMESPACE: "clodhub"}


def repository(name: str) -> str | None:
    """A package's source repository github.com/<owner>/<name>, the owner being its namespace's owner; None when the
    owner is not known here."""
    parts = parse_package(name)
    namespace = parts["namespace"]
    owner = namespace[len("io.github."):] if namespace.startswith("io.github.") else NAMESPACE_OWNERS.get(namespace)
    return None if owner is None else f"https://github.com/{owner}/{parts['name']}"


def references(name: str, kind: str, source: str | None) -> list[dict]:
    """A package's vcs and website (its catalogue page) external references."""
    page = f"{CATALOGUE}/{'recipes' if kind == 'recipe' else 'components'}/{parse_package(name)['name']}"
    return [*([{"type": "vcs", "url": source}] if source is not None else []), {"type": "website", "url": page}]


def entry(name: str, version: str) -> dict:
    """group (the namespace), name and version of a package, with its versioned package URL as purl and bom-ref."""
    parts = parse_package(name)
    return {"bom-ref": package_url(name, version), "group": parts["namespace"], "name": parts["name"], "version": version,
            "purl": package_url(name, version)}


@guarded
def bill_of_materials(ref: PackageRef, store: Path) -> dict:
    component, payloads = read_package(ref, Path(store))
    identity = component["identity"]
    root = package_url(identity["name"], identity["version"])
    files = [{"type": "file", "bom-ref": "file:" + item["path"], "name": item["path"],
              "hashes": [{"alg": "SHA-256", "content": digest(payloads[item["path"]])}]}
             for item in component["files"]]
    libraries = [{"type": "library", **entry(item["name"], item["version"]), "scope": "required",
                  "externalReferences": references(item["name"], "component", repository(item["name"]))}
                 for item in component["dependencies"]]
    upstream = [{"type": "library", "bom-ref": "upstream:" + item["purl"], "name": item["name"],
                 "version": item["version"], "purl": item["purl"], "licenses": [{"expression": item["licence"]}],
                 "externalReferences": [{"type": "vcs", "url": item["repository"]}],
                 "properties": [*([{"name": "clod:upstream:revision", "value": item["revision"]}] if item["revision"] is not None
                                  else [{"name": "clod:upstream:revision-status", "value": "unavailable"}]),
                                {"name": "clod:upstream:delivery", "value": item["delivery"]["kind"]},
                                {"name": "clod:upstream:delivery-details", "value": canonical(item["delivery"]).decode()},
                                *[{"name": "clod:upstream:notice", "value": path} for path in item["notices"]]]}
                for item in component["upstream"]]
    libraries += upstream
    return {
        "bomFormat": "CycloneDX", "specVersion": SPEC_VERSION, "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(SERIAL_NAMESPACE, ref["digest"])),
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "clod"}]},
            "component": {"type": "application" if component["kind"] == "recipe" else "library",
                          **entry(identity["name"], identity["version"]), "licenses": [{"expression": identity["licence"]}],
                          "hashes": [{"alg": "SHA-256", "content": ref["digest"]}],
                          "externalReferences": references(identity["name"], component["kind"],
                                                           component["maintenance"]["repository"])},
        },
        "components": files + libraries,
        "dependencies": [{"ref": root, "dependsOn": [item["bom-ref"] for item in libraries]},
                         *[{"ref": item["bom-ref"]} for item in libraries]],
    }
