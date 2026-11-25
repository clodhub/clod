"""CycloneDX 1.6 JSON bill of materials for one stored package archive."""

from __future__ import annotations

from pathlib import Path
import uuid

from .bundle import read_package
from .model import SCOPE, PackageRef, canonical, digest, guarded

SPEC_VERSION = "1.6"
SERIAL_NAMESPACE = uuid.UUID("6f1c0a52-3e7d-5b8a-9c41-0d2e8f7a6b13")


def repository(name: str, kind: str) -> str:
    """GitHub repository of a package: clodhub/<name>, with a -recipe suffix for recipes."""
    short = name.split("/", 1)[1]
    return short + "-recipe" if kind == "recipe" else short


def purl(name: str, version: str, kind: str = "component") -> str:
    return f"pkg:github/{SCOPE}/{repository(name, kind)}@v{version}"


@guarded
def bill_of_materials(ref: PackageRef, store: Path) -> dict:
    component, payloads = read_package(ref, Path(store))
    identity = component["identity"]
    root = purl(identity["name"], identity["version"], component["kind"])
    files = [{"type": "file", "bom-ref": "file:" + item["path"], "name": item["path"],
              "hashes": [{"alg": "SHA-256", "content": digest(payloads[item["path"]])}]}
             for item in component["files"]]
    libraries = [{"type": "library", "bom-ref": purl(item["name"], item["version"]), "group": SCOPE,
                  "name": item["name"].split("/", 1)[1], "version": item["version"], "purl": purl(item["name"], item["version"]),
                  "scope": "required"}
                 for item in component["dependencies"]]
    upstream = [{"type": "library", "bom-ref": "upstream:" + item["purl"], "name": item["name"],
                 "version": item["version"], "purl": item["purl"], "licenses": [{"expression": item["licence"]}],
                 "externalReferences": [{"type": "vcs", "url": item["repository"]}],
                 "properties": [*([{"name": "aepm:upstream:revision", "value": item["revision"]}] if item["revision"] is not None
                                  else [{"name": "aepm:upstream:revision-status", "value": "unavailable"}]),
                                {"name": "aepm:upstream:delivery", "value": item["delivery"]["kind"]},
                                {"name": "aepm:upstream:delivery-details", "value": canonical(item["delivery"]).decode()},
                                *[{"name": "aepm:upstream:notice", "value": path} for path in item["notices"]]]}
                for item in component["upstream"]]
    libraries += upstream
    return {
        "bomFormat": "CycloneDX", "specVersion": SPEC_VERSION, "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(SERIAL_NAMESPACE, ref["digest"])),
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "aepm"}]},
            "component": {"type": "application" if component["kind"] == "recipe" else "library", "bom-ref": root,
                          "group": SCOPE, "name": identity["name"].split("/", 1)[1], "version": identity["version"],
                          "purl": root, "licenses": [{"expression": identity["licence"]}],
                          "hashes": [{"alg": "SHA-256", "content": ref["digest"]}]},
        },
        "components": files + libraries,
        "dependencies": [{"ref": root, "dependsOn": [item["bom-ref"] for item in libraries]},
                         *[{"ref": item["bom-ref"]} for item in libraries]],
    }
