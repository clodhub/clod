"""Update channels: what each channel offers an installed application, and the next design it leads to."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import urllib.parse

from .model import AepmError, PACKAGE_VERSION, advisory, fail, guarded, preview, version_key


def published_versions(package: str, origin: str) -> dict[str, dict]:
    """Every listed version of a package with its release `{channel, fixes}`, from the catalogue's version view. A listed
    channel that the version's form does not give is refused."""
    from .fetch import _json
    short = urllib.parse.quote(package.split("/", 1)[1])
    for kind in ("components", "recipes"):
        value = _json(f"{origin.rstrip('/')}/api/{kind}/{short}/latest")
        if value is not None:
            if value.get("name") != package or type(value.get("versions")) is not list:
                fail("catalogue-identity", package)
            found = {}
            for item in value["versions"]:
                if type(item) is not dict or type(item.get("version")) is not str or not PACKAGE_VERSION.fullmatch(item["version"]):
                    fail("invalid-response", package + ".versions")
                fixes = item.get("fixes")
                if item.get("channel") != channel_of(item["version"]) or type(fixes) is not list:
                    fail("release-channel", f"{package}@{item['version']}")
                for fix in fixes:
                    advisory(fix, "versions.fixes")
                if bool(fixes) != (item["channel"] == "security"):
                    fail("release-channel", f"{package}@{item['version']}")
                found[item["version"]] = {"channel": item["channel"], "fixes": list(fixes)}
            return dict(sorted(found.items(), key=lambda pair: version_key(pair[0])))
    fail("unknown-package", package)


def channel_of(number: str) -> str:
    return "preview" if preview(number) else "features" if version_key(number)[2] == 0 else "security"


def newest(installed: str, versions: list[str], channel: str) -> str | None:
    """The newest version above `installed` that `channel` offers: `security` on the installed MAJOR.MINOR line only,
    `features` releases with patch 0, `preview` those and previews."""
    current = version_key(installed)
    allowed = {"security": ("security",), "features": ("features",), "preview": ("features", "preview")}[channel]
    offered = [number for number in versions if version_key(number) > current and channel_of(number) in allowed
               and (channel != "security" or version_key(number)[:2] == current[:2])]
    return max(offered, key=version_key) if offered else None


def _release(store: Path, package: str, number: str, origin: str, listed: dict) -> dict:
    """The fetched package's manifest, refused unless its release is the one the catalogue lists."""
    from .bundle import read_package
    from .fetch import fetch
    result = fetch(store, [(package, number)], origin=origin)[0]
    manifest, _ = read_package({"name": package, "version": number, "digest": result["digest"]}, store)
    if manifest["release"] != listed:
        fail("release-channel", f"{package}@{number}")
    return manifest


def _installed(definition: dict) -> list[tuple[str, str]]:
    return [(definition["recipe"]["name"], definition["recipe"]["version"])] + [(item["name"], item["version"]) for item in definition["components"]]


@guarded
def outdated(root: Path, origin: str) -> list[dict]:
    """Per installed package: its line, the application's policy, and what each channel offers, from the catalogue's
    version lists alone."""
    from .application import read_assembly, validate_definition
    from .io import load
    read_assembly(root)
    definition = validate_definition(load(Path(root) / ".aepm/definition.json"))
    result = []
    for package, installed in _installed(definition):
        versions = published_versions(package, origin)
        offers = {channel: newest(installed, list(versions), channel) for channel in ("security", "features", "preview")}
        security = None
        if offers["security"] is not None:
            security = {"version": offers["security"], "fixes": versions[offers["security"]]["fixes"]}
        key = version_key(installed)
        result.append({"name": package, "installed": installed, "line": f"{key[0]}.{key[1]}", "policy": definition["updatePolicy"],
                       "security": security,
                       "features": {"version": offers["features"]} if offers["features"] else None,
                       "preview": {"version": offers["preview"]} if offers["preview"] else None})
    return result


@guarded
def next_definition(root: Path, channel: str, store: Path, origin: str) -> dict:
    """The design an update on `channel` installs, with every package it needs fetched into the store."""
    from .application import read_assembly, validate_definition
    from .fetch import fetch
    from .io import load
    read_assembly(root)
    current = validate_definition(load(Path(root) / ".aepm/definition.json"))
    if current["updatePolicy"][channel] == "hold":
        fail("channel-held", channel)
    if channel == "security":
        nxt, moved = deepcopy(current), False
        for item in [nxt["recipe"], *nxt["components"]]:
            versions = published_versions(item["name"], origin)
            offered = newest(item["version"], list(versions), "security")
            if offered is not None:
                _release(store, item["name"], offered, origin, versions[offered])
                item["version"], moved = offered, True
        if not moved:
            fail("no-update", channel)
        fetch(store, _installed(nxt), with_dependencies=True, origin=origin)
        return validate_definition(nxt)
    recipe = current["recipe"]["name"]
    versions = published_versions(recipe, origin)
    offered = newest(current["recipe"]["version"], list(versions), channel)
    if offered is None:
        fail("no-update", channel)
    _release(store, recipe, offered, origin, versions[offered])
    substitutes = {slot: (item["component"], item["version"]) for slot, item in current.get("selections", {}).items()
                   if type(item) is dict and item.get("reason") == "substituted"}
    fetch(store, [(recipe, offered), *substitutes.values()], with_dependencies=True, origin=origin)
    from .recipe import World, evaluate
    world = World.from_store(recipe, offered, store, substitutes)
    result = evaluate(world, current.get("answers", {}), current["id"])
    if not result["ok"]:
        unfit = sorted({error["path"].split(":", 1)[0] for error in result["errors"] if error["code"] == "unfit"} & set(substitutes))
        if unfit:
            fail("substitute-unfit", ",".join(unfit))
        raise AepmError(result["errors"][0]["code"], result["errors"][0]["path"], detail={"errors": result["errors"]})
    design = result["design"]
    design["updatePolicy"] = deepcopy(current["updatePolicy"])
    return validate_definition(design)
