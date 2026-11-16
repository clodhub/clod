"""Build-tool declarations per target platform, their merge across a graph, and host probes."""

from __future__ import annotations

import re

from .model import array, bounded_text, canonical, fail, fields

INSTALLERS = {"macos": (("brew", "install"),), "windows": (("winget", "install"),),
              "linux": (("apt-get", "install"), ("sudo", "apt-get", "install"))}
TOOL = re.compile(r"[a-z][a-z0-9.+-]{0,63}")
COMMAND = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
VERSION = re.compile(r"(?<![0-9.])([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?")


def _argv(value, path):
    items = array(value, path, True)
    if len(items) > 64:
        fail("metadata-limit", path)
    for item in items:
        bounded_text(item, path, 512)
    return items


def _install(value, path):
    entry = fields(value, "macos windows linux", path)
    for host, prefixes in INSTALLERS.items():
        argv = entry[host]
        if argv is None:
            continue
        _argv(argv, path + "." + host)
        if not any(tuple(argv[:len(prefix)]) == prefix and len(argv) > len(prefix) for prefix in prefixes):
            fail("toolchain-installer", path + "." + host)
    return entry


def validate_tool(value: object, path: str = "toolchains") -> dict:
    from .foundations import _bounds
    tool = fields(value, "name versionRange probe install manual", path)
    if type(tool["name"]) is not str or not TOOL.fullmatch(tool["name"]):
        fail("toolchain-name", path)
    _bounds(tool["versionRange"])
    probe = _argv(tool["probe"], path + ".probe")
    if not COMMAND.fullmatch(probe[0]):
        fail("toolchain-probe", path + ".probe")
    install = _install(tool["install"], path + ".install")
    if tool["manual"] is not None:
        bounded_text(tool["manual"], path + ".manual", 2048)
    if tool["manual"] is None and all(item is None for item in install.values()):
        fail("toolchain-unavailable", tool["name"])
    return tool


def validate_toolchains(manifest: dict) -> None:
    value = manifest["toolchains"]
    if type(value) is not dict or set(value) != set(manifest["platforms"]):
        fail("toolchain-platforms", "toolchains")
    for platform, tools in value.items():
        for tool in array(tools, "toolchains." + platform):
            validate_tool(tool, "toolchains." + platform)
        if len({tool["name"] for tool in tools}) != len(tools):
            fail("duplicate-value", "toolchains." + platform)
    merge_toolchains([manifest])


def render_range(lower: tuple, upper: tuple | None) -> str:
    text = ">=" + ".".join(map(str, lower))
    return text if upper is None else text + " <" + ".".join(map(str, upper))


def merge_toolchains(manifests: list[dict], targets: list[str] | None = None) -> list[dict]:
    """One requirement per tool name over the given platforms: identical probe, installers and manual text; intersected ranges."""
    from .foundations import _bounds
    merged = {}
    for manifest in manifests:
        for platform, tools in manifest["toolchains"].items():
            if targets is not None and platform not in targets:
                continue
            for tool in tools:
                lower, upper = _bounds(tool["versionRange"])
                definition = canonical({key: tool[key] for key in ("probe", "install", "manual")})
                current = merged.get(tool["name"])
                if current is None:
                    merged[tool["name"]] = current = {"tool": tool, "definition": definition, "lower": lower, "upper": upper,
                                                      "platforms": set(), "packages": set()}
                elif current["definition"] != definition:
                    fail("toolchain-definition-conflict", tool["name"])
                else:
                    current["lower"] = max(current["lower"], lower)
                    current["upper"] = upper if current["upper"] is None else current["upper"] if upper is None else min(current["upper"], upper)
                    if current["upper"] is not None and current["lower"] >= current["upper"]:
                        fail("toolchain-conflict", tool["name"])
                current["platforms"].add(platform)
                current["packages"].add(manifest["identity"]["name"])
    return [{"name": name, "required": render_range(item["lower"], item["upper"]), "lower": item["lower"], "upper": item["upper"],
             "probe": item["tool"]["probe"], "install": item["tool"]["install"], "manual": item["tool"]["manual"],
             "platforms": sorted(item["platforms"]), "packages": sorted(item["packages"])}
            for name, item in sorted(merged.items())]


def probe_version(output: str) -> tuple | None:
    match = VERSION.search(output)
    return None if match is None else tuple(int(part or 0) for part in match.groups())
