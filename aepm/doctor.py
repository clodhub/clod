"""Check this host for the build tools a design's selected packages declare, and install missing ones on request."""

from __future__ import annotations

from pathlib import Path
import platform
import shlex
import subprocess
import sys

from .model import AepmError, fail
from .toolchains import merge_toolchains, probe_version


def host_os() -> str:
    if sys.platform == "darwin":
        return "macos"
    if sys.platform == "win32":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    fail("unsupported-host", "doctor")


def find(name: str) -> str | None:
    from .host_tools import host_tool
    found = host_tool(name)
    return None if found is None else str(found)


def run_probe(argv: list[str]) -> tuple[int | None, str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=60, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None, ""
    return result.returncode, result.stdout + "\n" + result.stderr


def run_install(argv: list[str]) -> int | None:
    """Run an installer with this terminal's input; its output goes to standard error."""
    try:
        descriptor = sys.stderr.fileno()
    except (AttributeError, OSError, ValueError):
        descriptor = None
    try:
        if descriptor is not None:
            return subprocess.run(argv, stdout=descriptor, stderr=descriptor).returncode
        result = subprocess.run(argv, capture_output=True, text=True, errors="replace")
    except (OSError, ValueError):
        return None
    sys.stderr.write(result.stdout + result.stderr)
    return result.returncode


def selected_graph(recipe: str, version: str, store: Path, answers: dict) -> tuple[list[str], list[dict]]:
    """The design's targets and the manifests of every package in its locked graph."""
    from .application import requirements, validate_definition
    from .bundle import read_package, resolve
    from .foundations import selected_targets, validate_graph
    from .model import canonical, digest
    from .recipe import World, evaluate
    store = Path(store)
    world = World.from_store(recipe, version, store)
    result = evaluate(world, answers)
    if not result["ok"]:
        raise Refused(result["errors"])
    definition = validate_definition(result["design"])
    lock = resolve(requirements(definition), store / "catalogue.json", definition["id"], digest(canonical(definition)))
    manifests = [read_package({key: ref[key] for key in ("name", "version", "digest")}, store)[0] for ref in lock["packages"]]
    targets = selected_targets(world.application, definition.get("answers", {}))
    validate_graph(manifests, targets)
    return targets, manifests


class Refused(AepmError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__("design-refused", "answers")


def probe(tool: dict, host: str, which=find, runner=run_probe) -> dict:
    record = {"name": tool["name"], "required": tool["required"], "platforms": tool["platforms"], "found": None, "version": None,
              "status": "missing", "install": tool["install"][host], "manual": tool["manual"]}
    executable = which(tool["probe"][0])
    if executable is None:
        return record
    record["found"] = executable
    code, output = runner([executable, *tool["probe"][1:]])
    found = probe_version(output) if code == 0 else None
    record["version"] = None if found is None else ".".join(map(str, found))
    ok = found is not None and tool["lower"] <= found and (tool["upper"] is None or found < tool["upper"])
    record["status"] = "ok" if ok else "wrong-version"
    return record


def doctor(recipe: str, version: str, store: Path, answers: dict, *, install: bool = False, host: str | None = None,
           which=find, runner=run_probe, installer=run_install, announce=None) -> dict:
    host = host or host_os()
    targets, manifests = selected_graph(recipe, version, store, answers)
    tools = merge_toolchains(manifests, targets)
    records = [probe(tool, host, which, runner) for tool in tools]
    report = {"host": {"os": host, "architecture": platform.machine()}, "targets": targets, "tools": records}
    if install:
        announce = announce or (lambda line: print(line, file=sys.stderr, flush=True))
        attempts = []
        for record in records:
            if record["status"] != "missing" or record["install"] is None:
                continue
            announce("$ " + (subprocess.list2cmdline(record["install"]) if host == "windows" else shlex.join(record["install"])))
            attempts.append({"name": record["name"], "argv": record["install"], "exitCode": installer(record["install"])})
        report["installed"] = attempts
        report["tools"] = [probe(tool, host, which, runner) for tool in tools]
    return report
