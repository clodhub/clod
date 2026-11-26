"""Verified, read-only dependency seeds shared by the checks of one run.

A passing check's downloads become seeds only when their bytes are proved to match an exact pin in that check's own
lock files: npm cache content by its lock integrity (SHA-512), and SwiftPM repositories whose pinned revision is
complete in object files that git verifies by hash. A Swift seed is a fresh bare repository clod creates, holding only
those object files, clod's own configuration and the pinned tag; no configuration, hooks, references or alternates of
the check's repository are copied. Without a working git, Swift seeding is off. Seeds live in clod's state folder,
never in the user's or the system's caches. A later check receives copies of the seeds its own pins name, verified
again, inside its private writable caches. Seeds are read-only and fingerprinted; any change discards them all.
Gradle downloads are not seeded: Gradle reads a shared cache only with its metadata stores, which no lock pins.
"""

from __future__ import annotations

import atexit
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

from .model import ClodError

LOCK_NAMES = ("package-lock.json", "npm-shrinkwrap.json")
SKIPPED = {"node_modules", ".git", "build", ".gradle", "DerivedData"}
_STATE = {"root": None, "entry": None, "fingerprint": None, "enabled": True, "events": []}


def _sha(path: Path, algorithm: str) -> str:
    value = hashlib.new(algorithm)
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _inputs(root: Path, names) -> list[Path]:
    """Lock files under a check root, outside dependency and build folders; at most 64."""
    found, pending = [], [Path(root)]
    while pending and len(found) < 64:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in SKIPPED:
                    pending.append(Path(entry.path))
            elif entry.is_file(follow_symlinks=False) and entry.name in names:
                found.append(Path(entry.path))
    return found


def npm_integrities(root: Path) -> set[str]:
    """Hexadecimal SHA-512 digests of every locked npm package in the check's lock files."""
    result = set()
    for path in _inputs(root, LOCK_NAMES):
        try:
            lock = json.loads(path.read_bytes())
        except (OSError, ValueError):
            continue
        for record in (lock.get("packages") or {}).values() if isinstance(lock, dict) else ():
            integrity = record.get("integrity") if isinstance(record, dict) else None
            for token in (integrity or "").split():
                if token.startswith("sha512-"):
                    try:
                        raw = base64.b64decode(token[7:], validate=True)
                    except ValueError:
                        continue
                    if len(raw) == 64:
                        result.add(raw.hex())
    return result


def swift_pins(root: Path) -> list[dict]:
    pins = []
    for path in _inputs(root, ("Package.resolved",)):
        try:
            value = json.loads(path.read_bytes())
        except (OSError, ValueError):
            continue
        for pin in value.get("pins", []) if isinstance(value, dict) else []:
            state = pin.get("state") if isinstance(pin, dict) else None
            if isinstance(state, dict) and isinstance(state.get("revision"), str) and isinstance(pin.get("location"), str):
                pins.append({"location": pin["location"], "revision": state["revision"], "version": state.get("version")})
    return pins


def _swift_cache(home: Path) -> Path:
    return home / ("Library/Caches/org.swift.swiftpm/repositories" if sys.platform == "darwin" else ".cache/org.swift.swiftpm/repositories")


OBJECT_NAME = re.compile(r"[0-9a-f]{38}")
PACK_NAME = re.compile(r"pack-[0-9a-f]{40,64}\.(?:pack|idx)")
_GIT = {"usable": None}


def _git(repository: Path, *arguments) -> str | None:
    """git on a repository clod created, reading neither system nor global configuration and running no hooks."""
    empty = Path(tempfile.gettempdir())
    environment = {"PATH": os.environ.get("PATH", os.defpath), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                   "HOME": str(empty), "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    try:
        result = subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false",
                                 "--git-dir", str(repository), *arguments], capture_output=True, text=True, timeout=600,
                                env=environment, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _source_location(repository: Path) -> str | None:
    """The origin a SwiftPM cache repository names, read as text; git is never run on the check's repository."""
    try:
        text = (repository / "config").read_text(errors="replace")
    except OSError:
        return None
    match = re.search(r'\[remote "origin"\][^\[]*?\n\s*url\s*=\s*(\S+)', text)
    return match[1] if match else None


def _same(location: str, other: str) -> bool:
    return location.rstrip("/").removesuffix(".git") == other.rstrip("/").removesuffix(".git")


def swift_seed(repository: Path, pins: list[dict], target: Path) -> str | None:
    """Build at `target` a fresh seed from the object files of a SwiftPM cache repository. Returns "pinned" when every
    object git can read verifies by hash and the pinned revision is a complete commit; "refused" when a pin names the
    repository but that cannot be proved (target is then removed); None when no pin names it."""
    location = _source_location(repository)
    pin = next((item for item in pins if location and _same(location, item["location"])), None)
    if pin is None:
        return None
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", pin["revision"]) or (pin["version"] and not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", pin["version"])):
        return "refused"
    template = target.parent / (target.name + ".template")
    try:
        template.mkdir(parents=True)
        made = subprocess.run(["git", "init", "-q", "--bare", "--template=" + str(template), str(target)], capture_output=True,
                              timeout=60, env={"PATH": os.environ.get("PATH", os.defpath), "GIT_CONFIG_NOSYSTEM": "1",
                                               "GIT_CONFIG_GLOBAL": os.devnull, "HOME": str(template)}, stdin=subprocess.DEVNULL)
        if made.returncode != 0:
            raise OSError("git init failed")
        source = repository / "objects"
        for entry in sorted(source.iterdir()) if source.is_dir() and not source.is_symlink() else []:
            if entry.is_symlink():
                continue
            if re.fullmatch(r"[0-9a-f]{2}", entry.name) and entry.is_dir():
                for item in entry.iterdir():
                    if OBJECT_NAME.fullmatch(item.name) and item.is_file() and not item.is_symlink():
                        _place(item, target / "objects" / entry.name / item.name)
            elif entry.name == "pack" and entry.is_dir():
                for item in entry.iterdir():
                    if PACK_NAME.fullmatch(item.name) and item.is_file() and not item.is_symlink():
                        _place(item, target / "objects/pack" / item.name)
        _set_pin(target, pin)
        if not swift_seed_verified(target, pins):
            raise OSError("unverified")
        return "pinned"
    except (OSError, ClodError, subprocess.TimeoutExpired):
        _remove(target)
        return "refused"
    finally:
        shutil.rmtree(template, ignore_errors=True)


def _set_pin(target: Path, pin: dict) -> None:
    (target / "config").write_text("[core]\n\trepositoryformatversion = 0\n\tbare = true\n"
                                   f"[remote \"origin\"]\n\turl = {pin['location']}\n")
    name = "refs/tags/" + pin["version"] if pin["version"] else "refs/clod/pinned"
    (target / name).parent.mkdir(parents=True, exist_ok=True)
    (target / name).write_text(pin["revision"] + "\n")


def swift_seed_verified(target: Path, pins: list[dict]) -> bool:
    """True when the seed holds clod's configuration and only verified objects, and the pin's reference names a
    commit whose whole history and trees are present."""
    location = _source_location(target)
    pin = next((item for item in pins if location and _same(location, item["location"])), None)
    if pin is None or not target.is_dir() or (target / "objects/info/alternates").exists() or (target / "hooks").exists():
        return False
    expected = ("[core]\n\trepositoryformatversion = 0\n\tbare = true\n" f"[remote \"origin\"]\n\turl = {pin['location']}\n")
    try:
        if (target / "config").read_text() != expected:
            return False
    except OSError:
        return False
    name = "refs/tags/" + pin["version"] if pin["version"] else "refs/clod/pinned"
    if _git(target, "fsck", "--full", "--strict", "--no-dangling", "--no-progress") is None:
        return False
    if _git(target, "rev-parse", "--verify", "--quiet", name + "^{commit}") != pin["revision"]:
        return False
    return _git(target, "rev-list", "--objects", "--missing=error", pin["revision"]) is not None


def git_usable() -> bool:
    """Swift seeding needs a git that can check objects; without one it is off."""
    if _GIT["usable"] is None:
        try:
            _GIT["usable"] = subprocess.run(["git", "--version"], capture_output=True, timeout=30).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            _GIT["usable"] = False
    return _GIT["usable"]


def _remove(path: Path) -> None:
    for directory, directories, _ in os.walk(path):
        os.chmod(directory, 0o700)
    shutil.rmtree(path, ignore_errors=True)


def _root() -> Path | None:
    if not _STATE["enabled"]:
        return None
    if _STATE["root"] is None:
        from .ledger import record
        from .state import RUN_ID, folder
        root = (folder("seeds") / RUN_ID).resolve()
        root.mkdir(mode=0o700)
        _STATE["root"], _STATE["entry"] = root, record(root, "work", purpose="dependency seeds for this run")
        atexit.register(discard)
    return _STATE["root"]


def discard() -> None:
    """Remove this run's seeds; later checks download their own dependencies."""
    root, entry = _STATE["root"], _STATE["entry"]
    _STATE.update(root=None, entry=None, fingerprint=None)
    if root is None:
        return
    for directory, directories, _ in os.walk(root):
        os.chmod(directory, 0o700)
    shutil.rmtree(root, ignore_errors=True)
    from .ledger import finish
    finish(entry)


def _fingerprint(root: Path) -> list:
    listing = []
    for directory, directories, files in os.walk(root):
        directories.sort()
        for name in sorted(files) + directories:
            info = os.lstat(os.path.join(directory, name))
            listing.append((os.path.relpath(os.path.join(directory, name), root), info.st_mode, info.st_size, info.st_mtime_ns, info.st_ino))
    return listing


def _intact() -> bool:
    root = _STATE["root"]
    if root is None:
        return False
    if _STATE["fingerprint"] is not None and _fingerprint(root) != _STATE["fingerprint"]:
        _STATE["events"].append("seed-changed")
        discard()
        _STATE["enabled"] = False
        return False
    return True


def _seal(root: Path) -> None:
    for directory, directories, files in os.walk(root, topdown=False):
        for name in files:
            os.chmod(os.path.join(directory, name), 0o444)
        os.chmod(directory, 0o555)
    _STATE["fingerprint"] = _fingerprint(root)


def _unseal(root: Path) -> None:
    for directory, directories, files in os.walk(root):
        os.chmod(directory, 0o755)


def _place(source: Path, destination: Path) -> None:
    from .copying import copy_file
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        copy_file(source, destination, mode=0o444)


def harvest_check(root: Path, environment: dict | None) -> None:
    """Add a finished check's verified downloads to this run's seeds. Unverifiable bytes are never added."""
    if not environment or os.name == "nt" or not _STATE["enabled"]:
        return
    try:
        _harvest(Path(root), environment)
    except (OSError, ClodError):
        _STATE["events"].append("harvest-failed")


def _harvest(root: Path, environment: dict) -> None:
    from .copying import copy_tree
    candidates = []
    integrities = npm_integrities(root)
    cache = Path(environment.get("npm_config_cache", "")) / "_cacache/content-v2/sha512"
    if integrities and cache.is_dir():
        for path in cache.rglob("*"):
            relative = path.relative_to(cache).parts
            if path.is_file() and not path.is_symlink() and len(relative) == 3:
                hexdigest = "".join(relative)
                if hexdigest in integrities and _sha(path, "sha512") == hexdigest:
                    candidates.append((path, Path("npm/_cacache/content-v2/sha512", *relative)))
    pins = swift_pins(root)
    pins = pins if pins and git_usable() else []
    repositories = []
    home = Path(environment.get("CFFIXED_USER_HOME") or environment.get("HOME", ""))
    if pins and _swift_cache(home).is_dir():
        for repository in sorted(_swift_cache(home).iterdir()):
            if repository.is_dir() and not repository.is_symlink():
                repositories.append(repository)
    if not candidates and not repositories:
        return
    seeds = _root()
    if seeds is None or not _intact():
        return
    _unseal(seeds)
    try:
        for source, relative in candidates:
            _place(source, seeds / relative)
        for repository in repositories:
            target = seeds / "swift" / repository.name
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                if swift_seed(repository, pins, target) == "refused":
                    _STATE["events"].append("refused swift:" + repository.name)
    finally:
        _seal(seeds)


def seed_check(root: Path, environment: dict | None) -> list[str]:
    """Clone into a check's private caches the seeds its own pins name, each verified again. Returns refusals."""
    refused = []
    seeds = _STATE["root"]
    if not environment or seeds is None or os.name == "nt" or not _intact():
        return refused
    from .copying import copy_tree
    root = Path(root)
    integrities = npm_integrities(root)
    content = seeds / "npm/_cacache/content-v2/sha512"
    cache = environment.get("npm_config_cache")
    if integrities and cache and content.is_dir():
        for hexdigest in sorted(integrities):
            seed = content / hexdigest[:2] / hexdigest[2:4] / hexdigest[4:]
            if seed.is_file():
                if _sha(seed, "sha512") != hexdigest:
                    refused.append("npm:" + hexdigest[:16])
                    continue
                _place(seed, Path(cache) / "_cacache/content-v2/sha512" / hexdigest[:2] / hexdigest[2:4] / hexdigest[4:])
    pins = swift_pins(root)
    pins = pins if pins and git_usable() else []
    repositories = seeds / "swift"
    home = environment.get("CFFIXED_USER_HOME") or environment.get("HOME")
    if pins and home and repositories.is_dir():
        for repository in sorted(repositories.iterdir()):
            location = _source_location(repository)
            if not any(location and _same(location, pin["location"]) for pin in pins):
                continue
            if not swift_seed_verified(repository, pins):
                refused.append("swift:" + repository.name)
                continue
            target = _swift_cache(Path(home)) / repository.name
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                copy_tree(repository, target)
                for directory, directories, names in os.walk(target):
                    os.chmod(directory, stat.S_IMODE(os.stat(directory).st_mode) | 0o700)
    _STATE["events"].extend("refused " + item for item in refused)
    return refused
