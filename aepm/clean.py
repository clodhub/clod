"""Find and remove leftovers that only aepm's own ledger proves are safe to remove."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

from .model import canonical, digest, fail

TEMPORARY = re.compile(r"aepm-(?:verification|context|review)-.+")
REMOVABLE_KINDS = ("check", "review", "install", "extract", "proof", "work")
PLATFORM = sys.platform
WINDOWS_OFF = "removal is off on Windows until open-file and process detection is verified there"


def duration(value: str | None) -> int | None:
    if value is None:
        return None
    match = re.fullmatch(r"([1-9][0-9]{0,8})([smhd])", value)
    if not match:
        fail("invalid-value", "older-than")
    return int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]


def _devices_gone(entry: dict) -> bool:
    """True only when every device the root's check created is confirmed absent from this machine."""
    for device in entry.get("devices", []):
        if device.get("kind") in ("apple-device", "android-device") and not device.get("resourceId"):
            return False  # only an intent was recorded: the device it made, if any, has an unknown identity
        if device.get("kind") == "apple-device":
            try:
                result = subprocess.run(["xcrun", "simctl", "list", "devices", "-j"], capture_output=True, text=True, timeout=60)
                listed = json.loads(result.stdout) if result.returncode == 0 else None
            except (OSError, ValueError, subprocess.TimeoutExpired):
                listed = None
            if listed is None:
                return False
            names = {value for group in listed.get("devices", {}).values() for item in group
                     for value in (item.get("udid"), item.get("name"))}
            if device.get("resourceId") in names or device.get("requestedId") in names:
                return False
        elif device.get("kind") == "android-device":
            home = Path(entry["root"]) / "protocol/profiles/android"
            if home.exists() and any(home.iterdir()):
                return False
            try:
                result = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                return False
            if result.returncode != 0 or (device.get("resourceId") and device["resourceId"] in result.stdout):
                return False
        else:
            return False
    return True


def _logs(root: Path) -> Path:
    """Where a proposal's checks write their logs inside its transaction folder."""
    return root / "verification" / "logs"


def _referenced_logs(entry: dict) -> set[str] | None:
    """Log file names a kept report names by digest, with the step logs each log index lists. None when a referencing
    report or a log index it names cannot be read, since its step logs are then unknown."""
    logs, names = _logs(Path(entry["root"])), set()
    for report_path in entry.get("references", []):
        try:
            report = json.loads(Path(report_path).read_bytes())
        except (OSError, ValueError):
            return None
        for suite in report.get("suites", []) if type(report) is dict else []:
            index = suite.get("logDigest") if type(suite) is dict else None
            if type(index) is not str:
                continue
            names.add(index + ".json")
            try:
                events = json.loads((logs / (index + ".json")).read_bytes())
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                return None
            for event in events if type(events) is list else []:
                if type(event) is dict and type(event.get("logDigest")) is str:
                    names.add(event["logDigest"] + ".log")
    return names


def _with_devices(entry: dict, root: Path) -> dict:
    """The entry with the devices its root's ownership records name, for a root whose entry recorded none (its owner
    died before finishing). With no record at all, the profiles alone keep it protected."""
    if entry.get("devices"):
        return entry
    from .contextual import device_records
    devices = device_records(root / "protocol" / "ownership")
    return {**entry, "devices": devices or [{"kind": "unrecorded"}]}


PROFILES = ("profiles/android", "profiles/apple", "android-user/avd")


def _holds_profile(root: Path) -> bool:
    """A check root holding an emulator or simulator profile; such a root is removed only by hand."""
    for name in PROFILES:
        folder = root / "protocol" / name
        try:
            if folder.is_dir() and any(folder.iterdir()):
                return True
        except OSError:
            return True
    return False


def _holds_ownership(root: Path) -> bool:
    """A check root holding a device or room ownership record."""
    ownership = root / "protocol" / "ownership"
    try:
        return ownership.is_dir() and any(ownership.glob("*.json"))
    except OSError:
        return True


def _processes_inside(root: Path) -> bool | None:
    """True when a running process has its executable or working directory inside root; None when that cannot be
    determined on this machine."""
    try:
        from .private_process import LinuxBackend, DarwinBackend, _matches
        import sys
        backend = DarwinBackend() if sys.platform == "darwin" else LinuxBackend() if sys.platform.startswith("linux") else None
        if backend is None:
            return None
        resolved = root.resolve()
        for pid in backend.pids():
            if pid == os.getpid():
                continue
            try:
                record = backend.capture(pid)
            except Exception:
                continue
            if record is None:
                continue
            try:
                if _matches(resolved, record):
                    return True
            finally:
                backend.close(record)
        return False
    except Exception:
        return None


def _transaction_busy(stage: Path) -> bool:
    directory = stage.parent
    return (directory / "journal.json").exists() or (directory / "backup").exists() or (directory / "failed-new").exists()


def open_paths() -> list[Path] | None:
    """Resolved paths every process of this user has open, including working folders and executables; None when the
    inspection fails or cannot see every such process."""
    if PLATFORM == "darwin":
        try:
            result = subprocess.run(["lsof", "-nP", "-w", "-u", str(os.geteuid()), "-Fpn"], capture_output=True, timeout=120,
                                    stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0 or not result.stdout:
            return None
        return [Path(line[1:].decode("utf-8", "surrogateescape")) for line in result.stdout.splitlines()
                if line.startswith(b"n/")]
    if PLATFORM.startswith("linux"):
        paths = []
        try:
            entries = [entry for entry in os.scandir("/proc") if entry.name.isdecimal()]
        except OSError:
            return None
        for entry in entries:
            try:
                if entry.stat().st_uid != os.geteuid():
                    continue
                names = [os.path.join(entry.path, "fd", name) for name in os.listdir(os.path.join(entry.path, "fd"))]
                names += [os.path.join(entry.path, "cwd"), os.path.join(entry.path, "exe")]
            except FileNotFoundError:
                continue
            except OSError:
                return None
            for name in names:
                try:
                    target = os.readlink(name)
                except FileNotFoundError:
                    continue
                except OSError:
                    return None
                if target.startswith("/"):
                    paths.append(Path(target.removesuffix(" (deleted)")))
        return paths
    return None


def _held(path: Path, opened: list[Path]) -> bool:
    resolved = path.resolve()
    return any(item == resolved or item.is_relative_to(resolved) for item in opened)


def _guard_open_files(candidates: list, protected: list) -> list:
    """Move to protected every candidate in which a process of this user holds a file open; all of them when that
    cannot be inspected."""
    if not candidates:
        return candidates
    opened = open_paths()
    kept = []
    for item in candidates:
        if opened is None:
            protected.append({**item, "reason": "open-files-unknown"})
        elif _held(Path(item["path"]), opened):
            protected.append({**item, "reason": "open-files-inside"})
        else:
            kept.append(item)
    return kept


def survey(*, older_than: int | None = None) -> dict:
    """Removable candidates, protected roots with reasons, and unknown aepm temporaries. Nothing is changed."""
    from .ledger import entries
    from .space import tree_bytes
    from .state import alive
    now, candidates, protected = time.time(), [], []
    known = set()
    for entry in entries():
        root = Path(entry["root"])
        known.add(str(root))
        if not root.exists():
            continue
        size = entry["bytesAtEnd"] if type(entry.get("bytesAtEnd")) is int else tree_bytes(root)
        item = {"path": str(root), "kind": entry["kind"], "purpose": entry.get("purpose"), "bytes": size,
                "retained": entry.get("retained"), "pid": entry.get("pid"), "runId": entry.get("runId"), "entry": digest(canonical(entry))}

        def protect(reason):
            protected.append({**item, "reason": reason})

        if entry.get("retained") == "keep":
            protect("keep")
        elif alive(entry):
            protect("owner-alive")
        elif older_than is not None and now - entry.get("created", now) < older_than:
            protect("newer-than-limit")
        elif _holds_profile(root):
            protect("device-profile-present")
        elif (_holds_ownership(root) or entry.get("retained") == "device-ownership") and not _devices_gone(_with_devices(entry, root)):
            protect("devices-not-confirmed-gone")
        elif PLATFORM != "win32" and entry["kind"] in ("check", "review", "install", "extract", "work") and (busy := _processes_inside(root)) is not False:
            protect("processes-inside" if busy else "processes-unknown")
        elif entry["kind"] == "stage":
            if _transaction_busy(root):
                protect("journal-or-backup-present")
            elif entry.get("retained") == "proposal":
                protect("pending-proposal")
            else:
                candidates.append(item)
        elif entry["kind"] == "transaction-logs":
            referenced = _referenced_logs(entry)
            if referenced is None:
                protect("referencing-report-unreadable")
                continue
            for path in sorted(_logs(root).glob("*")) if _logs(root).is_dir() else []:
                if path.is_file() and not path.is_symlink() and path.name not in referenced:
                    candidates.append({**item, "path": str(path), "bytes": tree_bytes(path), "within": str(root)})
            protected.append({**item, "reason": "referenced-logs", "referenced": len(referenced)})
        elif entry["kind"] in REMOVABLE_KINDS:
            candidates.append(item)
        else:
            protect("kind-not-removable")
    unknown = []
    known = {str(Path(path).resolve()) for path in known}
    temporary = Path(tempfile.gettempdir()).resolve()
    for path in sorted(temporary.iterdir()) if temporary.is_dir() else []:
        if TEMPORARY.fullmatch(path.name) and str(path.resolve()) not in known:
            unknown.append({"path": str(path.resolve()), "reason": "not-in-ledger"})
    if PLATFORM == "win32":
        return {"candidates": candidates, "protected": protected, "unknown": unknown, "removal": WINDOWS_OFF,
                "bytes": sum(item["bytes"] for item in candidates)}
    candidates = _guard_open_files(candidates, protected)
    return {"candidates": candidates, "protected": protected, "unknown": unknown, "removal": "on",
            "bytes": sum(item["bytes"] for item in candidates)}


def _writable_seeds(path: Path) -> None:
    """Seeds are sealed read-only; a dead run's seed folder, and only one inside aepm's own seeds folder, is made
    writable again so it can be removed."""
    from .state import folder
    seeds = folder("seeds").resolve()
    resolved = path.resolve()
    if resolved.parent != seeds:
        return
    for directory, directories, _ in os.walk(resolved):
        for name in directories:
            child = Path(directory) / name
            if not child.is_symlink():
                child.chmod(0o700)
        Path(directory).chmod(0o700)


def _listing(result: dict) -> list:
    return sorted([item["path"], item["entry"], item["bytes"]] for item in result["candidates"])


def clean(*, apply: bool = False, older_than: str | None = None) -> dict:
    """Dry run by default: list and save the plan. With apply, remove exactly the saved plan's candidates after checking
    that nothing changed and that each owner is still dead; failures are reported, never hidden."""
    from .ledger import entry_for, forget
    from .state import alive, folder, read_record, write_record
    limit = duration(older_than)
    result = survey(older_than=limit)
    plan_path = folder("clean") / "plan.json"
    listing = _listing(result)
    if not apply:
        write_record(plan_path, {"format": 1, "created": int(time.time()), "olderThan": limit, "candidates": listing})
        return {**result, "applied": False, "plan": str(plan_path)}
    if result["removal"] != "on":
        fail("clean-removal-off", "clean", detail={"reason": result["removal"], "candidates": len(listing)})
    plan = read_record(plan_path)
    if not plan or plan.get("olderThan") != limit or plan.get("candidates") != listing:
        fail("clean-plan-changed", str(plan_path), detail={"planned": len(plan.get("candidates", [])) if plan else None,
                                                             "current": len(listing)})
    removed, failed = [], []
    from .ledger import entries
    for entry in entries():
        if not Path(entry["root"]).exists() and not alive(entry):
            forget(entry["root"])
    for item in result["candidates"]:
        within = item.get("within")
        entry = entry_for(within or item["path"])
        if entry is None or digest(canonical(entry)) != item["entry"] or alive(entry):
            failed.append({**item, "error": "owner-or-entry-changed"})
            continue
        opened = open_paths()
        if opened is None or _held(Path(item["path"]), opened) or (within is None and _processes_inside(Path(item["path"])) is not False
                                                                    and entry["kind"] in ("check", "review", "install", "extract", "work")):
            failed.append({**item, "error": "open-files-unknown" if opened is None else "in-use"})
            continue
        errors = []
        path = Path(item["path"])

        def record_error(function, target, error):
            errors.append({"path": str(target), "error": type(error[1]).__name__ if isinstance(error, tuple) else type(error).__name__})

        try:
            if path.is_dir() and not path.is_symlink():
                _writable_seeds(path)
                shutil.rmtree(path, onerror=record_error)
            else:
                path.unlink()
        except OSError as error:
            errors.append({"path": str(path), "error": type(error).__name__})
        if errors or path.exists():
            failed.append({**item, "errors": errors or [{"path": str(path), "error": "still-present"}]})
        else:
            removed.append({**item, "ledger": entry})
            if within is None:
                forget(path)
    log = {"format": 1, "time": int(time.time()), "removed": removed, "failed": failed}
    log_path = folder("clean") / ("log-" + time.strftime("%Y%m%dT%H%M%S") + f"-{os.getpid()}.json")
    write_record(log_path, log)
    plan_path.unlink(missing_ok=True)
    return {"applied": True, "removed": removed, "failed": failed, "protected": result["protected"], "unknown": result["unknown"],
            "log": str(log_path), "bytes": sum(item["bytes"] for item in removed)}
