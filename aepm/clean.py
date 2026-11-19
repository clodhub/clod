"""Find and remove leftovers that only aepm's own ledger proves are safe to remove."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from .model import canonical, digest, fail

TEMPORARY = re.compile(r"aepm-(?:verification|context|review)-.+")
REMOVABLE_KINDS = ("check", "review", "install", "extract", "proof", "work")


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


def _referenced_logs(entry: dict) -> set[str]:
    """Log file names under a transaction log root that a kept report names by digest, with their step logs."""
    root, names = Path(entry["root"]), set()
    for report_path in entry.get("references", []):
        try:
            report = json.loads(Path(report_path).read_bytes())
        except (OSError, ValueError):
            return None
        for suite in report.get("suites", []):
            index = suite.get("logDigest")
            if type(index) is not str:
                continue
            names.add(index + ".json")
            try:
                events = json.loads((root / (index + ".json")).read_bytes())
            except (OSError, ValueError):
                continue
            for event in events if type(events) is list else []:
                if type(event) is dict and type(event.get("logDigest")) is str:
                    names.add(event["logDigest"] + ".log")
    return names


def _transaction_busy(stage: Path) -> bool:
    directory = stage.parent
    return (directory / "journal.json").exists() or (directory / "backup").exists() or (directory / "failed-new").exists()


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
        elif entry.get("retained") == "device-ownership" and not _devices_gone(entry):
            protect("devices-not-confirmed-gone")
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
            for path in sorted(root.rglob("*")):
                if path.is_file() and path.name not in referenced:
                    candidates.append({**item, "path": str(path), "bytes": tree_bytes(path), "within": str(root)})
            protected.append({**item, "reason": "referenced-logs", "referenced": len(referenced)})
        elif entry["kind"] in REMOVABLE_KINDS:
            candidates.append(item)
        else:
            protect("kind-not-removable")
    unknown = []
    temporary = Path(tempfile.gettempdir()).resolve()
    for path in sorted(temporary.iterdir()) if temporary.is_dir() else []:
        if TEMPORARY.fullmatch(path.name) and str(path.absolute()) not in known and str(path.resolve()) not in known:
            unknown.append({"path": str(path), "reason": "not-in-ledger"})
    return {"candidates": candidates, "protected": protected, "unknown": unknown,
            "bytes": sum(item["bytes"] for item in candidates)}


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
        errors = []
        path = Path(item["path"])

        def record_error(function, target, error):
            errors.append({"path": str(target), "error": type(error[1]).__name__ if isinstance(error, tuple) else type(error).__name__})

        try:
            if path.is_dir() and not path.is_symlink():
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
