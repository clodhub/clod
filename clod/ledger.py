"""The run ledger: every root clod creates or a caller registers, with its owner, size and retention."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import time

from .model import fail

KINDS = ("check", "review", "stage", "install", "extract", "transaction-logs", "proof", "work")
RETAINED = (None, "cleanup-failed", "resource-changed", "device-ownership", "proposal", "failed-proposal", "keep", "interrupted")


def _entry_path(root: Path) -> Path:
    from .state import folder
    return folder("ledger") / (hashlib.sha256(str(root).encode()).hexdigest() + ".json")


def _run_path() -> Path:
    from .state import RUN_ID, folder
    return folder("runs") / (RUN_ID + ".json")


def _run_update(**changes) -> None:
    from .state import RUN_ID, STARTED, owner, read_record, write_record
    path = _run_path()
    value = read_record(path) or {"format": 1, **owner(), "started": int(STARTED), "command": None,
                                  "created": 0, "removed": 0, "retained": 0, "bytesKept": 0}
    for key, amount in changes.items():
        value[key] = value.get(key, 0) + amount if type(amount) is int else amount
    value["runId"] = RUN_ID
    write_record(path, value)


def record(root, kind: str, *, purpose: str, keep: bool = False, references=()) -> dict:
    """Record a root this process owns. Returns the entry; pass it to `finish` when the work ends."""
    from .state import owner, write_record
    if kind not in KINDS:
        fail("invalid-value", "ledger-kind")
    root = Path(root).absolute()
    entry = {"format": 1, "root": str(root), "kind": kind, "purpose": purpose, **owner(), "created": int(time.time()),
             "ended": None, "bytesAtEnd": None, "retained": "keep" if keep else None, "references": sorted(set(map(str, references)))}
    write_record(_entry_path(root), entry)
    _run_update(created=1)
    return entry


def register(root, kind: str, *, purpose: str, keep: bool) -> dict:
    """Record a root a caller (a proof or work folder) owns. `keep` protects it from `clod clean`."""
    return record(root, kind, purpose=purpose, keep=keep)


def finish(entry: dict, *, retained: str | None = None, references=(), devices=()) -> dict:
    """Close an entry. A root that no longer exists drops its entry; a remaining root keeps it with its final size."""
    from .space import tree_bytes
    from .state import write_record
    if retained not in RETAINED:
        fail("invalid-value", "ledger-retained")
    root, path = Path(entry["root"]), _entry_path(Path(entry["root"]))
    if not root.exists():
        path.unlink(missing_ok=True)
        _run_update(removed=1)
        return {**entry, "ended": int(time.time()), "bytesAtEnd": 0}
    size = tree_bytes(root)
    value = {**entry, "ended": int(time.time()), "bytesAtEnd": size,
             "retained": "keep" if entry.get("retained") == "keep" else retained or "interrupted",
             "references": sorted(set(entry.get("references", [])) | set(map(str, references))),
             "devices": [dict(item) for item in devices]}
    write_record(path, value)
    _run_update(retained=1, bytesKept=size)
    return value


def entries() -> list[dict]:
    from .state import folder, read_record
    result = []
    for path in sorted(folder("ledger").glob("*.json")):
        value = read_record(path)
        if value and value.get("format") == 1 and type(value.get("root")) is str:
            result.append(value)
    return result


def entry_for(root) -> dict | None:
    from .state import read_record
    return read_record(_entry_path(Path(root).absolute()))


def forget(root) -> None:
    _entry_path(Path(root).absolute()).unlink(missing_ok=True)


def runs() -> list[dict]:
    """Every run summary with its live state and the ledger entries it still owns."""
    from .state import alive, folder, read_record
    owned: dict[str, list] = {}
    for item in entries():
        owned.setdefault(item.get("runId"), []).append(item)
    result = []
    for path in sorted(folder("runs").glob("*.json")):
        value = read_record(path)
        if not value:
            continue
        roots = owned.get(value.get("runId"), [])
        result.append({**value, "live": alive(value), "roots": [{key: item[key] for key in ("root", "kind", "purpose", "retained", "bytesAtEnd")}
                                                              for item in roots]})
    return result


class tracked:
    """Record a root for the length of a block; on exit `finish` it with the retention set on `self.retained`."""

    def __init__(self, root, kind: str, *, purpose: str):
        self.root, self.kind, self.purpose = root, kind, purpose
        self.retained, self.references, self.entry = None, [], None

    def __enter__(self):
        self.entry = record(self.root, self.kind, purpose=self.purpose)
        return self

    def __exit__(self, kind, error, trace):
        if self.entry is not None:
            if kind is not None and self.retained is None and Path(self.root).exists():
                self.retained = "interrupted"
            self.final = finish(self.entry, retained=self.retained, references=self.references)
        return False


def owner_alive(entry: dict) -> bool:
    from .state import alive
    return alive(entry)


def pid_exists(pid: int) -> bool:
    from .state import process_start
    return process_start(pid) is not None if pid != os.getpid() else True
