"""Free-space admission, out-of-space errors and bounded size measurement."""

from __future__ import annotations

import errno
import os
from pathlib import Path
import shutil
import stat

from .model import ClodError, fail

GIB = 1024 ** 3
DEFAULT_MARGIN = 10 * GIB
OUT_OF_SPACE = frozenset(code for code in (errno.ENOSPC, getattr(errno, "EDQUOT", None)) if code is not None)
TREE_ENTRY_LIMIT = 2_000_000

# Fallback bytes a step writes beyond its measured inputs, used only where no inventory gives a size. Admission adds
# tree_bytes() or inventory sizes of what is copied, then CLOD_FREE_SPACE_MARGIN.
# Android media check (Gradle build, unit tests and dependency report with a fresh Gradle home): provisional figure
# from the build disk safety plan, not yet measured by clod.
ANDROID_MEDIA_CHECK = 15 * GIB
# Apple design build (iOS, Mac Catalyst and television builds into one DerivedData folder): provisional figure from
# the build disk safety plan, not yet measured by clod.
APPLE_DESIGN_BUILD = 8 * GIB
# npm ci for one package.json, fresh npm cache plus node_modules. Measured: see NPM_INSTALL_MEASURED_BY.
NPM_INSTALL = 1 * GIB
NPM_INSTALL_MEASURED_BY = "provisional; replaced by the measured smoke figure"
# try_install.py for one design: provisional sum of the Android and Apple figures plus web and server builds.
TRY_INSTALL_DESIGN = 30 * GIB


def margin() -> int:
    value = os.environ.get("CLOD_FREE_SPACE_MARGIN")
    if value is None:
        return DEFAULT_MARGIN
    if not value.isdecimal() or len(value) > 18:
        fail("invalid-setting", "CLOD_FREE_SPACE_MARGIN")
    return int(value)


def _existing(path: Path) -> Path:
    path = Path(path).absolute()
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return path.anchor and Path(path.anchor) or path


def free_bytes(path) -> int:
    return shutil.disk_usage(_existing(Path(path))).free


def insufficient(path, purpose: str, required: int | None, free: int | None, reserved: int = 0) -> ClodError:
    return ClodError("insufficient-space", str(path), detail={"path": str(path), "purpose": purpose, "required": required,
                                                              "free": free, "margin": margin(), "reserved": reserved})


def _device(path) -> int:
    return os.stat(_existing(Path(path))).st_dev


def reserved_by_others(path) -> int:
    """Bytes live reservations of other processes hold on the volume of `path`; records of dead owners are ignored."""
    from .state import alive, folder, read_record
    device, total = _device(path), 0
    for record_path in folder("reservations").glob("*.json"):
        record = read_record(record_path)
        if not record or record.get("pid") == os.getpid() or record.get("device") != device or not alive(record):
            continue
        if type(record.get("bytes")) is int and record["bytes"] > 0:
            total += record["bytes"]
    return total


def require_space(path, needed_bytes: int, *, purpose: str) -> dict:
    """Refuse unless the volume holding `path` has `needed_bytes` plus the margin free after other processes'
    reservations. Returns the numbers. Use `reserve` to hold the bytes for the length of the work."""
    if type(needed_bytes) is not int or needed_bytes < 0:
        fail("invalid-input", "needed_bytes")
    free, reserved = free_bytes(path), reserved_by_others(path)
    if free - reserved < needed_bytes + margin():
        raise insufficient(path, purpose, needed_bytes, free, reserved)
    return {"path": str(path), "purpose": purpose, "required": needed_bytes, "free": free, "margin": margin(), "reserved": reserved}


class reserve:
    """Admit `needed_bytes` on the volume of `path` and hold them against other processes' admissions until exit.

    Admission and recording happen under one lock, so two processes that each fit alone but not together cannot
    both be admitted. The record is removed on exit; a dead owner's record is ignored by everyone."""

    def __init__(self, path, needed_bytes: int, *, purpose: str):
        self.path, self.needed, self.purpose = path, needed_bytes, purpose
        self.record_path = None
        self.numbers = None

    def __enter__(self):
        from .locks import file_lock
        from .state import folder, owner, write_record
        import secrets
        from .state import alive, read_record
        with file_lock(folder("locks") / "reservations.lock", timeout=30, purpose="space admission"):
            for stale in folder("reservations").glob("*.json"):
                record = read_record(stale)
                if record is None or not alive(record):
                    stale.unlink(missing_ok=True)
            self.numbers = require_space(self.path, self.needed, purpose=self.purpose)
            self.record_path = folder("reservations") / (secrets.token_hex(12) + ".json")
            write_record(self.record_path, {"format": 1, **owner(), "device": _device(self.path), "bytes": self.needed,
                                            "path": str(self.path), "purpose": self.purpose})
        return self.numbers

    def __exit__(self, *_):
        if self.record_path is not None:
            self.record_path.unlink(missing_ok=True)


def out_of_space(error: BaseException) -> bool:
    return isinstance(error, OSError) and error.errno in OUT_OF_SPACE


def from_os_error(error: OSError, purpose: str, path=None) -> ClodError:
    """The insufficient-space error for an operating system error that reports a full volume or exhausted quota."""
    location = path if path is not None else error.filename or ""
    try:
        free = free_bytes(location) if location else None
    except OSError:
        free = None
    return insufficient(location, purpose, None, free)


def tree_bytes(path, *, limit: int = TREE_ENTRY_LIMIT) -> int:
    """Bytes allocated to a file or directory tree, without following links. More than `limit` entries is refused."""
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return 0
    if not stat.S_ISDIR(info.st_mode):
        return _allocated(info)
    total, count, pending = _allocated(info), 0, [path]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except FileNotFoundError:
            continue
        for entry in entries:
            count += 1
            if count > limit:
                fail("metadata-limit", str(path))
            try:
                child = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            total += _allocated(child)
            if stat.S_ISDIR(child.st_mode):
                pending.append(entry.path)
    return total


def _allocated(info) -> int:
    blocks = getattr(info, "st_blocks", None)
    return blocks * 512 if blocks is not None else info.st_size
