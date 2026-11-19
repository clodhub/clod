"""The per-user state folder, this run's identity, and owner liveness by process id and start time."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import secrets
import sys
import time

from .model import fail

RUN_ID = secrets.token_hex(16)
STARTED = time.time()


def state_home() -> Path:
    """AEPM_STATE_HOME, else the platform's per-user application state folder."""
    configured = os.environ.get("AEPM_STATE_HOME")
    if configured:
        path = Path(configured)
    elif sys.platform == "darwin":
        path = Path.home() / "Library/Application Support/aepm"
    elif os.name == "nt":
        path = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local") / "aepm"
    else:
        path = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "aepm"
    if not path.is_absolute():
        fail("invalid-setting", "AEPM_STATE_HOME")
    return path


def folder(name: str) -> Path:
    path = state_home() / name
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def process_start(pid: int) -> str | None:
    """A token that differs between two processes that held the same number, or None when no such process exists."""
    if type(pid) is not int or pid <= 0:
        return None
    if sys.platform.startswith("linux"):
        try:
            data = Path(f"/proc/{pid}/stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            return None
        _, separator, body = data.rpartition(") ")
        values = body.split()
        return "linux:" + values[19] if separator and len(values) > 19 and values[0] not in ("Z", "X") else None
    if sys.platform == "darwin":
        from .posix_process import DarwinProcessInfo
        library = _LIBPROC
        info = DarwinProcessInfo()
        size = library.proc_pidinfo(pid, 3, ctypes.c_uint64(0), ctypes.byref(info), ctypes.sizeof(info))
        if size != ctypes.sizeof(info) or info.pid != pid or info.status == 5:
            return None
        return f"darwin:{info.started_seconds}.{info.started_microseconds:06d}"
    if os.name == "nt":
        from ctypes import wintypes as w
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = w.HANDLE
        kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        try:
            times = [w.FILETIME() for _ in range(4)]
            code = w.DWORD()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value != 259:
                return None
            if not kernel.GetProcessTimes(handle, *map(ctypes.byref, times)):
                return None
            return f"windows:{(times[0].dwHighDateTime << 32) | times[0].dwLowDateTime}"
        finally:
            kernel.CloseHandle(handle)
    return None


_LIBPROC = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True) if sys.platform == "darwin" else None
_OWN = {"pid": None, "start": None}


def owner() -> dict:
    pid = os.getpid()
    if _OWN["pid"] != pid:
        _OWN.update(pid=pid, start=process_start(pid))
    return {"pid": pid, "processStart": _OWN["start"], "runId": RUN_ID}


def alive(record: dict) -> bool:
    """True when the recorded process is still the same running process."""
    start = record.get("processStart")
    return start is not None and process_start(record.get("pid")) == start


def write_record(path: Path, value: dict) -> None:
    from .io import write
    write(path, value)


def read_record(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_bytes())
    except (FileNotFoundError, ValueError):
        return None
    return value if type(value) is dict else None

