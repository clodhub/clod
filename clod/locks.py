"""Machine-wide locks: one heavy build of a kind at a time, released by the operating system when the holder dies."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sys
import threading
import time

from .model import fail

KINDS = ("xcode", "gradle", "android-emulator", "apple-simulator")
DEFAULT_TIMEOUT = 3600
_HELD: dict[str, list] = {}
_GUARD = threading.Lock()


class _Handle:
    """An open lock file whose first byte is locked exclusively: fcntl.flock on POSIX, msvcrt.locking on Windows."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.stream = open(path, "a+b")

    def try_lock(self) -> bool:
        try:
            if os.name == "nt":
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def unlock(self) -> None:
        try:
            if os.name == "nt":
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream, fcntl.LOCK_UN)
        finally:
            self.stream.close()


@contextmanager
def file_lock(path: Path, *, timeout: float, purpose: str, holder_path: Path | None = None, kind: str = "file"):
    """Hold `path` exclusively for the block; wait at most `timeout` seconds, then fail resource-busy naming the holder.

    Yields the seconds spent waiting."""
    from .state import alive, owner, read_record, write_record
    handle, started = _Handle(Path(path)), time.monotonic()
    try:
        while not handle.try_lock():
            if time.monotonic() - started >= timeout:
                holder = read_record(holder_path) if holder_path else None
                live = holder if holder and alive(holder) else None
                fail("resource-busy", kind, detail={"kind": kind, "purpose": purpose, "timeoutSeconds": timeout, "holder": live})
            time.sleep(0.1)
    except BaseException:
        handle.stream.close()
        raise
    waited = time.monotonic() - started
    try:
        if holder_path is not None:
            write_record(holder_path, {"format": 1, **owner(), "kind": kind, "purpose": purpose,
                                       "command": " ".join(sys.argv)[:1024], "since": int(time.time())})
        yield waited
    finally:
        if holder_path is not None:
            holder_path.unlink(missing_ok=True)
        handle.unlock()


def _paths(kind: str) -> tuple[Path, Path]:
    from .state import folder
    if kind not in KINDS:
        fail("invalid-value", "lock-kind")
    directory = folder("locks")
    return directory / (kind + ".lock"), directory / (kind + ".holder.json")


@contextmanager
def heavy(kind: str, *, purpose: str, timeout: float = DEFAULT_TIMEOUT):
    """One holder of `kind` per machine. Re-entrant within a thread: the lock is released only when the last of that
    thread's blocks exits, in whatever order they exit. Yields the seconds this call waited."""
    lock_path, holder_path = _paths(kind)
    me = threading.get_ident()
    with _GUARD:
        state = _HELD.get(kind)
        nested = state is not None and state[0] == me
        if nested:
            state[1] += 1
    waited = 0.0
    if not nested:
        manager = file_lock(lock_path, timeout=timeout, purpose=purpose, holder_path=holder_path, kind=kind)
        waited = manager.__enter__()
        with _GUARD:
            _HELD[kind] = [me, 1, manager]
    try:
        yield waited
    finally:
        with _GUARD:
            state = _HELD[kind]
            state[1] -= 1
            last = state[1] == 0
            if last:
                del _HELD[kind]
        if last:
            state[2].__exit__(None, None, None)


def holders() -> list[dict]:
    """Every kind with its live holder record, or null when free. A record left by a dead process is not a holder."""
    from .state import alive, read_record
    result = []
    for kind in KINDS:
        lock_path, holder_path = _paths(kind)
        probe = _Handle(lock_path)
        free = probe.try_lock()
        if free:
            probe.unlock()
            result.append({"kind": kind, "held": False, "holder": None})
            continue
        probe.stream.close()
        record = read_record(holder_path)
        result.append({"kind": kind, "held": True, "holder": record if record and alive(record) else None})
    return result


def kinds_for(suite: dict) -> list[str]:
    """The heavy kinds a check needs, from its declared tools, operations and resources."""
    tools = set(suite.get("tools", {}))
    execution = suite.get("execution") or {}
    operations = set(execution.get("operations", []))
    resources = {item["id"] for item in execution.get("resources", [])}
    kinds = []
    if tools & {"xcodebuild", "xcrun", "swift", "swiftc", "xcodegen"} or "appleDeveloperDirectory" in resources:
        kinds.append("xcode")
    if tools & {"gradle", "java", "javac", "kotlinc"} or resources & {"androidSdk", "androidJavaHome", "androidCache"}:
        kinds.append("gradle")
    if "create-temporary-emulator" in operations or "emulator" in tools or "adb" in tools:
        kinds.append("android-emulator")
    if "create-temporary-simulator" in operations or "external:compatible-apple-simulator" in suite.get("requirements", []):
        kinds.append("apple-simulator")
    return [kind for kind in KINDS if kind in kinds]


def free_port(*, host: str = "127.0.0.1", start: int = 5554, end: int = 5682, step: int = 2) -> int:
    """An emulator console port whose console and adb ports are both free now. Call under the android-emulator lock,
    which keeps other clod processes from choosing the same pair until the emulator owns it."""
    import socket
    for port in range(start, end, step):
        sockets = []
        try:
            for value in (port, port + 1):
                candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sockets.append(candidate)
                candidate.bind((host, value))
            return port
        except OSError:
            continue
        finally:
            for candidate in sockets:
                candidate.close()
    fail("resource-busy", "android-emulator-port")
