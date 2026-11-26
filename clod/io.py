"""Bounded documents and ordinary filesystem paths."""

import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, NoReturn

from .model import ClodError, canonical, digest, parse_package
from . import state as _state  # noqa: F401  (owner identity read before any test replaces native libraries)


class VerificationDirectory:
    """A check's private root, recorded in the run ledger. Kept, with its reason, when owned-process or device cleanup
    cannot be confirmed; otherwise removed on exit. `written` and `kept` hold its bytes at the end."""

    def __init__(self, prefix, *, purpose="check"):
        self.temporary = tempfile.TemporaryDirectory(prefix=prefix, delete=False)
        self.path = Path(self.temporary.name).resolve()
        self.preserve, self.retained, self.devices = False, None, []
        self.written = self.kept = 0
        if os.name == "posix":
            try:
                from .private_process import enroll_root
                enroll_root(self.path, before_work=True)
            except BaseException:
                self.temporary.cleanup()
                raise
        from .ledger import record
        self.entry = record(self.path, "check", purpose=purpose)

    def __enter__(self):
        return self.path

    def __exit__(self, kind, error, trace):
        from .ledger import finish
        from .space import tree_bytes
        try:
            self.written = tree_bytes(self.path)
        except Exception:
            self.written = 0
        if not self.preserve:
            self.temporary.cleanup()
            self.kept = 0
        else:
            self.kept = self.written
        finish(self.entry, retained=(self.retained or "cleanup-failed") if self.preserve else None, devices=self.devices)
        return False


def fail(code: str, path: object, *, detail: dict | None = None) -> NoReturn:
    raise ClodError(code, str(path), detail=detail)


def fields(value, required, optional=(), path="document"):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        fail("fields", path)


def load(path: str | Path) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail("duplicate-key", path)
            result[key] = value
        return result

    try:
        with Path(path).open("rb") as stream:
            data = stream.read(1_048_577)
        if len(data) > 1_048_576:
            fail("metadata-limit", path)
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: fail("nonfinite", path))
    except (OSError, ValueError, UnicodeError, RecursionError):
        fail("document", path)


def linked(path) -> bool:
    """True for a symbolic link, junction or other reparse point."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def sync_directory(path):
    if os.name == "nt":
        from .windows import ntfs
        ntfs(path)
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if linked(path):
        fail("symlink", path)
    descriptor, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            from .windows import publish
            publish(temporary, path, replace=True)
        else:
            os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_directory(path):
    path = Path(path)
    from .bundle import ordinary_path
    ordinary_path(path, missing=True)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "nt":
        from .windows import protect
        protect(path)
    else:
        path.chmod(0o700)
    return path


def exclusive(path, value):
    """Publish once; even an interrupted creation consumes this filename."""
    path = Path(path)
    from .bundle import ordinary_path
    ordinary_path(path.parent)
    data = canonical(value)
    if os.name == "nt":
        from .windows import exclusive_bytes
        exclusive_bytes(path, data)
        return
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        fail("execution-replayed", "execution-state")
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def immutable(path, value):
    immutable_blob(path, canonical(value))


def immutable_blob(path, data):
    path = Path(path)
    private_directory(path.parent)
    if path.is_symlink():
        fail("immutable-evidence", "evidence")
    if path.exists():
        if not path.is_file() or path.read_bytes() != data:
            fail("immutable-evidence", "evidence")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".evidence-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            from .windows import publish
            publish(temporary, path)
        else:
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError:
                if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                    fail("immutable-evidence", "evidence")
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def relative(value, path="path", dot=False):
    if dot and value == ".":
        return value
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        fail("unsafe-path", path)
    if any(part in ("", ".", "..") for part in value.split("/")) or value.startswith("/"):
        fail("unsafe-path", path)
    return value


def rooted(root, value, dot=False):
    relative(value, dot=dot)
    root = Path(root)
    candidate = root / value
    for parent in (candidate, *candidate.parents):
        if linked(parent):
            fail("symlink", value)
        if parent == root:
            break
    if not candidate.resolve().is_relative_to(root.resolve()):
        fail("path-escape", value)
    return candidate


def exact(value, path="version"):
    """A package version's sort key; a preview sorts before the release of the same MAJOR.MINOR.PATCH."""
    from .model import PACKAGE_VERSION, version_key
    if not isinstance(value, str) or not PACKAGE_VERSION.fullmatch(value):
        fail("version", path)
    return version_key(value)


def package_name(value, kind=None):
    """A package name, of the given kind when one is named."""
    parsed = parse_package(value)
    if parsed is None or (kind is not None and parsed["kind"] != kind):
        fail("package-name", "name")
    return value


def snapshot(root, assembly=None):
    root = Path(root)
    if linked(root) or not root.is_dir():
        fail("ordinary-directory", root)
    owners = {item["path"]: item["owner"] for item in (assembly or {}).get("files", [])}
    records = [{"path": ".", "kind": "directory", "digest": None,
                "mode": stat.S_IMODE(root.stat().st_mode), "owner": None}]
    seen = set()
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            path = Path(directory) / name
            key = path.relative_to(root).as_posix()
            relative(key)
            if key.casefold() in seen:
                fail("case-collision", key)
            seen.add(key.casefold())
            info = path.lstat()
            if linked(path) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                fail("special-file", key)
            records.append({"path": key, "kind": "directory" if path.is_dir() else "file",
                            "digest": None if path.is_dir() else digest(path.read_bytes()),
                            "mode": stat.S_IMODE(info.st_mode), "owner": owners.get(key)})
    return sorted(records, key=lambda item: item["path"])
