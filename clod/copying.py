"""Copy files and ordinary trees by clone where the filesystem supports it, else by bytes; links are refused."""

from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import shutil
import stat
import sys

from .model import fail

FICLONE = 0x40049409
_LIBC = None
_CLONES = {"enabled": True}


def _libc():
    global _LIBC
    if _LIBC is None:
        _LIBC = ctypes.CDLL(None, use_errno=True)
    return _LIBC


def clone_file(source: Path, destination: Path) -> bool:
    """Make `destination` a copy-on-write clone of `source`. False when the filesystem or platform cannot clone."""
    if not _CLONES["enabled"]:
        return False
    if sys.platform == "darwin":
        library = _libc()
        library.clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
        if library.clonefile(os.fsencode(source), os.fsencode(destination), 0) == 0:
            return True
        number = ctypes.get_errno()
        if number in (errno.ENOTSUP, errno.EXDEV, errno.EINVAL, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)):
            return False
        raise OSError(number, os.strerror(number), str(destination))
    if sys.platform.startswith("linux"):
        import fcntl
        with open(source, "rb") as reader:
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
            try:
                fcntl.ioctl(descriptor, FICLONE, reader.fileno())
                return True
            except OSError as error:
                os.close(descriptor)
                descriptor = None
                os.unlink(destination)
                if error.errno in (errno.EOPNOTSUPP, errno.ENOTTY, errno.EXDEV, errno.EINVAL, errno.ENOSYS, errno.EBADF):
                    return False
                raise
            finally:
                if descriptor is not None:
                    os.close(descriptor)
    return False


def copy_file(source, destination, *, mode: int | None = None) -> str:
    """Copy one ordinary file. Returns "clone" or "bytes". Errors, including a full volume, are raised unchanged."""
    source, destination = Path(source), Path(destination)
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        fail("unsafe-file", str(source))
    if os.path.lexists(destination):
        fail("destination-not-empty", str(destination))
    method = "clone" if clone_file(source, destination) else "bytes"
    if method == "bytes":
        shutil.copyfile(source, destination)
    os.chmod(destination, stat.S_IMODE(info.st_mode) if mode is None else mode)
    return method


def copy_tree(source, destination) -> dict:
    """Copy an ordinary tree with its file and directory modes. Any link, junction or special file is refused.

    Returns counts of clone and byte copies. A failure leaves a partial destination for the caller to remove."""
    source, destination = Path(source), Path(destination)
    counts = {"clone": 0, "bytes": 0}
    info = source.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        fail("unsafe-file", str(source))
    destination.mkdir()
    directories = [(source, destination, stat.S_IMODE(info.st_mode))]
    pending = [(source, destination)]
    while pending:
        current, target = pending.pop()
        for entry in sorted(os.scandir(current), key=lambda item: item.name):
            child = entry.stat(follow_symlinks=False)
            path, copied = Path(entry.path), target / entry.name
            if getattr(child, "st_file_attributes", 0) & 0x400 or stat.S_ISLNK(child.st_mode):
                fail("unsafe-file", str(path))
            if stat.S_ISDIR(child.st_mode):
                copied.mkdir()
                directories.append((path, copied, stat.S_IMODE(child.st_mode)))
                pending.append((path, copied))
            elif stat.S_ISREG(child.st_mode):
                counts[copy_file(path, copied)] += 1
            else:
                fail("unsafe-file", str(path))
    for _, copied, mode in reversed(directories):
        os.chmod(copied, mode)
    return counts
