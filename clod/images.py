"""Example images checked from their PNG and WebP structure, with no image library and no decompression."""

from __future__ import annotations

import struct
import zlib

from .model import MAXIMUM_IMAGE_BYTES, fail

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _png(data: bytes, path: str) -> tuple[int, int]:
    """Every chunk complete with a matching CRC, IHDR first, at least one IDAT, and IEND last at the end of the file."""
    offset, chunks = 8, []
    while offset < len(data):
        if offset + 12 > len(data):
            fail("image-header", path)
        length, kind = struct.unpack(">I4s", data[offset:offset + 8])
        end = offset + 12 + length
        if end > len(data) or struct.unpack(">I", data[end - 4:end])[0] != zlib.crc32(data[offset + 4:end - 4]) & 0xFFFFFFFF:
            fail("image-header", path)
        chunks.append((kind, data[offset + 8:end - 4]))
        offset = end
        if kind == b"IEND":
            break
    if offset != len(data) or not chunks or chunks[0][0] != b"IHDR" or len(chunks[0][1]) != 13 or chunks[-1] != (b"IEND", b"") \
            or not any(kind == b"IDAT" for kind, _ in chunks):
        fail("image-header", path)
    width, height = struct.unpack(">II", chunks[0][1][:8])
    if not width or not height:
        fail("image-header", path)
    return width, height


def _vp8(body: bytes, path: str) -> tuple[int, int]:
    # A key frame: a three-byte frame tag with bit 0 clear and a first-partition size within the chunk, the start
    # code, then 14-bit width and height.
    if len(body) < 10 or body[0] & 1 or body[3:6] != b"\x9d\x01\x2a":
        fail("image-header", path)
    partition = (body[0] | body[1] << 8 | body[2] << 16) >> 5
    if partition == 0 or 10 + partition > len(body):
        fail("image-header", path)
    width, height = struct.unpack("<HH", body[6:10])
    return width & 0x3FFF, height & 0x3FFF


def _vp8l(body: bytes, path: str) -> tuple[int, int]:
    if len(body) < 5 or body[0] != 0x2F:
        fail("image-header", path)
    bits = struct.unpack("<I", body[1:5])[0]
    if bits >> 29:
        fail("image-header", path)
    return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1


def _webp(data: bytes, path: str) -> tuple[int, int]:
    """The RIFF size equals the file size, every chunk is complete, and the image data is present."""
    if len(data) < 20 or struct.unpack("<I", data[4:8])[0] + 8 != len(data):
        fail("image-header", path)
    chunks, offset = [], 12
    while offset < len(data):
        if offset + 8 > len(data):
            fail("image-header", path)
        kind, size = struct.unpack("<4sI", data[offset:offset + 8])
        end = offset + 8 + size
        if end > len(data):
            fail("image-header", path)
        chunks.append((kind, data[offset + 8:end]))
        offset = end + (size & 1)
    if offset != len(data) or not chunks:
        fail("image-header", path)
    first, body = chunks[0]
    if first == b"VP8 " and len(chunks) == 1:
        return _vp8(body, path)
    if first == b"VP8L" and len(chunks) == 1:
        return _vp8l(body, path)
    if first == b"VP8X" and len(body) >= 10:
        width, height = int.from_bytes(body[4:7], "little") + 1, int.from_bytes(body[7:10], "little") + 1
        images = [(kind, value) for kind, value in chunks[1:] if kind in (b"VP8 ", b"VP8L")]
        if len(images) != 1 or any(kind in (b"ANIM", b"ANMF") for kind, _ in chunks):
            fail("image-header", path)
        kind, value = images[0]
        inner = _vp8(value, path) if kind == b"VP8 " else _vp8l(value, path)
        if inner != (width, height):
            fail("image-header", path)
        return width, height
    fail("image-header", path)


def image_size(data: bytes, path: str) -> tuple[str, int, int]:
    """("png" or "webp", width, height) for a structurally complete image; anything else is refused."""
    if data.startswith(PNG_SIGNATURE):
        return ("png", *_png(data, path))
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ("webp", *_webp(data, path))
    fail("image-type", path)


def validate_images(manifest: dict, payloads: dict[str, bytes]) -> None:
    """Each listed image is a PNG or WebP of at most 2 MiB whose structure checks and whose size is the stated one."""
    for image in manifest["images"]:
        data = payloads[image["path"]]
        if len(data) > MAXIMUM_IMAGE_BYTES:
            fail("image-limit", image["path"])
        kind, width, height = image_size(data, image["path"])
        if not image["path"].lower().endswith("." + kind):
            fail("image-type", image["path"])
        if (width, height) != (image["width"], image["height"]):
            fail("image-size", image["path"])
