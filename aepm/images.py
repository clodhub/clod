"""Example image sizes read from PNG and WebP headers, with no image library."""

from __future__ import annotations

import struct

from .model import MAXIMUM_IMAGE_BYTES, fail

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def image_size(data: bytes, path: str) -> tuple[str, int, int]:
    """("png" or "webp", width, height) from the image's header; anything else is refused."""
    if data.startswith(PNG_SIGNATURE):
        if len(data) < 33 or data[8:16] != b"\x00\x00\x00\x0dIHDR":
            fail("image-header", path)
        width, height = struct.unpack(">II", data[16:24])
        return "png", width, height
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        if len(data) < 30 or struct.unpack("<I", data[4:8])[0] + 8 != len(data):
            fail("image-header", path)
        chunk, size, body = data[12:16], struct.unpack("<I", data[16:20])[0], data[20:]
        if size > len(body):
            fail("image-header", path)
        if chunk == b"VP8 ":
            # A key frame: a three-byte frame tag with bit 0 clear, the start code, then 14-bit width and height.
            if size < 10 or body[0] & 1 or body[3:6] != b"\x9d\x01\x2a":
                fail("image-header", path)
            width, height = struct.unpack("<HH", body[6:10])
            return "webp", width & 0x3FFF, height & 0x3FFF
        if chunk == b"VP8L":
            if size < 5 or body[0] != 0x2F:
                fail("image-header", path)
            bits = struct.unpack("<I", body[1:5])[0]
            return "webp", (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
        if chunk == b"VP8X":
            if size < 10:
                fail("image-header", path)
            return "webp", int.from_bytes(body[4:7], "little") + 1, int.from_bytes(body[7:10], "little") + 1
    fail("image-type", path)


def validate_images(manifest: dict, payloads: dict[str, bytes]) -> None:
    """Each listed image is a PNG or WebP of at most 2 MiB whose header gives the width and height the manifest states."""
    for image in manifest["images"]:
        data = payloads[image["path"]]
        if len(data) > MAXIMUM_IMAGE_BYTES:
            fail("image-limit", image["path"])
        kind, width, height = image_size(data, image["path"])
        if not image["path"].lower().endswith("." + kind):
            fail("image-type", image["path"])
        if (width, height) != (image["width"], image["height"]):
            fail("image-size", image["path"])
