"""Release channels, preview versions, update policy, example images, class and category fields, vulnerability waivers
and the questions to ask."""

import copy
import json
import struct
import tempfile
import unittest
from pathlib import Path

from aepm.model import AepmError, canonical, digest, package_version, validate_component, version_key
from tests.core.test_core import CLASS_FIELDS, fixture, png


def webp(chunk, body):
    payload = b"WEBP" + chunk + struct.pack("<I", len(body)) + body + (b"\x00" if len(body) % 2 else b"")
    return b"RIFF" + struct.pack("<I", len(payload)) + payload


def vp8_body(width, height):
    # A shown key frame whose first partition is 8 bytes.
    return b"\x10\x01\x00" + b"\x9d\x01\x2a" + struct.pack("<HH", width, height) + b"\x00" * 8


def vp8(width, height):
    return webp(b"VP8 ", vp8_body(width, height))


def vp8l(width, height):
    return webp(b"VP8L", b"\x2f" + struct.pack("<I", (width - 1) | ((height - 1) << 14)) + b"\x00" * 4)


def chunk(kind, body):
    return kind + struct.pack("<I", len(body)) + body + (b"\x00" if len(body) % 2 else b"")


def vp8x(width, height, *chunks):
    header = b"\x10\x00\x00\x00" + (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(3, "little")
    payload = b"WEBP" + chunk(b"VP8X", header) + b"".join(chunks or (chunk(b"ALPH", b"\x00" * 5), chunk(b"VP8 ", vp8_body(width, height))))
    return b"RIFF" + struct.pack("<I", len(payload)) + payload


class Base(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.manifest = fixture(self.root / "source")

    def refused(self, code, manifest=None):
        with self.assertRaises(AepmError) as raised:
            validate_component(manifest if manifest is not None else self.manifest)
        self.assertEqual(raised.exception.code, code)

    def with_class(self, manifest, **fields):
        """The manifest's own class with changed descriptor fields, its reference re-bound."""
        manifest = copy.deepcopy(manifest)
        descriptor = {**manifest["classes"][0]["descriptor"], **fields}
        reference = {"name": descriptor["name"], "version": descriptor["version"], "digest": digest(canonical(descriptor))}
        manifest["classes"] = [{"reference": reference, "descriptor": descriptor}]
        manifest["implements"] = [reference]
        return manifest


class ReleaseTests(Base):
    def at(self, number, channel, fixes=()):
        manifest = copy.deepcopy(self.manifest)
        manifest["identity"]["version"] = number
        manifest["release"] = {"channel": channel, "fixes": list(fixes)}
        return manifest

    def test_the_channel_follows_the_version(self):
        for number, channel, fixes in (("1.2.0", "features", ()), ("1.2.3", "security", ("GHSA-abcd-efgh-ijkl",)),
                                       ("1.3.0-preview.2", "preview", ()), ("0.9.1", "security", ("CVE-2026-12345", "PYSEC-2026-7"))):
            with self.subTest(number=number):
                validate_component(self.at(number, channel, fixes))
        for number, channel, fixes in (("1.2.3", "features", ()), ("1.2.0", "security", ("CVE-2026-1",)),
                                       ("1.2.3", "security", ()), ("1.2.0", "features", ("CVE-2026-1",)),
                                       ("1.3.0-preview.1", "features", ()), ("1.3.0", "preview", ()),
                                       ("1.3.0-preview.1", "preview", ("GO-2026-1",))):
            with self.subTest(number=number, channel=channel, fixes=fixes):
                self.refused("release-channel", self.at(number, channel, fixes))

    def test_advisory_ids_and_channels_are_checked(self):
        for fixes in (["ghsa-lower-case"], ["CVE"], ["GHSA-" + "x" * 60], ["CVE-2026-1", "CVE-2026-1"]):
            with self.subTest(fixes=fixes), self.assertRaises(AepmError):
                validate_component(self.at("1.0.1", "security", fixes))
        for value in ({"channel": "stable", "fixes": []}, {"channel": "features"}, None):
            manifest = copy.deepcopy(self.manifest)
            manifest["release"] = value
            with self.subTest(value=value), self.assertRaises(AepmError):
                validate_component(manifest)

    def test_preview_versions_and_their_order(self):
        for number in ("1.0.0-preview.1", "0.9.0-preview.12"):
            package_version(number, "version")
        for number in ("1.0.0-preview.0", "1.0.0-beta.1", "1.0.0-preview", "1.0.0+build.1", "1.0.0-preview.01", "01.0.0"):
            with self.subTest(number=number), self.assertRaises(AepmError):
                package_version(number, "version")
        ordered = ["0.9.0", "1.0.0-preview.1", "1.0.0-preview.2", "1.0.0-preview.10", "1.0.0", "1.0.1", "1.1.0-preview.1"]
        self.assertEqual(sorted(reversed(ordered), key=version_key), ordered)

    def test_class_and_interface_versions_have_no_preview(self):
        self.refused("invalid-version", self.with_class(self.manifest, version="1.0.0-preview.1"))
        manifest = copy.deepcopy(self.manifest)
        manifest["provides"] = [{"id": "port", "type": "port", "version": "1.0.0-preview.1", "path": "interface.txt"}]
        self.refused("invalid-version", manifest)

    def test_earlier_manifest_formats_and_upgrade_policy_are_refused(self):
        for number in (1, 2):
            manifest = copy.deepcopy(self.manifest)
            manifest["format"] = number
            with self.subTest(format=number):
                self.refused("manifest-format-outdated", manifest)
        manifest = copy.deepcopy(self.manifest)
        manifest["upgrade"]["policy"] = "patch"
        self.refused("invalid-fields", manifest)


class WaiverTests(Base):
    def test_waivers_name_an_advisory_and_a_reason(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["vulnerabilityWaivers"] = [{"id": "GHSA-abcd-efgh-ijkl", "reason": "the affected parser is never called"},
                                            {"id": "RUSTSEC-2026-0001", "reason": "build time only"}]
        validate_component(manifest)
        for waivers in ([{"id": "GHSA-abcd", "reason": ""}], [{"id": "not an id", "reason": "x"}], [{"id": "CVE-2026-1"}],
                        [{"id": "CVE-2026-1", "reason": "a"}, {"id": "CVE-2026-1", "reason": "b"}], None):
            manifest["vulnerabilityWaivers"] = waivers
            with self.subTest(waivers=waivers), self.assertRaises(AepmError):
                validate_component(manifest)


class ImageTests(Base):
    def packed(self, manifest, files):
        """Pack a copy of the fixture with these image files; the AepmError code, or None when it packs."""
        from aepm.bundle import pack
        source = self.root / ("source-" + digest(canonical(manifest))[:8])
        fixture(source)
        for path, data in files.items():
            (source / path).write_bytes(data)
            if path not in {item["path"] for item in manifest["files"]}:
                manifest["files"].append({"path": path, "executable": False})
        manifest["files"].sort(key=lambda item: item["path"])
        (source / "component.json").write_bytes(canonical(manifest))
        try:
            pack(source, self.root / "store")
        except AepmError as error:
            return error.code
        return None

    def image(self, path, width, height, **changes):
        return {"path": path, "caption": "The example", "platform": "web", "width": width, "height": height, **changes}

    def test_png_and_webp_sizes_are_read_from_their_headers(self):
        from aepm.images import image_size
        self.assertEqual(image_size(png(7, 5), "a.png"), ("png", 7, 5))
        self.assertEqual(image_size(vp8(640, 480), "a.webp"), ("webp", 640, 480))
        self.assertEqual(image_size(vp8l(1280, 800), "a.webp"), ("webp", 1280, 800))
        self.assertEqual(image_size(vp8x(4000, 3000), "a.webp"), ("webp", 4000, 3000))
        good = png(3, 2)
        idat = good.index(b"IDAT") - 4
        no_idat = good[:idat] + good[good.index(b"IEND") - 4:]
        bad_crc = bytearray(good)
        bad_crc[idat + 9] ^= 1
        vp8l_version = webp(b"VP8L", b"\x2f" + struct.pack("<I", 9 | (9 << 14) | (1 << 29)) + b"\x00" * 4)
        for name, data in (("gif", b"GIF89a" + b"\x00" * 40), ("short png", good[:20]), ("png crc", bytes(bad_crc)),
                           ("png without image data", no_idat), ("png after its end", good + b"\x00"),
                           ("png without end", good[:good.index(b"IEND") - 4]),
                           ("webp truncated", vp8(10, 10)[:-4]), ("webp riff size", vp8(10, 10) + b"\x00\x00"),
                           ("vp8 not a key frame", webp(b"VP8 ", b"\x11" + vp8_body(10, 10)[1:])),
                           ("vp8 partition past the chunk", webp(b"VP8 ", b"\x10\x08\x00" + vp8_body(10, 10)[3:])),
                           ("vp8l signature", webp(b"VP8L", b"\x00" * 5)), ("vp8l version", vp8l_version),
                           ("alpha only", webp(b"ALPH", b"\x00" * 10)),
                           ("vp8x without image data", vp8x(8, 8, chunk(b"ALPH", b"\x00" * 5))),
                           ("vp8x size disagrees", vp8x(8, 8, chunk(b"VP8 ", vp8_body(9, 8)))),
                           ("vp8x animation", vp8x(8, 8, chunk(b"ANIM", b"\x00" * 6), chunk(b"VP8 ", vp8_body(8, 8))))):
            with self.subTest(name=name), self.assertRaises(AepmError):
                image_size(data, "image")

    def test_listed_images_must_match_their_files(self):
        cases = {
            None: ({"shot.webp": vp8l(320, 200)}, [self.image("shot.webp", 320, 200)]),
            "image-size": ({"shot.png": png(8, 6)}, [self.image("shot.png", 8, 7)]),
            "image-type": ({"shot.png": vp8(8, 8)}, [self.image("shot.png", 8, 8)]),
            "image-limit": ({"big.png": png(1, 1) + b"\x00" * (2 * 1024 * 1024)}, [self.image("big.png", 1, 1)]),
        }
        for expected, (files, images) in cases.items():
            manifest = copy.deepcopy(self.manifest)
            manifest["images"] = images
            with self.subTest(expected=expected):
                self.assertEqual(self.packed(manifest, files), expected)

    def test_image_list_rules(self):
        base = self.image("example.png", 4, 3)
        for code, images in (("image-limit", [dict(base, path=f"i{n}.png") for n in range(13)]),
                             ("invalid-string", [dict(base, caption="x" * 141)]),
                             ("image-platform", [dict(base, platform="ios")]),
                             ("image-type", [dict(base, path="example.gif")]),
                             ("missing-required-path", [dict(base, path="absent.png")]),
                             ("duplicate-value", [base, base])):
            manifest = copy.deepcopy(self.manifest)
            manifest["images"] = images
            manifest["files"] += [{"path": item["path"], "executable": False} for item in images
                                  if item["path"] not in {f["path"] for f in manifest["files"]} and item["path"] != "absent.png"]
            with self.subTest(code=code):
                self.refused(code, manifest)

    def test_images_are_required_for_visual_classes_and_client_recipes(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["images"] = []
        validate_component(manifest)
        self.refused("images-required", self.with_class(manifest, presentation="visual"))
        recipe = dict(copy.deepcopy(manifest), kind="recipe", implements=[])
        recipe["artefacts"] = []
        self.refused("images-required", recipe)
        recipe.update(platforms=["server"], toolchains={"server": []})
        validate_component(recipe)


class ClassTests(Base):
    def test_class_fields_are_validated(self):
        validate_component(self.with_class(self.manifest, category="games/cards", presentation="visual",
                                           title="Card graphics", summary="Card faces and backs"))
        for change in ({"category": "Games/Cards"}, {"category": "games//cards"}, {"category": ""}, {"presentation": "hidden"},
                       {"title": ""}, {"summary": "x" * 501}):
            with self.subTest(change=change), self.assertRaises(AepmError):
                validate_component(self.with_class(self.manifest, **change))
        descriptor = dict(self.manifest["classes"][0]["descriptor"])
        del descriptor["presentation"]
        from aepm.foundations import validate_class_descriptor
        with self.assertRaises(AepmError):
            validate_class_descriptor(descriptor)

    def test_earlier_class_format_is_refused(self):
        from aepm.foundations import validate_class_descriptor
        descriptor = {key: value for key, value in self.manifest["classes"][0]["descriptor"].items()
                      if key not in ("title", "summary", "category", "presentation")}
        descriptor["format"] = 1
        with self.assertRaises(AepmError) as raised:
            validate_class_descriptor(descriptor)
        self.assertEqual(raised.exception.code, "class-format-outdated")

    def test_category_tree(self):
        from aepm.foundations import validate_categories

        def tree(*entries):
            return {"format": 1, "categories": [{"id": item, "title": item.title(), "parent": parent} for item, parent in entries]}

        good = tree(("games", None), ("games/cards", "games"), ("media", None))
        validate_categories(good, ["games/cards", "media"])
        for code, document, classes in (
                ("duplicate-value", tree(("games", None), ("games", None)), ()),
                ("category-unknown", tree(("games", None), ("games/cards/poker", "games/cards")), ()),
                ("category-unknown", tree(("games/cards", "games"),), ()),
                ("category-parent", tree(("a", "b"), ("b", "a")), ()),
                ("category-parent", tree(("games", None), ("games/cards", None)), ()),
                ("category-parent", tree(("games", None), ("media", None), ("games/cards", "media")), ()),
                ("category-parent", tree(("games", "games"),), ()),
                ("category-unknown", good, ["games/dice"]),
                ("invalid-category", tree(("Games", None)), ()),
                ("invalid-format", {"format": 2, "categories": []}, ()),
                ("expected-object", [], ())):
            with self.subTest(code=code, document=document), self.assertRaises(AepmError) as raised:
                validate_categories(document, classes)
            self.assertEqual(raised.exception.code, code)


class RecipeDocumentTests(unittest.TestCase):
    def test_recipe_format_and_question_rules(self):
        from aepm.recipe import validate_recipe_document
        good = {"format": 2, "questions": [
            {"id": "targets", "question": "Which devices?", "ask": "unless-settled", "default": ["web"]},
            {"id": "key", "question": "Which key?", "ask": "required"},
            {"id": "scale", "question": "How many?", "ask": "default", "default": "small"}]}
        validate_recipe_document(good)
        with self.assertRaises(AepmError) as raised:
            validate_recipe_document({**good, "format": 1})
        self.assertEqual(raised.exception.code, "recipe-format-outdated")
        for code, question in (("question-default", {"id": "a", "question": "A?", "ask": "required", "default": 1}),
                               ("question-default", {"id": "a", "question": "A?", "ask": "default"}),
                               ("question-default", {"id": "a", "question": "A?", "ask": "unless-settled"}),
                               ("invalid-value", {"id": "a", "question": "A?", "ask": "Which devices?", "default": 1}),
                               ("invalid-value", {"id": "a", "question": "A?", "default": 1}),
                               ("expected-string", {"id": "a", "ask": "default", "default": 1}),
                               ("expected-string", {"id": "a", "question": " ", "ask": "default", "default": 1})):
            with self.subTest(question=question), self.assertRaises(AepmError) as raised:
                validate_recipe_document({"format": 2, "questions": [question]})
            self.assertEqual(raised.exception.code, code)
        for document in ({"format": 3, "questions": []}, {"questions": []}, {"format": 2}):
            with self.subTest(document=document), self.assertRaises(AepmError) as raised:
                validate_recipe_document(document)
            self.assertEqual(raised.exception.code, "recipe-format")


class PurlTests(unittest.TestCase):
    """The package URL rule the catalogue applies (shared/src/foundations.ts parsePurl)."""

    CORPUS_SHA256 = "84e429d012f0931f6db2e67f2e4d2f61b76fab24b7a23a4e2ec6ea688563b470"

    def test_the_shared_corpus(self):
        import hashlib
        import json
        from aepm.foundations import parse_purl
        raw = (Path(__file__).parent / "fixtures/purl-cases.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.CORPUS_SHA256)
        cases = json.loads(raw)
        self.assertEqual((len(cases), sum(case["accept"] for case in cases)), (2069, 1905))
        wrong = [case["purl"] for case in cases if (parse_purl(case["purl"]) if case["accept"] else None) != (case.get("parts") if case["accept"] else None)
                 or (parse_purl(case["purl"]) is None) == case["accept"]]
        self.assertEqual(wrong, [])

    def test_package_urls_follow_the_specification(self):
        from aepm.foundations import _purl, parse_purl
        for value in ("pkg:npm/left-pad@1.3.0", "pkg:npm/%40angular/core@17.0.0", "pkg:npm/@angular/core@17.0.0",
                      "pkg:maven/org.example/lib@1.0", "pkg:swift/github.com/vapor/vapor@4.0.0", "pkg:golang/golang.org/x/net@0.1.0",
                      "pkg:pypi/requests@2.31.0", "pkg:cargo/serde@1.0.0", "pkg:generic/lib@1.0"):
            with self.subTest(value=value):
                self.assertIsNotNone(parse_purl(value))
        self.assertEqual(parse_purl("pkg:npm/%40angular/core@17.0.0"),
                         {"type": "npm", "namespace": ["@angular"], "name": "core", "version": "17.0.0", "qualifiers": {}, "subpath": []})
        for value in ("pkg:npm/@1.3.0", "pkg:swift/client-sdk-swift@2.19.0", "pkg:npm/", "npm/left-pad@1.3.0", "pkg:maven/lib@1.0",
                      "pkg:swift/lib@1.0", "pkg:swift/vapor/vapor@4.0.0", "pkg:pypi/acme/requests@1.0", "pkg:NPM/left-pad@1.0",
                      "pkg:npm/a//b@1.0", "pkg:npm/left pad@1.0", "pkg:npm/%E0%A4%A@1.0", "pkg:npm/a/b/c@1.0"):
            with self.subTest(value=value):
                self.assertIsNone(parse_purl(value))
                with self.assertRaisesRegex(AepmError, "invalid-purl"):
                    _purl(value, "upstream.purl", "1.0")
        _purl("pkg:swift/github.com/livekit/client-sdk-swift@2.19.0", "upstream.purl", "2.19.0")
        with self.assertRaisesRegex(AepmError, "upstream-purl"):
            _purl("pkg:npm/left-pad@1.3.0", "upstream.purl", "1.3.1")


class PolicyTests(unittest.TestCase):
    def test_update_policy_and_earlier_definitions(self):
        from aepm.application import DEFAULT_POLICY, parse_update_policy, validate_definition
        definition = {"format": 2, "id": "app", "title": "App", "recipe": {"name": "ourapps-ae/recipe", "version": "1.0.0-preview.1"},
                      "components": [], "configuration": {}, "design": {"definitions": [], "instances": [], "connections": []},
                      "updatePolicy": dict(DEFAULT_POLICY)}
        validate_definition(definition)
        self.assertEqual(DEFAULT_POLICY, {"security": "auto", "features": "manual", "preview": "hold"})
        for policy in ("patch", {"security": "auto", "features": "manual"}, {**DEFAULT_POLICY, "preview": "never"}):
            with self.subTest(policy=policy), self.assertRaises(AepmError):
                validate_definition({**definition, "updatePolicy": policy})
        with self.assertRaises(AepmError) as raised:
            validate_definition({**definition, "format": 1, "updatePolicy": "patch"})
        self.assertEqual(raised.exception.code, "definition-format-outdated")
        self.assertEqual(parse_update_policy("preview=manual,security=manual"), {"security": "manual", "features": "manual", "preview": "manual"})
        for text in ("preview", "nightly=auto", "security=sometimes"):
            with self.subTest(text=text), self.assertRaises(AepmError):
                parse_update_policy(text)

    def test_earlier_proposal_format_is_refused(self):
        from aepm.update import proposal_context
        from aepm.io import write
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proposal.json"
            write(path, {"format": 1, "stage": "/x/.app.aepm-transaction/stage", "changes": []})
            with self.assertRaises(AepmError) as raised:
                proposal_context(path)
        self.assertEqual(raised.exception.code, "proposal-format-outdated")

    def test_channel_offers(self):
        from aepm.channels import newest
        versions = ["1.0.0", "1.0.1", "1.0.2", "1.1.0-preview.1", "1.1.0", "1.1.1", "2.0.0-preview.1"]
        self.assertEqual(newest("1.0.0", versions, "security"), "1.0.2")
        self.assertEqual(newest("1.0.2", versions, "security"), None)
        self.assertEqual(newest("1.0.1", versions, "features"), "1.1.0")
        self.assertEqual(newest("1.0.1", versions, "preview"), "2.0.0-preview.1")
        self.assertEqual(newest("1.1.0", versions, "security"), "1.1.1")


if __name__ == "__main__":
    unittest.main()
