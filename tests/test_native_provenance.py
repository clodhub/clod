"""Native resolved pins, checksum inventories and wrapper byte binding."""

from copy import deepcopy
import base64
import io
from pathlib import Path
import tempfile
import unittest
import zipfile

from clod.bom import bill_of_materials
from clod.bundle import pack, read_package
from clod.foundations import validate_graph, validate_package_foundations
from clod.io import load, write
from clod.model import ClodError, canonical, digest, validate_component
from tests.core.test_core import fixture

FIXTURES = Path(__file__).parent / "fixtures/native"


class NativeProvenanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source, self.store = self.root / "source", self.root / "store"
        self.manifest = fixture(self.source)
        self.add_file("notices/upstream.txt", b"Test fixture notice for external dependency metadata.\n")

    def add_file(self, path, raw):
        target = self.source / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        if path not in {item["path"] for item in self.manifest["files"]}:
            self.manifest["files"].append({"path": path, "executable": False})
        return digest(raw)

    def payloads(self):
        return {item["path"]: (self.source / item["path"]).read_bytes() for item in self.manifest["files"]}

    def check(self):
        return validate_package_foundations(self.manifest, self.payloads())

    def swift(self):
        lock = "native/apple/Package.resolved"
        checksum = self.add_file(lock, (FIXTURES / "Package.resolved").read_bytes())
        self.manifest["upstream"] = [{"name": "client-sdk-swift", "version": "2.19.0",
            "revision": "43c1c0870e51eedbfd95b20b1b5c43a767886786", "repository": "https://github.com/livekit/client-sdk-swift",
            "purl": "pkg:swift/github.com/livekit/client-sdk-swift@2.19.0", "licence": "Apache-2.0", "notices": ["notices/upstream.txt"],
            "delivery": {"kind": "build-time", "manager": "swift", "lock": lock, "digest": checksum}}]
        return self.manifest["upstream"][0]

    def gradle(self):
        lock, verification = "native/android/gradle.lockfile", "native/android/gradle/verification-metadata.xml"
        checksum = self.add_file(lock, (FIXTURES / "gradle.lockfile").read_bytes())
        metadata = self.add_file(verification, (FIXTURES / "verification-metadata.xml").read_bytes())
        self.manifest["upstream"] = [{"name": "livekit-android", "version": "2.29.0", "revision": None,
            "repository": "https://github.com/livekit/client-sdk-android", "purl": "pkg:maven/io.livekit/livekit-android@2.29.0",
            "licence": "Apache-2.0", "notices": ["notices/upstream.txt"], "delivery": {
                "kind": "build-time", "manager": "gradle", "lock": lock, "digest": checksum,
                "verification": {"path": verification, "digest": metadata}, "configurations": ["debugCompileClasspath", "releaseRuntimeClasspath"],
                "artifacts": [
                    {"name": "livekit-android-2.29.0.aar", "digest": "5b9f4d46471f5c1bd068b9f397218e1b3966ad27e3a8a7fe5c3eaff715c25e6e"},
                    {"name": "livekit-android-2.29.0.module", "digest": "e47125e4412a3f8dada5e43baba42be8f47ceb0ce2c4a10028276ce93d6fe259"}]}}]
        return self.manifest["upstream"][0]

    def wrapper(self):
        jar, properties = "wrapper/gradle-wrapper.jar", "wrapper/gradle-wrapper.properties"
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        jar_digest = self.add_file(jar, output.getvalue())
        properties_digest = self.add_file(properties, (FIXTURES / "gradle-wrapper.properties").read_bytes())
        self.manifest["upstream"] = [{"name": "gradle-wrapper", "version": "9.4.0", "revision": None,
            "repository": "https://github.com/gradle/gradle", "purl": "pkg:github/gradle/gradle@9.4.0", "licence": "Apache-2.0",
            "notices": ["notices/upstream.txt"], "delivery": {"kind": "bundled", "files": [
                {"path": jar, "digest": jar_digest}, {"path": properties, "digest": properties_digest}],
                "gradleWrapper": {"jar": jar, "properties": properties, "distribution": {
                    "url": "https://services.gradle.org/distributions/gradle-9.4.0-bin.zip",
                    "digest": "60ea723356d81263e8002fec0fcf9e2b0eee0c0850c7a3d7ab0a63f2ccc601f3"}}}}]
        return self.manifest["upstream"][0]

    def test_real_swift_pins_pack_and_read(self):
        self.swift()
        write(self.source / "component.json", self.manifest)
        ref = pack(self.source, self.store)
        manifest, payloads = read_package(ref, self.store)
        self.assertEqual(manifest["upstream"][0]["revision"], "43c1c0870e51eedbfd95b20b1b5c43a767886786")
        self.assertEqual(payloads["native/apple/Package.resolved"], (FIXTURES / "Package.resolved").read_bytes())

    def test_swift_identity_location_version_and_revision_bind(self):
        upstream = self.swift()
        original = load(self.source / upstream["delivery"]["lock"])
        changes = (
            lambda pin: pin.update(identity="different"), lambda pin: pin.update(location="https://example.org/source"),
            lambda pin: pin["state"].update(version="2.19.1"), lambda pin: pin["state"].update(revision="a" * 40),
        )
        for change in changes:
            document = deepcopy(original)
            change(document["pins"][0])
            upstream["delivery"]["digest"] = self.add_file(upstream["delivery"]["lock"], canonical(document))
            with self.assertRaisesRegex(ClodError, "upstream-lock-pin"):
                self.check()

    def test_swift_branch_duplicate_and_unknown_format_reject(self):
        upstream = self.swift()
        original = load(self.source / upstream["delivery"]["lock"])
        for change in (lambda value: value.update(version=2), lambda value: value["pins"].append(deepcopy(value["pins"][0])),
                       lambda value: value["pins"][0]["state"].update(branch="main")):
            document = deepcopy(original)
            change(document)
            upstream["delivery"]["digest"] = self.add_file(upstream["delivery"]["lock"], canonical(document))
            with self.assertRaises(ClodError):
                self.check()

    def test_swift_lock_bytes_and_missing_notice_reject(self):
        upstream = self.swift()
        self.add_file(upstream["delivery"]["lock"], b"{}")
        with self.assertRaisesRegex(ClodError, "upstream-lock-digest"):
            self.check()
        upstream["notices"] = ["missing"]
        with self.assertRaisesRegex(ClodError, "upstream-notice-missing"):
            validate_component(self.manifest)

    def test_real_gradle_coordinate_checksums_pack_and_bom(self):
        self.gradle()
        write(self.source / "component.json", self.manifest)
        ref = pack(self.source, self.store)
        read_package(ref, self.store)
        document = bill_of_materials(ref, self.store)
        imported = next(item for item in document["components"] if item.get("purl", "").startswith("pkg:maven/"))
        self.assertIn({"name": "clod:upstream:revision-status", "value": "unavailable"}, imported["properties"])
        self.assertFalse(any(item["name"] == "clod:upstream:revision" for item in imported["properties"]))

    def test_gradle_configuration_and_coordinate_bind(self):
        upstream = self.gradle()
        upstream["delivery"]["configurations"] = ["missingConfiguration"]
        with self.assertRaisesRegex(ClodError, "upstream-lock-pin"):
            self.check()
        upstream["delivery"]["configurations"] = ["debugCompileClasspath"]
        upstream["version"] = "2.29.1"
        upstream["purl"] = "pkg:maven/io.livekit/livekit-android@2.29.1"
        with self.assertRaisesRegex(ClodError, "upstream-lock-pin"):
            self.check()

    def test_gradle_same_module_different_configuration_versions_allowed(self):
        upstream = self.gradle()
        upstream.update(name="annotation", version="1.3.0", purl="pkg:maven/androidx.annotation/annotation@1.3.0")
        upstream["delivery"]["configurations"] = ["debugAndroidTestCompileClasspath"]
        upstream["delivery"]["artifacts"] = [
            {"name": "annotation-1.3.0.jar", "digest": "97dc45afefe3a1e421da42b8b6e9f90491477c45fc6178203e3a5e8a05ee8553"},
            {"name": "annotation-1.3.0.module", "digest": "9516c2ae44284ea0bd3d0eade0ee638879b708cbe31e3af92ba96c300604ebc3"}]
        self.check()
        upstream["delivery"]["configurations"].append("debugCompileClasspath")
        with self.assertRaisesRegex(ClodError, "upstream-lock-pin"):
            self.check()

    def test_gradle_duplicate_configuration_coordinate_rejects(self):
        upstream = self.gradle()
        path = upstream["delivery"]["lock"]
        raw = (self.source / path).read_bytes() + b"io.livekit:livekit-android:2.29.1=debugCompileClasspath\n"
        upstream["delivery"]["digest"] = self.add_file(path, raw)
        with self.assertRaisesRegex(ClodError, "upstream-lock-duplicate"):
            self.check()

    def test_gradle_lock_and_metadata_byte_tampering_reject(self):
        upstream = self.gradle()
        for key in ("lock", "verification"):
            if key == "lock":
                path, expected = upstream["delivery"]["lock"], upstream["delivery"]["digest"]
            else:
                path, expected = upstream["delivery"]["verification"].values()
            original = (self.source / path).read_bytes()
            self.add_file(path, original + b" ")
            with self.subTest(key=key), self.assertRaisesRegex(ClodError, "upstream-lock-digest"):
                self.check()
            self.add_file(path, original)
            self.assertEqual(digest(original), expected)

    def test_gradle_declared_checksums_and_inventory_bind(self):
        upstream = self.gradle()
        artifacts = upstream["delivery"]["artifacts"]
        artifacts[0]["digest"] = "a" * 64
        with self.assertRaisesRegex(ClodError, "upstream-verification-checksum"):
            self.check()
        artifacts.pop()
        with self.assertRaisesRegex(ClodError, "upstream-verification-inventory"):
            self.check()

    def test_gradle_metadata_coordinate_and_xml_entities_reject(self):
        upstream = self.gradle()
        verification = upstream["delivery"]["verification"]
        original = (self.source / verification["path"]).read_bytes()
        verification["digest"] = self.add_file(verification["path"], original.replace(b'name="livekit-android"', b'name="different"'))
        with self.assertRaisesRegex(ClodError, "upstream-verification-coordinate"):
            self.check()
        verification["digest"] = self.add_file(verification["path"], b'<!DOCTYPE data [<!ENTITY x "test">]>' + original)
        with self.assertRaisesRegex(ClodError, "upstream-verification-format"):
            self.check()

    def test_bundled_wrapper_has_separate_valid_inventory(self):
        self.wrapper()
        write(self.source / "component.json", self.manifest)
        ref = pack(self.source, self.store)
        read_package(ref, self.store)

    def test_wrapper_jar_and_properties_inventory_bind(self):
        upstream = self.wrapper()
        wrapper = upstream["delivery"]["gradleWrapper"]
        self.add_file(wrapper["jar"], b"changed")
        with self.assertRaisesRegex(ClodError, "upstream-file-digest"):
            self.check()
        upstream["delivery"]["files"] = [item for item in upstream["delivery"]["files"] if item["path"] != wrapper["properties"]]
        with self.assertRaisesRegex(ClodError, "upstream-wrapper-inventory"):
            validate_component(self.manifest)

    def test_wrapper_distribution_checksum_and_version_bind(self):
        upstream = self.wrapper()
        wrapper = upstream["delivery"]["gradleWrapper"]
        wrapper["distribution"]["digest"] = "a" * 64
        with self.assertRaisesRegex(ClodError, "upstream-wrapper-distribution"):
            self.check()
        wrapper["distribution"]["url"] = "https://services.gradle.org/distributions/gradle-9.4.1-bin.zip"
        with self.assertRaisesRegex(ClodError, "upstream-distribution-version"):
            validate_component(self.manifest)

    def test_wrapper_without_separate_upstream_record_rejects(self):
        self.wrapper()
        self.manifest["upstream"] = []
        with self.assertRaisesRegex(ClodError, "upstream-wrapper-unattributed"):
            validate_component(self.manifest)

    def test_native_external_dependency_pins_are_exact_identifiers(self):
        self.manifest["compatibility"]["dependencies"] = [{"name": "pkg:maven/com.google.guava/guava", "version": "33.3.1-jre", "isolation": "shared"}]
        validate_component(self.manifest)
        other = deepcopy(self.manifest)
        other["compatibility"]["dependencies"][0]["version"] = "32.0.1-jre"
        with self.assertRaisesRegex(ClodError, "shared-dependency-conflict"):
            validate_graph([self.manifest, other])
        for value in ("1.+", "[1,2)", "latest.release", "^1.0.0"):
            self.manifest["compatibility"]["dependencies"][0]["version"] = value
            with self.subTest(version=value), self.assertRaises(ClodError):
                validate_component(self.manifest)

    def test_missing_or_unsupported_manager_rejects(self):
        upstream = self.swift()
        upstream["delivery"].pop("manager")
        with self.assertRaises(ClodError):
            validate_component(self.manifest)
        upstream["delivery"]["manager"] = "other"
        with self.assertRaises(ClodError):
            validate_component(self.manifest)

    def npm_nested(self):
        integrity = "sha512-" + base64.b64encode(b"a" * 64).decode()
        lock = "package-lock.json"
        raw = canonical({"lockfileVersion": 3, "packages": {
            "node_modules/@scope/example": {"version": "2.0.0", "integrity": integrity},
            "node_modules/parent/node_modules/@scope/example": {"version": "1.0.0", "integrity": integrity}}})
        checksum = self.add_file(lock, raw)
        upstream = {"name": "@scope/example", "version": "1.0.0", "revision": "fixture-source", "repository": "https://example.org/source",
            "purl": "pkg:npm/%40scope/example@1.0.0", "licence": "MIT", "notices": ["notices/upstream.txt"],
            "delivery": {"kind": "build-time", "manager": "npm", "lock": lock, "digest": checksum,
                         "packagePath": "node_modules/parent/node_modules/@scope/example", "integrity": integrity}}
        self.manifest["upstream"] = [upstream]
        return upstream

    def test_nested_scoped_npm_pin_uses_explicit_lock_key(self):
        upstream = self.npm_nested()
        self.check()
        write(self.source / "component.json", self.manifest)
        ref = pack(self.source, self.store)
        read_package(ref, self.store)
        upstream["delivery"]["packagePath"] = "node_modules/@scope/example"
        with self.assertRaisesRegex(ClodError, "upstream-lock-pin"):
            self.check()

    def test_npm_lock_key_name_path_and_integrity_bind(self):
        upstream = self.npm_nested()
        for path in ("node_modules/different", "../node_modules/@scope/example", "node_modules/parent/@scope/example"):
            upstream["delivery"]["packagePath"] = path
            with self.subTest(path=path), self.assertRaises(ClodError):
                self.check()
        upstream["delivery"]["packagePath"] = "node_modules/parent/node_modules/@scope/example"
        upstream["delivery"]["integrity"] = "sha512-" + base64.b64encode(b"b" * 64).decode()
        with self.assertRaisesRegex(ClodError, "upstream-lock-pin"):
            self.check()


if __name__ == "__main__":
    unittest.main()
