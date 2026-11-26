"""Package class behaviour, provenance and graph acceptance boundaries."""

import base64
from copy import deepcopy
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from clod.application import assemble, requirements
from clod.bom import bill_of_materials
from clod.bundle import pack, read_archive, read_package, resolve, source_tree_digest
from clod.foundations import (class_descriptor, maintenance_facts, module_sources, selected_targets,
                             source_for_module, validate_graph, validate_package_foundations)
from clod.io import load, write
from clod.model import ClodError, canonical, digest, validate_component
from clod.recipe import Package, fit
from clod.test_identities import generate
from clod.trust import publish_release, publish_review, review_bindings, verify_package
from clod.verification import review_package
from tests.core.test_core import CLASS_FIELDS, PYTHON, fixture, without_execution


CHECK = b"""import importlib.util, json, os
from pathlib import Path
root = Path(os.environ['CLOD_CANDIDATE_ROOT'])
manifest = json.loads(Path(os.environ['CLOD_CANDIDATE_MANIFEST']).read_text())
destination = 'components/' + manifest['identity']['name'].rsplit('/', 1)[1] + '/counter.py'
path = Path(json.loads(os.environ['CLOD_MODULE_MAP'])[destination])
assert path.is_relative_to(root)
assert not os.environ.get('AWS_SECRET_ACCESS_KEY')
spec = importlib.util.spec_from_file_location('candidate', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.increment(4) == 5
assert len(os.environ['CLOD_CANDIDATE_DIGEST']) == 64
"""


def counter(root, name="counter", implementation=b"def increment(value):\n    return value + 1\n"):
    manifest = fixture(root, name)
    data = {"classes/counter/interface.json": b'{"type":"com.clodhub/counter"}', "classes/counter/check.py": CHECK,
            "source/counter.py": implementation}
    for path, raw in data.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        manifest["files"].append({"path": path, "executable": False})
    descriptor = {**CLASS_FIELDS, "name": "pkg:clod/com.clodhub/counter-class", "version": "1.0.0",
                  "provides": [{"type": "com.clodhub/counter", "version": "1.0.0", "path": "classes/counter/interface.json",
                                "modules": {"web": ["counter.py"], "ios": ["counter.py"]}}],
                  "requires": [], "settings": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
                  "inventory": [{"path": path, "digest": digest(raw)} for path, raw in data.items() if path.startswith("classes/")],
                  "verification": [{**without_execution(manifest["verification"][0]), "id": "increment", "argv": [PYTHON, "classes/counter/check.py"],
                                    "fixtures": ["classes/counter/check.py"]}]}
    reference = {"name": descriptor["name"], "version": descriptor["version"], "digest": digest(canonical(descriptor))}
    manifest.update(platforms=["web", "ios"], toolchains={"web": [], "ios": []}, classes=[{"reference": reference, "descriptor": descriptor}], implements=[reference],
                    provides=[{"id": "counter", "type": "com.clodhub/counter", "version": "1.0.0", "path": "interface.txt"}],
                    artefacts=[{"source": "source/counter.py", "destination": f"components/{name}/counter.py", "template": False, "executable": False}])
    write(root / "component.json", manifest)
    return manifest


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source, self.store = self.root / "source", self.root / "store"
        self.manifest = counter(self.source)

    def save(self):
        write(self.source / "component.json", self.manifest)

    def package(self, manifest=None, root=None):
        manifest, root = manifest or self.manifest, root or self.source
        return Package(manifest, lambda path: (root / path).read_bytes())

    def ref(self):
        return self.manifest["implements"][0]

    def sign_for_review(self, refs):
        policy = generate(self.root / "keys")
        document = load(policy)
        document["trustedExecution"] = [ref["digest"] for ref in refs]
        write(policy, document)
        for ref in refs:
            publish_release(self.store, ref, self.root / "keys/release.pem")
        return policy

    def test_required_metadata_is_strict(self):
        for key in ("classes", "implements", "platforms", "toolchains", "upstream", "compatibility", "maintenance"):
            changed = deepcopy(self.manifest)
            del changed[key]
            with self.subTest(key=key), self.assertRaisesRegex(ClodError, "invalid-fields"):
                validate_component(changed)
        for change in (lambda m: m.update(implements=[]), lambda m: m.update(platforms=["apple"]),
                       lambda m: m["maintenance"].update(lastSuccessfulVerification="2026-01-01"),
                       lambda m: m["classes"][0]["descriptor"].update(extra=True)):
            changed = deepcopy(self.manifest)
            change(changed)
            with self.assertRaises(ClodError):
                validate_component(changed)

    def test_descriptor_and_interface_and_test_tampering_rejected(self):
        self.manifest["classes"][0]["descriptor"]["requires"] = [{"type": "com.clodhub/other", "version": "1.0.0"}]
        self.save()
        with self.assertRaisesRegex(ClodError, "class-digest"):
            pack(self.source, self.store)
        self.manifest = counter(self.root / "intact")
        self.source = self.root / "intact"
        for path in ("classes/counter/check.py", "classes/counter/interface.json"):
            original = (self.source / path).read_bytes()
            (self.source / path).write_bytes(b"assert True\n")
            with self.subTest(path=path), self.assertRaisesRegex(ClodError, "class-file-digest"):
                pack(self.source, self.store)
            (self.source / path).write_bytes(original)
        self.assertFalse(self.store.exists())

    def test_archive_reader_rejects_tampering_with_recomputed_source_and_archive_hashes(self):
        ref = pack(self.source, self.store)
        manifest, payloads = read_package(ref, self.store)
        payloads["classes/counter/check.py"] = b"assert True\n"
        manifest["identity"]["sourceTreeDigest"] = source_tree_digest(manifest, payloads)
        payloads["component.json"] = canonical(manifest)
        output = io.BytesIO()
        executable = {item["path"] for item in manifest["files"] if item["executable"]}
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for path in sorted(payloads):
                info = tarfile.TarInfo(path)
                info.size = len(payloads[path])
                info.mode = 0o755 if path in executable else 0o644
                archive.addfile(info, io.BytesIO(payloads[path]))
        raw = output.getvalue()
        with self.assertRaisesRegex(ClodError, "class-file-digest"):
            read_archive({**ref, "digest": digest(raw)}, raw)

    def test_candidate_documents_are_independent(self):
        other_root = self.root / "other"
        other = counter(other_root, "other")
        (other_root / "interface.txt").write_text("Provider-specific explanation\n")
        self.assertEqual(fit(self.ref(), self.package(other, other_root), self.package(), ["web"]), [])
        self.assertEqual(source_for_module(other, other_root, "components/other/counter.py"), other_root / "source/counter.py")
        self.assertEqual(source_for_module(other, other_root, "components/theme/counter.py", slot="theme"), other_root / "source/counter.py")
        self.assertEqual(module_sources(other, other_root)["components/other/counter.py"], str(other_root / "source/counter.py"))

    def test_fit_reads_only_the_exact_class_inventory_without_caching(self):
        authority = self.package()
        other_root = self.root / "other"
        other = counter(other_root, "other")
        candidate = self.package(other, other_root)
        expected = {item["path"] for item in self.manifest["classes"][0]["descriptor"]["inventory"]}
        reads = {"authority": [], "candidate": []}
        for label, package in (("authority", authority), ("candidate", candidate)):
            original = package.file

            def limited(path, label=label, original=original):
                self.assertIn(path, expected, "Fit read a file outside its referenced class inventory")
                reads[label].append(path)
                return original(path)

            package.file = limited
        self.assertEqual(fit(self.ref(), candidate, authority, ["web"]), [])
        self.assertEqual(set(reads["authority"]), expected)
        self.assertEqual(set(reads["candidate"]), expected)
        for root, reader in ((other_root, "candidate"), (self.source, "authority")):
            path = root / "classes/counter/check.py"
            original = path.read_bytes()
            path.write_bytes(b"assert True\n")
            self.assertEqual(fit(self.ref(), candidate, authority, ["web"]), ["class-file-digest:pkg:clod/com.clodhub/counter-class"])
            self.assertGreater(len(reads[reader]), len(expected))
            path.write_bytes(original)

    def test_weak_candidate_class_is_not_the_recipe_class(self):
        other_root = self.root / "other"
        other = counter(other_root, "other")
        (other_root / "classes/counter/check.py").write_bytes(b"assert True\n")
        descriptor = other["classes"][0]["descriptor"]
        descriptor["inventory"][1]["digest"] = digest(b"assert True\n")
        other["classes"][0]["reference"]["digest"] = digest(canonical(descriptor))
        self.assertEqual(fit(self.ref(), self.package(other, other_root), self.package(), ["web"]), ["class-unavailable:pkg:clod/com.clodhub/counter-class"])

    def test_actual_candidate_failure_defeats_own_passing_tests(self):
        (self.source / "source/counter.py").write_bytes(b"def increment(value):\n    return value + 9\n")
        ref = pack(self.source, self.store)
        policy = self.sign_for_review([ref])
        report = review_package(ref, self.store, policy, True)
        own = next(item for item in report["suites"] if item["id"] == "unit")
        shared = next(item for item in report["suites"] if item["id"].startswith("class:"))
        self.assertEqual((own["status"], shared["status"], report["summary"]["required-local"]), ("passed", "failed", "failed"))
        self.assertEqual(shared["package"], ref["digest"])
        inventory = self.manifest["classes"][0]["descriptor"]["inventory"]
        self.assertEqual(shared["classEvidence"]["inventoryDigest"], digest(canonical(inventory)))
        self.assertIn({"path": "classes/counter/check.py", "digest": digest(CHECK)}, inventory)
        with self.assertRaisesRegex(ClodError, "report-verdict"):
            publish_review(self.store, ref, report, self.root / "keys/guardian.pem", policy=policy)

    def test_signed_class_results_and_maintenance_facts(self):
        ref = pack(self.source, self.store)
        policy = self.sign_for_review([ref])
        with patch.dict("os.environ", {"AWS_SECRET_ACCESS_KEY": "not-for-tests"}):
            report = review_package(ref, self.store, policy, True)
        self.assertEqual(report["summary"]["required-local"], "passed")
        publish_review(self.store, ref, report, self.root / "keys/guardian.pem", policy=policy)
        verify_package(ref, self.store, policy)
        facts = maintenance_facts(ref, self.store, policy)
        self.assertEqual(facts["reportDigest"], digest(canonical(report)))
        self.assertRegex(facts["lastSuccessfulVerification"], r"^\d{4}-\d\d-\d\dT")
        self.reject_class_evidence_changes(ref, report, policy)

    def reject_class_evidence_changes(self, ref, report, policy):
        def shared(value):
            return next(item for item in value["suites"] if "classEvidence" in item)

        def plain(value):
            return next(item for item in value["suites"] if "classEvidence" not in item)

        for code, change in (
                ("class-evidence-inventory", lambda value: shared(value)["classEvidence"].update(inventoryDigest=digest(b"other inventory"))),
                ("class-evidence-binding", lambda value: shared(value)["classEvidence"]["reference"].update(version="1.0.1")),
                ("class-evidence-time", lambda value: shared(value)["classEvidence"].update(startedAt=shared(value)["classEvidence"]["completedAt"] + 1)),
                ("invalid-fields", lambda value: shared(value)["classEvidence"].update(files=[])),
                ("expected-object", lambda value: shared(value).pop("classEvidence")),
                ("class-evidence-unexpected", lambda value: plain(value).update(classEvidence=deepcopy(shared(value)["classEvidence"]))),
                ("suite-coverage", lambda value: value.update(suites=[item for item in value["suites"] if "classEvidence" not in item]))):
            changed = deepcopy(report)
            change(changed)
            with self.subTest(code=code), self.assertRaisesRegex(ClodError, code):
                publish_review(self.store, ref, changed, self.root / "keys/guardian.pem", policy=policy)

    def test_report_size_is_independent_of_class_inventory_size(self):
        """A class inventory of several megabytes run by many class suites keeps each signed record constant-size."""
        entry = self.manifest["classes"][0]
        descriptor = entry["descriptor"]
        for index in range(48):
            raw = canonical({"index": index, "text": "x" * 120000})
            path = f"classes/counter/data/part-{index:02d}.json"
            (self.source / path).parent.mkdir(parents=True, exist_ok=True)
            (self.source / path).write_bytes(raw)
            self.manifest["files"].append({"path": path, "executable": False})
            descriptor["inventory"].append({"path": path, "digest": digest(raw)})
        template = descriptor["verification"][0]
        descriptor["verification"] = [{**deepcopy(template), "id": f"increment-{index}"} for index in range(6)]
        entry["reference"]["digest"] = digest(canonical(descriptor))
        self.manifest["implements"] = [entry["reference"]]
        self.manifest["format"] = 4
        for suite in self.manifest["verification"]:
            suite["execution"] = {"kind": "local", "simulation": False, "operations": [], "settings": [],
                                  "secrets": [], "resources": [], "assertions": [], "cleanup": None}
        self.save()
        ref = pack(self.source, self.store)
        inventory_bytes = sum(len((self.source / item["path"]).read_bytes()) for item in descriptor["inventory"])
        self.assertGreater(inventory_bytes, 5 * 1024 * 1024)
        policy = self.sign_for_review([ref])
        report = review_package(ref, self.store, policy, True)
        self.assertEqual((report["format"], report["summary"]["required-local"]), (4, "passed"), report)
        records = [item["classEvidence"] for item in report["suites"] if "classEvidence" in item]
        self.assertEqual(len(records), 6)
        self.assertTrue(all(len(canonical(record)) < 400 for record in records))
        self.assertLess(len(canonical(report)), 8 * 1024)
        # 112 class suites, as in the full OurPoker update, stay far below the 1 MiB report limit.
        self.assertLess(112 * max(len(canonical(item)) for item in report["suites"]), 128 * 1024)
        publish_review(self.store, ref, report, self.root / "keys/guardian.pem", policy=policy)
        verify_package(ref, self.store, policy)
        self.reject_class_evidence_changes(ref, report, policy)

    def test_class_suite_records_only_bytes_matching_its_inventory(self):
        from clod.foundations import class_result_evidence, class_suites
        suite = class_suites(self.manifest)[0]
        record = class_result_evidence(suite, self.source, 10, 11)
        self.assertEqual(record, {"reference": suite["class"], "inventoryDigest": digest(canonical(suite["classInventory"])),
                                  "startedAt": 10, "completedAt": 11})
        (self.source / "classes/counter/check.py").write_bytes(b"assert True\n")
        with self.assertRaisesRegex(ClodError, "class-file-digest"):
            class_result_evidence(suite, self.source, 10, 11)

    def test_class_identity_conflict_across_graph(self):
        other = counter(self.root / "other", "other")
        other["classes"][0]["descriptor"]["settings"]["required"] = []
        other["classes"][0]["descriptor"]["verification"][0]["timeoutSeconds"] = 20
        other["classes"][0]["reference"]["digest"] = digest(canonical(other["classes"][0]["descriptor"]))
        with self.assertRaisesRegex(ClodError, "class-identity-conflict"):
            validate_graph([self.manifest, other])

    def test_exact_reference_and_missing_inventory_rejected(self):
        payloads = {item["path"]: (self.source / item["path"]).read_bytes() for item in self.manifest["files"]}
        for reference in ({**self.ref(), "version": "1.0.1"}, {**self.ref(), "digest": "f" * 64}):
            with self.assertRaisesRegex(ClodError, "class-unavailable"):
                class_descriptor(self.manifest, payloads, reference)
        del payloads["classes/counter/check.py"]
        with self.assertRaisesRegex(ClodError, "class-file-digest"):
            validate_package_foundations(self.manifest, payloads)

    def test_web_only_candidate_fails_native_fit(self):
        other_root = self.root / "other"
        other = counter(other_root, "other")
        other["platforms"] = ["web"]
        other["toolchains"] = {"web": []}
        self.assertEqual(fit(self.ref(), self.package(other, other_root), self.package(), ["web"]), [])
        self.assertEqual(fit(self.ref(), self.package(other, other_root), self.package(), ["ios"]), ["platform:ios"])
        other["artefacts"] = []
        self.assertIn("module:web:counter.py", fit(self.ref(), self.package(other, other_root), self.package(), ["web"]))

    def test_blanket_platform_claim_does_not_replace_interface_modules(self):
        other_root = self.root / "other"
        other = counter(other_root, "other")
        for manifest in (self.manifest, other):
            descriptor = manifest["classes"][0]["descriptor"]
            descriptor["provides"][0]["modules"]["ios"] = ["native/Counter.swift"]
            manifest["classes"][0]["reference"]["digest"] = digest(canonical(descriptor))
        self.assertEqual(fit(self.ref(), self.package(other, other_root), self.package(), ["web"]), [])
        self.assertEqual(fit(self.ref(), self.package(other, other_root), self.package(), ["ios"]), ["module:ios:native/Counter.swift"])

    def test_selected_targets_are_checked(self):
        self.assertEqual(selected_targets(self.manifest, {"targets": ["web"]}), ["web"])
        with self.assertRaisesRegex(ClodError, "unsupported-platform"):
            selected_targets(self.manifest, {"targets": ["android"]})
        other = deepcopy(self.manifest)
        other["platforms"] = ["web"]
        other["toolchains"] = {"web": []}
        with self.assertRaisesRegex(ClodError, "unsupported-platform"):
            validate_graph([other], ["ios"])

    def test_runtime_and_framework_intersections(self):
        other = deepcopy(self.manifest)
        for kind in ("runtimes", "frameworks"):
            def entry(raw):
                return raw if kind == "runtimes" else {"name": "react", "range": raw}
            self.manifest["compatibility"][kind] = {"client": entry(">=18.0.0 <20.0.0")}
            other["compatibility"][kind] = {"client": entry(">=19.0.0 <=20.0.0")}
            validate_graph([self.manifest, other])
            other["compatibility"][kind] = {"client": entry(">=20.0.0 <21.0.0")}
            with self.assertRaisesRegex(ClodError, "compatibility-range-conflict"):
                validate_graph([self.manifest, other])
            self.manifest["compatibility"][kind] = {}
            other["compatibility"][kind] = {}
        self.manifest["compatibility"]["frameworks"] = {"web-ui": {"name": "vue", "range": ">=3.0.0 <4.0.0"}}
        other["compatibility"]["frameworks"] = {"web-ui": {"name": "react", "range": ">=19.0.0 <20.0.0"}}
        with self.assertRaisesRegex(ClodError, "framework-conflict"):
            validate_graph([self.manifest, other])

    def test_unknown_range_forms_rejected(self):
        for expression in ("^1.0.0", "~1.0.0", "1.x", "1.0.0", ">=1.0.0 || <2.0.0", ">=1.0.0-beta", ">=2.0.0 <2.0.0"):
            self.manifest["compatibility"]["runtimes"] = {"node": expression}
            with self.subTest(expression=expression), self.assertRaises(ClodError):
                validate_component(self.manifest)

    def test_shared_conflict_and_isolated_versions(self):
        other = deepcopy(self.manifest)
        self.manifest["compatibility"]["dependencies"] = [{"name": "pkg:npm/example", "version": "1.0.0", "isolation": "shared"}]
        other["compatibility"]["dependencies"] = [{"name": "pkg:npm/example", "version": "2.0.0", "isolation": "shared"}]
        with self.assertRaisesRegex(ClodError, "shared-dependency-conflict"):
            validate_graph([self.manifest, other])
        other["compatibility"]["dependencies"][0]["isolation"] = "isolated"
        validate_graph([self.manifest, other])
        self.manifest["compatibility"]["dependencies"][0]["isolation"] = "isolated"
        validate_graph([self.manifest, other])

    def test_stylesheet_collisions_and_explicit_conflicts(self):
        other = deepcopy(self.manifest)
        styles = {"scope": "global", "namespaces": ["button"], "conflicts": []}
        self.manifest["compatibility"]["styles"] = deepcopy(styles)
        other["compatibility"]["styles"] = deepcopy(styles)
        with self.assertRaisesRegex(ClodError, "stylesheet-conflict"):
            validate_graph([self.manifest, other])
        other["compatibility"]["styles"].update(scope="scoped", namespaces=["counter"])
        validate_graph([self.manifest, other])
        self.manifest["compatibility"]["styles"]["conflicts"] = ["counter"]
        with self.assertRaisesRegex(ClodError, "stylesheet-conflict"):
            validate_graph([self.manifest, other])

    def upstream(self, delivery):
        notice = "vendor-NOTICE"
        (self.source / notice).write_text("Copyright Example. MIT licence applies to upstream code.\n")
        self.manifest["files"].append({"path": notice, "executable": False})
        return {"name": "example", "version": "4.2.0", "revision": "abc123", "repository": "https://example.org/source",
                "purl": "pkg:npm/example@4.2.0", "licence": "MIT OR BSD-2-Clause", "notices": [notice], "delivery": delivery}

    def test_mixed_licences_and_bundled_source_inventory(self):
        raw = (self.source / "source/counter.py").read_bytes()
        upstream = self.upstream({"kind": "bundled", "files": [{"path": "source/counter.py", "digest": digest(raw)}]})
        self.manifest["upstream"] = [upstream]
        self.save()
        ref = pack(self.source, self.store)
        document = bill_of_materials(ref, self.store)
        self.assertEqual(document["metadata"]["component"]["licenses"], [{"expression": "Apache-2.0"}])
        imported = next(item for item in document["components"] if item.get("purl") == upstream["purl"])
        self.assertEqual((imported["licenses"], imported["version"]), ([{"expression": upstream["licence"]}], "4.2.0"))
        (self.source / "source/counter.py").write_bytes(b"changed")
        with self.assertRaisesRegex(ClodError, "upstream-file-digest"):
            pack(self.source, self.root / "other-store")

    def test_build_lock_integrity_and_version_tampering(self):
        integrity = "sha512-" + base64.b64encode(b"a" * 64).decode()
        lock = {"lockfileVersion": 3, "packages": {"node_modules/example": {"version": "4.2.0", "integrity": integrity}}}
        raw = canonical(lock)
        (self.source / "package-lock.json").write_bytes(raw)
        self.manifest["files"].append({"path": "package-lock.json", "executable": False})
        self.manifest["upstream"] = [self.upstream({"kind": "build-time", "manager": "npm", "lock": "package-lock.json", "digest": digest(raw), "packagePath": "node_modules/example", "integrity": integrity})]
        self.save()
        ref = pack(self.source, self.store)
        self.assertEqual(read_package(ref, self.store)[1]["package-lock.json"], raw)
        (self.source / "package-lock.json").write_bytes(raw + b" ")
        with self.assertRaisesRegex(ClodError, "upstream-lock-digest"):
            pack(self.source, self.root / "other-store")
        lock["packages"]["node_modules/example"]["version"] = "4.2.1"
        raw = canonical(lock)
        (self.source / "package-lock.json").write_bytes(raw)
        self.manifest["upstream"][0]["delivery"]["digest"] = digest(raw)
        self.save()
        with self.assertRaisesRegex(ClodError, "upstream-lock-pin"):
            pack(self.source, self.root / "other-store")

    def test_missing_notices_and_upstream_inventory_rejected(self):
        self.manifest["upstream"] = [self.upstream({"kind": "bundled", "files": [{"path": "absent", "digest": "0" * 64}]})]
        with self.assertRaisesRegex(ClodError, "upstream-source-missing"):
            validate_component(self.manifest)
        self.manifest["upstream"][0]["notices"] = ["absent-NOTICE"]
        with self.assertRaisesRegex(ClodError, "upstream-notice-missing"):
            validate_component(self.manifest)

    def test_native_build_time_delivery_cannot_declare_npm_manager(self):
        integrity = "sha512-" + base64.b64encode(b"a" * 64).decode()
        records = (
            ("pkg:maven/org.example/example@4.2.0", "gradle.lockfile", b"org.example:example:4.2.0=runtimeClasspath\n"),
            ("pkg:swift/example.org/owner/example@4.2.0", "Package.resolved", canonical({"pins": [], "version": 3})),
        )
        for purl, path, raw in records:
            with self.subTest(purl=purl):
                (self.source / path).write_bytes(raw)
                self.manifest["files"].append({"path": path, "executable": False})
                upstream = self.upstream({"kind": "build-time", "manager": "npm", "lock": path, "digest": digest(raw), "packagePath": "node_modules/example", "integrity": integrity})
                upstream["purl"] = purl
                self.manifest["upstream"] = [upstream]
                with self.assertRaisesRegex(ClodError, "unsupported-upstream-delivery"):
                    validate_component(self.manifest)
                self.manifest["files"] = [item for item in self.manifest["files"] if item["path"] not in (path, "vendor-NOTICE")]

    def test_native_identity_cannot_use_an_npm_lock_as_delivery_evidence(self):
        integrity = "sha512-" + base64.b64encode(b"a" * 64).decode()
        raw = canonical({"lockfileVersion": 3, "packages": {"node_modules/example": {"version": "4.2.0", "integrity": integrity}}})
        (self.source / "package-lock.json").write_bytes(raw)
        self.manifest["files"].append({"path": "package-lock.json", "executable": False})
        upstream = self.upstream({"kind": "build-time", "manager": "npm", "lock": "package-lock.json", "digest": digest(raw), "packagePath": "node_modules/example", "integrity": integrity})
        upstream["purl"] = "pkg:maven/org.example/example@4.2.0"
        self.manifest["upstream"] = [upstream]
        self.save()
        with self.assertRaisesRegex(ClodError, "unsupported-upstream-delivery"):
            pack(self.source, self.store)
        self.assertFalse(self.store.exists())

    def test_graph_conflict_fails_resolve_and_install_before_writes(self):
        other_root = self.root / "other"
        other = counter(other_root, "other")
        self.manifest["compatibility"]["runtimes"] = {"node": ">=20.0.0 <21.0.0"}
        other["compatibility"]["runtimes"] = {"node": ">=22.0.0 <23.0.0"}
        other["kind"] = "recipe"
        other["identity"]["name"] = "pkg:clod/com.clodhub/other-recipe"
        other["artefacts"][0]["destination"] = "counter.py"
        self.save()
        write(other_root / "component.json", other)
        pack(self.source, self.store)
        pack(other_root, self.store)
        definition = {"format": 3, "id": "counter-app", "title": "Counter", "recipe": {"name": "pkg:clod/com.clodhub/other-recipe", "version": "0.1.0"},
                      "components": [{"id": "counter", "name": "pkg:clod/com.clodhub/counter", "version": "0.1.0", "configuration": {}}],
                      "configuration": {}, "design": {"definitions": [], "instances": [], "connections": []}, "updatePolicy": {"security": "auto", "features": "manual", "preview": "hold"}}
        for operation in (lambda: resolve(requirements(definition), self.store / "catalogue.json", "counter-app", digest(canonical(definition))),
                          lambda: assemble(definition, {"format": 2, "application": "counter-app", "definitionDigest": digest(canonical(definition)),
                                                        "packages": [{**entry, "dependencies": []} for entry in load(self.store / "catalogue.json")["entries"]]},
                                           self.store, self.root / "application", self.root / "absent-policy")):
            with self.assertRaisesRegex(ClodError, "compatibility-range-conflict"):
                operation()
        self.assertFalse((self.root / "application").exists())

    def test_complete_documented_example(self):
        source = Path(__file__).resolve().parents[1] / "examples/counter"
        ref = pack(source, self.store)
        manifest, payloads = read_package(ref, self.store)
        document = (source.parents[1] / "FOUNDATIONS.md").read_text()
        examples = [json.loads(raw) for raw in re.findall(r"```json\n(.*?)\n```", document, re.S)]
        self.assertEqual(examples[0], {key: manifest[key] for key in examples[0]})
        self.assertEqual(digest(canonical(examples[1])), manifest["implements"][0]["digest"])
        self.assertEqual(manifest["implements"][0]["digest"], "1be56b8267bce466095dc55ae78b72c78446203b2e62bd71c8a657307498d816")
        self.assertEqual(fit(manifest["implements"][0], Package(manifest, payloads.__getitem__), Package(manifest, payloads.__getitem__), ["web"]), [])
        policy = self.sign_for_review([ref])
        report = review_package(ref, self.store, policy, True)
        self.assertEqual(report["summary"]["required-local"], "passed", report)
        publish_review(self.store, ref, report, self.root / "keys/guardian.pem", policy=policy)
        verify_package(ref, self.store, policy)


if __name__ == "__main__":
    unittest.main()
