import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from clod.__main__ import main
from clod.bom import bill_of_materials
from clod.bundle import pack, read_package
from clod.model import ClodError, canonical, digest
from tests.core.test_core import fixture

SCHEMAS = Path(__file__).resolve().parents[1] / "fixtures" / "cyclonedx"
AJV_MODULES = Path(os.environ.get("CLOD_AJV_MODULES", Path(__file__).resolve().parents[3] / "tools" / "standards" / "node_modules"))


class BillOfMaterialsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.store = self.root / "store"
        fixture(self.root / "dependency", "dependency")
        component = fixture(self.root / "sample", dependencies=[{"name": "pkg:clod/com.clodhub/dependency", "version": "0.1.0"}])
        self.component = component
        self.dependency_ref = pack(self.root / "dependency", self.store)
        self.ref = pack(self.root / "sample", self.store)

    def schema_check(self, *paths):
        if shutil.which("node") is None or not (AJV_MODULES / "ajv").is_dir():
            self.fail(f"schema validation needs node and ajv under {AJV_MODULES} (set CLOD_AJV_MODULES)")
        result = subprocess.run(["node", str(SCHEMAS / "validate.mjs"), *map(str, paths)], capture_output=True, text=True,
                                env={**os.environ, "AJV_MODULES": str(AJV_MODULES)}, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def test_component_bom_content_and_schema(self):
        document = bill_of_materials(self.ref, self.store)
        manifest, payloads = read_package(self.ref, self.store)
        root = document["metadata"]["component"]
        self.assertEqual((document["bomFormat"], document["specVersion"]), ("CycloneDX", "1.6"))
        self.assertEqual(root["type"], "library")
        self.assertEqual((root["group"], root["name"], root["version"]), ("com.clodhub", "sample", "0.1.0"))
        self.assertEqual((root["purl"], root["bom-ref"]), ("pkg:clod/com.clodhub/sample@0.1.0", "pkg:clod/com.clodhub/sample@0.1.0"))
        self.assertEqual(root["externalReferences"], [{"type": "vcs", "url": "https://example.org/fixture"},
                                                      {"type": "website", "url": "https://clodhub.com/components/sample"}])
        self.assertEqual(root["licenses"], [{"expression": "Apache-2.0"}])
        self.assertEqual(root["hashes"], [{"alg": "SHA-256", "content": self.ref["digest"]}])
        files = [item for item in document["components"] if item["type"] == "file"]
        self.assertEqual([item["name"] for item in files], [item["path"] for item in manifest["files"]])
        for item in files:
            self.assertEqual(item["hashes"], [{"alg": "SHA-256", "content": digest(payloads[item["name"]])}])
        libraries = [item for item in document["components"] if item["type"] == "library"]
        self.assertEqual([(item["group"], item["name"], item["version"], item["purl"], item["bom-ref"]) for item in libraries],
                         [("com.clodhub", "dependency", "0.1.0", "pkg:clod/com.clodhub/dependency@0.1.0", "pkg:clod/com.clodhub/dependency@0.1.0")])
        self.assertEqual(libraries[0]["externalReferences"], [{"type": "vcs", "url": "https://github.com/clodhub/dependency"},
                                                              {"type": "website", "url": "https://clodhub.com/components/dependency"}])
        self.assertEqual(document["dependencies"][0], {"ref": root["bom-ref"], "dependsOn": ["pkg:clod/com.clodhub/dependency@0.1.0"]})
        self.assertEqual(bill_of_materials(self.ref, self.store), document)
        path = self.root / "sample.cdx.json"
        path.write_bytes(canonical(document))
        self.schema_check(path)

    def test_recipe_is_an_application(self):
        self.component["kind"] = "recipe"
        self.component["identity"]["name"] = "pkg:clod/com.clodhub/sample-recipe"
        self.component["artefacts"][0]["destination"] = "run.sh"
        self.component["dependencies"] = []
        self.component["identity"]["version"] = "0.2.0"
        (self.root / "sample" / "component.json").write_bytes(canonical(self.component))
        ref = pack(self.root / "sample", self.store)
        document = bill_of_materials(ref, self.store)
        root = document["metadata"]["component"]
        self.assertEqual((root["type"], root["purl"]), ("application", "pkg:clod/com.clodhub/sample-recipe@0.2.0"))
        self.assertEqual(root["externalReferences"][1], {"type": "website", "url": "https://clodhub.com/recipes/sample-recipe"})
        self.assertEqual(document["dependencies"], [{"ref": root["bom-ref"], "dependsOn": []}])
        path = self.root / "recipe.cdx.json"
        path.write_bytes(canonical(document))
        self.schema_check(path)

    def test_schema_rejects_a_broken_document(self):
        document = bill_of_materials(self.ref, self.store)
        document["components"][0]["type"] = "not-a-type"
        path = self.root / "broken.cdx.json"
        path.write_bytes(canonical(document))
        result = subprocess.run(["node", str(SCHEMAS / "validate.mjs"), str(path)], capture_output=True, text=True,
                                env={**os.environ, "AJV_MODULES": str(AJV_MODULES)}, timeout=120)
        self.assertEqual(result.returncode, 1)

    def test_command_writes_the_document(self):
        out = self.root / "out" / "sample-0.1.0.cdx.json"
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(main(["bom", self.ref["digest"], "--store", str(self.store), "--out", str(out)]), 0)
        self.assertTrue(json.loads(stream.getvalue())["ok"])
        self.assertEqual(out.read_bytes(), canonical(bill_of_materials(self.ref, self.store)))

    def test_changed_archive_is_refused(self):
        path = self.store / "objects" / (self.ref["digest"] + ".tar")
        path.write_bytes(path.read_bytes() + b"\0")
        with self.assertRaises(ClodError):
            bill_of_materials(self.ref, self.store)


if __name__ == "__main__":
    unittest.main()
