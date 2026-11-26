import contextlib
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest

from clod.__main__ import main
from clod.bundle import pack, read_package
from clod.fetch import fetch
from clod.model import ClodError, canonical, digest
from tests.core.test_core import fixture


class Catalogue(http.server.BaseHTTPRequestHandler):
    routes: dict = {}

    def do_GET(self):
        body = self.routes.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body if type(body) is bytes else json.dumps(body).encode())

    def log_message(self, *args):
        pass


class FetchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.source = self.root / "source-store"
        fixture(self.root / "leaf", "leaf")
        fixture(self.root / "sample", dependencies=[{"name": "pkg:clod/com.clodhub/leaf", "version": "0.1.0"}])
        self.leaf = pack(self.root / "leaf", self.source)
        self.sample = pack(self.root / "sample", self.source)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Catalogue)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        Catalogue.routes = {}
        for ref in (self.leaf, self.sample):
            self.publish(ref)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.store = self.root / "store"

    def publish(self, ref, *, served=None, listed=None):
        short = ref["name"].rsplit("/", 1)[1]
        base = f"/api/components/{short}/{ref['version']}"
        data = served if served is not None else (self.source / "objects" / (ref["digest"] + ".tar")).read_bytes()
        Catalogue.routes[base] = {"name": ref["name"], "version": ref["version"], "digest": "sha256:" + (listed or ref["digest"]),
                                  "source": {"repository": "clodhub/" + short, "tag": "v" + ref["version"]}}
        Catalogue.routes[base + "/bundle"] = {"digest": "sha256:" + (listed or ref["digest"]), "url": f"{self.origin}/dl/{short}"}
        Catalogue.routes[f"/dl/{short}"] = data
        return f"/gh/clodhub/{short}/releases/download/v{ref['version']}/{short}-{ref['version']}"

    def command(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([str(item) for item in args])
        return code, json.loads(output.getvalue())

    def test_fetch_adds_archive_and_assets_like_pack(self):
        assets = self.publish(self.sample)
        envelope = {"payload": "e30=", "payloadType": "application/vnd.in-toto+json", "signatures": []}
        report = {"format": 3, "context": "review"}
        Catalogue.routes[assets + ".release.dsse.json"] = canonical(envelope)
        Catalogue.routes[assets + ".review.json"] = canonical(report)
        results = fetch(self.store, [("pkg:clod/com.clodhub/sample", "0.1.0")], origin=self.origin, assets=self.origin + "/gh")
        self.assertEqual(results, [{**self.sample, "kind": "component", "assets": ["release", "review"]}])
        self.assertEqual((self.store / "objects" / (self.sample["digest"] + ".tar")).read_bytes(),
                         (self.source / "objects" / (self.sample["digest"] + ".tar")).read_bytes())
        self.assertEqual(json.loads((self.store / "catalogue.json").read_text())["entries"], [self.sample])
        read_package(self.sample, self.store)
        self.assertEqual((self.store / "statements" / self.sample["digest"] / "release.dsse.json").read_bytes(), canonical(envelope))
        self.assertFalse((self.store / "statements" / self.sample["digest"] / "guardian.dsse.json").exists())
        self.assertTrue((self.store / "reports" / (digest(canonical(report)) + ".json")).is_file())

    def test_dependencies_and_command(self):
        code, value = self.command("fetch", "sample@0.1.0", "--store", self.store, "--from", self.origin, "--with-dependencies")
        self.assertEqual(code, 0, value)
        self.assertEqual([item["name"] for item in value["result"]], ["pkg:clod/com.clodhub/sample", "pkg:clod/com.clodhub/leaf"])
        self.assertEqual(sorted(e["name"] for e in json.loads((self.store / "catalogue.json").read_text())["entries"]),
                         ["pkg:clod/com.clodhub/leaf", "pkg:clod/com.clodhub/sample"])

    def test_recipe_dependencies_follow_slots_and_job_candidates(self):
        from clod.io import write
        recipe_root = self.root / "game"
        manifest = fixture(recipe_root, "game-recipe")
        manifest["kind"] = "recipe"
        manifest["artefacts"][0]["destination"] = "run.sh"
        write(recipe_root / "recipe.json", {"format": 3, "questions": [], "name": "pkg:clod/com.clodhub/game-recipe", "version": "0.1.0", "components": [
            {"id": "sample", "class": manifest["classes"][0]["reference"],
             "preferred": {"name": "pkg:clod/com.clodhub/sample", "version": "0.1.0"}, "configuration": {}, "includedWhen": None}],
            "jobs": [{"id": "job", "slot": "sample", "candidates": [
                {"component": "pkg:clod/com.clodhub/sample", "profile": "any"},
                {"component": "pkg:clod/com.clodhub/leaf", "version": "0.1.0", "profile": "any"}]}]})
        manifest["files"].append({"path": "recipe.json", "executable": False})
        manifest["files"].sort(key=lambda item: item["path"])
        (recipe_root / "component.json").write_bytes(canonical(manifest))
        game = pack(recipe_root, self.source)
        short = "game-recipe"
        Catalogue.routes[f"/api/recipes/{short}/0.1.0"] = {"name": game["name"], "version": "0.1.0", "digest": "sha256:" + game["digest"]}
        Catalogue.routes[f"/api/recipes/{short}/0.1.0/bundle"] = {"digest": "sha256:" + game["digest"], "url": f"{self.origin}/dl/{short}"}
        Catalogue.routes[f"/dl/{short}"] = (self.source / "objects" / (game["digest"] + ".tar")).read_bytes()
        results = fetch(self.store, [("pkg:clod/com.clodhub/game-recipe", "0.1.0")], with_dependencies=True, origin=self.origin)
        self.assertEqual([item["name"] for item in results], ["pkg:clod/com.clodhub/game-recipe", "pkg:clod/com.clodhub/sample", "pkg:clod/com.clodhub/leaf"])

    def test_digest_mismatch_and_unknown_are_refused(self):
        leaf_bytes = (self.source / "objects" / (self.leaf["digest"] + ".tar")).read_bytes()
        self.publish(self.sample, served=leaf_bytes)
        with self.assertRaisesRegex(ClodError, "archive-digest"):
            fetch(self.store, [("pkg:clod/com.clodhub/sample", "0.1.0")], origin=self.origin)
        self.publish(self.sample, served=leaf_bytes, listed=self.leaf["digest"])
        with self.assertRaisesRegex(ClodError, "identity-mismatch"):
            fetch(self.store, [("pkg:clod/com.clodhub/sample", "0.1.0")], origin=self.origin)
        self.assertFalse((self.store / "catalogue.json").exists())
        with self.assertRaisesRegex(ClodError, "unknown-package"):
            fetch(self.store, [("pkg:clod/com.clodhub/absent", "0.1.0")], origin=self.origin)

    def test_noncanonical_report_refused(self):
        assets = self.publish(self.sample)
        Catalogue.routes[assets + ".review.json"] = b'{"format": 1}'
        with self.assertRaisesRegex(ClodError, "invalid-report"):
            fetch(self.store, [("pkg:clod/com.clodhub/sample", "0.1.0")], origin=self.origin, assets=self.origin + "/gh")


if __name__ == "__main__":
    unittest.main()


class FetchInstallTests(unittest.TestCase):
    """A reviewed format-2 recipe published with its evidence archive installs and verifies after fetch alone."""

    def test_fetch_install_and_verify_with_published_evidence(self):
        from clod.application import assemble, requirements
        from clod.bundle import resolve
        from clod.evidence import evidence_paths, pack_evidence
        from clod.io import load, write
        from clod.test_identities import generate
        from clod.trust import publish_release, publish_review
        from clod.verification import review_package, verify_application
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        from tests.test_application import source as recipe_source
        manifest = recipe_source(root / "game", "game-recipe", recipe=True)
        manifest["format"] = 4
        manifest["verification"] = [suite for suite in manifest["verification"] if suite["root"] == "package"]
        for suite in manifest["verification"]:
            suite["requirements"] = []
            suite["execution"] = {"kind": "local", "simulation": False, "operations": [], "settings": [], "secrets": [],
                                  "resources": [], "assertions": [], "cleanup": None}
        (root / "game" / "component.json").write_bytes(canonical(manifest))
        source = root / "source-store"
        ref = pack(root / "game", source)
        policy = generate(root / "identities")
        trusted = load(policy)
        trusted["trustedExecution"] = [ref["digest"]]
        write(policy, trusted)
        publish_release(source, ref, root / "identities/release.pem")
        report = review_package(ref, source, policy, True)
        self.assertEqual((report["format"], report["summary"]["required-local"]), (4, "passed"))
        publish_review(source, ref, report, root / "identities/guardian.pem", policy=policy)
        paths = evidence_paths(report)
        self.assertIn(f"execution-evidence/{report['execution']['evidenceDigest']}.json", paths)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Catalogue)
        origin = f"http://127.0.0.1:{server.server_port}"
        statements = source / "statements" / ref["digest"]
        assets = "/gh/clodhub/game-recipe/releases/download/v0.1.0/game-recipe-0.1.0"
        Catalogue.routes = {
            "/api/recipes/game-recipe/0.1.0": {"name": ref["name"], "version": "0.1.0", "digest": "sha256:" + ref["digest"],
                                               "source": {"repository": "clodhub/game-recipe", "tag": "v0.1.0"}},
            "/api/recipes/game-recipe/0.1.0/bundle": {"digest": "sha256:" + ref["digest"], "url": origin + "/dl/game"},
            "/dl/game": (source / "objects" / (ref["digest"] + ".tar")).read_bytes(),
            assets + ".release.dsse.json": (statements / "release.dsse.json").read_bytes(),
            assets + ".guardian.dsse.json": (statements / "guardian.dsse.json").read_bytes(),
            assets + ".review.json": canonical(report)}
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        store = root / "store"
        with self.assertRaisesRegex(ClodError, "evidence-missing"):
            fetch(store, [("pkg:clod/com.clodhub/game-recipe", "0.1.0")], origin=origin, assets=origin + "/gh")
        evidence = pack_evidence(source, report)
        tampered = evidence.replace(b'"format":1', b'"format":9', 1)
        Catalogue.routes[assets + ".evidence.tar"] = tampered
        with self.assertRaisesRegex(ClodError, "evidence-digest"):
            fetch(root / "store-tampered", [("pkg:clod/com.clodhub/game-recipe", "0.1.0")], origin=origin, assets=origin + "/gh")
        Catalogue.routes[assets + ".evidence.tar"] = evidence
        results = fetch(store, [("pkg:clod/com.clodhub/game-recipe", "0.1.0")], origin=origin, assets=origin + "/gh")
        self.assertEqual(results[0]["assets"], ["release", "guardian", "evidence", "review"])
        for path in paths:
            self.assertEqual((store / path).read_bytes(), (source / path).read_bytes())

        definition = {"format": 3, "id": "game", "title": "Game", "recipe": {"name": ref["name"], "version": "0.1.0"},
                      "components": [], "configuration": {}, "design": {"definitions": [], "instances": [], "connections": []},
                      "updatePolicy": {"security": "auto", "features": "manual", "preview": "hold"}}
        lock = resolve(requirements(definition), store / "catalogue.json", "game", digest(canonical(definition)))
        app = root / "app"
        assemble(definition, lock, store, app, policy)
        self.assertEqual(verify_application(app, policy, True)["summary"]["required-local"], "passed")
