import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aepm.__main__ import main
from aepm.application import validate_definition
from aepm.bundle import pack
from aepm.io import load, write
from aepm.model import canonical, digest
from aepm.recipe import CelError, World, evaluate, evaluate_condition, fit, parse_condition, question_kinds, questions, slot_fit
from tests.core.test_core import CLASS_FIELDS, PYTHON, fixture, without_execution


def component(root, name, provides=(), requires=(), collect=(), profiles=None, document="{}"):
    manifest = fixture(root, name)
    for port in (*provides, *requires):
        (root / f"{port}.json").write_text(document)
    manifest["files"] += [{"path": f"{port}.json", "executable": False} for port in (*provides, *requires)]
    manifest["provides"] = [{"id": port, "type": "ae/" + port, "version": "1.0.0", "path": f"{port}.json"} for port in provides]
    manifest["requires"] = [{"id": port, "type": "ae/" + port, "version": "1.0.0", "path": f"{port}.json"} for port in requires]
    manifest["collect"] = list(collect)
    key = "deck" if name.startswith("deck") else name
    if key in SLOT_CLASSES:
        attach_class(root, manifest, SLOT_CLASSES[key])
    write(root / "suitability.json", {"format": 1, "jobs": [name], "profiles": profiles or [
        {"id": "any", "load": {}, "cost": "none", "regions": ["any"], "compliance": []}], "notes": ""})
    manifest["files"].append({"path": "suitability.json", "executable": False})
    manifest["files"].sort(key=lambda item: item["path"])
    (root / "component.json").write_bytes(canonical(manifest))
    return manifest


LABEL = {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9 -]{0,63}$"}
SLOT_CLASSES = {}


def attach_class(root, manifest, entry):
    manifest["classes"] = [copy.deepcopy(entry)]
    manifest["implements"] = [copy.deepcopy(entry["reference"])]
    listed = {item["path"] for item in manifest["files"]}
    for item in entry["descriptor"]["inventory"]:
        if item["path"] == "class-check.py":
            continue
        path = root / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{}")
        if item["path"] not in listed:
            manifest["files"].append({"path": item["path"], "executable": False})


def slot(identifier, name, provides=(), properties=None, required=(), includedWhen=None):
    check = b"import json, os\nfrom pathlib import Path\nm = json.loads(Path(os.environ['AEPM_CANDIDATE_MANIFEST']).read_text())\nassert m['identity']['name'].startswith('clodhub/')\nassert all(Path(p).is_file() for p in json.loads(os.environ['AEPM_MODULE_MAP']).values())\n"
    descriptor = {**CLASS_FIELDS, "name": "clodhub/" + identifier + "-class", "version": "1.0.0",
                  "provides": [{"type": "ae/" + port, "version": "1.0.0", "path": f"classes/{identifier}/{port}.json", "modules": {"web": ["run.sh"]}} for port in provides],
                  "requires": [], "settings": {"type": "object", "properties": properties or {}, "required": list(required), "additionalProperties": False},
                  "inventory": [{"path": "class-check.py", "digest": digest(check)},
                                *[{"path": f"classes/{identifier}/{port}.json", "digest": digest(b"{}")} for port in provides]],
                  "verification": [{"id": "behaviour", "root": "package", "argv": [PYTHON, "class-check.py"], "cwd": ".", "prepare": [],
                                    "tools": {PYTHON: "3"}, "fixtures": ["class-check.py"], "locks": [], "network": False,
                                    "timeoutSeconds": 10, "expectedExit": 0, "scope": "required-local", "requirements": []}]}
    reference = {"name": descriptor["name"], "version": descriptor["version"], "digest": digest(canonical(descriptor))}
    SLOT_CLASSES[identifier] = {"reference": reference, "descriptor": descriptor}
    return {"id": identifier,
            "class": reference,
            "preferred": {"name": name, "version": "0.1.0"}, "configuration": {}, "includedWhen": includedWhen}


RECIPE = {
    "format": 2, "name": "clodhub/game", "version": "0.1.0", "title": "Game",
    "components": [
        slot("deck", "clodhub/deck", ["deck"], {"targets": LABEL}, ["targets"]),
        slot("video", "clodhub/video", properties={"key": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_]{0,63}$"}},
             includedWhen="video"),
        slot("host", "clodhub/host", properties={"provider": {"type": "string", "pattern": "^[a-z][a-z0-9-]{0,63}$"}}),
    ],
    "jobs": [{"id": "server", "slot": "host", "overrideQuestion": "server", "candidates": [
        {"component": "clodhub/host", "profile": "free"}, {"component": "clodhub/host", "profile": "paid"}]}],
    "scale": {"question": "scale", "bands": [
        {"id": "small", "label": "small", "load": {"concurrentPeople": 10}},
        {"id": "large", "label": "large", "load": {"concurrentPeople": 1000}}]},
    "questions": [
        {"id": "targets", "question": "Devices?", "ask": "unless-settled", "askAgent": "infer", "type": "set", "options": ["web", "ios"], "default": ["web"],
         "effects": [{"sets": {"deck.targets": "$answer"}}]},
        {"id": "video", "question": "Video?", "ask": "default", "askAgent": "ask", "type": "boolean", "default": False, "effects": []},
        {"id": "videoKey", "question": "Key?", "ask": "required", "askAgent": "ask", "type": "secretRef", "askWhen": "video",
         "effects": [{"sets": {"video.key": {"ref": "videoKey"}}}]},
        {"id": "scale", "question": "How many?", "ask": "default", "askAgent": "infer", "type": "choice", "options": ["small", "large"], "default": "small",
         "effects": []},
        {"id": "server", "question": "Server?", "ask": "default", "askAgent": "ask", "type": "text", "default": "cloudflare", "effects": []},
    ],
    "connections": [{"source": {"instance": "deck", "port": "deck"}, "target": {"instance": "application", "port": "deck"}}],
    "tests": {"defaultAnswers": {}, "answerSets": []},
}


DECK_SETTINGS = [{"id": "targets", "type": "string", "grammar": "label", "required": True, "secret": False, "default": "web"}]
HOST_SETTINGS = [{"id": "provider", "type": "string", "grammar": "slug", "required": True, "secret": False, "default": "none"}]
HOST_PROFILES = [{"id": "free", "load": {"concurrentPeople": 50}, "cost": "free", "regions": ["any"], "compliance": [],
                  "provider": {"name": "Cloudflare Workers", "tier": "free", "limitsSource": None}},
                 {"id": "paid", "load": {}, "cost": "paid", "regions": ["any"], "compliance": [],
                  "provider": {"name": "Cloudflare Workers", "tier": "paid", "limitsSource": None}}]


class RecipeDesignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name).resolve()
        cls.store = cls.root / "store"
        component(cls.root / "deck", "deck", provides=["deck"], collect=DECK_SETTINGS)
        component(cls.root / "video", "video",
                  collect=[{"id": "key", "type": "string", "grammar": "identifier", "required": False, "secret": True}])
        component(cls.root / "host", "host", collect=HOST_SETTINGS, profiles=HOST_PROFILES)
        component(cls.root / "deck2", "deck2", provides=["deck"], collect=DECK_SETTINGS)
        component(cls.root / "deck3", "deck3", provides=["deck"], collect=DECK_SETTINGS, document='{"other": true}')
        component(cls.root / "deck4", "deck4", provides=["deck"],
                  collect=[{"id": "targets", "type": "string", "grammar": "slug", "required": True, "secret": False, "default": "web"},
                           {"id": "size", "type": "integer", "grammar": "integer", "required": True, "secret": False}],
                  requires=["random-source"])
        for name in ("deck", "video", "host", "deck2", "deck3", "deck4"):
            pack(cls.root / name, cls.store)
        recipe = component(cls.root / "game", "game", requires=["deck"])
        recipe["platforms"] = ["web", "ios"]
        recipe["toolchains"] = {"web": [], "ios": []}
        recipe["kind"] = "recipe"
        recipe["artefacts"][0]["destination"] = "run.sh"
        recipe["classes"] = []
        recipe["implements"] = []
        for entry in SLOT_CLASSES.values():
            listed = {item["path"] for item in recipe["files"]}
            for item in entry["descriptor"]["inventory"]:
                if item["path"] not in listed:
                    path = cls.root / "game" / item["path"]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"{}")
                    recipe["files"].append({"path": item["path"], "executable": False})
            recipe["classes"].append(copy.deepcopy(entry))
        write(cls.root / "game" / "recipe.json", RECIPE)
        recipe["files"].append({"path": "recipe.json", "executable": False})
        recipe["files"].sort(key=lambda item: item["path"])
        (cls.root / "game" / "component.json").write_bytes(canonical(recipe))
        pack(cls.root / "game", cls.store)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def world(self, **substitutes):
        return World.from_store("clodhub/game", "0.1.0", self.store,
                                {key: ("clodhub/" + value, "0.1.0") for key, value in substitutes.items()})

    def command(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([str(item) for item in args])
        return code, json.loads(output.getvalue())

    def test_world_from_store_matches_source_directories(self):
        stored = self.world()
        self.assertEqual(stored.recipe, RECIPE)
        self.assertEqual(set(stored.manifests), {"deck", "video", "host", "application"})
        sources = self.root / "sources"
        sources.mkdir(exist_ok=True)
        for name in ("deck", "video", "host"):
            if not (sources / name).exists():
                (sources / name).symlink_to(self.root / name)
        directories = World.from_directories(self.root / "game", sources)
        self.assertEqual(evaluate(stored, {})["design"]["components"], evaluate(directories, {})["design"]["components"])

    def test_design_defaults_selection_and_conditions(self):
        result = evaluate(self.world(), {})
        self.assertTrue(result["ok"], result)
        design = validate_definition(result["design"])
        self.assertEqual([(item["id"], item["name"]) for item in design["components"]], [("deck", "clodhub/deck"), ("host", "clodhub/host")])
        self.assertEqual(design["selections"]["server"], {"component": "clodhub/host", "version": "0.1.0", "profile": "free",
                                                         "reason": "scale small; 2 of 2 candidates fit; lowest cost free"})
        self.assertEqual(next(c for c in design["components"] if c["id"] == "host")["configuration"], {"provider": "free"})
        large = evaluate(self.world(), {"scale": "large", "targets": ["ios", "web"]})
        self.assertEqual(large["design"]["selections"]["server"]["profile"], "paid")
        self.assertEqual(large["design"]["components"][0]["configuration"], {"targets": "web ios"})
        self.assertEqual(large["design"]["answers"]["targets"], ["web", "ios"])

    def test_errors_are_values(self):
        world = self.world()
        self.assertEqual(evaluate(world, {"video": True})["errors"], [{"code": "unanswered", "path": "answers.videoKey"}])
        self.assertEqual(evaluate(world, {"scale": "huge"})["errors"][0], {"code": "invalid-answer", "path": "answers.scale"})
        self.assertEqual(evaluate(world, {"server": "nobody"})["errors"], [{"code": "uncovered", "path": "server"}])
        with_video = evaluate(world, {"video": True, "videoKey": "keys/video"})
        self.assertEqual(next(c for c in with_video["design"]["components"] if c["id"] == "video")["configuration"],
                          {"key": {"secretRef": "keys/video"}})

    def test_empty_or_unsupported_targets_are_error_values(self):
        world = self.world()
        self.assertEqual(evaluate(world, {"targets": []}), {"ok": False, "errors": [{"code": "invalid-answer", "path": "answers.targets"}]})
        world.application["platforms"] = ["web"]
        self.assertEqual(evaluate(world, {"targets": ["ios"]}), {"ok": False, "errors": [{"code": "invalid-answer", "path": "answers.targets"}]})

    def test_fit_rule(self):
        world = self.world()
        packages = {key[0].split("/")[1]: package for key, package in world.packages.items()}
        self.assertEqual(slot_fit(world, "deck", packages["deck"]), [])
        alternative = self.world(deck="deck2")
        self.assertEqual(slot_fit(alternative, "deck", alternative.filling["deck"]), [])
        for name, reasons in (("deck3", []),
                              ("deck4", ["requires:ae/random-source@1.0.0", "setting-type:targets", "unset-setting:size"]),
                              ("host", ["class-unavailable:clodhub/deck-class"])):
            other = self.world(deck=name)
            with self.subTest(name=name):
                self.assertEqual(slot_fit(other, "deck", other.filling["deck"]), reasons)

    def test_entry_modules_are_part_of_the_fit(self):
        world = self.world()
        preferred = world.filling["deck"]
        manifest = json.loads(json.dumps(preferred.manifest))

        class Fake:
            def __init__(self, destinations):
                self.manifest = {**manifest, "artefacts": [{"destination": "components/deck/" + item} for item in destinations]}
                self.name, self.version = "clodhub/deck", "0.1.0"

            def file(self, path):
                return preferred.file(path)

        self.assertEqual(fit(RECIPE["components"][0]["class"], Fake(["run.sh"]), world.authority), [])
        self.assertEqual(fit(RECIPE["components"][0]["class"], Fake(["web/deck.ts"]), Fake([])),
                          ["module:web:run.sh"])

    def test_substitution(self):
        result = evaluate(self.world(deck="deck2"), {})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["design"]["components"][0], {"id": "deck", "name": "clodhub/deck2", "version": "0.1.0",
                                                             "configuration": {"targets": "web"}})
        self.assertEqual(result["design"]["selections"]["deck"], {"component": "clodhub/deck2", "version": "0.1.0", "reason": "substituted"})
        self.assertTrue(evaluate(self.world(deck="deck3"), {})["ok"])
        self.assertEqual(evaluate(self.world(nowhere="deck2"), {})["errors"], [{"code": "unknown-slot", "path": "nowhere"}])

    def test_offline_substitution_without_preferred_archive(self):
        from aepm.bundle import add_archive
        with tempfile.TemporaryDirectory() as temporary:
            store = Path(temporary).resolve() / "store"
            entries = load(self.store / "catalogue.json")["entries"]
            for entry in entries:
                if entry["name"] in ("clodhub/game", "clodhub/deck2", "clodhub/host", "clodhub/video"):
                    add_archive(store, entry, (self.store / "objects" / (entry["digest"] + ".tar")).read_bytes())
            world = World.from_store("clodhub/game", "0.1.0", store, {"deck": ("clodhub/deck2", "0.1.0")})
            result = evaluate(world, {})
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["design"]["components"][0]["name"], "clodhub/deck2")

    def test_design_rejects_selected_graph_conflicts(self):
        world = self.world()
        world.application["compatibility"]["frameworks"] = {"web-ui": {"name": "vue", "range": ">=3.0.0 <4.0.0"}}
        world.filling["deck"].manifest["compatibility"]["frameworks"] = {"web-ui": {"name": "react", "range": ">=19.0.0 <20.0.0"}}
        self.assertIn("framework-conflict:web-ui", fit(world.slots["deck"]["class"], world.filling["deck"], world.authority, ["web"]))
        result = evaluate(world, {})
        self.assertFalse(result["ok"])
        self.assertIn({"code": "framework-conflict", "path": "web-ui"}, result["errors"])

    def test_evaluation_validates_the_selected_graph_once(self):
        from aepm.foundations import validate_graph
        world = self.world()
        with patch("aepm.foundations.validate_graph", wraps=validate_graph) as checked:
            result = evaluate(world, {})
        self.assertTrue(result["ok"], result)
        checked.assert_called_once()
        manifests, targets = checked.call_args.args
        self.assertEqual({item["identity"]["name"] for item in manifests}, {"clodhub/game", "clodhub/deck", "clodhub/host"})
        self.assertEqual(targets, ["web"])

    def test_evaluation_rechecks_class_bytes_on_every_call(self):
        world = self.world()
        self.assertTrue(evaluate(world, {})["ok"])
        original = world.authority.file
        path = SLOT_CLASSES["deck"]["descriptor"]["inventory"][-1]["path"]
        world.authority.file = lambda name: b"tampered" if name == path else original(name)
        result = evaluate(world, {})
        self.assertFalse(result["ok"])
        self.assertIn({"code": "unfit", "path": "deck:class-file-digest:clodhub/deck-class"}, result["errors"])
        world.authority.file = original
        self.assertTrue(evaluate(world, {})["ok"])

    def test_alternatives_from_the_catalogue(self):
        import http.server
        import threading
        from tests.test_fetch import Catalogue
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Catalogue)
        origin = f"http://127.0.0.1:{server.server_port}"
        catalogue = json.loads((self.store / "catalogue.json").read_text())["entries"]
        Catalogue.routes = {"/api/components?provides=ae%2Fdeck&limit=100": {"components": [
            {"name": "clodhub/" + name, "version": "0.1.0"} for name in ("deck", "deck2", "deck3")]}}
        for entry in catalogue:
            short = entry["name"].split("/")[1]
            base = f"/api/components/{short}/0.1.0"
            Catalogue.routes[base] = {"name": entry["name"], "version": "0.1.0", "digest": "sha256:" + entry["digest"]}
            Catalogue.routes[base + "/bundle"] = {"digest": "sha256:" + entry["digest"], "url": f"{origin}/dl/{short}"}
            Catalogue.routes[f"/dl/{short}"] = (self.store / "objects" / (entry["digest"] + ".tar")).read_bytes()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        code, value = self.command("alternatives", "game@0.1.0", "deck", "--store", self.store, "--from", origin)
        self.assertEqual(code, 0, value)
        self.assertEqual(value["result"], [
            {"name": "clodhub/deck", "version": "0.1.0", "fits": True, "reasons": []},
            {"name": "clodhub/deck2", "version": "0.1.0", "fits": True, "reasons": []},
            {"name": "clodhub/deck3", "version": "0.1.0", "fits": True, "reasons": []}])
        code, value = self.command("alternatives", "game@0.1.0", "nowhere", "--store", self.store, "--from", origin)
        self.assertEqual((code, value["error"]["code"]), (1, "unknown-slot"))

    def test_cel_subset(self):
        kinds = question_kinds(RECIPE)
        self.assertTrue(evaluate_condition("'ios' in targets && !video", {"targets": ["ios"], "video": False}, kinds))
        self.assertTrue(evaluate_condition("size(targets) >= 2", {"targets": ["ios", "web"]}, kinds))
        for text in ("targets + 1", "has(video)", "video ? 1 : 2", "1.5 == 1.5", "unknown", "-1 < 0 && -video"):
            with self.subTest(text=text), self.assertRaises(CelError):
                evaluate_condition(text, {"targets": [], "video": False}, kinds)
        self.assertEqual(parse_condition("video"), ("id", "video"))

    def test_commands(self):
        answers = self.root / "answers.json"
        write(answers, {"targets": ["web", "ios"]})
        out = self.root / "definition.json"
        code, value = self.command("design", "game@0.1.0", "--store", self.store, "--answers", answers, "--out", out)
        self.assertEqual(code, 0, value)
        self.assertEqual(validate_definition(load(out))["answers"], {"targets": ["web", "ios"], "video": False, "scale": "small", "server": "cloudflare"})
        code, value = self.command("design", "clodhub/game@0.1.0", "--store", self.store, "--substitute", "deck=deck2@0.1.0",
                                   "--out", self.root / "substituted.json")
        self.assertEqual(code, 0, value)
        self.assertEqual(load(self.root / "substituted.json")["components"][0]["name"], "clodhub/deck2")
        self.assertEqual(load(self.root / "substituted.json")["updatePolicy"], {"security": "auto", "features": "manual", "preview": "hold"})
        code, value = self.command("design", "game@0.1.0", "--store", self.store, "--update-policy", "security=manual,preview=manual",
                                   "--out", self.root / "policy.json")
        self.assertEqual(code, 0, value)
        self.assertEqual(load(self.root / "policy.json")["updatePolicy"], {"security": "manual", "features": "manual", "preview": "manual"})
        code, value = self.command("design", "game@0.1.0", "--store", self.store, "--update-policy", "security=always", "--out", self.root / "x.json")
        self.assertEqual((code, value["error"]["code"]), (1, "invalid-value"))
        code, value = self.command("design", "game@0.1.0", "--store", self.store, "--substitute", "deck=deck9@0.1.0", "--out", self.root / "x.json")
        self.assertEqual((code, value["error"]["code"]), (1, "unknown-package"))
        write(answers, {"video": True})
        code, value = self.command("design", "game@0.1.0", "--store", self.store, "--answers", answers, "--out", self.root / "bad.json")
        self.assertEqual((code, value), (1, {"ok": False, "errors": [{"code": "unanswered", "path": "answers.videoKey"}]}))
        self.assertFalse((self.root / "bad.json").exists())
        code, value = self.command("questions", "game@0.1.0", "--store", self.store)
        self.assertEqual(code, 0)
        self.assertEqual(value["result"]["questions"], questions(RECIPE))
        self.assertEqual(value["result"]["questions"][2], {"id": "videoKey", "question": "Key?", "ask": "required", "askAgent": "ask",
                                                           "type": "secretRef", "askWhen": "video"})
        self.assertEqual((value["result"]["toAsk"], value["result"]["followUps"]),
                         (["targets"], [{"id": "videoKey", "askWhen": "video", "dependsOn": ["video"]}]))
        write(answers, {"video": True, "targets": ["web"]})
        code, value = self.command("questions", "game@0.1.0", "--store", self.store, "--answers", answers)
        self.assertEqual((value["result"]["toAsk"], value["result"]["followUps"]), (["videoKey"], []))
        for partial, path in (({"scale": "huge"}, "answers.scale"), ({"video": "yes"}, "answers.video"),
                              ({"targets": ["web", "tv"]}, "answers.targets"), ({"colour": "red"}, "answers.colour")):
            write(answers, partial)
            code, value = self.command("questions", "game@0.1.0", "--store", self.store, "--answers", answers)
            self.assertEqual((code, value["error"]["code"], value["error"]["path"]), (1, "invalid-answer", path))
        code, value = self.command("design", "deck@0.1.0", "--store", self.store, "--out", self.root / "x.json")
        self.assertEqual((code, value["error"]["code"]), (1, "not-a-recipe"))
        code, value = self.command("questions", "game@9.9.9", "--store", self.store)
        self.assertEqual((code, value["error"]["code"]), (1, "unknown-package"))


if __name__ == "__main__":
    unittest.main()
