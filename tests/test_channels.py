"""Update channels against a served catalogue: `outdated`, and the next design `propose-update --channel` installs."""

import copy
import http.server
import json
from pathlib import Path
import shutil
import threading
import unittest
from unittest.mock import patch

from aepm.bundle import pack, read_package
from aepm.io import load, write
from aepm.model import AepmError, canonical, digest
from aepm.recipe import World, evaluate
from tests import test_recipe_design as design
from tests.test_fetch import Catalogue
from tests.test_recipe_design import LABEL, RECIPE, SLOT_CLASSES, component


class ChannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        design.RecipeDesignTests.setUpClass.__func__(cls)
        # deck2 0.1.1: a security release on deck2's 0.1 line.
        manifest = component(cls.root / "deck2-security", "deck2", provides=["deck"],
                             collect=[{"id": "targets", "type": "string", "grammar": "label", "required": True, "secret": False, "default": "web"}])
        manifest["identity"]["version"] = "0.1.1"
        manifest["release"] = {"channel": "security", "fixes": ["GHSA-deck-0001-test"]}
        (cls.root / "deck2-security" / "component.json").write_bytes(canonical(manifest))
        pack(cls.root / "deck2-security", cls.store)
        # game 0.2.0: a features release with the same slot classes; game 0.3.0-preview.1: its deck slot needs a new
        # class version that deck2 does not implement.
        cls.recipe("0.2.0", RECIPE)
        deck = copy.deepcopy(SLOT_CLASSES["deck"])
        descriptor = deck["descriptor"]
        descriptor.update(version="1.1.0")
        descriptor["settings"]["properties"]["colour"] = LABEL
        deck["reference"] = {"name": descriptor["name"], "version": "1.1.0", "digest": digest(canonical(descriptor))}
        changed = copy.deepcopy(RECIPE)
        changed["components"][0]["class"] = deck["reference"]
        cls.recipe("0.3.0-preview.1", changed, extra_class=deck)
        cls.serve()

    @classmethod
    def recipe(cls, number, document, extra_class=None):
        source = cls.root / ("game-" + number)
        shutil.copytree(cls.root / "game", source)
        manifest = json.loads((source / "component.json").read_text())
        manifest["identity"]["version"] = number
        manifest["release"] = {"channel": "preview" if "-" in number else "features", "fixes": []}
        if extra_class is not None:
            manifest["classes"].append(extra_class)
        write(source / "recipe.json", {**document, "version": number})
        (source / "component.json").write_bytes(canonical(manifest))
        pack(source, cls.store)

    @classmethod
    def serve(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Catalogue)
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        Catalogue.routes = {}
        listed = {}
        for ref in json.loads((cls.store / "catalogue.json").read_text())["entries"]:
            manifest, _ = read_package(ref, cls.store)
            kind = "recipes" if manifest["kind"] == "recipe" else "components"
            short = ref["name"].split("/")[1]
            base = f"/api/{kind}/{short}/{ref['version']}"
            Catalogue.routes[base] = {"name": ref["name"], "version": ref["version"], "digest": "sha256:" + ref["digest"]}
            Catalogue.routes[base + "/bundle"] = {"digest": "sha256:" + ref["digest"], "url": f"{cls.origin}/dl/{ref['digest']}"}
            Catalogue.routes[f"/dl/{ref['digest']}"] = (cls.store / "objects" / (ref["digest"] + ".tar")).read_bytes()
            listed.setdefault((kind, short, ref["name"]), []).append({"version": ref["version"], **manifest["release"]})
        for (kind, short, name), versions in listed.items():
            Catalogue.routes[f"/api/{kind}/{short}/latest"] = {"name": name, "versions": versions}
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.temp.cleanup()

    def setUp(self):
        self.routes = copy.deepcopy(Catalogue.routes)
        self.addCleanup(setattr, Catalogue, "routes", self.routes)
        world = World.from_store("ourapps-ae/game", "0.1.0", self.store, {"deck": ("ourapps-ae/deck2", "0.1.0")})
        self.definition = evaluate(world, {})["design"]
        self.app = Path(self.temp.name) / ("app-" + self.id().rsplit(".", 1)[1])
        write(self.app / ".aepm/definition.json", self.definition)
        self.fresh = Path(self.temp.name) / ("store-" + self.id().rsplit(".", 1)[1])
        patcher = patch("aepm.application.read_assembly")
        patcher.start()
        self.addCleanup(patcher.stop)

    def policy(self, **changes):
        self.definition["updatePolicy"].update(changes)
        write(self.app / ".aepm/definition.json", self.definition)

    def test_outdated_lists_each_channel_from_the_catalogue_alone(self):
        from aepm.channels import outdated
        with patch("aepm.fetch.fetch", side_effect=AssertionError("no download")):
            rows = {row["name"]: row for row in outdated(self.app, self.origin)}
        self.assertEqual(rows["ourapps-ae/deck2"], {"name": "ourapps-ae/deck2", "installed": "0.1.0", "line": "0.1",
                                                    "policy": self.definition["updatePolicy"],
                                                    "security": {"version": "0.1.1", "fixes": ["GHSA-deck-0001-test"]},
                                                    "features": None, "preview": None})
        game = rows["ourapps-ae/game"]
        self.assertEqual((game["security"], game["features"], game["preview"]),
                         (None, {"version": "0.2.0"}, {"version": "0.3.0-preview.1"}))

    def test_security_moves_every_package_on_its_line(self):
        from aepm.channels import next_definition
        nxt = next_definition(self.app, "security", self.fresh, self.origin)
        self.assertEqual(nxt["recipe"], self.definition["recipe"])
        self.assertEqual({item["name"]: item["version"] for item in nxt["components"]}["ourapps-ae/deck2"], "0.1.1")
        self.assertEqual(nxt["updatePolicy"], self.definition["updatePolicy"])

    def test_features_keeps_answers_and_substitutes(self):
        from aepm.channels import next_definition
        self.policy(features="manual")
        nxt = next_definition(self.app, "features", self.fresh, self.origin)
        self.assertEqual(nxt["recipe"]["version"], "0.2.0")
        self.assertEqual({item["id"]: item["name"] for item in nxt["components"]}["deck"], "ourapps-ae/deck2")

    def test_a_substitute_that_no_longer_fits_stops_the_preview_proposal(self):
        from aepm.channels import next_definition
        self.policy(preview="manual")
        with self.assertRaises(AepmError) as raised:
            next_definition(self.app, "preview", self.fresh, self.origin)
        self.assertEqual((raised.exception.code, raised.exception.path), ("substitute-unfit", "deck"))

    def test_held_channel_and_mismatched_releases_are_refused(self):
        from aepm.channels import next_definition
        with self.assertRaises(AepmError) as raised:
            next_definition(self.app, "preview", self.fresh, self.origin)
        self.assertEqual(raised.exception.code, "channel-held")
        listing = Catalogue.routes["/api/components/deck2/latest"]
        entry = next(item for item in listing["versions"] if item["version"] == "0.1.1")
        entry["fixes"] = ["GHSA-other-0002-test"]
        with self.assertRaises(AepmError) as raised:
            next_definition(self.app, "security", self.fresh, self.origin)
        self.assertEqual(raised.exception.code, "release-channel")
        entry.update(channel="features", fixes=[])
        with self.assertRaises(AepmError) as raised:
            next_definition(self.app, "security", self.fresh, self.origin)
        self.assertEqual(raised.exception.code, "release-channel")


if __name__ == "__main__":
    unittest.main()
