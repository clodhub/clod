"""Build-tool declarations, graph merges and doctor probes with fake tools and installers."""

import contextlib
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from clod.__main__ import main
from clod.bundle import pack
from clod.doctor import doctor
from clod.io import write
from clod.model import ClodError, validate_component
from clod.toolchains import merge_toolchains, probe_version, validate_tool
from tests.core.test_core import fixture


def tool(name, version_range, probe, macos=None, windows=None, linux=None, manual=None):
    return {"name": name, "versionRange": version_range, "probe": probe,
            "install": {"macos": macos, "windows": windows, "linux": linux}, "manual": manual}


NODE = tool("node", ">=22.0.0 <27.0.0", ["node", "--version"], ["brew", "install", "node"],
            ["winget", "install", "--exact", "--id", "OpenJS.NodeJS"], ["sudo", "apt-get", "install", "--yes", "nodejs"])
XCODE = tool("xcodebuild", ">=16.0.0", ["xcodebuild", "-version"], manual="Install Xcode from the Mac App Store and accept its licence.")
XCODEGEN = tool("xcodegen", ">=2.40.0 <3.0.0", ["xcodegen", "--version"], ["brew", "install", "xcodegen"],
                linux=["sudo", "apt-get", "install", "--yes", "xcodegen"])
QUESTIONS = [{"id": "targets", "question": "Devices?", "ask": "unless-settled", "askAgent": "infer", "type": "set", "options": ["web", "ios"],
              "default": ["web", "ios"], "effects": []}]


def package(root, name, toolchains, *, recipe=False, dependencies=None):
    manifest = fixture(root, name, dependencies=dependencies)
    manifest.update(platforms=sorted(toolchains), toolchains=toolchains)
    if recipe:
        manifest.update(kind="recipe", implements=[], classes=[])
        manifest["artefacts"][0]["destination"] = "run.sh"
        write(root / "recipe.json", {"format": 3, "name": "pkg:clod/com.clodhub/" + name, "version": "0.1.0", "title": "Game", "components": [],
                                      "questions": QUESTIONS, "connections": [], "tests": {"defaultAnswers": {}, "answerSets": []}})
        manifest["files"].append({"path": "recipe.json", "executable": False})
        manifest["files"].sort(key=lambda item: item["path"])
    write(root / "component.json", manifest)
    return manifest


class Host:
    """Fake PATH lookups, version outputs and installers."""

    def __init__(self, tools):
        self.tools = dict(tools)
        self.installed = []

    def which(self, name):
        return "/fake/bin/" + name if name in self.tools else None

    def run(self, argv):
        output = self.tools.get(Path(argv[0]).name)
        return (None, "") if output is None else (0, output)

    def install(self, argv):
        self.installed.append(argv)
        self.tools[{"node": "node", "xcodegen": "xcodegen"}[argv[-1]]] = "2.42.0" if argv[-1] == "xcodegen" else "v26.5.0"
        return 0


class DoctorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.store = self.root / "store"
        self.component_tools = {"web": [{**NODE, "versionRange": ">=24.0.0"}], "ios": [XCODEGEN]}

    def build(self):
        package(self.root / "renderer", "renderer", self.component_tools)
        package(self.root / "game", "game-recipe", {"web": [NODE], "ios": [XCODE]}, recipe=True,
                dependencies=[{"name": "pkg:clod/com.clodhub/renderer", "version": "0.1.0"}])
        pack(self.root / "renderer", self.store)
        pack(self.root / "game", self.store)

    def run_doctor(self, host, answers=None, **options):
        return doctor("pkg:clod/com.clodhub/game-recipe", "0.1.0", self.store, answers or {}, host="macos", which=host.which, runner=host.run,
                      installer=host.install, **options)

    def test_versions_parse_from_real_output_shapes(self):
        for output, expected in (("v26.5.0", (26, 5, 0)), ('openjdk version "21.0.4" 2024-07-16', (21, 0, 4)),
                                 ("Xcode 16.1\nBuild version 16B40", (16, 1, 0)), ("Version: 2.42.0", (2, 42, 0)),
                                 ("javac 26", (26, 0, 0)), ("no version here", None)):
            self.assertEqual(probe_version(output), expected)

    def test_selected_targets_merge_ranges_and_report_each_status(self):
        self.build()
        host = Host({"node": "v26.5.0", "xcodebuild": "Xcode 15.4\nBuild version 15F31d"})
        report = self.run_doctor(host)
        self.assertEqual(report["targets"], ["ios", "web"])
        self.assertEqual(report["host"]["os"], "macos")
        tools = {item["name"]: item for item in report["tools"]}
        self.assertEqual(tools["node"], {"name": "node", "required": ">=24.0.0 <27.0.0", "platforms": ["web"], "found": "/fake/bin/node",
                                         "version": "26.5.0", "status": "ok", "install": ["brew", "install", "node"], "manual": None})
        self.assertEqual((tools["xcodebuild"]["status"], tools["xcodebuild"]["version"], tools["xcodebuild"]["install"]), ("wrong-version", "15.4.0", None))
        self.assertEqual((tools["xcodegen"]["status"], tools["xcodegen"]["found"]), ("missing", None))
        self.assertNotIn("installed", report)
        self.assertEqual(host.installed, [])
        web = self.run_doctor(host, {"targets": ["web"]})
        self.assertEqual((web["targets"], [item["name"] for item in web["tools"]]), (["web"], ["node"]))

    def test_install_runs_only_host_installers_for_missing_tools_then_probes_again(self):
        self.build()
        host = Host({"xcodebuild": "Xcode 16.1"})
        lines = []
        report = self.run_doctor(host, install=True, announce=lines.append)
        self.assertEqual(host.installed, [["brew", "install", "node"], ["brew", "install", "xcodegen"]])
        self.assertEqual(lines, ["$ brew install node", "$ brew install xcodegen"])
        self.assertEqual(report["installed"], [{"name": "node", "argv": ["brew", "install", "node"], "exitCode": 0},
                                               {"name": "xcodegen", "argv": ["brew", "install", "xcodegen"], "exitCode": 0}])
        self.assertEqual({item["name"]: item["status"] for item in report["tools"]}, {"node": "ok", "xcodebuild": "ok", "xcodegen": "ok"})

    def test_manual_and_wrong_version_tools_are_never_installed(self):
        self.build()
        host = Host({"node": "v20.0.0"})
        report = self.run_doctor(host, install=True, announce=lambda line: None)
        self.assertEqual(host.installed, [["brew", "install", "xcodegen"]])
        statuses = {item["name"]: item["status"] for item in report["tools"]}
        self.assertEqual(statuses, {"node": "wrong-version", "xcodebuild": "missing", "xcodegen": "ok"})

    def test_host_specific_installers(self):
        self.build()
        host = Host({})
        for name, expected in (("windows", None), ("linux", ["sudo", "apt-get", "install", "--yes", "xcodegen"])):
            report = doctor("pkg:clod/com.clodhub/game-recipe", "0.1.0", self.store, {}, host=name, which=host.which, runner=host.run)
            self.assertEqual(next(item for item in report["tools"] if item["name"] == "xcodegen")["install"], expected)

    def test_conflicting_ranges_and_definitions_are_errors(self):
        self.component_tools = {"web": [{**NODE, "versionRange": "<20.0.0"}], "ios": [XCODEGEN]}
        self.build()
        with self.assertRaisesRegex(ClodError, "toolchain-conflict"):
            self.run_doctor(Host({}))
        conflicting = {**NODE, "probe": ["node", "-v"]}
        first = {"identity": {"name": "pkg:clod/com.clodhub/a"}, "toolchains": {"web": [NODE]}}
        second = {"identity": {"name": "pkg:clod/com.clodhub/b"}, "toolchains": {"web": [conflicting]}}
        with self.assertRaisesRegex(ClodError, "toolchain-definition-conflict"):
            merge_toolchains([first, second])
        self.assertEqual([item["name"] for item in merge_toolchains([first, second], ["ios"])], [])

    def test_graph_validation_merges_only_selected_targets(self):
        self.component_tools = {"web": [{**NODE, "versionRange": "<20.0.0"}], "ios": [XCODEGEN]}
        self.build()
        from clod.bundle import read_package
        from clod.foundations import validate_graph
        from clod.io import load
        manifests = [read_package(entry, self.store)[0] for entry in load(self.store / "catalogue.json")["entries"]]
        validate_graph(manifests)
        validate_graph(manifests, ["ios"])
        with self.assertRaisesRegex(ClodError, "toolchain-conflict"):
            validate_graph(manifests, ["web"])

    def test_strict_tool_declarations(self):
        validate_tool(NODE)
        for change in (lambda t: t.update(extra=True), lambda t: t.update(name="Node"), lambda t: t.update(versionRange="^22.0.0"),
                       lambda t: t.update(probe=["/usr/bin/node", "--version"]), lambda t: t.update(probe=[]),
                       lambda t: t["install"].update(macos=["port", "install", "node"]), lambda t: t["install"].update(macos=["brew", "install"]),
                       lambda t: t["install"].update(windows=["choco", "install", "nodejs"]), lambda t: t["install"].update(linux=["apt", "install", "nodejs"]),
                       lambda t: t["install"].pop("linux"), lambda t: t.update(manual=""),
                       lambda t: t.update(install={"macos": None, "windows": None, "linux": None}, manual=None)):
            changed = deepcopy(NODE)
            change(changed)
            with self.subTest(changed=changed), self.assertRaises(ClodError):
                validate_tool(changed)
        manifest = fixture(self.root / "strict", "strict")
        validate_component(manifest)
        for toolchains in ({}, {"web": [], "ios": []}, {"web": [NODE, NODE]}, {"web": None}):
            with self.subTest(toolchains=toolchains), self.assertRaises(ClodError):
                validate_component({**manifest, "toolchains": toolchains})
        with self.assertRaisesRegex(ClodError, "toolchain-definition-conflict"):
            validate_component({**manifest, "platforms": ["server", "web"], "toolchains": {"web": [NODE], "server": [{**NODE, "manual": "Other"}]}})

    @unittest.skipIf(os.name == "nt", "Fake shell-script tools and installers need a POSIX shell")
    def test_command_probes_path_and_installs_only_with_flag(self):
        self.build()
        bin_path = self.root / "bin"
        bin_path.mkdir()

        def script(name, body):
            path = bin_path / name
            path.write_text("#!/bin/sh\n" + body + "\n")
            path.chmod(0o755)

        script("node", "echo v26.5.0")
        installer = f"printf '#!/bin/sh\\necho 2.42.0\\n' > {bin_path}/xcodegen; /bin/chmod 755 {bin_path}/xcodegen; echo installer-output"
        script("brew", installer)
        script("sudo", installer)
        answers = self.root / "answers.json"
        write(answers, {"targets": ["ios"]})

        def command(*extra):
            output, errors = io.StringIO(), io.StringIO()
            with patch.dict(os.environ, {"PATH": str(bin_path)}), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                code = main(["doctor", "game-recipe@0.1.0", "--store", str(self.store), "--answers", str(answers), *extra])
            return code, json.loads(output.getvalue()), errors.getvalue()

        code, value, _ = command()
        self.assertEqual((code, value["ok"]), (1, False))
        self.assertEqual({item["name"]: item["status"] for item in value["result"]["tools"]}, {"xcodebuild": "missing", "xcodegen": "missing"})
        self.assertFalse((bin_path / "xcodegen").exists())
        code, value, errors = command("--install")
        self.assertEqual(code, 1)
        self.assertIn("$ ", errors)
        self.assertIn("install xcodegen", errors)
        self.assertIn("installer-output", errors)
        statuses = {item["name"]: item for item in value["result"]["tools"]}
        self.assertEqual((statuses["xcodegen"]["status"], statuses["xcodegen"]["version"]), ("ok", "2.42.0"))
        self.assertEqual(statuses["xcodebuild"]["status"], "missing")
        self.assertEqual([item["name"] for item in value["result"]["installed"]], ["xcodegen"])
        write(answers, {"targets": ["web"]})
        code, value, _ = command()
        self.assertEqual((code, value["ok"], value["result"]["tools"][0]["status"]), (0, True, "ok"))

    def test_command_reports_design_errors_as_values(self):
        self.build()
        answers = self.root / "answers.json"
        write(answers, {"targets": []})
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(["doctor", "game-recipe@0.1.0", "--store", str(self.store), "--answers", str(answers)])
        self.assertEqual((code, json.loads(output.getvalue())), (1, {"ok": False, "errors": [{"code": "invalid-answer", "path": "answers.targets"}]}))


if __name__ == "__main__":
    unittest.main()
