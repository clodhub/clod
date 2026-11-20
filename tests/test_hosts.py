"""Host-independent archives, link rejection on every host, and update command usage."""

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from aepm.__main__ import main
from aepm.bundle import pack, read_package
from aepm.io import linked, rooted, snapshot, write
from aepm.model import AepmError
from tests.core.test_core import fixture

# The archive digest of tests.core.test_core.fixture(); identical on macOS, Linux and Windows.
FIXTURE_DIGEST = "d2ce3d4978386522e8b8a99a060f923a2fa131b38dc92bc6370b370556ed1952"
DEFINITION = {"format": 2, "id": "sample-app", "title": "Sample", "recipe": {"name": "ourapps-ae/recipe", "version": "0.1.0"},
              "components": [], "configuration": {}, "design": {"definitions": [], "instances": [], "connections": []}, "updatePolicy": {"security": "auto", "features": "manual", "preview": "hold"}}


class Reparse:
    """An lstat result for a Windows reparse point (junction) that is otherwise a directory."""
    st_mode = stat.S_IFDIR | 0o777
    st_file_attributes = 0x10 | 0x400


class HostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_archive_bytes_do_not_depend_on_host_or_source_location(self):
        fixture(self.root / "source", python="python3")
        self.assertEqual(pack(self.root / "source", self.root / "store")["digest"], FIXTURE_DIGEST)
        manifest, _ = read_package({"name": "ourapps-ae/sample", "version": "0.1.0", "digest": FIXTURE_DIGEST}, self.root / "store")
        self.assertEqual([item["path"] for item in manifest["files"] if item["executable"]], ["run.sh"])

    @unittest.skipUnless(os.name == "nt", "Windows has no execute bits; POSIX packing compares them with the manifest")
    def test_windows_execute_flags_come_from_the_manifest(self):
        component = fixture(self.root / "source")
        component["files"] = [{**item, "executable": item["path"] in ("run.sh", "test.py")} for item in component["files"]]
        write(self.root / "source/component.json", component)
        ref = pack(self.root / "source", self.root / "store")
        import tarfile
        with tarfile.open(self.root / "store/objects" / (ref["digest"] + ".tar")) as archive:
            modes = {member.name: member.mode for member in archive}
        self.assertEqual((modes["run.sh"], modes["test.py"], modes["NOTICE"]), (0o755, 0o755, 0o644))

    def test_reparse_points_are_links(self):
        (self.root / "tree/inner").mkdir(parents=True)
        real = os.lstat
        target = str(self.root / "tree/inner")
        with patch("aepm.io.os.lstat", lambda path, *a, **k: Reparse() if str(path) == target else real(path, *a, **k)):
            self.assertTrue(linked(target))
            with self.assertRaisesRegex(AepmError, "special-file"):
                snapshot(self.root / "tree")
            with self.assertRaisesRegex(AepmError, "symlink"):
                rooted(self.root / "tree", "inner/file")
        self.assertFalse(linked(target))
        self.assertFalse(linked(self.root / "absent"))

    @unittest.skipUnless(os.name == "nt", "Junctions exist only on Windows")
    def test_windows_junctions_are_rejected(self):
        (self.root / "outside").mkdir()
        (self.root / "outside/secret").write_text("outside")
        fixture(self.root / "source")
        subprocess.run(["cmd", "/c", "mklink", "/J", str(self.root / "source/linked"), str(self.root / "outside")], check=True,
                       capture_output=True)
        self.assertTrue(linked(self.root / "source/linked"))
        with self.assertRaisesRegex(AepmError, "special-file"):
            snapshot(self.root / "source")
        with self.assertRaisesRegex(AepmError, "symlink"):
            rooted(self.root / "source", "linked/secret")
        component = json.loads((self.root / "source/component.json").read_text())
        component["files"].append({"path": "linked/secret", "executable": False})
        component["files"].sort(key=lambda item: item["path"])
        write(self.root / "source/component.json", component)
        with self.assertRaisesRegex(AepmError, "unsafe-file"):
            pack(self.root / "source", self.root / "store")

    def test_update_without_trusted_names_what_trusted_permits(self):
        write(self.root / "next.json", DEFINITION)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["propose-update", str(self.root / "app"), str(self.root / "next.json"), "--store", str(self.root / "store"),
                         "--policy", str(self.root / "policy.json"), "--out", str(self.root / "proposal.json")])
        error = json.loads(output.getvalue())["error"]
        self.assertEqual(code, 1)
        self.assertEqual(error["code"], "trusted-execution-required")
        self.assertIn("--trusted", error["path"])
        self.assertIn("declared verification checks", error["path"])
        self.assertFalse((self.root / "proposal.json").exists())


if __name__ == "__main__":
    unittest.main()
