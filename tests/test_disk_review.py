"""Cleanup protections, liveness, results that combine a full volume with a failed cleanup, and later checks after an
admission refusal."""

import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from aepm.model import AepmError
from tests.core.test_core import PYTHON, fixture
from tests.test_disk_safety import LedgerAndCleanTests, StateTest

POSIX = unittest.skipIf(os.name == "nt", "POSIX processes and modes")


class CleanProtectionTests(StateTest):
    SLEEP = LedgerAndCleanTests.SLEEP
    dead_root = LedgerAndCleanTests.dead_root

    def survey(self):
        from aepm.clean import survey
        value = survey()
        return [item["path"] for item in value["candidates"]], {item["path"]: item["reason"] for item in value["protected"]}, value

    @POSIX
    def test_root_recorded_through_a_linked_temporary_folder_is_known(self):
        real = self.root / "real-temporary"
        real.mkdir()
        linked = self.root / "linked-temporary"
        linked.symlink_to(real)
        from aepm.ledger import record
        with patch("tempfile.tempdir", str(linked)):
            ledgered = linked / "aepm-verification-ledgered"
            ledgered.mkdir()
            record(ledgered, "check", purpose="fixture")
            (linked / "aepm-verification-unledgered").mkdir()
            _, _, value = self.survey()
        unknown = [item["path"] for item in value["unknown"]]
        self.assertEqual(unknown, [str(real / "aepm-verification-unledgered")])

    @POSIX
    def test_killed_owner_root_with_an_emulator_profile_is_protected(self):
        root = self.dead_root("check-profile")
        profile = root / "protocol/profiles/android/avd"
        profile.mkdir(parents=True)
        (profile / "config.ini").write_text("hw.ramSize=2048\n")
        candidates, protected, _ = self.survey()
        self.assertNotIn(str(root), candidates)
        self.assertEqual(protected[str(root)], "device-profile-present")

    @POSIX
    def test_a_profile_root_is_never_removed_even_when_its_devices_are_confirmed_gone(self):
        root = self.dead_root("check-gone-devices", retained="device-ownership",
                              devices=[{"kind": "apple-device", "requestedId": "aepm-a", "resourceId": "0000-gone"}])
        (root / "protocol/profiles/apple").mkdir(parents=True)
        (root / "protocol/profiles/apple/device.plist").write_text("profile")
        with patch("aepm.clean._devices_gone", return_value=True):
            candidates, protected, _ = self.survey()
        self.assertNotIn(str(root), candidates)
        self.assertEqual(protected[str(root)], "device-profile-present")

    @POSIX
    def test_killed_owner_root_with_device_intent_records_is_protected(self):
        root = self.dead_root("check-intent", retained="cleanup-failed")
        (root / "protocol/ownership").mkdir(parents=True)
        (root / "protocol/ownership/intent-1.json").write_text(json.dumps({"kind": "apple-device", "requestedId": "aepm-x"}))
        candidates, protected, _ = self.survey()
        self.assertNotIn(str(root), candidates)
        self.assertEqual(protected[str(root)], "devices-not-confirmed-gone")

    @POSIX
    def test_root_with_a_process_still_running_inside_is_protected(self):
        for retained in (None, "cleanup-failed"):
            with self.subTest(retained=retained):
                root = self.dead_root("check-busy-" + str(retained), **({"retained": retained} if retained else {}))
                leftover = subprocess.Popen(["sleep", "60"], cwd=root)
                self.addCleanup(leftover.kill)
                candidates, protected, _ = self.survey()
                self.assertNotIn(str(root), candidates)
                self.assertEqual(protected[str(root)], "processes-inside")
                leftover.kill()
                leftover.wait()
                candidates, _, _ = self.survey()
                self.assertIn(str(root), candidates)

    @POSIX
    def test_unknown_owner_start_time_is_treated_as_alive(self):
        root = self.dead_root("check-unknown-start", processStart=None)
        candidates, protected, _ = self.survey()
        self.assertNotIn(str(root), candidates)
        self.assertEqual(protected[str(root)], "owner-alive")
        from aepm.space import _device, reserved_by_others
        from aepm.state import folder, write_record
        write_record(folder("reservations") / "unknown.json", {"format": 1, "pid": 999999, "processStart": None, "runId": "x",
                                                               "device": _device(self.root), "bytes": 12345, "path": str(self.root),
                                                               "purpose": "fixture"})
        self.assertEqual(reserved_by_others(self.root), 12345)

    @POSIX
    def test_clean_removes_a_dead_runs_read_only_seeds(self):
        seeds = self.dead_root("state/seeds/dead-run", kind="work")
        (seeds / "npm/_cacache").mkdir(parents=True)
        (seeds / "npm/_cacache/blob").write_bytes(b"seed")
        for directory, directories, files in os.walk(seeds, topdown=False):
            for name in files:
                os.chmod(os.path.join(directory, name), 0o444)
            os.chmod(directory, 0o555)
        self.addCleanup(lambda: seeds.exists() and [os.chmod(d, 0o700) for d, _, _ in os.walk(seeds)])
        self.assertIn(str(seeds), self.survey()[0])
        self.command("clean")
        code, value = self.command("clean", "--apply")
        self.assertEqual((code, value["result"]["failed"]), (0, []), value)
        self.assertFalse(seeds.exists())


class OpenFileTests(StateTest):
    SLEEP = LedgerAndCleanTests.SLEEP
    dead_root = LedgerAndCleanTests.dead_root
    HOLD = "import sys, time\nstream = open(sys.argv[1], 'rb')\nprint('ready', flush=True)\ntime.sleep(60)\n"

    def holder(self, path):
        """A process whose working folder is outside `path`'s root and which holds `path` open."""
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir(exist_ok=True)
        process = subprocess.Popen([sys.executable, "-B", "-c", self.HOLD, str(path)], cwd=elsewhere, stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        self.assertEqual(process.stdout.readline().strip(), "ready")
        return process

    @POSIX
    def test_a_file_held_open_from_outside_keeps_the_root_protected_at_listing_and_removal(self):
        from aepm.clean import clean, survey
        root = self.dead_root("check-open")
        holder = self.holder(root / "data")
        listed = survey()
        self.assertNotIn(str(root), [item["path"] for item in listed["candidates"]])
        self.assertEqual({item["path"]: item["reason"] for item in listed["protected"]}[str(root)], "open-files-inside")
        holder.kill()
        holder.wait()
        clean()
        from aepm import clean as module
        real = module.open_paths
        calls = []

        def appears_after_listing():
            # The apply step lists first (nothing open yet), then the holder opens the file before removal.
            calls.append(1)
            if len(calls) == 2:
                holders.append(self.holder(root / "data"))
            return real()

        holders = []
        with patch.object(module, "open_paths", side_effect=appears_after_listing):
            removed = clean(apply=True)
        holder = holders[0]
        self.assertEqual([(item["path"], item["error"]) for item in removed["failed"]], [(str(root), "in-use")])
        self.assertTrue(root.exists())
        holder.kill()
        holder.wait()
        clean()
        self.assertEqual([item["path"] for item in clean(apply=True)["removed"]], [str(root)])

    @POSIX
    def test_an_inspection_failure_protects_every_candidate(self):
        from aepm import clean as module
        first, second = self.dead_root("check-first"), self.dead_root("check-second")
        with patch.object(module, "open_paths", return_value=None):
            listed = module.survey()
        self.assertEqual(listed["candidates"], [])
        reasons = {item["path"]: item["reason"] for item in listed["protected"]}
        self.assertEqual((reasons[str(first)], reasons[str(second)]), ("open-files-unknown", "open-files-unknown"))
        module.clean()
        with patch.object(module, "open_paths", side_effect=[[], None, None]):
            removed = module.clean(apply=True)
        self.assertEqual(sorted(item["error"] for item in removed["failed"]), ["open-files-unknown", "open-files-unknown"])
        self.assertTrue(first.exists() and second.exists())

    def test_open_file_inspection_fails_closed(self):
        from types import SimpleNamespace
        from aepm import clean as module
        with patch.object(module, "PLATFORM", "darwin"), \
                patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout=b"p1\nn/x\n")):
            self.assertIsNone(module.open_paths())
        with patch.object(module, "PLATFORM", "darwin"), patch.object(module.subprocess, "run", side_effect=OSError("no lsof")):
            self.assertIsNone(module.open_paths())
        with patch.object(module, "PLATFORM", "linux"), patch.object(module.os, "scandir", side_effect=PermissionError()):
            self.assertIsNone(module.open_paths())
        with patch.object(module, "PLATFORM", "win32"):
            self.assertIsNone(module.open_paths())

    @POSIX
    def test_windows_lists_but_never_removes(self):
        from aepm import clean as module
        root = self.dead_root("check-windows")
        with patch.object(module, "PLATFORM", "win32"):
            code, value = self.command("clean")
            self.assertEqual(code, 0)
            self.assertIn(str(root), [item["path"] for item in value["result"]["candidates"]])
            self.assertEqual(value["result"]["removal"], module.WINDOWS_OFF)
            code, value = self.command("clean", "--apply")
        self.assertEqual((code, value["error"]["code"]), (1, "clean-removal-off"))
        self.assertTrue(root.exists())


class FullVolumeAndCleanupTests(StateTest):
    def setUp(self):
        super().setUp()
        patcher = patch.dict(os.environ, {"AEPM_FREE_SPACE_MARGIN": "0"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def suite(self, **changes):
        return {"package": "0" * 64, "id": "unit", "scope": "required-local", "root": "package", "argv": [PYTHON, "-c", "pass"],
                "cwd": ".", "prepare": [], "tools": {PYTHON: "3"}, "fixtures": [], "locks": [], "network": False,
                "timeoutSeconds": 30, "expectedExit": 0, "requirements": [], **changes}

    def retained(self):
        from aepm.ledger import entries
        roots = [Path(entry["root"]) for entry in entries() if entry["kind"] == "check" and entry.get("retained") == "cleanup-failed"]
        for root in roots:
            self.addCleanup(lambda root=root: root.exists() and ([os.chmod(d, 0o700) for d, _, _ in os.walk(root)], shutil.rmtree(root, ignore_errors=True)))
        return roots

    @POSIX
    def test_failed_cleanup_then_a_full_volume_keeps_the_root_and_names_cleanup_failed(self):
        from aepm import verification
        from aepm.trust import validate_suite_resources
        source = self.root / "package"
        source.mkdir()
        (source / "data").write_bytes(b"d" * 1000)
        original = verification.immutable_blob

        def run(argv, cwd, environment, timeout, limit, **_):
            if argv[-1] in ("--version", "-version"):
                return 0, 0, "", b"Python 3.12.8\n"
            return -9, 1, "cleanup-failed", b"output"

        def blob(path, data):
            if Path(path).suffix == ".log":
                raise OSError(errno.ENOSPC, "No space left on device", str(path))
            return original(path, data)

        with patch.object(verification, "run", side_effect=run), patch.object(verification, "immutable_blob", side_effect=blob):
            result = verification.execute_suite(self.suite(), source, False, self.root / "logs")
        self.assertEqual((result["status"], result["reason"]), ("failed", "cleanup-failed"))
        self.assertIn("space", result)
        roots = self.retained()
        self.assertEqual(len(roots), 1)
        self.assertTrue((roots[0] / "root/data").exists())
        self.assertEqual(result["storage"]["keptBytes"], result["storage"]["writtenBytes"])
        validate_suite_resources(result)

    @POSIX
    def test_full_volume_then_a_failed_cleanup_hook_gives_a_result_that_validates(self):
        from types import SimpleNamespace
        from aepm import contextual
        from aepm.trust import validate_suite_resources
        source = self.root / "package"
        source.mkdir()
        suite = self.suite(id="room", scope="platform", argv=["fixture"], tools={}, execution={
            "kind": "local", "simulation": False, "operations": [], "settings": [], "secrets": [], "resources": [],
            "assertions": [], "cleanup": None})

        def prepare(suite, private):
            ownership = Path(private) / "protocol/ownership"
            ownership.mkdir(parents=True)
            (ownership / "intent-1.json").write_text(json.dumps({"kind": "provider-room", "requestedId": "room"}))
            return "local", {"settings": {}, "operations": [], "simulationKind": None}, [], [], {}

        execution = SimpleNamespace(check_time=lambda: None, run_id="fixture", authorization=None, selection=lambda suite: ("local", {}),
                                    prepare=prepare)

        def run(*_, **__):
            raise OSError(errno.ENOSPC, "No space left on device", str(self.root / "full"))

        with patch.object(contextual, "tool_environment", side_effect=lambda home, *a, **k: {"PATH": "/usr/bin",
                          "AEPM_PRIVATE_ROOT": str(home.parent)}), \
                patch.object(contextual, "tool_versions", return_value={}), \
                patch.object(contextual, "prerequisites", return_value=[]), \
                patch.object(contextual, "resolve_command", side_effect=lambda argv, *a, **k: argv), \
                patch.object(contextual, "run", side_effect=run):
            result, record = contextual.execute(suite, source, False, self.root / "logs", execution)
        self.retained()
        self.assertEqual((result["status"], result["reason"]), ("failed", "cleanup-failed"))
        self.assertEqual(result["space"]["path"], str(self.root / "full"))
        self.assertFalse(record["cleanup"]["completed"])
        validate_suite_resources(result)


class AdmissionTests(StateTest):
    def test_a_check_refused_at_admission_does_not_stop_a_smaller_later_check(self):
        from aepm.bundle import pack
        from aepm.io import load, write
        from aepm.test_identities import generate
        from aepm.trust import publish_release
        from aepm import verification
        source = self.root / "source"
        manifest = fixture(source)
        small = dict(manifest["verification"][0], id="z-small")
        manifest["verification"] = [dict(manifest["verification"][0], id="a-large"), small]
        write(source / "component.json", manifest)
        store, policy = self.root / "store", generate(self.root / "keys")
        ref = pack(source, store)
        publish_release(store, ref, self.root / "keys/release.pem")
        trusted = load(policy)
        trusted["trustedExecution"] = [ref["digest"]]
        write(policy, trusted)
        original = verification.check_bytes

        def sized(suite, *args):
            return 10 ** 15 if suite["id"] == "a-large" else original(suite, *args)

        with patch.dict(os.environ, {"AEPM_FREE_SPACE_MARGIN": "0"}), patch.object(verification, "check_bytes", side_effect=sized):
            report = verification.review_package(ref, store, policy, True)
        results = {item["id"]: item for item in report["suites"]}
        self.assertEqual((results["a-large"]["status"], results["a-large"]["reason"]), ("blocked", "insufficient-space"))
        self.assertEqual((results["z-small"]["status"], results["z-small"]["reason"]), ("passed", ""))


if __name__ == "__main__":
    unittest.main()
