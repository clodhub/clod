"""Free-space admission, reservations, machine locks, the run ledger and safe cleanup."""

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from aepm.__main__ import main
from aepm.model import AepmError, canonical, digest

ROOT = Path(__file__).resolve().parents[1]
GIB = 1024 ** 3


class StateTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.state = self.root / "state"
        patcher = patch.dict(os.environ, {"AEPM_STATE_HOME": str(self.state), "AEPM_FREE_SPACE_MARGIN": str(GIB)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def command(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([str(item) for item in args])
        return code, json.loads(output.getvalue())

    def child(self, code, *args, wait_for=None):
        """A separate Python process running `code`; waits until it prints `ready` when wait_for is set."""
        process = subprocess.Popen([sys.executable, "-B", "-c", code, *map(str, args)], cwd=ROOT, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env={**os.environ, "PYTHONPATH": str(ROOT)})
        self.addCleanup(lambda: process.poll() is None and process.kill())
        if wait_for:
            line = process.stdout.readline()
            self.assertEqual(line.strip(), wait_for, process.stderr.read() if process.poll() is not None else line)
        return process


class SpaceTests(StateTest):
    def test_admission_refuses_with_numbers(self):
        from aepm.space import require_space
        with patch("aepm.space.shutil.disk_usage", return_value=type("U", (), {"free": 3 * GIB, "total": 9 * GIB})()):
            numbers = require_space(self.root, GIB, purpose="fixture")
            self.assertEqual((numbers["free"], numbers["margin"], numbers["reserved"]), (3 * GIB, GIB, 0))
            with self.assertRaises(AepmError) as raised:
                require_space(self.root / "absent/below", 2 * GIB + 1, purpose="fixture")
        error = raised.exception
        self.assertEqual(error.code, "insufficient-space")
        self.assertEqual(error.detail, {"path": str(self.root / "absent/below"), "purpose": "fixture", "required": 2 * GIB + 1,
                                        "free": 3 * GIB, "margin": GIB, "reserved": 0})

    def test_margin_setting_is_strict(self):
        from aepm.space import margin
        for value in ("-1", "1e9", "ten", ""):
            with self.subTest(value=value), patch.dict(os.environ, {"AEPM_FREE_SPACE_MARGIN": value}), self.assertRaises(AepmError):
                margin()

    def test_out_of_space_errors_are_insufficient_space(self):
        from aepm.model import guarded
        import errno

        @guarded
        def failing():
            raise OSError(errno.ENOSPC, "No space left on device", str(self.root / "file"))

        with self.assertRaises(AepmError) as raised:
            failing()
        self.assertEqual((raised.exception.code, raised.exception.detail["path"], raised.exception.detail["purpose"]),
                         ("insufficient-space", str(self.root / "file"), "failing"))
        if hasattr(errno, "EDQUOT"):
            @guarded
            def quota():
                raise OSError(errno.EDQUOT, "Disc quota exceeded")
            with self.assertRaisesRegex(AepmError, "insufficient-space"):
                quota()

    def test_command_reports_numbers(self):
        code, value = self.command("space", self.root, "--need", 10 ** 15)
        self.assertEqual((code, value["ok"], value["result"]["need"]), (1, False, 10 ** 15))
        code, value = self.command("space", self.root / "absent", "--need", 1)
        self.assertEqual((code, value["ok"]), (0, True))

    def test_tree_bytes_is_bounded_and_does_not_follow_links(self):
        from aepm.space import tree_bytes
        (self.root / "tree/inner").mkdir(parents=True)
        (self.root / "tree/inner/data").write_bytes(b"x" * 100000)
        (self.root / "outside").write_bytes(b"y" * 1000000)
        (self.root / "tree/link").symlink_to(self.root / "outside")
        size = tree_bytes(self.root / "tree")
        self.assertGreaterEqual(size, 100000)
        self.assertLess(size, 1000000)
        self.assertEqual(tree_bytes(self.root / "absent"), 0)
        with self.assertRaisesRegex(AepmError, "metadata-limit"):
            tree_bytes(self.root / "tree", limit=2)

    def test_concurrent_admissions_that_fit_alone_but_not_together(self):
        free = 8 * GIB
        code = ("import os, sys, time\nfrom unittest.mock import patch\nfrom aepm.space import reserve\n"
                f"usage = type('U', (), {{'free': {free}, 'total': {free}}})()\n"
                "with patch('aepm.space.shutil.disk_usage', return_value=usage):\n"
                "    with reserve(sys.argv[1], int(sys.argv[2]), purpose='holder'):\n"
                "        print('ready', flush=True)\n        time.sleep(60)\n")
        holder = self.child(code, self.root, 4 * GIB, wait_for="ready")
        from aepm.space import reserve
        usage = type("U", (), {"free": free, "total": free})()
        with patch("aepm.space.shutil.disk_usage", return_value=usage):
            with self.assertRaises(AepmError) as raised:
                with reserve(self.root, 4 * GIB, purpose="second"):
                    pass
            self.assertEqual((raised.exception.code, raised.exception.detail["reserved"]), ("insufficient-space", 4 * GIB))
            with reserve(self.root, 2 * GIB, purpose="fits beside"):
                pass
            holder.kill()
            holder.wait()
            with reserve(self.root, 4 * GIB, purpose="after holder died") as numbers:
                self.assertEqual(numbers["reserved"], 0)
        self.assertEqual(list((self.state / "reservations").glob("*.json")), [])


class LockTests(StateTest):
    HOLD = ("import sys, time\nfrom aepm.locks import heavy\n"
            "with heavy(sys.argv[1], purpose='fixture holder', timeout=5):\n    print('ready', flush=True)\n    time.sleep(float(sys.argv[2]))\n")

    def test_second_holder_waits_then_runs(self):
        holder = self.child(self.HOLD, "gradle", 1.5, wait_for="ready")
        from aepm.locks import heavy
        started = time.monotonic()
        with heavy("gradle", purpose="second", timeout=30) as waited:
            self.assertGreater(waited, 0.5)
            self.assertEqual(holder.poll(), 0)
        self.assertLess(time.monotonic() - started, 30)

    def test_timeout_names_the_live_holder(self):
        holder = self.child(self.HOLD, "xcode", 30, wait_for="ready")
        code, value = self.command("locks")
        listed = {item["kind"]: item for item in value["result"]}
        self.assertTrue(listed["xcode"]["held"])
        self.assertEqual(listed["xcode"]["holder"]["pid"], holder.pid)
        self.assertEqual(listed["xcode"]["holder"]["purpose"], "fixture holder")
        self.assertFalse(listed["gradle"]["held"])
        from aepm.locks import heavy
        with self.assertRaises(AepmError) as raised:
            with heavy("xcode", purpose="impatient", timeout=0.3):
                pass
        self.assertEqual(raised.exception.code, "resource-busy")
        self.assertEqual(raised.exception.detail["holder"]["pid"], holder.pid)

    def test_killed_holder_releases_at_once_and_its_record_is_ignored(self):
        holder = self.child(self.HOLD, "android-emulator", 60, wait_for="ready")
        os.kill(holder.pid, signal.SIGKILL if hasattr(signal, "SIGKILL") else signal.SIGTERM)
        holder.wait()
        self.assertTrue((self.state / "locks/android-emulator.holder.json").exists())
        code, value = self.command("locks")
        self.assertEqual(next(item for item in value["result"] if item["kind"] == "android-emulator")["held"], False)
        from aepm.locks import heavy
        with heavy("android-emulator", purpose="after kill", timeout=2) as waited:
            self.assertLess(waited, 1)

    def test_reentrant_within_one_process_and_unknown_kind(self):
        from aepm.locks import heavy
        with heavy("apple-simulator", purpose="outer", timeout=1):
            with heavy("apple-simulator", purpose="inner", timeout=1) as waited:
                self.assertEqual(waited, 0.0)
        with self.assertRaises(AepmError):
            with heavy("disk", purpose="unknown", timeout=1):
                pass

    PROBE = ("from aepm.locks import heavy\ntry:\n    with heavy('gradle', purpose='other process', timeout=0.3):\n"
             "        print('acquired')\nexcept Exception as error:\n    print(error.code)\n")

    def other_process(self):
        """What a second process gets when it asks for the gradle lock with a short timeout."""
        return self.child(self.PROBE).communicate(timeout=30)[0].strip()

    def assert_free_everywhere(self):
        from aepm.locks import _HELD, holders
        self.assertNotIn("gradle", _HELD)
        self.assertFalse(next(item for item in holders() if item["kind"] == "gradle")["held"])
        self.assertEqual(self.other_process(), "acquired")

    def test_inner_hold_that_outlives_the_outer_keeps_the_lock(self):
        from contextlib import ExitStack
        from aepm.locks import heavy
        inner = ExitStack()
        with heavy("gradle", purpose="outer", timeout=1):
            inner.enter_context(heavy("gradle", purpose="inner", timeout=1))
        self.assertEqual(self.other_process(), "resource-busy")
        inner.close()
        self.assert_free_everywhere()

    def test_nested_holds_release_only_when_the_last_exits(self):
        from aepm.locks import heavy
        with heavy("gradle", purpose="outer", timeout=1):
            with heavy("gradle", purpose="middle", timeout=1):
                with heavy("gradle", purpose="inner", timeout=1):
                    self.assertEqual(self.other_process(), "resource-busy")
                self.assertEqual(self.other_process(), "resource-busy")
            self.assertEqual(self.other_process(), "resource-busy")
        self.assert_free_everywhere()

    def test_errors_and_cancellation_in_inner_or_outer_block_release_once(self):
        from contextlib import ExitStack
        from aepm.locks import heavy
        for error in (RuntimeError("check failed"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__, place="inner"):
                with self.assertRaises(type(error)):
                    with heavy("gradle", purpose="outer", timeout=1):
                        try:
                            with heavy("gradle", purpose="inner", timeout=1):
                                raise error
                        finally:
                            self.assertEqual(self.other_process(), "resource-busy")
                self.assert_free_everywhere()
            with self.subTest(error=type(error).__name__, place="outer with outliving inner"):
                inner = ExitStack()
                with self.assertRaises(type(error)):
                    with heavy("gradle", purpose="outer", timeout=1):
                        inner.enter_context(heavy("gradle", purpose="inner", timeout=1))
                        raise error
                self.assertEqual(self.other_process(), "resource-busy")
                inner.close()
                self.assert_free_everywhere()

    def test_second_process_waits_for_the_final_holder_then_gets_the_lock(self):
        from contextlib import ExitStack
        from aepm.locks import heavy
        waiting = self.child("import time\nfrom aepm.locks import heavy\nstarted = time.monotonic()\n"
                             "with heavy('gradle', purpose='waiting process', timeout=30) as waited:\n"
                             "    print('acquired', round(waited, 1), flush=True)\n")
        inner = ExitStack()
        with heavy("gradle", purpose="outer", timeout=1):
            inner.enter_context(heavy("gradle", purpose="inner", timeout=1))
            time.sleep(0.5)
        time.sleep(1.0)
        self.assertIsNone(waiting.poll(), "the second process got the lock before the final holder exited")
        inner.close()
        output = waiting.communicate(timeout=30)[0].split()
        self.assertEqual(output[0], "acquired")
        self.assertGreaterEqual(float(output[1]), 1.0)

    def test_lock_command_runs_and_returns_the_exit_code(self):
        code, value = self.command("lock", "gradle", "--timeout", 5, "--", sys.executable, "-c", "raise SystemExit(3)")
        self.assertEqual((code, value["result"]["exitCode"]), (3, 3))

    def test_kinds_for_checks(self):
        from aepm.locks import kinds_for
        self.assertEqual(kinds_for({"tools": {"python3": "3"}}), [])
        self.assertEqual(kinds_for({"tools": {"swiftc": "6"}}), ["xcode"])
        self.assertEqual(kinds_for({"tools": {"python3": "3"}, "requirements": ["external:android-test-environment"],
                                    "execution": {"operations": ["native-build", "create-temporary-emulator"],
                                                  "resources": [{"id": "androidSdk"}]}}), ["gradle", "android-emulator"])
        self.assertEqual(kinds_for({"tools": {"xcodebuild": "26"}, "requirements": ["external:compatible-apple-simulator"],
                                    "execution": {"operations": ["create-temporary-simulator"], "resources": []}}), ["xcode", "apple-simulator"])

    def test_emulator_port_pair_is_free(self):
        import socket
        from aepm.locks import free_port
        taken = socket.socket()
        taken.bind(("127.0.0.1", 0))
        self.addCleanup(taken.close)
        port = free_port(start=taken.getsockname()[1] - (taken.getsockname()[1] % 2), end=65534)
        for value in (port, port + 1):
            probe = socket.socket()
            probe.bind(("127.0.0.1", value))
            probe.close()


class LedgerAndCleanTests(StateTest):
    SLEEP = "import sys, time\nfrom aepm.ledger import record\nrecord(sys.argv[1], sys.argv[2], purpose='fixture')\nprint('ready', flush=True)\ntime.sleep(60)\n"

    def dead_root(self, name, kind="check", **changes):
        """A ledgered root whose owner was a process that has exited."""
        root = self.root / name
        root.mkdir(parents=True)
        (root / "data").write_bytes(b"z" * 5000)
        process = self.child(self.SLEEP, root, kind, wait_for="ready")
        process.kill()
        process.wait()
        if changes:
            from aepm.ledger import _entry_path
            path = _entry_path(root)
            value = json.loads(path.read_bytes())
            value.update(changes)
            path.write_bytes(canonical(value))
        return root

    def test_record_finish_and_runs(self):
        from aepm.ledger import entries, finish, record
        gone, kept = self.root / "gone", self.root / "kept"
        gone.mkdir()
        kept.mkdir()
        (kept / "file").write_bytes(b"k" * 4096)
        first, second = record(gone, "check", purpose="a"), record(kept, "check", purpose="b")
        gone.rmdir()
        self.assertEqual(finish(first)["bytesAtEnd"], 0)
        value = finish(second, retained="cleanup-failed")
        self.assertGreaterEqual(value["bytesAtEnd"], 4096)
        self.assertEqual([item["root"] for item in entries()], [str(kept)])
        code, listed = self.command("runs")
        this = next(item for item in listed["result"] if item["live"])
        self.assertEqual((this["created"], this["removed"], this["retained"]), (2, 1, 1))
        self.assertEqual(this["roots"][0]["retained"], "cleanup-failed")
        with self.assertRaises(AepmError):
            record(gone, "store", purpose="not a kind")

    def test_dry_run_lists_only_safe_candidates_and_apply_removes_them(self):
        from aepm.ledger import record, register
        dead = self.dead_root("dead-check")
        live = self.root / "live-check"
        live.mkdir()
        sleeper = self.child(self.SLEEP, live, "check", wait_for="ready")
        kept = self.root / "proof"
        kept.mkdir()
        register(kept, "proof", purpose="historical proof", keep=True)
        stage_parent = self.root / ".app.aepm-transaction"
        busy_stage = stage_parent / "stage"
        busy_stage.mkdir(parents=True)
        (stage_parent / "journal.json").write_text("{}")
        record(busy_stage, "stage", purpose="propose")
        from aepm.ledger import _entry_path
        entry = json.loads(_entry_path(busy_stage).read_bytes())
        entry.update(pid=999999, processStart="gone")
        _entry_path(busy_stage).write_bytes(canonical(entry))
        failed_stage = self.dead_root("other/.b.aepm-transaction/stage", kind="stage", retained="failed-proposal")
        pending_stage = self.dead_root("third/.c.aepm-transaction/stage", kind="stage", retained="proposal")
        device_root = self.dead_root("device-check", retained="device-ownership",
                                     devices=[{"kind": "provider-room", "requestedId": "room", "resourceId": "room"}])
        logs = self.root / "logs"
        logs.mkdir()
        (logs / ("a" * 64 + ".json")).write_text(json.dumps([{"logDigest": "b" * 64}]))
        (logs / ("b" * 64 + ".log")).write_text("kept output")
        (logs / ("c" * 64 + ".log")).write_text("unreferenced output")
        report = self.root / "report.json"
        report.write_text(json.dumps({"suites": [{"logDigest": "a" * 64}]}))
        self.dead_root("logs-owner")
        log_entry = record(logs, "transaction-logs", purpose="propose logs", references=[report])
        log_entry.update(pid=999999, processStart="gone")
        _entry_path(logs).write_bytes(canonical(log_entry))
        unknown = Path(tempfile.gettempdir()) / ("aepm-verification-unknown-" + digest(str(self.root).encode())[:8])
        unknown.mkdir()
        self.addCleanup(unknown.rmdir)

        code, value = self.command("clean")
        listed = value["result"]
        paths = sorted(item["path"] for item in listed["candidates"])
        self.assertEqual(paths, sorted([str(dead), str(failed_stage), str(logs / ("c" * 64 + ".log")), str(self.root / "logs-owner")]))
        reasons = {item["path"]: item["reason"] for item in listed["protected"]}
        self.assertEqual(reasons[str(live)], "owner-alive")
        self.assertEqual(reasons[str(kept)], "keep")
        self.assertEqual(reasons[str(busy_stage)], "journal-or-backup-present")
        self.assertEqual(reasons[str(pending_stage)], "pending-proposal")
        self.assertEqual(reasons[str(device_root)], "devices-not-confirmed-gone")
        self.assertIn(str(unknown), [item["path"] for item in listed["unknown"]])
        self.assertTrue(dead.exists())

        code, value = self.command("clean", "--apply")
        self.assertEqual(code, 0, value)
        self.assertEqual(sorted(item["path"] for item in value["result"]["removed"]), paths)
        for path in paths:
            self.assertFalse(Path(path).exists())
        for path in (live, kept, busy_stage, pending_stage, device_root, unknown, logs / ("b" * 64 + ".log"), logs / ("a" * 64 + ".json")):
            self.assertTrue(path.exists(), path)
        log = json.loads(Path(value["result"]["log"]).read_bytes())
        self.assertEqual(len(log["removed"]), 4)
        self.assertTrue(all("ledger" in item and "bytes" in item for item in log["removed"]))
        sleeper.kill()

    def test_apply_refuses_a_changed_plan_and_reports_partial_failures(self):
        first = self.dead_root("first")
        code, value = self.command("clean", "--apply")
        self.assertEqual((code, value["error"]["code"]), (1, "clean-plan-changed"))
        self.command("clean")
        self.dead_root("second")
        code, value = self.command("clean", "--apply")
        self.assertEqual((code, value["error"]["code"]), (1, "clean-plan-changed"))
        self.assertTrue(first.exists())
        if os.name != "nt":
            stuck = first / "locked"
            stuck.mkdir()
            (stuck / "file").write_text("cannot remove")
            stuck.chmod(0o500)
            self.addCleanup(stuck.chmod, 0o700)
        from aepm.ledger import _entry_path
        for root in (first, self.root / "second"):
            entry = json.loads(_entry_path(root).read_bytes())
            entry["bytesAtEnd"] = 1
            _entry_path(root).write_bytes(canonical(entry))
        self.command("clean")
        code, value = self.command("clean", "--apply")
        if os.name != "nt":
            self.assertEqual(code, 1)
            failed = value["result"]["failed"]
            self.assertEqual([item["path"] for item in failed], [str(first)])
            self.assertTrue(any(error["path"].startswith(str(stuck)) for error in failed[0]["errors"]))
            self.assertIsNotNone(json.loads(_entry_path(first).read_bytes()))
        self.assertFalse((self.root / "second").exists())

    def test_owner_that_comes_back_alive_blocks_removal(self):
        root = self.dead_root("revived")
        self.command("clean")
        from aepm.ledger import _entry_path
        from aepm.state import owner
        entry = json.loads(_entry_path(root).read_bytes())
        plan = json.loads((self.state / "clean/plan.json").read_bytes())
        entry.update({key: value for key, value in owner().items() if key != "runId"})
        _entry_path(root).write_bytes(canonical(entry))
        code, value = self.command("clean", "--apply")
        self.assertEqual(value["error"]["code"], "clean-plan-changed")
        self.assertTrue(root.exists())
        self.assertTrue(plan["candidates"])

    def test_older_than_limit(self):
        self.dead_root("recent")
        code, value = self.command("clean", "--older-than", "2h")
        self.assertEqual(value["result"]["candidates"], [])
        self.assertEqual(value["result"]["protected"][0]["reason"], "newer-than-limit")
        code, value = self.command("clean", "--older-than", "soon")
        self.assertEqual(value["error"]["code"], "invalid-value")


if __name__ == "__main__":
    unittest.main()
