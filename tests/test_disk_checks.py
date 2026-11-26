"""Checks under low space, injected out-of-space errors, interruption, clone copies and dependency seeds."""

import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from clod.model import ClodError, canonical, digest
from tests.core.test_core import PYTHON, fixture

ROOT = Path(__file__).resolve().parents[1]
GIB = 1024 ** 3


class Base(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        patcher = patch.dict(os.environ, {"CLOD_STATE_HOME": str(self.root / "state"), "CLOD_FREE_SPACE_MARGIN": "0"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def suite(self, **changes):
        base = {"package": "0" * 64, "id": "unit", "scope": "required-local", "root": "package", "argv": [PYTHON, "-c", "pass"],
                "cwd": ".", "prepare": [], "tools": {PYTHON: "3"}, "fixtures": [], "locks": [], "network": False,
                "timeoutSeconds": 30, "expectedExit": 0, "requirements": []}
        return {**base, **changes}

    def package(self):
        source = self.root / "package"
        source.mkdir(exist_ok=True)
        (source / "data.bin").write_bytes(b"d" * 200000)
        return source

    def leftovers(self):
        return sorted(path.name for path in Path(tempfile.gettempdir()).iterdir() if path.name.startswith("clod-verification-")
                      and (path / "root").exists() and any(entry["root"] == str(path) for entry in self.entries()))

    def entries(self):
        from clod.ledger import entries
        return entries()


class CheckSpaceTests(Base):
    def test_low_free_space_blocks_before_any_copy(self):
        from clod.verification import execute_suite
        before = set(Path(tempfile.gettempdir()).iterdir())
        with patch("clod.space.shutil.disk_usage", return_value=type("U", (), {"free": 1000, "total": 1000})()):
            result = execute_suite(self.suite(), self.package(), False, self.root / "logs")
        self.assertEqual((result["status"], result["reason"]), ("blocked", "insufficient-space"))
        self.assertEqual(result["space"]["free"], 1000)
        self.assertGreaterEqual(result["space"]["required"], 200000)
        self.assertEqual(set(Path(tempfile.gettempdir()).iterdir()), before)

    def test_out_of_space_during_the_check_copy_fails_and_removes_the_root(self):
        from clod import copying
        from clod.verification import execute_suite
        original = copying.copy_file

        def full(source, destination, **options):
            if Path(source).name == "data.bin":
                raise OSError(errno.ENOSPC, "No space left on device", str(destination))
            return original(source, destination, **options)

        with patch("clod.copying.copy_file", full):
            result = execute_suite(self.suite(), self.package(), False, self.root / "logs")
        self.assertEqual((result["status"], result["reason"], result["storage"]["keptBytes"]), ("failed", "insufficient-space", 0))
        self.assertIn("data.bin", result["space"]["path"])
        self.assertEqual([entry for entry in self.entries() if entry["kind"] == "check"], [])

    def test_report_stops_remaining_checks_and_still_verifies(self):
        from clod.bundle import pack
        from clod.io import load, write
        from clod.test_identities import generate
        from clod.trust import publish_release, publish_review, review_bindings, validate_report_evidence
        from clod.verification import review_package
        from clod import copying
        source = self.root / "source"
        manifest = fixture(source)
        manifest["verification"].append({**manifest["verification"][0], "id": "later"})
        write(source / "component.json", manifest)
        store, policy = self.root / "store", generate(self.root / "keys")
        ref = pack(source, store)
        publish_release(store, ref, self.root / "keys/release.pem")
        trusted = load(policy)
        trusted["trustedExecution"] = [ref["digest"]]
        write(policy, trusted)
        objects = {path.name: path.read_bytes() for path in (store / "objects").iterdir()}
        original = copying.copy_file

        def full(source_path, destination, **options):
            if Path(source_path).name == "test.py":
                raise OSError(errno.ENOSPC, "No space left on device", str(destination))
            return original(source_path, destination, **options)

        with patch("clod.copying.copy_file", full):
            report = review_package(ref, store, policy, True)
        results = {item["id"]: item for item in report["suites"]}
        first = sorted(report["suites"], key=lambda item: (item["package"], item["id"]))
        stopped = [item for item in first if item["reason"] == "insufficient-space"]
        self.assertTrue(all(item["space"] == stopped[0]["space"] for item in stopped))
        self.assertEqual(stopped[0]["status"], "failed")
        self.assertTrue(all(item["status"] == "blocked" for item in stopped[1:]))
        self.assertEqual(report["summary"]["required-local"], "failed")
        self.assertEqual({path.name: path.read_bytes() for path in (store / "objects").iterdir()}, objects)
        binding = review_bindings(ref, store)
        with self.assertRaisesRegex(ClodError, "report-verdict"):
            validate_report_evidence(report, binding, "review", store, policy)
        with self.assertRaisesRegex(ClodError, "report-verdict"):
            publish_review(store, ref, report, self.root / "keys/guardian.pem", policy=policy)
        self.assertIn("later", results)

    def test_atomic_writes_leave_no_partial_file_when_the_volume_is_full(self):
        from clod.bundle import atomic_write
        from clod.io import write
        target = self.root / "out"
        target.mkdir()
        (target / "existing.json").write_bytes(b"{}")
        real = os.fsync

        def full(descriptor):
            raise OSError(errno.ENOSPC, "No space left on device")

        for function in (lambda: atomic_write(target / "existing.json", b"x" * 1000), lambda: write(target / "existing.json", {"new": 1})):
            with self.subTest(function=function), patch("os.fsync", full), self.assertRaises((ClodError, OSError)) as raised:
                function()
            error = raised.exception
            if isinstance(error, ClodError):
                self.assertEqual(error.code, "insufficient-space")
            self.assertEqual(sorted(path.name for path in target.iterdir()), ["existing.json"])
            self.assertEqual((target / "existing.json").read_bytes(), b"{}")
        self.assertIs(os.fsync, real)

    def test_install_refuses_without_space_and_creates_nothing(self):
        from clod.application import assemble
        base = Path(tempfile.mkdtemp(dir=self.root))
        store = self.root / "store"
        from clod.bundle import pack
        source = self.root / "source"
        manifest = fixture(source, "sample-recipe")
        manifest.update(kind="recipe", implements=[])
        manifest["artefacts"][0]["destination"] = "run.sh"
        (source / "component.json").write_bytes(canonical(manifest))
        ref = pack(source, store)
        definition = {"format": 3, "id": "app", "title": "App", "recipe": {"name": ref["name"], "version": ref["version"]},
                      "components": [], "configuration": {}, "design": {"definitions": [], "instances": [], "connections": []},
                      "updatePolicy": {"security": "auto", "features": "manual", "preview": "hold"}}
        lock = {"format": 2, "application": "app", "definitionDigest": digest(canonical(definition)),
                "packages": [{**ref, "dependencies": []}]}
        before = sorted(base.iterdir())
        with patch("clod.space.shutil.disk_usage", return_value=type("U", (), {"free": 10, "total": 10})()):
            with self.assertRaises(ClodError) as raised:
                assemble(definition, lock, store, base / "app", self.root / "policy.json")
        self.assertEqual(raised.exception.code, "insufficient-space")
        self.assertEqual(sorted(base.iterdir()), before)

    def test_command_line_prints_the_numbers(self):
        import contextlib
        import io
        from clod.__main__ import main
        output = io.StringIO()
        with patch("clod.space.shutil.disk_usage", return_value=type("U", (), {"free": 10, "total": 10})()), contextlib.redirect_stdout(output):
            fixture(self.root / "source")
            code = main(["pack", str(self.root / "source"), "--store", str(self.root / "store")])
        value = json.loads(output.getvalue())
        self.assertEqual((code, value["error"]["code"]), (1, "insufficient-space"))
        self.assertEqual(set(value["error"]["detail"]), {"path", "purpose", "required", "free", "margin", "reserved"})
        self.assertFalse((self.root / "store/objects").exists())


class UnauthorizedCheckTests(Base):
    def test_an_unauthorized_check_needs_no_space(self):
        from clod.contextual import execute
        class Execution:
            context = {"resources": []}

            def selection(self, suite):
                raise ClodError("authorization-denied", "suite")

            def prepare(self, suite, private):
                raise ClodError("authorization-denied", "suite")

            def check_time(self):
                pass

            authorization = None
        suite = self.suite(execution={"kind": "native", "simulation": False, "operations": ["native-build"], "settings": [], "secrets": [],
                                      "resources": [], "assertions": ["build-produced"], "cleanup": None}, tools={"java": "26"})
        with patch("clod.space.shutil.disk_usage", return_value=type("U", (), {"free": 10, "total": 10})()):
            result, _ = execute(suite, self.package(), False, self.root / "logs", Execution())
        self.assertEqual(result["reason"], "authorization-denied")


class ReportFormatTests(Base):
    def test_reports_without_storage_and_lock_records_are_refused(self):
        from clod.trust import validate_report_evidence
        from tests.core.test_core import CoreTests
        case = CoreTests("test_report_bytes_and_suite_coverage")
        CoreTests.setUpClass()
        case.setUp()
        self.addCleanup(case.temp.cleanup)
        from clod.bundle import pack
        from clod.trust import review_bindings
        ref = pack(case.source, case.store)
        report = case.report(ref)
        binding = review_bindings(ref, case.store)
        validate_report_evidence(report, binding, "review", None, None)
        for key in ("storage", "locks"):
            earlier = json.loads(canonical(report))
            for suite in earlier["suites"]:
                suite.pop(key)
            with self.subTest(missing=key), self.assertRaisesRegex(ClodError, "report-format-outdated"):
                validate_report_evidence(earlier, binding, "review", None, None)
        for change in (lambda item: item["storage"].update(keptBytes=5), lambda item: item["locks"].append({"kind": "disk", "waitedMilliseconds": 0}),
                       lambda item: item.update(space={"path": "/", "purpose": "x", "required": 1, "free": 1, "margin": 0, "reserved": 0})):
            changed = json.loads(canonical(report))
            change(changed["suites"][0])
            with self.assertRaises(ClodError):
                validate_report_evidence(changed, binding, "review", None, None)


class InterruptionTests(Base):
    CHECK = ("import os, sys\nfrom pathlib import Path\nfrom clod.verification import execute_suite\n"
             "suite = {'package': '0' * 64, 'id': 'slow', 'scope': 'required-local', 'root': 'package', 'argv': [sys.argv[2], '-c', "
             "\"import time; open('started', 'w').close(); time.sleep(60)\"], 'cwd': '.', 'prepare': [], 'tools': {sys.argv[2]: '3'}, "
             "'fixtures': [], 'locks': [], 'network': False, 'timeoutSeconds': 120, 'expectedExit': 0, 'requirements': []}\n"
             "execute_suite(suite, Path(sys.argv[1]), False, Path(sys.argv[1]).parent / 'logs')\n")

    def interrupted(self, number):
        process = subprocess.Popen([sys.executable, "-B", "-c", self.CHECK, str(self.package()), PYTHON], cwd=ROOT,
                                   env={**os.environ, "PYTHONPATH": str(ROOT)}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            roots = [entry for entry in self.entries() if entry["kind"] == "check" and entry["pid"] == process.pid]
            if roots and (Path(roots[0]["root"]) / "root/started").exists():
                break
            time.sleep(0.1)
        else:
            self.fail(process.stderr.read().decode())
        root = Path(roots[0]["root"])
        from clod.clean import survey
        self.assertEqual(next(item for item in survey()["protected"] if item["path"] == str(root))["reason"], "owner-alive")
        os.kill(process.pid, number)
        process.wait(timeout=60)
        return root

    @staticmethod
    def inside(root):
        """Process ids whose executable or working folder is inside root."""
        from clod.private_process import DarwinBackend, LinuxBackend, _matches
        backend = DarwinBackend() if sys.platform == "darwin" else LinuxBackend()
        found = []
        for pid in backend.pids():
            try:
                record = backend.capture(pid)
            except Exception:
                continue
            if record is not None:
                if _matches(root.resolve(), record):
                    found.append(pid)
                backend.close(record)
        return found

    def test_crash_leaves_a_ledgered_root_that_clean_removes_only_after_the_owner_died(self):
        root = self.interrupted(signal.SIGKILL)
        self.assertTrue(root.exists())
        from clod.clean import clean, survey
        leftovers = self.inside(root)
        if leftovers:
            # The killed run's check process outlives it; while it runs there, the root stays protected.
            self.assertEqual(next(item for item in survey()["protected"] if item["path"] == str(root))["reason"], "processes-inside")
            for pid in leftovers:
                os.kill(pid, signal.SIGKILL)
            deadline = time.monotonic() + 30
            while self.inside(root) and time.monotonic() < deadline:
                time.sleep(0.1)
        listed = clean()
        self.assertIn(str(root), [item["path"] for item in listed["candidates"]])
        removed = clean(apply=True)
        self.assertEqual([item["path"] for item in removed["removed"]], [str(root)])
        self.assertFalse(root.exists())

    def test_cancellation_removes_the_root_or_leaves_it_ledgered(self):
        root = self.interrupted(signal.SIGINT)
        if root.exists():
            from clod.clean import clean
            self.assertIn(str(root), [item["path"] for item in clean()["candidates"]])
            clean(apply=True)
        self.assertFalse(root.exists())
        self.assertEqual([entry for entry in self.entries() if entry["root"] == str(root)], [])


class CopyTests(Base):
    def tree(self):
        source = self.root / "tree"
        (source / "inner").mkdir(parents=True)
        (source / "inner/data").write_bytes(os.urandom(300000))
        (source / "script").write_bytes(b"#!/bin/sh\n")
        (source / "script").chmod(0o755)
        (source / "inner").chmod(0o750)
        return source

    def listing(self, root):
        result = []
        for path in sorted(root.rglob("*")):
            info = path.lstat()
            result.append((path.relative_to(root).as_posix(), oct(info.st_mode), path.read_bytes() if path.is_file() else None))
        return result

    def test_clone_and_byte_copy_give_identical_trees(self):
        from clod import copying
        source = self.tree()
        listings = {}
        for clones in (True, False):
            with patch.dict(copying._CLONES, {"enabled": clones}):
                target = self.root / ("clones" if clones else "bytes")
                counts = copying.copy_tree(source, target)
                listings[clones] = self.listing(target)
                if not clones:
                    self.assertEqual(counts["clone"], 0)
        self.assertEqual(listings[True], listings[False])
        self.assertEqual(listings[True], self.listing(source))

    def test_unsupported_clone_falls_back_to_bytes(self):
        from clod import copying
        source = self.tree()
        with patch("clod.copying.clone_file", return_value=False):
            counts = copying.copy_tree(source, self.root / "copy")
        self.assertEqual((counts["clone"], counts["bytes"]), (0, 2))
        self.assertEqual(self.listing(self.root / "copy"), self.listing(source))

    def test_clone_is_independent_of_its_source(self):
        from clod.copying import copy_file
        source = self.root / "original"
        source.write_bytes(b"a" * 100000)
        copy_file(source, self.root / "copy")
        (self.root / "copy").write_bytes(b"changed")
        self.assertEqual(source.read_bytes(), b"a" * 100000)

    @unittest.skipIf(os.name == "nt", "POSIX symbolic links")
    def test_links_and_special_files_are_refused(self):
        from clod.copying import copy_tree
        source = self.tree()
        (source / "link").symlink_to(self.root)
        with self.assertRaisesRegex(ClodError, "unsafe-file"):
            copy_tree(source, self.root / "copy")

    @unittest.skipUnless(sys.platform == "darwin", "APFS clones")
    def test_apfs_clone_is_used_on_macos(self):
        from clod.copying import copy_file
        source = self.root / "original"
        source.write_bytes(os.urandom(100000))
        self.assertEqual(copy_file(source, self.root / "copy"), "clone")

    def test_resource_is_copied_once_with_its_digest_checks(self):
        from clod.environment import describe_resource, prepare_working_resources, validate_resource
        sdk = self.root / "sdk"
        (sdk / "platform-tools").mkdir(parents=True)
        (sdk / "platform-tools/data").write_bytes(b"s" * 100000)
        resource = describe_resource("androidSdk", sdk, executables=[] if os.name == "nt" else None)
        protocol = self.root / "private/protocol"
        with patch("clod.environment.materialize", wraps=__import__("clod.environment", fromlist=["materialize"]).materialize) as copies:
            prepare_working_resources([resource], protocol)
        self.assertEqual(copies.call_count, 1)
        self.assertEqual((protocol / "android-sdk-working/platform-tools/data").read_bytes(), b"s" * 100000)
        (protocol / "android-sdk-working/platform-tools/data").write_bytes(b"private change")
        validate_resource(resource)


class SeedTests(Base):
    def setUp(self):
        super().setUp()
        from clod import seeds
        self.seeds = seeds
        seeds._STATE.update(root=None, entry=None, fingerprint=None, enabled=True, events=[])
        self.addCleanup(seeds.discard)

    def npm_check(self, name, content):
        """A check root with a locked npm package and an npm cache holding its tarball under the lock's integrity."""
        root = self.root / name / "root"
        root.mkdir(parents=True)
        raw = hashlib.sha512(content).digest()
        (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/example": {"version": "1.0.0", "integrity": "sha512-" + base64.b64encode(raw).decode()}}}))
        home = self.root / name / "home"
        cache = home / "npm/_cacache/content-v2/sha512"
        hexdigest = raw.hex()
        blob = cache / hexdigest[:2] / hexdigest[2:4] / hexdigest[4:]
        blob.parent.mkdir(parents=True)
        blob.write_bytes(content)
        return root, {"npm_config_cache": str(home / "npm"), "HOME": str(home), "CLOD_PRIVATE_ROOT": str(self.root / name)}, hexdigest

    def test_verified_npm_seed_reaches_the_next_check_only_as_a_private_copy(self):
        root, environment, hexdigest = self.npm_check("first", b"tarball bytes")
        self.seeds.harvest_check(root, environment)
        seed = self.seeds._STATE["root"]
        self.assertTrue(str(seed).startswith(str(self.root / "state")))
        self.assertFalse(os.access(next(seed.rglob(hexdigest[4:])), os.W_OK))
        second_root, second_environment, _ = self.npm_check("second", b"tarball bytes")
        shutil.rmtree(Path(second_environment["npm_config_cache"]))
        self.assertEqual(self.seeds.seed_check(second_root, second_environment), [])
        copied = Path(second_environment["npm_config_cache"]) / "_cacache/content-v2/sha512" / hexdigest[:2] / hexdigest[2:4] / hexdigest[4:]
        self.assertEqual(copied.read_bytes(), b"tarball bytes")
        self.assertNotEqual(copied.stat().st_ino, next(seed.rglob(hexdigest[4:])).stat().st_ino)

    def test_unpinned_or_mismatched_npm_bytes_are_never_seeded(self):
        root, environment, hexdigest = self.npm_check("first", b"tarball bytes")
        blob = next(Path(environment["npm_config_cache"]).rglob(hexdigest[4:]))
        blob.write_bytes(b"poisoned bytes")
        self.seeds.harvest_check(root, environment)
        self.assertIsNone(self.seeds._STATE["root"])

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_tampered_seed_is_refused_and_all_seeds_are_discarded(self):
        root, environment, hexdigest = self.npm_check("first", b"tarball bytes")
        self.seeds.harvest_check(root, environment)
        seed = next(self.seeds._STATE["root"].rglob(hexdigest[4:]))
        seed.parent.chmod(0o755)
        seed.chmod(0o644)
        seed.write_bytes(b"poisoned bytes")
        second_root, second_environment, _ = self.npm_check("second", b"tarball bytes")
        shutil.rmtree(Path(second_environment["npm_config_cache"]))
        self.seeds.seed_check(second_root, second_environment)
        self.assertFalse((Path(second_environment["npm_config_cache"]) / "_cacache").exists())
        self.assertIn("seed-changed", self.seeds._STATE["events"])
        self.assertIsNone(self.seeds._STATE["root"])

    def git(self, *arguments, cwd=None):
        environment = {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                       "HOME": str(self.root), "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.org",
                       "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.org"}
        return subprocess.run(["git", *arguments], cwd=cwd, check=True, capture_output=True, text=True, env=environment).stdout.strip()

    def swift_check(self, name, *, upstream=None):
        """A check root pinning one Swift package, and a home whose SwiftPM cache holds a bare clone of it carrying
        its own hooks and configuration, as a package author could supply them."""
        if upstream is None:
            upstream = self.root / "upstream"
            if not upstream.exists():
                upstream.mkdir()
                self.git("init", "-q", cwd=upstream)
                (upstream / "Sources.swift").write_text("let value = 1\n")
                self.git("add", ".", cwd=upstream)
                self.git("commit", "-q", "-m", "one", cwd=upstream)
                self.git("tag", "1.0.0", cwd=upstream)
        revision = self.git("rev-parse", "HEAD", cwd=upstream)
        root = self.root / name / "root"
        root.mkdir(parents=True)
        (root / "Package.resolved").write_text(json.dumps({"version": 2, "pins": [{"identity": "library", "kind": "remoteSourceControl",
            "location": "https://example.org/library.git", "state": {"revision": revision, "version": "1.0.0"}}]}))
        home = self.root / name / "home"
        cache = self.seeds._swift_cache(home)
        cache.mkdir(parents=True)
        repository = cache / "library-0123abcd"
        self.git("clone", "-q", "--bare", "--no-local", str(upstream), str(repository))
        self.git("--git-dir", str(repository), "config", "remote.origin.url", "https://example.org/library.git")
        self.git("--git-dir", str(repository), "config", "core.fsmonitor", "touch " + str(self.root / "fsmonitor-ran"))
        (repository / "hooks").mkdir(exist_ok=True)
        (repository / "hooks/post-checkout").write_text("#!/bin/sh\ntouch " + str(self.root / "hook-ran") + "\n")
        (repository / "hooks/post-checkout").chmod(0o755)
        return root, {"HOME": str(home), "CFFIXED_USER_HOME": str(home), "CLOD_PRIVATE_ROOT": str(self.root / name)}, repository, revision

    def loose(self, repository, revision):
        """Unpack the repository's objects so each is its own file, then return the path of the tracked file's blob."""
        packs = list((repository / "objects/pack").glob("*.pack"))
        for pack in packs:
            moved = self.root / pack.name
            pack.rename(moved)
            pack.with_suffix(".idx").unlink()
            subprocess.run(["git", "--git-dir", str(repository), "unpack-objects", "-q"], stdin=open(moved, "rb"), check=True)
        blob = self.git("--git-dir", str(repository), "rev-parse", revision + ":Sources.swift")
        return repository / "objects" / blob[:2] / blob[2:]

    @unittest.skipUnless(shutil.which("git") and os.name != "nt", "git and POSIX modes required")
    def test_swift_seed_is_a_fresh_repository_without_the_packages_hooks_or_configuration(self):
        root, environment, _, revision = self.swift_check("first")
        self.seeds.harvest_check(root, environment)
        seed = self.seeds._STATE["root"] / "swift/library-0123abcd"
        self.assertFalse((seed / "hooks").exists())
        self.assertNotIn("fsmonitor", (seed / "config").read_text())
        second_root, second_environment, second_cache, _ = self.swift_check("second")
        shutil.rmtree(second_cache)
        self.assertEqual(self.seeds.seed_check(second_root, second_environment), [])
        copied = self.seeds._swift_cache(Path(second_environment["HOME"])) / "library-0123abcd"
        self.assertFalse((copied / "hooks").exists())
        self.assertEqual(self.git("--git-dir", str(copied), "rev-parse", "refs/tags/1.0.0^{commit}"), revision)
        self.assertFalse((self.root / "hook-ran").exists() or (self.root / "fsmonitor-ran").exists())

    @unittest.skipUnless(shutil.which("git") and os.name != "nt", "git and POSIX modes required")
    def test_swift_repository_with_an_altered_object_is_not_seeded(self):
        import zlib
        root, environment, repository, revision = self.swift_check("first")
        blob = self.loose(repository, revision)
        blob.chmod(0o644)
        blob.write_bytes(zlib.compress(b"blob 24\x00let value = 666 // evil\n"))
        self.seeds.harvest_check(root, environment)
        seeds = self.seeds._STATE["root"]
        self.assertFalse(seeds is not None and (seeds / "swift/library-0123abcd").exists())
        second_root, second_environment, second_cache, _ = self.swift_check("second")
        shutil.rmtree(second_cache)
        self.seeds.seed_check(second_root, second_environment)
        self.assertFalse(self.seeds._swift_cache(Path(second_environment["HOME"])).joinpath("library-0123abcd").exists())

    @unittest.skipUnless(shutil.which("git") and os.name != "nt", "git and POSIX modes required")
    def test_swift_repository_missing_part_of_the_pinned_history_is_not_seeded(self):
        root, environment, repository, revision = self.swift_check("first")
        blob = self.loose(repository, revision)
        blob.unlink()
        self.seeds.harvest_check(root, environment)
        seeds = self.seeds._STATE["root"]
        self.assertFalse(seeds is not None and (seeds / "swift/library-0123abcd").exists())

    def test_user_and_system_caches_are_never_touched(self):
        root, environment, hexdigest = self.npm_check("first", b"tarball bytes")
        self.seeds.harvest_check(root, environment)
        for path in self.root.rglob("*"):
            if path.is_relative_to(self.root / "state") or path.is_relative_to(self.root / "first"):
                continue
            self.fail(f"unexpected write outside the check and the state folder: {path}")


if __name__ == "__main__":
    unittest.main()
