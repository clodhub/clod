"""Opt-in review of a real producer package, using temporary external identities."""

import os
from pathlib import Path
import tempfile
import unittest

from clod.bundle import pack, read_package
from clod.io import load, write
from clod.model import canonical, digest
from clod.test_identities import generate
from clod.trust import publish_release, publish_review, sign, verify_package
from clod.verification import review_package


@unittest.skipUnless(os.environ.get("CLOD_REVIEW_SOURCE"), "Set CLOD_REVIEW_SOURCE to a real package directory")
class PackagedReviewTests(unittest.TestCase):
    def test_real_package_review_and_guardian(self):
        with tempfile.TemporaryDirectory(prefix="clod-real-review-") as temporary:
            root = Path(temporary).resolve()
            policy_path = generate(root / "identities")
            store = root / "store"
            ref = pack(Path(os.environ["CLOD_REVIEW_SOURCE"]).resolve(), store)
            manifest, _ = read_package(ref, store)
            self.assertFalse(manifest["dependencies"], "This focused fixture requires a dependency-free package")
            policy = load(policy_path)
            policy["trustedExecution"] = [ref["digest"]]
            write(policy_path, policy)
            statements = store / "statements" / ref["digest"]
            statements.mkdir(parents=True)
            publish_release(store, ref, root / "identities/release.pem")
            report = review_package(ref, store, policy_path, True)
            evidence = os.environ.get("CLOD_REVIEW_EVIDENCE")
            if evidence:
                write(Path(evidence), report)
            self.assertEqual(report["summary"]["required-local"], "passed", report)
            from clod.foundations import class_suites
            self.assertEqual(len(report["suites"]), len([suite for suite in manifest["verification"] if suite["root"] == "package"]) + len(class_suites(manifest)))
            publish_review(store, ref, report, root / "identities/guardian.pem", policy=policy_path)
            verify_package(ref, store, policy_path)
