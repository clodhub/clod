"""Pack, review, install and update a small fixture through the command line, then recover an interrupted apply.

Run from the clod checkout: python -B tests/run_update_cycle.py WORK. WORK must not exist. Prints one JSON summary.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True

from clod import update  # noqa: E402
from clod.io import load, snapshot, write  # noqa: E402
from clod.model import ClodError  # noqa: E402
from clod.test_identities import generate  # noqa: E402
from clod.trust import publish_release, publish_review  # noqa: E402
from tests.test_application import source  # noqa: E402

work = Path(sys.argv[1]).resolve()
work.mkdir()
results = {"host": os.name, "steps": []}


def clod(*args):
    completed = subprocess.run([sys.executable, "-B", "-m", "clod", *map(str, args)], capture_output=True, text=True,
                               cwd=Path(__file__).resolve().parents[1])
    value = json.loads(completed.stdout.strip().splitlines()[-1])
    results["steps"].append({"command": args[0], "exit": completed.returncode, "ok": value["ok"],
                             "error": value.get("error")})
    return completed.returncode, value


policy = generate(work / "identities")
store, refs = work / "store", []
for name, version, recipe in (("sample", "0.1.0", False), ("sample", "0.1.1", False), ("sample-recipe", "0.1.0", True)):
    directory = work / "sources" / (name + version)
    source(directory, name, version, recipe)
    code, value = clod("pack", directory, "--store", store)
    assert code == 0, value
    refs.append(value["result"])
    publish_release(store, value["result"], work / "identities/release.pem")
trusted = load(policy)
trusted["trustedExecution"] = [ref["digest"] for ref in refs]
write(policy, trusted)
for ref in refs:
    code, value = clod("review", ref["digest"], "--store", store, "--policy", policy, "--trusted")
    assert code == 0 and value["result"]["summary"]["required-local"] == "passed", value
    publish_review(store, ref, value["result"], work / "identities/guardian.pem", policy=policy)
definition = {"format": 3, "id": "sample-app", "title": "Sample", "recipe": {"name": "pkg:clod/com.clodhub/sample-recipe", "version": "0.1.0"},
              "components": [{"id": "sample", "name": "pkg:clod/com.clodhub/sample", "version": "0.1.0", "configuration": {}}],
              "configuration": {}, "design": {"definitions": [], "instances": [], "connections": []}, "updatePolicy": {"security": "auto", "features": "manual", "preview": "hold"}}
write(work / "definition.json", definition)
assert clod("resolve", work / "definition.json", "--catalogue", store / "catalogue.json", "--out", work / "lock.json")[0] == 0
app = work / "app"
assert clod("install", work / "definition.json", "--lock", work / "lock.json", "--store", store, "--policy", policy, "--target", app)[0] == 0
(app / "notes.txt").write_text("unmanaged and preserved")
results["installedValue"] = (app / "components/sample/value.txt").read_text()
definition["components"][0]["version"] = "0.1.1"
write(work / "next.json", definition)
code, refused = clod("propose-update", app, work / "next.json", "--store", store, "--policy", policy, "--out", work / "proposal.json")
results["withoutTrusted"] = refused["error"]
assert code == 1 and not (work / "proposal.json").exists()
code, value = clod("propose-update", app, work / "next.json", "--store", store, "--policy", policy, "--trusted", "--out", work / "proposal.json")
assert code == 0, value
assert clod("approve", work / "proposal.json", "--key", work / "identities/owner.pem", "--policy", policy, "--out", work / "approval.json")[0] == 0
code, value = clod("apply", app, work / "proposal.json", "--approval", work / "approval.json", "--policy", policy)
assert code == 0, value
results["appliedValue"] = (app / "components/sample/value.txt").read_text()
results["unmanagedPreserved"] = (app / "notes.txt").read_text() == "unmanaged and preserved"
code, value = clod("recover", app)
assert code == 0, value
results["recoverAfterCommitKeepsNew"] = "0.1.1" in (app / "components/sample/value.txt").read_text()

# An apply interrupted after the old tree moved aside, then recovered through the command line.
second = work / "second"
definition["components"][0]["version"] = "0.1.0"
write(work / "definition-old.json", definition)
assert clod("install", work / "definition-old.json", "--lock", work / "lock.json", "--store", store, "--policy", policy, "--target", second)[0] == 0
before = snapshot(second)
definition["components"][0]["version"] = "0.1.1"
code, value = clod("propose-update", second, work / "next.json", "--store", store, "--policy", policy, "--trusted", "--out", work / "proposal2.json")
assert code == 0, value
assert clod("approve", work / "proposal2.json", "--key", work / "identities/owner.pem", "--policy", policy, "--out", work / "approval2.json")[0] == 0
actual = update.rename
calls = 0


def interrupted(source_path, target_path):
    global calls
    calls += 1
    actual(source_path, target_path)
    if calls == 1:
        raise InterruptedError("simulated power loss after the old tree moved aside")


with patch.object(update, "rename", interrupted), contextlib.redirect_stdout(io.StringIO()):
    try:
        update.apply(second, work / "proposal2.json", work / "approval2.json", policy)
        results["interrupted"] = False
    except ClodError as error:
        results["interrupted"] = error.code
results["applicationAbsentAfterInterrupt"] = not second.exists()
results["journalPhase"] = load(work / ".second.clod-transaction/journal.json")["phase"]
code, value = clod("recover", second)
assert code == 0, value
results["recoveredSnapshotEqual"] = snapshot(second) == before
results["recoveredValue"] = (second / "components/sample/value.txt").read_text()
print(json.dumps(results, indent=2))
