import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {pathToFileURL} from "node:url";
const manifest = JSON.parse(await readFile(process.env.AEPM_CANDIDATE_MANIFEST, "utf8"));
const path = "components/" + manifest.identity.name.split("/")[1] + "/counter.mjs";
const candidate = await import(pathToFileURL(JSON.parse(process.env.AEPM_MODULE_MAP)[path]));
assert.equal(candidate.increment(4), 5);
