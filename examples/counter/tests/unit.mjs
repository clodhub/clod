import assert from "node:assert/strict";
import {increment} from "../src/counter.mjs";
assert.equal(increment(0), 1);
