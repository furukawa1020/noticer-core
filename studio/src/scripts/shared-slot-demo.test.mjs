import assert from "node:assert/strict";
import test from "node:test";
import { evaluateFirstSend } from "./shared-slot-demo.mjs";

test("the two synthetic continuations require opposite sends", () => {
  assert.deepEqual(evaluateFirstSend("A"), { a: false, b: true });
  assert.deepEqual(evaluateFirstSend("B"), { a: true, b: false });
  assert.deepEqual(evaluateFirstSend("wait"), { a: false, b: false });
  assert.equal(evaluateFirstSend("unknown"), null);
});
