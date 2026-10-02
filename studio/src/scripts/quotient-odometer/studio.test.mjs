import assert from "node:assert/strict";
import test from "node:test";
import { simulateOdometer, verifyReceiptChain } from "./studio.ts";

test("nominal run never exceeds budget and preserves receipt chain", () => {
  const run = simulateOdometer("nominal");
  assert.equal(run.frames.length, 12);
  assert.equal(run.frames.every((frame) => frame.spent <= run.budget), true);
  assert.equal(verifyReceiptChain(run), true);
});

test("coalition scope charges joint observations and rejects before excess", () => {
  const run = simulateOdometer("coalition");
  assert.equal(run.frames.some((frame) => frame.coalition === "C:{1,2,4}"), true);
  assert.equal(run.rejected > 0, true);
  assert.equal(run.frames.every((frame) => frame.spent <= run.budget), true);
});

test("crash recovery keeps durable privacy spend", () => {
  const run = simulateOdometer("crash");
  const recovery = run.frames.find((frame) => frame.decision === "RECOVER");
  assert.ok(recovery);
  assert.equal(recovery.spent, recovery.durableSpent);
  assert.equal(verifyReceiptChain(run), true);
});

test("profile invalidation fails closed for subsequent releases", () => {
  const run = simulateOdometer("invalidation");
  const invalid = run.frames.filter((frame) => frame.profile === "INVALIDATED");
  assert.equal(invalid.length > 0, true);
  assert.equal(invalid.every((frame) => frame.decision === "REJECT"), true);
});

test("receipt tampering is detected", () => {
  const run = simulateOdometer("nominal");
  run.frames[4].receipt = "00000000";
  assert.equal(verifyReceiptChain(run), false);
});
