import assert from "node:assert/strict";
import test from "node:test";
import { simulateGuard, verifyPublicCapsuleChain } from "./observatory.ts";

test("nominal public trace stays equivalent", () => {
  const run = simulateGuard("nominal");
  assert.equal(run.frames.every((frame) => frame.relation === "EQUIVALENT"), true);
  assert.equal(run.finalState, "MONITORING");
  assert.equal(verifyPublicCapsuleChain(run), true);
});

test("first divergence is sticky and all later releases use safe sink", () => {
  const run = simulateGuard("drift");
  assert.equal(run.firstDivergence, 4);
  assert.equal(run.frames.slice(4).every((frame) => frame.firstDivergence === 4), true);
  assert.equal(run.frames.slice(5).every((frame) => frame.publicAction === "NO_RELEASE"), true);
});

test("slot reorder fails closed without exposing a private index", () => {
  const run = simulateGuard("reorder");
  assert.equal(run.finalState, "SAFE_SINK");
  assert.equal(JSON.stringify(run).includes("private"), false);
  assert.equal(JSON.stringify(run).includes("shadowIndex"), false);
});

test("reconnect requires a new epoch and explicit recovery", () => {
  const run = simulateGuard("reconnect");
  assert.equal(run.frames[3].state, "HOLD");
  assert.equal(run.frames[4].publicAction, "NO_RELEASE");
  assert.equal(run.frames[5].state, "RECOVERED");
  assert.equal(run.frames[5].capsuleEpoch, 8);
  assert.equal(run.finalState, "MONITORING");
});

test("binding mismatch enters an irreversible safe sink", () => {
  const run = simulateGuard("binding");
  assert.equal(run.frames[2].state, "SAFE_SINK");
  assert.equal(run.frames.slice(2).every((frame) => frame.state === "SAFE_SINK"), true);
});

test("capsule mutation is rejected", () => {
  const run = simulateGuard("nominal");
  run.frames[6].capsuleDigest = "00000000";
  assert.equal(verifyPublicCapsuleChain(run), false);
});
