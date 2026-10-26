import assert from "node:assert/strict";
import test from "node:test";
import { simulateCommit, simulateRecoveryDrill, validateCommitRun } from "./studio.ts";

test("nominal transaction releases exactly once after commit", () => {
  const run = simulateCommit("nominal");
  assert.deepEqual(run.frames.map((frame) => frame.state), [
    "PREPARED",
    "MONITOR_ACCEPTED",
    "BUDGET_RESERVED",
    "COMMITTED",
  ]);
  assert.equal(run.frames.filter((frame) => frame.output === "RELEASED").length, 1);
  assert.equal(run.releasePermit, true);
  assert.equal(validateCommitRun(run), true);
});

for (const scenario of ["relation", "budget", "substitution"]) {
  test(`${scenario} failure never exposes a release permit`, () => {
    const run = simulateCommit(scenario);
    assert.equal(run.releasePermit, false);
    assert.equal(run.frames.every((frame) => frame.output === "SEALED"), true);
    assert.equal(validateCommitRun(run), true);
  });
}

test("terminal extension is rejected by the trace validator", () => {
  const run = simulateCommit("relation");
  run.frames.push({
    state: "COMMITTED",
    monitor: "ACCEPT",
    budget: "RESERVED",
    output: "RELEASED",
    event: "invalid terminal extension",
  });
  run.releasePermit = true;
  assert.equal(validateCommitRun(run), false);
});

test("normal recovery drill opens every deployment gate", () => {
  const drill = simulateRecoveryDrill("normal");
  assert.equal(drill.ready, true);
  assert.equal(drill.gates.every((gate) => gate.passed), true);
  assert.equal(drill.attackDetected, false);
});

for (const [scenario, gate] of [["tamper", "proof"], ["replay", "replay"], ["split-brain", "lease"]]) {
  test(`${scenario} is detected by ${gate} without deployment`, () => {
    const drill = simulateRecoveryDrill(scenario);
    assert.equal(drill.ready, false);
    assert.equal(drill.attackDetected, true);
    assert.equal(drill.gates.find((item) => item.id === gate)?.passed, false);
  });
}
