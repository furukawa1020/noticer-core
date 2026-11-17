import assert from "node:assert/strict";
import test from "node:test";
import { simulateCommit, simulateMinimalOracleLab, simulateMissionControl, simulateProofControlPlane, simulateProofFabric, simulateRecoveryDrill, simulateRecoveryFlightDeck, simulateResilienceTimeline, validateCommitRun } from "./studio.ts";

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

test("resilience timeline blocks every stage after the detected fault", () => {
  const timeline = simulateResilienceTimeline("lease");
  assert.equal(timeline[3].state, "detected");
  assert.equal(timeline.slice(4).every((step) => step.state === "blocked"), true);
  assert.equal(simulateResilienceTimeline("clean").every((step) => step.state === "passed"), true);
});

test("mission control withholds every downstream stage after interception", () => {
  const mission = simulateMissionControl("privacy");
  assert.equal(mission[4].status, "intercepted");
  assert.equal(mission.slice(5).every((stage) => stage.status === "withheld"), true);
  assert.equal(simulateMissionControl("clean").every((stage) => stage.status === "verified"), true);
});

test("recovery flight deck verifies every stage on a clean run", () => {
  assert.equal(simulateRecoveryFlightDeck("clean").every((stage) => stage.status === "verified"), true);
});

for (const [threat, index] of [["rollback", 0], ["custody", 1], ["fork", 3], ["restore", 4], ["liveness", 5], ["export", 8]]) {
  test(`${threat} is intercepted and withholds every downstream recovery stage`, () => {
    const stages = simulateRecoveryFlightDeck(threat);
    assert.equal(stages[index].status, "intercepted");
    assert.equal(stages.slice(index + 1).every((stage) => stage.status === "withheld"), true);
  });
}

test("proof control plane proves every stage on a clean run", () => {
  assert.equal(simulateProofControlPlane("clean").every((stage) => stage.status === "proven"), true);
});

for (const [threat, index] of [["escalation", 0], ["delegation", 1], ["monoculture", 2], ["evidence", 3], ["fork", 4], ["rollback", 5], ["replay", 6]]) {
  test(`${threat} is intercepted by the proof control plane`, () => {
    const stages = simulateProofControlPlane(threat);
    assert.equal(stages[index].status, "intercepted");
    assert.equal(stages.slice(index + 1).every((stage) => stage.status === "withheld"), true);
  });
}

test("proof fabric verifies all stages when independent evidence agrees", () => {
  assert.equal(simulateProofFabric("clean").every((stage) => stage.status === "verified"), true);
});

for (const [threat, index] of [["collusion", 0], ["clock", 1], ["domain", 2], ["fragment", 3], ["cache", 8]]) {
  test(`${threat} is detected by the proof fabric`, () => {
    const stages = simulateProofFabric(threat);
    assert.equal(stages[index].status, "detected");
    assert.equal(stages.slice(index + 1).every((stage) => stage.status === "blocked"), true);
  });
}

test("minimal counterexample lab verifies every stage on a clean run", () => {
  assert.equal(simulateMinimalOracleLab("clean").every((stage) => stage.status === "verified"), true);
});

for (const [threat, index, status] of [["invalid-input", 0, "invalid"], ["node-limit", 1, "inconclusive"], ["depth-limit", 1, "inconclusive"], ["replay-disagreement", 5, "inconclusive"], ["state-mutation", 7, "invalid"]]) {
  test(`${threat} never promotes to verified`, () => {
    const stages = simulateMinimalOracleLab(threat);
    assert.equal(stages[index].status, status);
    assert.equal(stages.slice(index + 1).every((stage) => stage.status === "blocked"), true);
    assert.equal(stages.at(-1)?.status === "verified", false);
  });
}
