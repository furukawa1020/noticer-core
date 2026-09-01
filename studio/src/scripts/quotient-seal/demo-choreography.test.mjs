import assert from "node:assert/strict";
import test from "node:test";
import {
  WISS_ATTACK_SCENARIOS,
  WISS_DEMO_DURATION_SECONDS,
  WISS_DEMO_MAX_EXPORT_BYTES,
  WISS_DEMO_STEPS,
  createWissDemoExport,
  encodeWissDemoExport,
} from "./demo-choreography.ts";

test("guided choreography covers exactly ninety seconds without gaps", () => {
  assert.equal(WISS_DEMO_DURATION_SECONDS, 90);
  assert.equal(WISS_DEMO_STEPS[0]?.startSecond, 0);
  assert.equal(WISS_DEMO_STEPS.at(-1)?.endSecond, 90);
  WISS_DEMO_STEPS.forEach((step, index) => {
    assert.equal(step.index, index);
    if (index > 0) assert.equal(WISS_DEMO_STEPS[index - 1].endSecond, step.startSecond);
  });
});

test("first attack is reachable within the explicit interaction budget", () => {
  const artifact = createWissDemoExport();
  assert.equal(artifact.interactionBudgetToFirstAttack <= 3, true);
  assert.equal(artifact.choreography[1].id, "ATTACK");
});

test("all three attack stories reproduce as digest-linked INVALID evidence", () => {
  const artifact = createWissDemoExport();
  assert.deepEqual(
    artifact.attacks.map((attack) => attack.scenarioId),
    WISS_ATTACK_SCENARIOS,
  );
  artifact.attacks.forEach((attack) => {
    assert.equal(attack.verdict, "INVALID");
    assert.equal(attack.oneMinimal, true);
    assert.match(attack.counterexampleSha256, /^[0-9a-f]{64}$/);
    assert.match(attack.replaySha256, /^[0-9a-f]{64}$/);
  });
});

test("repair export preserves security and performance independence", () => {
  const artifact = createWissDemoExport();
  const utility = artifact.repairs.find((repair) => repair.fixtureId === "UTILITY_REGRESSION");
  const budget = artifact.repairs.find(
    (repair) => repair.fixtureId === "PERFORMANCE_BUDGET_FAIL",
  );
  assert.equal(utility?.securityVerdict, "INVALID");
  assert.equal(utility?.performanceVerdict, "PASS");
  assert.equal(budget?.securityVerdict, "VALID");
  assert.equal(budget?.performanceVerdict, "FAIL");
});

test("shareable export is deterministic, bounded, and contains no prohibited fields", () => {
  const first = encodeWissDemoExport();
  const second = encodeWissDemoExport();
  assert.equal(first, second);
  assert.equal(new TextEncoder().encode(first).byteLength < WISS_DEMO_MAX_EXPORT_BYTES, true);
  assert.doesNotMatch(
    first.toLowerCase(),
    /raw_biosignal|subject_id|stable_identifier|secret_key|ppg_samples|ibi_samples/,
  );
  const parsed = JSON.parse(first);
  assert.match(parsed.exportSha256, /^[0-9a-f]{64}$/);
  assert.equal(parsed.hardwareStatus, "NOT_VERIFIED");
});

test("export keeps capsule uncertainty and explicit claim boundaries", () => {
  const artifact = createWissDemoExport();
  assert.equal(artifact.capsule.verdict, "INCONCLUSIVE");
  assert.equal(artifact.capsule.reason, "NATIVE_SEMANTIC_CHECK_REQUIRED");
  assert.equal(artifact.claimBoundary.some((claim) => claim.includes("world-first")), true);
  assert.equal(artifact.claimBoundary.some((claim) => claim.includes("NOT_VERIFIED")), true);
});

