import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_SCENARIO_ACTIONS,
  SCENARIO_CATALOG,
  minimizeScenarioActions,
  replayScenario,
  sha256Hex,
} from "./adversarial-lab.ts";

test("browser-side SHA-256 matches the standard abc vector", () => {
  assert.equal(
    sha256Hex("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("three fixed-seed attack fixtures reproduce as INVALID", () => {
  for (const scenario of SCENARIO_CATALOG.slice(0, 3)) {
    const first = replayScenario(scenario.id, scenario.defaultActions);
    const second = replayScenario(scenario.id, scenario.defaultActions);
    assert.equal(first.verdict, "INVALID");
    assert.equal(first.reason, "COUNTEREXAMPLE_REPRODUCED");
    assert.equal(first.replayAgreement, true);
    assert.equal(first.oneMinimal, true);
    assert.deepEqual(first, second);
  }
});

test("counterexamples shrink deterministically to one-minimal action sequences", () => {
  for (const scenario of SCENARIO_CATALOG.slice(0, 3)) {
    const minimized = minimizeScenarioActions(scenario.id, scenario.defaultActions);
    assert.deepEqual(minimized, scenario.requiredActions);
    for (let index = 0; index < minimized.length; index += 1) {
      const candidate = minimized.filter((_, candidateIndex) => candidateIndex !== index);
      if (candidate.length === 0) continue;
      assert.equal(replayScenario(scenario.id, candidate).verdict, "INCONCLUSIVE");
    }
  }
});

test("engine disagreement remains INCONCLUSIVE", () => {
  const scenario = SCENARIO_CATALOG[3];
  const result = replayScenario(scenario.id, scenario.defaultActions);
  assert.equal(result.verdict, "INCONCLUSIVE");
  assert.equal(result.reason, "ENGINE_DISAGREEMENT");
  assert.equal(result.replayAgreement, false);
  assert.deepEqual(
    result.replays.map((item) => item.finding),
    ["COUNTEREXAMPLE", "NO_COUNTEREXAMPLE"],
  );
});

test("action input is allowlisted and bounded", () => {
  assert.throws(
    () => replayScenario("EXTRA_HOST_CALL", Array(MAX_SCENARIO_ACTIONS + 1).fill("TICK")),
    /1\.\.16/,
  );
  assert.throws(() => replayScenario("EXTRA_HOST_CALL", ["EXECUTE_CODE"]), /unknown public action/);
  assert.throws(() => replayScenario("UNKNOWN_SCENARIO", ["TICK"]), /unknown scenario/);
});

test("artifact links are digest-addressed and exclude prohibited evidence fields", () => {
  const result = replayScenario("RESOURCE_ONLY_LEAK", ["TICK", "FUTURE_SLOT"]);
  assert.equal(result.artifactLinks.length, 4);
  for (const artifact of result.artifactLinks) {
    assert.match(artifact.sha256, /^[0-9a-f]{64}$/);
    for (const dependency of artifact.dependsOn) {
      assert.match(dependency, /^[0-9a-f]{64}$/);
    }
  }
  assert.equal(result.evidenceOrigin, "INJECTED_TEST_FIXTURE");
  assert.equal(result.hardwareStatus, "NOT_VERIFIED");
  assert.equal(result.securityInterpretation, "BOUNDED_SECURITY_EVIDENCE");
  assert.doesNotMatch(
    JSON.stringify(result).toLowerCase(),
    /raw_biosignal|subject_id|stable_identifier|secret_key/,
  );
});

