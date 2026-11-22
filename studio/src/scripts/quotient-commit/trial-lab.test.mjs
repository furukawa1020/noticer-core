import assert from "node:assert/strict";
import test from "node:test";

import { ABLATIONS, ATTACKS, METRICS, runTrialFixture } from "./trial-lab.ts";

test("full fixture exposes all systems and statistical gates", () => {
  const result = runTrialFixture("identity", "leakage", "full");
  assert.equal(result.fixtureOnly, true);
  assert.equal(result.systems.length, 4);
  assert.equal(result.gates.length, 5);
  assert.equal(result.claimPass, true);
});

test("every attack metric and ablation combination is deterministic", () => {
  for (const attack of ATTACKS) {
    for (const metric of METRICS) {
      for (const ablation of ABLATIONS) {
        assert.deepEqual(
          runTrialFixture(attack.id, metric.id, ablation.id),
          runTrialFixture(attack.id, metric.id, ablation.id),
        );
      }
    }
  }
});

test("ablation cannot inherit the full-stack publication claim", () => {
  for (const ablation of ABLATIONS.filter((item) => item.id !== "full")) {
    assert.equal(runTrialFixture("identity", "leakage", ablation.id).claimPass, false);
  }
});

test("unknown controls fail closed", () => {
  assert.throws(() => runTrialFixture("unknown", "latency", "full"), /unknown attack/);
});

