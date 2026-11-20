import assert from "node:assert/strict";
import test from "node:test";

import { REMEDY_SCENARIOS, REMEDY_STAGES, runRemedyScenario } from "./remedy-lab.ts";

test("clean repair reaches a deployment permit", () => {
  const result = runRemedyScenario("clean");
  assert.equal(result.verdict, "repaired");
  assert.equal(result.deployable, true);
  assert.equal(result.stages.length, REMEDY_STAGES.length);
  assert.ok(result.stages.every((stage) => stage.status === "verified"));
  assert.equal(result.capsule.checks, "5/5 + dual replay");
});

test("every adversarial scenario blocks all downstream stages", () => {
  for (const scenario of REMEDY_SCENARIOS.filter((item) => item.fault)) {
    const result = runRemedyScenario(scenario.id);
    const fault = result.stages.findIndex((stage) =>
      stage.status === "blocked" || stage.status === "inconclusive",
    );
    assert.ok(fault >= 0, scenario.id);
    assert.ok(result.stages.slice(fault + 1).every((stage) => stage.status === "withheld"));
    assert.equal(result.deployable, false);
    assert.equal(result.capsule.certificateDigest, "withheld");
  }
});

test("budget exhaustion is inconclusive rather than repaired", () => {
  const result = runRemedyScenario("budget-limit");
  assert.equal(result.verdict, "inconclusive");
  assert.equal(result.stages.find((stage) => stage.name === "SEARCH").status, "inconclusive");
});

test("unknown scenario is rejected", () => {
  assert.throws(() => runRemedyScenario("unknown"), /unknown remedy scenario/);
});

