import assert from "node:assert/strict";
import test from "node:test";

import { SENTINEL_SCENARIOS, SENTINEL_STAGES, runSentinelScenario } from "./sentinel-lab.ts";

test("healthy runtime keeps the deployment permit active", () => {
  const result = runSentinelScenario("healthy");
  assert.equal(result.permitActive, true);
  assert.equal(result.quarantine, false);
  assert.equal(result.stages.length, SENTINEL_STAGES.length);
  assert.ok(result.stages.every((stage) => stage.status === "verified"));
});

test("every injected fault withholds all downstream assurance", () => {
  for (const scenario of SENTINEL_SCENARIOS.filter((item) => item.fault)) {
    const result = runSentinelScenario(scenario.id);
    const fault = result.stages.findIndex((stage) => stage.status !== "verified");
    assert.ok(fault >= 0, scenario.id);
    assert.ok(result.stages.slice(fault + 1).every((stage) => stage.status === "withheld"));
    assert.equal(result.permitActive, false);
    assert.equal(result.quarantine, true);
  }
});

test("certified violations revoke while evidence gaps only quarantine", () => {
  assert.equal(runSentinelScenario("privacy-drift").revocationIssued, true);
  assert.equal(runSentinelScenario("lease-expired").revocationIssued, false);
  assert.equal(runSentinelScenario("lease-expired").scenario.verdict, "inconclusive");
});

test("unknown scenario fails closed", () => {
  assert.throws(() => runSentinelScenario("unknown"), /unknown sentinel scenario/);
});

