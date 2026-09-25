import assert from "node:assert/strict";
import test from "node:test";
import {
  DEFAULT_STUDIO_INPUT,
  solveStudio,
  verifyStudioCertificate,
} from "./studio.ts";

test("immediate release exposes different private ready times", () => {
  const result = solveStudio(DEFAULT_STUDIO_INPUT);
  assert.equal(result.immediateReleaseViolates, true);
});

test("exact AETP waits for the latest equivalent history", () => {
  const result = solveStudio(DEFAULT_STUDIO_INPUT);
  assert.equal(result.status, "CERTIFIED_OPTIMAL");
  assert.equal(result.releaseSlot, 9);
  assert.equal(result.worstCaseLatency, 6);
  assert.equal(verifyStudioCertificate(DEFAULT_STUDIO_INPUT, result), true);
});

test("deadline before the release floor has an infeasibility core", () => {
  const input = { ...DEFAULT_STUDIO_INPUT, deadline: 8 };
  const result = solveStudio(input);
  assert.equal(result.status, "CERTIFIED_INFEASIBLE");
  assert.equal(result.releaseSlot, null);
  assert.match(result.explanation.join(" "), /deadline = 8/);
});

test("approximate privacy moves the bounded latency frontier", () => {
  const exact = solveStudio(DEFAULT_STUDIO_INPUT);
  const approximateInput = { ...DEFAULT_STUDIO_INPUT, privacyMode: "tv", tolerance: 0.5 };
  const approximate = solveStudio(approximateInput);
  assert.equal(approximate.worstCaseLatency < exact.worstCaseLatency, true);
});

test("collusion selects a joint mechanism with extra cost", () => {
  const result = solveStudio({ ...DEFAULT_STUDIO_INPUT, colludingServices: 2 });
  assert.equal(result.mechanism, "joint");
  assert.equal(result.releaseSlot, 10);
});

test("frontier keeps certified lower bound distinct from stack comparisons", () => {
  const result = solveStudio(DEFAULT_STUDIO_INPUT);
  assert.deepEqual(result.frontier.map((point) => point.mechanism), [
    "LOWER BOUND",
    "QUOTIENTLIMIT",
    "AETS",
    "APLOT",
  ]);
  assert.equal(result.frontier[0].certified, true);
  assert.equal(result.frontier[2].certified, false);
});
