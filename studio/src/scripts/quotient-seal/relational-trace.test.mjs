import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_RENDERED_TRACE_STEPS,
  createRelationalTraceFixture,
  projectTraceStep,
  windowRelationalTrace,
} from "./relational-trace.ts";

test("complete congruent fixture is VALID and preserves stuttering steps", () => {
  const trace = createRelationalTraceFixture({ length: 64 });
  assert.equal(trace.verdict, "VALID");
  assert.equal(trace.firstDivergenceIndex, null);
  assert.equal(trace.steps.some((step) => step.relationStatus === "STUTTER"), true);
});

test("first relation divergence is INVALID and deterministic", () => {
  const trace = createRelationalTraceFixture({ length: 96, divergenceAt: 37 });
  assert.equal(trace.verdict, "INVALID");
  assert.equal(trace.firstDivergenceIndex, 37);
  assert.equal(trace.steps[37]?.relationStatus, "DIVERGED");
});

test("resource bound, unsupported, and engine disagreement remain INCONCLUSIVE", () => {
  for (const termination of ["RESOURCE_BOUND", "UNSUPPORTED", "ENGINE_DISAGREEMENT"]) {
    const trace = createRelationalTraceFixture({ length: 12, termination });
    assert.equal(trace.verdict, "INCONCLUSIVE");
    assert.equal(trace.termination, termination);
  }
});

test("observer projection does not mutate or widen the source artifact", () => {
  const trace = createRelationalTraceFixture({ length: 16 });
  const original = JSON.stringify(trace.steps[7]);
  const memory = projectTraceStep(trace.steps[7], ["MEMORY"]);
  const resource = projectTraceStep(trace.steps[7], ["RESOURCE"]);
  assert.equal(memory.visibleObservations.every((item) => item.channel === "MEMORY"), true);
  assert.equal(resource.visibleObservations.every((item) => item.channel === "RESOURCE"), true);
  assert.equal(JSON.stringify(trace.steps[7]), original);
  assert.equal(Object.isFrozen(trace.steps[7]?.observations), true);
});

test("ten-thousand-step fixture renders only a bounded window with omission counts", () => {
  const trace = createRelationalTraceFixture({ length: 10_000 });
  const window = windowRelationalTrace(trace, 5_000);
  assert.equal(window.steps.length, MAX_RENDERED_TRACE_STEPS);
  assert.equal(window.omittedBefore > 0, true);
  assert.equal(window.omittedAfter > 0, true);
  assert.equal(window.omittedBefore + window.steps.length + window.omittedAfter, 10_000);
});
