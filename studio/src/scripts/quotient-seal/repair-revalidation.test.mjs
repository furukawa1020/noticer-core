import assert from "node:assert/strict";
import test from "node:test";
import {
  REPAIR_FIXTURES,
  RESOURCE_AXES,
  createRepairComparison,
} from "./repair-revalidation.ts";

test("resource-only counterexample becomes independently revalidated VALID", () => {
  const result = createRepairComparison("FUEL_PAD_PASS");
  assert.equal(result.attackVerdict, "INVALID");
  assert.equal(result.security.verdict, "VALID");
  assert.equal(result.security.resource, "NORMALIZED");
  assert.equal(result.security.utilityPreserved, true);
  assert.equal(result.security.deadlinesPreserved, true);
  assert.equal(result.performance.verdict, "PASS");
});

test("performance PASS cannot promote a utility regression to security PASS", () => {
  const result = createRepairComparison("UTILITY_REGRESSION");
  assert.equal(result.performance.verdict, "PASS");
  assert.equal(result.performance.securityInterpretation, "NOT_A_SECURITY_VERDICT");
  assert.equal(result.security.verdict, "INVALID");
  assert.equal(result.security.reason, "NORMALIZATION_CHANGED_UTILITY");
});

test("security VALID does not hide a performance budget failure", () => {
  const result = createRepairComparison("PERFORMANCE_BUDGET_FAIL");
  assert.equal(result.security.verdict, "VALID");
  assert.equal(result.performance.verdict, "FAIL");
  assert.equal(result.performance.observedRatioMillionths, 1_380_000);
});

test("resource-bound revalidation and insufficient samples remain INCONCLUSIVE", () => {
  const result = createRepairComparison("REVALIDATION_UNRESOLVED");
  assert.equal(result.security.verdict, "INCONCLUSIVE");
  assert.equal(result.performance.verdict, "INCONCLUSIVE");
  assert.equal(result.performance.candidateValue, null);
  assert.equal(result.trace.every((point) => point.afterEqual === null), true);
});

test("comparison projects exactly six immutable resource axes", () => {
  const result = createRepairComparison("FUEL_PAD_PASS");
  assert.deepEqual(
    result.trace.map((point) => point.axis),
    RESOURCE_AXES,
  );
  assert.equal(result.trace.length, 6);
  assert.equal(result.trace.filter((point) => !point.beforeEqual).length, 1);
  assert.equal(result.trace.every((point) => point.afterEqual === true), true);
  assert.equal(Object.isFrozen(result.trace), true);
  assert.equal(Object.isFrozen(result.candidate.operations), true);
});

test("all fixtures are deterministic and artifact-linked", () => {
  for (const fixture of REPAIR_FIXTURES) {
    const first = createRepairComparison(fixture.id);
    const second = createRepairComparison(fixture.id);
    assert.deepEqual(first, second);
    assert.equal(first.artifacts.length, 8);
    for (const artifact of first.artifacts) {
      assert.match(artifact.sha256, /^[0-9a-f]{64}$/);
      artifact.dependsOn.forEach((dependency) => assert.match(dependency, /^[0-9a-f]{64}$/));
    }
    assert.equal(first.hardwareStatus, "NOT_VERIFIED");
    assert.doesNotMatch(
      JSON.stringify(first).toLowerCase(),
      /raw_biosignal|subject_id|stable_identifier|secret_key/,
    );
  }
});

test("unknown repair fixture fails closed", () => {
  assert.throws(() => createRepairComparison("UNKNOWN"), /unknown repair fixture/);
});

