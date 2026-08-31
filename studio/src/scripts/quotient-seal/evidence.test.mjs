import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parseStudioEvidence, StudioEvidenceError } from "./evidence.ts";

const fixtureUrl = new URL("../../fixtures/quotient-seal/evidence-valid.json", import.meta.url);
const fixture = readFileSync(fixtureUrl, "utf8");
const parsedFixture = JSON.parse(fixture);

function expectCode(expected, operation) {
  assert.throws(operation, (error) => error instanceof StudioEvidenceError && error.code === expected);
}

test("allowlist fixture becomes an immutable deterministic view model", () => {
  const first = parseStudioEvidence(fixture);
  const second = parseStudioEvidence(new TextEncoder().encode(fixture));
  assert.deepEqual(first, second);
  assert.equal(first.kind, "PERFORMANCE_BUNDLE");
  assert.equal(first.verdict, "VALID");
  assert.equal(first.hardwareStatus, "NOT_VERIFIED");
  assert.equal(first.securityInterpretation, "NOT_A_SECURITY_VERDICT");
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.facts), true);
  assert.equal(Object.isFrozen(first.links), true);
});

test("unsupported and resource-bound evidence cannot become VALID", () => {
  const inconclusive = structuredClone(parsedFixture);
  inconclusive.kind = "ENGINE_DIFFERENTIAL";
  inconclusive.provenance = "ENGINE_DIFFERENTIAL";
  inconclusive.security_interpretation = "BOUNDED_SECURITY_EVIDENCE";
  inconclusive.verdict = "INCONCLUSIVE";
  inconclusive.facts = {
    engine_count: 2,
    agreement_count: 1,
    disagreement_count: 1,
    inconclusive_count: 1,
  };
  inconclusive.links = [];
  inconclusive.diagnostics = [{ code: "ENGINE_DISAGREEMENT", location_index: 3 }];
  assert.equal(parseStudioEvidence(JSON.stringify(inconclusive)).verdict, "INCONCLUSIVE");

  inconclusive.verdict = "VALID";
  expectCode("SEMANTIC_MISMATCH", () => parseStudioEvidence(JSON.stringify(inconclusive)));
});

test("private and secret-bearing fields are rejected before projection", () => {
  for (const forbidden of ["raw_biosignal", "secret_key", "subject_id", "baseline"]) {
    const evidence = structuredClone(parsedFixture);
    evidence.facts[forbidden] = 1;
    expectCode("SECRET_FIELD", () => parseStudioEvidence(JSON.stringify(evidence)));
  }
});

test("unknown schemas, fields, provenance, and digests fail closed", () => {
  const unknownSchema = { ...parsedFixture, schema: "quotient-seal.future.v9" };
  expectCode("UNKNOWN_SCHEMA", () => parseStudioEvidence(JSON.stringify(unknownSchema)));

  const unknownField = { ...parsedFixture, narrative: "unreviewed free text" };
  expectCode("UNKNOWN_FIELD", () => parseStudioEvidence(JSON.stringify(unknownField)));

  const wrongProvenance = { ...parsedFixture, provenance: "QSM_CHECKER" };
  expectCode("SEMANTIC_MISMATCH", () => parseStudioEvidence(JSON.stringify(wrongProvenance)));

  const wrongDigest = { ...parsedFixture, artifact_sha256: "ABC" };
  expectCode("INVALID_VALUE", () => parseStudioEvidence(JSON.stringify(wrongDigest)));
});

test("byte, depth, collection, and caller-supplied limits remain bounded", () => {
  expectCode("OVERSIZED", () => parseStudioEvidence(fixture, { maxBytes: 16 }));
  expectCode("BOUND_EXCEEDED", () => parseStudioEvidence(fixture, { maxDepth: 1 }));
  expectCode("BOUND_EXCEEDED", () => parseStudioEvidence(fixture, { maxArrayItems: 1 }));
  expectCode("INVALID_LIMIT", () => parseStudioEvidence(fixture, { maxNodes: 999_999 }));
  expectCode("INVALID_UTF8", () => parseStudioEvidence(new Uint8Array([0xff, 0xfe])));
});
