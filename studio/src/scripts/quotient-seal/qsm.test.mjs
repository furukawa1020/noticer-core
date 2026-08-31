import assert from "node:assert/strict";
import test from "node:test";
import { auditQsmCapsule, buildQsmAuditFixture, tamperQsmSection } from "./qsm.ts";

test("canonical fixture exposes all sections but requires native semantic checking", async () => {
  const fixture = await buildQsmAuditFixture();
  const audit = await auditQsmCapsule(fixture);
  assert.equal(audit.verdict, "INCONCLUSIVE");
  assert.equal(audit.reasonCode, "NATIVE_SEMANTIC_CHECK_REQUIRED");
  assert.equal(audit.sections.length, 9);
  assert.equal(audit.sections.every((section) => section.digestMatches), true);
  assert.equal(audit.abi?.privatePolicy, "TCB ONLY / NOT IMPORT / NOT EXPORT / NOT WIRE");
  assert.deepEqual(audit.abi?.publicExports, [
    "qseal.public.tick",
    "qseal.public.reset",
    "qseal.public.handoff",
    "qseal.public.status",
  ]);
});

test("one-bit payload mutation is INVALID and focuses the affected section", async () => {
  const fixture = await buildQsmAuditFixture();
  const audit = await auditQsmCapsule(tamperQsmSection(fixture, 1));
  assert.equal(audit.verdict, "INVALID");
  assert.equal(audit.reasonCode, "SECTION_DIGEST_MISMATCH");
  assert.equal(audit.focusSectionIndex, 1);
  assert.equal(audit.sections[1]?.name, "SOURCE CERTIFICATE");
  assert.equal(audit.sections[1]?.digestMatches, false);
});

test("unknown section and unsupported version remain INCONCLUSIVE", async () => {
  const unknownSection = await buildQsmAuditFixture();
  new DataView(unknownSection.buffer).setUint16(24, 99, true);
  assert.equal((await auditQsmCapsule(unknownSection)).reasonCode, "UNKNOWN_SECTION");
  assert.equal((await auditQsmCapsule(unknownSection)).verdict, "INCONCLUSIVE");

  const future = await buildQsmAuditFixture();
  new DataView(future.buffer).setUint16(8, 2, true);
  assert.equal((await auditQsmCapsule(future)).verdict, "INCONCLUSIVE");
});

test("noncanonical order, trailing bytes, and bad magic are INVALID", async () => {
  const order = await buildQsmAuditFixture();
  new DataView(order.buffer).setUint16(24, 2, true);
  assert.equal((await auditQsmCapsule(order)).reasonCode, "SECTION_ORDER");

  const trailing = await buildQsmAuditFixture();
  const extended = new Uint8Array(trailing.length + 1);
  extended.set(trailing);
  assert.equal((await auditQsmCapsule(extended)).reasonCode, "DECLARED_LENGTH");

  const magic = await buildQsmAuditFixture();
  magic[0] ^= 1;
  assert.equal((await auditQsmCapsule(magic)).reasonCode, "BAD_MAGIC");
});
