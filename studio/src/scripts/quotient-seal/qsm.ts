const QSM_MAGIC = new TextEncoder().encode("QSEALCAP");
const ARTIFACT_PREFIX = new TextEncoder().encode("CAQT-ARTIFACT\0");
const QSM_VERSION = 1;
const QSM_SECTION_COUNT = 9;
const HEADER_BYTES = 24;
const SECTION_HEADER_BYTES = 44;
const MAX_CAPSULE_BYTES = 16 * 1024 * 1024;
const MAX_SECTION_BYTES = 8 * 1024 * 1024;

const SECTION_DEFINITIONS = [
  [1, "RESOURCE BOUNDS", "noticer-core/qseal/section/resource-bounds/v1"],
  [2, "SOURCE CERTIFICATE", "noticer-core/qseal/section/source-certificate/v1"],
  [3, "WASM MODULE", "noticer-core/qseal/section/wasm-module/v1"],
  [4, "ABI MANIFEST", "noticer-core/qseal/section/abi-manifest/v1"],
  [5, "OBSERVER REGISTRY", "noticer-core/qseal/section/observer-registry/v1"],
  [6, "RELATION CERTIFICATE", "noticer-core/qseal/section/relation-certificate/v1"],
  [7, "ROBUST CERTIFICATE", "noticer-core/qseal/section/robust-certificate/v1"],
  [8, "RESOURCE CERTIFICATE", "noticer-core/qseal/section/resource-certificate/v1"],
  [9, "COMPILER MANIFEST", "noticer-core/qseal/section/compiler-manifest/v1"],
] as const;

export type QsmAuditVerdict = "VALID" | "INVALID" | "INCONCLUSIVE";

export interface QsmSectionAudit {
  readonly tag: number;
  readonly name: string;
  readonly offset: number;
  readonly length: number;
  readonly declaredDigest: string;
  readonly actualDigest: string;
  readonly digestMatches: boolean;
}

export interface QsmAbiAudit {
  readonly version: number;
  readonly profile: "P0 PUBLIC QUOTIENT ONLY" | "P1 SEALED ADMISSION";
  readonly abiHash: string;
  readonly privateCapability: "qseal.private.ingest";
  readonly privatePolicy: "TCB ONLY / NOT IMPORT / NOT EXPORT / NOT WIRE";
  readonly hostImports: readonly string[];
  readonly publicExports: readonly string[];
}

export interface QsmAuditResult {
  readonly verdict: QsmAuditVerdict;
  readonly reasonCode: string;
  readonly reason: string;
  readonly totalBytes: number;
  readonly formatVersion: number | null;
  readonly capsuleDigest: string | null;
  readonly sections: readonly QsmSectionAudit[];
  readonly focusSectionIndex: number | null;
  readonly abi: QsmAbiAudit | null;
}

export async function auditQsmCapsule(bytes: Uint8Array): Promise<QsmAuditResult> {
  const sections: QsmSectionAudit[] = [];
  const fail = (
    verdict: Exclude<QsmAuditVerdict, "VALID">,
    reasonCode: string,
    reason: string,
    formatVersion: number | null,
    focusSectionIndex: number | null = null,
  ): QsmAuditResult =>
    freezeResult({
      verdict,
      reasonCode,
      reason,
      totalBytes: bytes.byteLength,
      formatVersion,
      capsuleDigest: null,
      sections,
      focusSectionIndex,
      abi: null,
    });

  if (bytes.byteLength > MAX_CAPSULE_BYTES) {
    return fail(
      "INCONCLUSIVE",
      "RESOURCE_BOUND",
      "Capsule exceeds the Studio byte bound; native verification was not attempted.",
      null,
    );
  }
  if (bytes.byteLength < HEADER_BYTES) {
    return fail("INVALID", "TRUNCATED_HEADER", "Capsule header is truncated.", null);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (!equalBytes(bytes.subarray(0, 8), QSM_MAGIC)) {
    return fail("INVALID", "BAD_MAGIC", "Capsule magic is not QSEALCAP.", null);
  }
  const version = view.getUint16(8, true);
  if (version !== QSM_VERSION) {
    return fail(
      "INCONCLUSIVE",
      "UNSUPPORTED_VERSION",
      "Capsule version is outside the Studio v1 parser.",
      version,
    );
  }
  const count = view.getUint16(10, true);
  if (count !== QSM_SECTION_COUNT) {
    return fail(
      "INCONCLUSIVE",
      "UNSUPPORTED_SECTION_SET",
      "Capsule does not use the frozen nine-section registry.",
      version,
    );
  }
  if (view.getUint32(12, true) !== 0) {
    return fail("INVALID", "RESERVED_HEADER", "Capsule reserved header bits are non-zero.", version);
  }
  const declaredLength = safeNumber(view.getBigUint64(16, true));
  if (declaredLength === null || declaredLength !== bytes.byteLength) {
    return fail("INVALID", "DECLARED_LENGTH", "Capsule length does not match its header.", version);
  }

  let offset = HEADER_BYTES;
  let abiPayload: Uint8Array | null = null;
  let wasmPayload: Uint8Array | null = null;
  for (let index = 0; index < SECTION_DEFINITIONS.length; index += 1) {
    const definition = SECTION_DEFINITIONS[index];
    if (!definition || offset + SECTION_HEADER_BYTES > bytes.byteLength) {
      return fail("INVALID", "TRUNCATED_SECTION", "A section header is truncated.", version, index);
    }
    const tag = view.getUint16(offset, true);
    if (!SECTION_DEFINITIONS.some(([known]) => known === tag)) {
      return fail(
        "INCONCLUSIVE",
        "UNKNOWN_SECTION",
        "An unknown section tag requires a newer native checker.",
        version,
        index,
      );
    }
    if (tag !== definition[0]) {
      return fail("INVALID", "SECTION_ORDER", "Capsule sections are not in canonical order.", version, index);
    }
    if (view.getUint16(offset + 2, true) !== 0) {
      return fail("INVALID", "SECTION_FLAGS", "A section declares unsupported flags.", version, index);
    }
    const length = safeNumber(view.getBigUint64(offset + 4, true));
    if (length === null || length < 1 || length > MAX_SECTION_BYTES) {
      return fail(
        "INCONCLUSIVE",
        "SECTION_RESOURCE_BOUND",
        "A section exceeds the Studio parser bound.",
        version,
        index,
      );
    }
    const payloadOffset = offset + SECTION_HEADER_BYTES;
    const payloadEnd = payloadOffset + length;
    if (payloadEnd > bytes.byteLength) {
      return fail("INVALID", "TRUNCATED_PAYLOAD", "A section payload is truncated.", version, index);
    }
    const declaredDigestBytes = bytes.subarray(offset + 12, offset + 44);
    const payload = bytes.subarray(payloadOffset, payloadEnd);
    const actualDigestBytes = await artifactDigest(definition[2], payload);
    const section: QsmSectionAudit = Object.freeze({
      tag,
      name: definition[1],
      offset: payloadOffset,
      length,
      declaredDigest: digestHex(declaredDigestBytes),
      actualDigest: digestHex(actualDigestBytes),
      digestMatches: equalBytes(declaredDigestBytes, actualDigestBytes),
    });
    sections.push(section);
    if (!section.digestMatches) {
      return fail(
        "INVALID",
        "SECTION_DIGEST_MISMATCH",
        "A section payload does not match its domain-separated digest.",
        version,
        index,
      );
    }
    if (tag === 3) wasmPayload = payload;
    if (tag === 4) abiPayload = payload;
    offset = payloadEnd;
  }
  if (offset !== bytes.byteLength) {
    return fail("INVALID", "TRAILING_BYTES", "Capsule contains trailing bytes.", version);
  }
  if (!wasmPayload || !isSupportedWasmHeader(wasmPayload)) {
    return fail(
      "INCONCLUSIVE",
      "UNSUPPORTED_WASM",
      "The embedded module is outside the supported WASM v1 header.",
      version,
      2,
    );
  }
  const abi = abiPayload ? parseAbiManifest(abiPayload) : null;
  if (!abi) {
    return fail("INVALID", "ABI_MANIFEST", "The ABI manifest is malformed.", version, 3);
  }
  const capsuleDigest = digestHex(await artifactDigest("noticer-core/qseal/capsule/v1", bytes));
  return freezeResult({
    verdict: "INCONCLUSIVE",
    reasonCode: "NATIVE_SEMANTIC_CHECK_REQUIRED",
    reason: "Structure and digests match. Native certificate semantics remain authoritative.",
    totalBytes: bytes.byteLength,
    formatVersion: version,
    capsuleDigest,
    sections,
    focusSectionIndex: null,
    abi,
  });
}

export async function buildQsmAuditFixture(): Promise<Uint8Array> {
  const bounds = new Uint8Array(120);
  bounds.set(new TextEncoder().encode("QSBL"), 0);
  new DataView(bounds.buffer).setUint16(4, QSM_VERSION, true);
  for (let index = 0; index < 14; index += 1) {
    new DataView(bounds.buffer).setBigUint64(8 + index * 8, BigInt(index + 1), true);
  }
  const abi = new Uint8Array(40);
  abi.set(new TextEncoder().encode("QSAM"), 0);
  const abiView = new DataView(abi.buffer);
  abiView.setUint16(4, 1, true);
  abi[6] = 1;
  abi.fill(0xab, 8);
  const compilerManifest = new Uint8Array([
    0x51, 0x53, 0x43, 0x4d, 0x01, 0x00, 0x01, 0x00, 0x07, 0x00, 0x66, 0x69, 0x78, 0x74,
    0x75, 0x72, 0x65, 0x02, 0x00, 0x00, 0x00, 0x76, 0x31,
  ]);
  const payloads = [
    bounds,
    new TextEncoder().encode("SOURCE-CERTIFICATE-V1"),
    new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    abi,
    new Uint8Array([0x51, 0x53, 0x4f, 0x52, 0x01, 0x00, 0x07, 0x00, 0, 1, 2, 3, 4, 5, 6]),
    new TextEncoder().encode("RELATION-CERTIFICATE-V1"),
    new TextEncoder().encode("ROBUST-CERTIFICATE-V1"),
    new TextEncoder().encode("RESOURCE-CERTIFICATE-V1"),
    compilerManifest,
  ];
  const total = HEADER_BYTES + payloads.reduce((sum, payload) => sum + SECTION_HEADER_BYTES + payload.length, 0);
  const output = new Uint8Array(total);
  const view = new DataView(output.buffer);
  output.set(QSM_MAGIC, 0);
  view.setUint16(8, QSM_VERSION, true);
  view.setUint16(10, QSM_SECTION_COUNT, true);
  view.setBigUint64(16, BigInt(total), true);
  let offset = HEADER_BYTES;
  for (let index = 0; index < payloads.length; index += 1) {
    const payload = payloads[index];
    const definition = SECTION_DEFINITIONS[index];
    if (!payload || !definition) throw new Error("Fixture section registry mismatch");
    view.setUint16(offset, definition[0], true);
    view.setBigUint64(offset + 4, BigInt(payload.length), true);
    output.set(await artifactDigest(definition[2], payload), offset + 12);
    output.set(payload, offset + SECTION_HEADER_BYTES);
    offset += SECTION_HEADER_BYTES + payload.length;
  }
  return output;
}

export function tamperQsmSection(bytes: Uint8Array, sectionIndex: number): Uint8Array {
  const copy = bytes.slice();
  if (sectionIndex < 0 || sectionIndex >= QSM_SECTION_COUNT || copy.byteLength < HEADER_BYTES) return copy;
  const view = new DataView(copy.buffer);
  let offset = HEADER_BYTES;
  for (let index = 0; index <= sectionIndex; index += 1) {
    if (offset + SECTION_HEADER_BYTES > copy.byteLength) return copy;
    const length = safeNumber(view.getBigUint64(offset + 4, true));
    if (length === null || offset + SECTION_HEADER_BYTES + length > copy.byteLength) return copy;
    if (index === sectionIndex) {
      copy[offset + SECTION_HEADER_BYTES] ^= 1;
      return copy;
    }
    offset += SECTION_HEADER_BYTES + length;
  }
  return copy;
}

function parseAbiManifest(bytes: Uint8Array): QsmAbiAudit | null {
  if (
    bytes.byteLength !== 40 ||
    new TextDecoder().decode(bytes.subarray(0, 4)) !== "QSAM" ||
    bytes[7] !== 0
  ) {
    return null;
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const profileByte = bytes[6];
  if (profileByte !== 0 && profileByte !== 1) return null;
  return Object.freeze({
    version: view.getUint16(4, true),
    profile: profileByte === 0 ? "P0 PUBLIC QUOTIENT ONLY" : "P1 SEALED ADMISSION",
    abiHash: digestHex(bytes.subarray(8, 40)),
    privateCapability: "qseal.private.ingest",
    privatePolicy: "TCB ONLY / NOT IMPORT / NOT EXPORT / NOT WIRE",
    hostImports: Object.freeze(["qseal.emit_frame", "qseal.emit_action", "qseal.public_failure"]),
    publicExports: Object.freeze([
      "qseal.public.tick",
      "qseal.public.reset",
      "qseal.public.handoff",
      "qseal.public.status",
    ]),
  });
}

async function artifactDigest(domain: string, payload: Uint8Array): Promise<Uint8Array> {
  const domainBytes = new TextEncoder().encode(domain);
  const material = concatBytes(
    ARTIFACT_PREFIX,
    littleEndianU64(domainBytes.length),
    domainBytes,
    littleEndianU64(payload.length),
    payload,
  );
  const digestInput = new ArrayBuffer(material.byteLength);
  new Uint8Array(digestInput).set(material);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", digestInput));
}

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function littleEndianU64(value: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
  return bytes;
}

function safeNumber(value: bigint): number | null {
  return value > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(value);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function isSupportedWasmHeader(bytes: Uint8Array): boolean {
  return (
    bytes.byteLength >= 8 &&
    equalBytes(bytes.subarray(0, 4), new Uint8Array([0x00, 0x61, 0x73, 0x6d])) &&
    equalBytes(bytes.subarray(4, 8), new Uint8Array([0x01, 0x00, 0x00, 0x00]))
  );
}

function digestHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function freezeResult(result: QsmAuditResult): QsmAuditResult {
  return Object.freeze({ ...result, sections: Object.freeze([...result.sections]) });
}
