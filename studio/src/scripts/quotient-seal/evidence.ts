export const STUDIO_EVIDENCE_SCHEMA = "quotient-seal.studio-evidence.v1" as const;

export type StudioEvidenceKind =
  | "QSM_CAPSULE"
  | "TRANSLATION_VALIDATION"
  | "ADVERSARIAL_CONTEXT"
  | "MUTATION_CAMPAIGN"
  | "ENGINE_DIFFERENTIAL"
  | "PERFORMANCE_BUNDLE";

export type StudioEvidenceVerdict = "VALID" | "INVALID" | "INCONCLUSIVE";

export type StudioEvidenceErrorCode =
  | "INVALID_LIMIT"
  | "OVERSIZED"
  | "INVALID_UTF8"
  | "INVALID_JSON"
  | "BOUND_EXCEEDED"
  | "UNKNOWN_SCHEMA"
  | "UNKNOWN_FIELD"
  | "SECRET_FIELD"
  | "INVALID_VALUE"
  | "SEMANTIC_MISMATCH";

export interface StudioEvidenceLimits {
  readonly maxBytes: number;
  readonly maxDepth: number;
  readonly maxNodes: number;
  readonly maxArrayItems: number;
  readonly maxObjectKeys: number;
  readonly maxStringBytes: number;
}

export interface StudioEvidenceLink {
  readonly relation:
    | "SOURCE_CERTIFICATE"
    | "TARGET_MODULE"
    | "CONTEXT_FIXTURE"
    | "COUNTEREXAMPLE"
    | "BASELINE_STATISTICS"
    | "CANDIDATE_STATISTICS"
    | "BUDGET_GATE";
  readonly artifactSha256: string;
}

export interface StudioEvidenceDiagnostic {
  readonly code: DiagnosticCode;
  readonly message: string;
  readonly locationIndex: number | null;
}

export interface StudioEvidenceViewModel {
  readonly schema: typeof STUDIO_EVIDENCE_SCHEMA;
  readonly kind: StudioEvidenceKind;
  readonly title: string;
  readonly verdict: StudioEvidenceVerdict;
  readonly verdictLabel: string;
  readonly artifactSha256: string;
  readonly provenance: Provenance;
  readonly hardwareStatus: "NOT_VERIFIED";
  readonly securityInterpretation: "BOUNDED_SECURITY_EVIDENCE" | "NOT_A_SECURITY_VERDICT";
  readonly facts: Readonly<Record<string, number | boolean | null>>;
  readonly links: readonly StudioEvidenceLink[];
  readonly diagnostics: readonly StudioEvidenceDiagnostic[];
}

type Provenance =
  | "QSM_CHECKER"
  | "TRANSLATION_VALIDATOR"
  | "CONTEXT_CHECKER"
  | "MUTATION_CAMPAIGN"
  | "ENGINE_DIFFERENTIAL"
  | "SOFTWARE_FIXTURE";

type DiagnosticCode =
  | "DIGEST_MISMATCH"
  | "RELATION_DIVERGENCE"
  | "CAPABILITY_VIOLATION"
  | "EXTRA_HOST_CALL"
  | "PRIVATE_TRAP"
  | "RESOURCE_TRACE_DIVERGENCE"
  | "BUDGET_EXCEEDED"
  | "UNSUPPORTED"
  | "RESOURCE_BOUND"
  | "ENGINE_DISAGREEMENT"
  | "PARSER_DISAGREEMENT"
  | "MISSING_EVIDENCE";

const HARD_LIMITS: StudioEvidenceLimits = Object.freeze({
  maxBytes: 512 * 1024,
  maxDepth: 12,
  maxNodes: 4096,
  maxArrayItems: 512,
  maxObjectKeys: 128,
  maxStringBytes: 4096,
});

const TOP_LEVEL_KEYS = [
  "schema",
  "kind",
  "verdict",
  "artifact_sha256",
  "provenance",
  "hardware_status",
  "security_interpretation",
  "facts",
  "links",
  "diagnostics",
] as const;

const TITLES: Readonly<Record<StudioEvidenceKind, string>> = Object.freeze({
  QSM_CAPSULE: "Quotient-Sealed Module",
  TRANSLATION_VALIDATION: "Source-target relation",
  ADVERSARIAL_CONTEXT: "Adversarial context product",
  MUTATION_CAMPAIGN: "Compiler and WASM mutation campaign",
  ENGINE_DIFFERENTIAL: "Cross-engine differential execution",
  PERFORMANCE_BUNDLE: "Performance reproduction bundle",
});

const EXPECTED_PROVENANCE: Readonly<Record<StudioEvidenceKind, Provenance>> = Object.freeze({
  QSM_CAPSULE: "QSM_CHECKER",
  TRANSLATION_VALIDATION: "TRANSLATION_VALIDATOR",
  ADVERSARIAL_CONTEXT: "CONTEXT_CHECKER",
  MUTATION_CAMPAIGN: "MUTATION_CAMPAIGN",
  ENGINE_DIFFERENTIAL: "ENGINE_DIFFERENTIAL",
  PERFORMANCE_BUNDLE: "SOFTWARE_FIXTURE",
});

const FACT_KEYS: Readonly<Record<StudioEvidenceKind, readonly string[]>> = Object.freeze({
  QSM_CAPSULE: Object.freeze([
    "schema_version",
    "module_bytes",
    "section_count",
    "import_count",
    "export_count",
    "capability_count",
  ]),
  TRANSLATION_VALIDATION: Object.freeze([
    "source_steps",
    "target_steps",
    "relation_pairs",
    "first_divergence",
  ]),
  ADVERSARIAL_CONTEXT: Object.freeze([
    "context_count",
    "action_count",
    "search_bound",
    "first_divergence",
  ]),
  MUTATION_CAMPAIGN: Object.freeze([
    "mutant_count",
    "killed_count",
    "escaped_count",
    "inconclusive_count",
  ]),
  ENGINE_DIFFERENTIAL: Object.freeze([
    "engine_count",
    "agreement_count",
    "disagreement_count",
    "inconclusive_count",
  ]),
  PERFORMANCE_BUNDLE: Object.freeze([
    "rule_count",
    "pass_count",
    "fail_count",
    "inconclusive_count",
    "fixture_samples",
  ]),
});

const LINK_RELATIONS = new Set<StudioEvidenceLink["relation"]>([
  "SOURCE_CERTIFICATE",
  "TARGET_MODULE",
  "CONTEXT_FIXTURE",
  "COUNTEREXAMPLE",
  "BASELINE_STATISTICS",
  "CANDIDATE_STATISTICS",
  "BUDGET_GATE",
]);

const INCONCLUSIVE_CODES = new Set<DiagnosticCode>([
  "UNSUPPORTED",
  "RESOURCE_BOUND",
  "ENGINE_DISAGREEMENT",
  "PARSER_DISAGREEMENT",
  "MISSING_EVIDENCE",
]);

const INVALID_CODES = new Set<DiagnosticCode>([
  "DIGEST_MISMATCH",
  "RELATION_DIVERGENCE",
  "CAPABILITY_VIOLATION",
  "EXTRA_HOST_CALL",
  "PRIVATE_TRAP",
  "RESOURCE_TRACE_DIVERGENCE",
  "BUDGET_EXCEEDED",
]);

const DIAGNOSTIC_MESSAGES: Readonly<Record<DiagnosticCode, string>> = Object.freeze({
  DIGEST_MISMATCH: "Artifact digest does not match the declared evidence link.",
  RELATION_DIVERGENCE: "Source and target leave the declared relation.",
  CAPABILITY_VIOLATION: "A host operation exceeds its declared capability.",
  EXTRA_HOST_CALL: "The target emits an additional observable host call.",
  PRIVATE_TRAP: "A private-dependent target trap reaches the observer.",
  RESOURCE_TRACE_DIVERGENCE: "Action-equivalent executions expose different resource traces.",
  BUDGET_EXCEEDED: "A declared performance budget is exceeded.",
  UNSUPPORTED: "The input is outside the supported verification fragment.",
  RESOURCE_BOUND: "Verification stopped at its declared resource bound.",
  ENGINE_DISAGREEMENT: "Independent engines disagree on the target execution.",
  PARSER_DISAGREEMENT: "Independent parsers disagree on the target module.",
  MISSING_EVIDENCE: "Required linked evidence is not present.",
});

const FORBIDDEN_NORMALIZED_KEYS = new Set([
  "rawbiosignal",
  "biosignal",
  "ppg",
  "ibi",
  "ecg",
  "baseline",
  "secret",
  "secretkey",
  "privatekey",
  "stableidentifier",
  "subjectid",
  "participantid",
  "userid",
]);

const DANGEROUS_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export class StudioEvidenceError extends Error {
  readonly code: StudioEvidenceErrorCode;

  constructor(code: StudioEvidenceErrorCode, message: string) {
    super(message);
    this.name = "StudioEvidenceError";
    this.code = code;
  }
}

export function parseStudioEvidence(
  input: string | Uint8Array,
  requestedLimits: Partial<StudioEvidenceLimits> = {},
): StudioEvidenceViewModel {
  const limits = resolveLimits(requestedLimits);
  const source = decodeInput(input, limits.maxBytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(source) as unknown;
  } catch {
    throw new StudioEvidenceError("INVALID_JSON", "Evidence is not valid JSON.");
  }
  inspectBounds(parsed, limits);
  const envelope = requireRecord(parsed);
  requireExactKeys(envelope, TOP_LEVEL_KEYS);
  if (envelope.schema !== STUDIO_EVIDENCE_SCHEMA) {
    throw new StudioEvidenceError("UNKNOWN_SCHEMA", "Evidence schema is not supported.");
  }

  const kind = requireOneOf<StudioEvidenceKind>(envelope.kind, Object.keys(TITLES));
  const verdict = requireOneOf<StudioEvidenceVerdict>(envelope.verdict, [
    "VALID",
    "INVALID",
    "INCONCLUSIVE",
  ]);
  const provenance = requireOneOf<Provenance>(envelope.provenance, [
    "QSM_CHECKER",
    "TRANSLATION_VALIDATOR",
    "CONTEXT_CHECKER",
    "MUTATION_CAMPAIGN",
    "ENGINE_DIFFERENTIAL",
    "SOFTWARE_FIXTURE",
  ]);
  if (provenance !== EXPECTED_PROVENANCE[kind]) {
    throw new StudioEvidenceError("SEMANTIC_MISMATCH", "Evidence provenance does not match its kind.");
  }
  if (envelope.hardware_status !== "NOT_VERIFIED") {
    throw new StudioEvidenceError(
      "SEMANTIC_MISMATCH",
      "Studio evidence v1 accepts only explicitly unverified hardware status.",
    );
  }
  const expectedInterpretation =
    kind === "PERFORMANCE_BUNDLE" ? "NOT_A_SECURITY_VERDICT" : "BOUNDED_SECURITY_EVIDENCE";
  if (envelope.security_interpretation !== expectedInterpretation) {
    throw new StudioEvidenceError(
      "SEMANTIC_MISMATCH",
      "Security interpretation does not match the evidence kind.",
    );
  }

  const diagnostics = parseDiagnostics(envelope.diagnostics);
  enforceVerdictSemantics(verdict, diagnostics);
  const model: StudioEvidenceViewModel = {
    schema: STUDIO_EVIDENCE_SCHEMA,
    kind,
    title: TITLES[kind],
    verdict,
    verdictLabel: verdictCopy(verdict),
    artifactSha256: requireDigest(envelope.artifact_sha256),
    provenance,
    hardwareStatus: "NOT_VERIFIED",
    securityInterpretation: expectedInterpretation,
    facts: parseFacts(envelope.facts, kind),
    links: parseLinks(envelope.links),
    diagnostics,
  };
  return freezeModel(model);
}

function resolveLimits(requested: Partial<StudioEvidenceLimits>): StudioEvidenceLimits {
  const resolved = { ...HARD_LIMITS, ...requested };
  for (const key of Object.keys(HARD_LIMITS) as (keyof StudioEvidenceLimits)[]) {
    const value = resolved[key];
    if (!Number.isSafeInteger(value) || value < 1 || value > HARD_LIMITS[key]) {
      throw new StudioEvidenceError("INVALID_LIMIT", "Evidence limit is outside the hard bound.");
    }
  }
  return Object.freeze(resolved);
}

function decodeInput(input: string | Uint8Array, maxBytes: number): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  if (bytes.byteLength > maxBytes) {
    throw new StudioEvidenceError("OVERSIZED", "Evidence exceeds its byte bound.");
  }
  if (typeof input === "string") return input;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    throw new StudioEvidenceError("INVALID_UTF8", "Evidence is not valid UTF-8.");
  }
}

function inspectBounds(root: unknown, limits: StudioEvidenceLimits): void {
  let nodes = 0;
  const visit = (value: unknown, depth: number): void => {
    nodes += 1;
    if (nodes > limits.maxNodes || depth > limits.maxDepth) {
      throw new StudioEvidenceError("BOUND_EXCEEDED", "Evidence exceeds its structural bound.");
    }
    if (typeof value === "string") {
      if (new TextEncoder().encode(value).byteLength > limits.maxStringBytes) {
        throw new StudioEvidenceError("BOUND_EXCEEDED", "Evidence string exceeds its bound.");
      }
      return;
    }
    if (typeof value === "number" && (!Number.isFinite(value) || !Number.isSafeInteger(value))) {
      throw new StudioEvidenceError("INVALID_VALUE", "Evidence number must be a safe integer.");
    }
    if (Array.isArray(value)) {
      if (value.length > limits.maxArrayItems) {
        throw new StudioEvidenceError("BOUND_EXCEEDED", "Evidence array exceeds its bound.");
      }
      value.forEach((item) => visit(item, depth + 1));
      return;
    }
    if (value !== null && typeof value === "object") {
      const entries = Object.entries(value);
      if (entries.length > limits.maxObjectKeys) {
        throw new StudioEvidenceError("BOUND_EXCEEDED", "Evidence object exceeds its key bound.");
      }
      for (const [key, child] of entries) {
        if (DANGEROUS_KEYS.has(key)) {
          throw new StudioEvidenceError("UNKNOWN_FIELD", "Evidence contains a dangerous field.");
        }
        const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (FORBIDDEN_NORMALIZED_KEYS.has(normalized)) {
          throw new StudioEvidenceError("SECRET_FIELD", "Evidence contains a forbidden private field.");
        }
        visit(child, depth + 1);
      }
    }
  };
  visit(root, 0);
}

function parseFacts(value: unknown, kind: StudioEvidenceKind): Readonly<Record<string, number | boolean | null>> {
  const facts = requireRecord(value);
  requireExactKeys(facts, FACT_KEYS[kind], true);
  const output: Record<string, number | boolean | null> = {};
  for (const [key, fact] of Object.entries(facts)) {
    if (fact !== null && typeof fact !== "boolean" && typeof fact !== "number") {
      throw new StudioEvidenceError("INVALID_VALUE", "Public facts must be integers, booleans, or null.");
    }
    output[key] = fact;
  }
  return Object.freeze(output);
}

function parseLinks(value: unknown): readonly StudioEvidenceLink[] {
  if (!Array.isArray(value)) {
    throw new StudioEvidenceError("INVALID_VALUE", "Evidence links must be an array.");
  }
  return Object.freeze(
    value.map((item) => {
      const link = requireRecord(item);
      requireExactKeys(link, ["relation", "artifact_sha256"]);
      const relation = requireOneOf<StudioEvidenceLink["relation"]>(
        link.relation,
        [...LINK_RELATIONS],
      );
      return Object.freeze({ relation, artifactSha256: requireDigest(link.artifact_sha256) });
    }),
  );
}

function parseDiagnostics(value: unknown): readonly StudioEvidenceDiagnostic[] {
  if (!Array.isArray(value)) {
    throw new StudioEvidenceError("INVALID_VALUE", "Evidence diagnostics must be an array.");
  }
  return Object.freeze(
    value.map((item) => {
      const diagnostic = requireRecord(item);
      requireExactKeys(diagnostic, ["code", "location_index"]);
      const code = requireOneOf<DiagnosticCode>(diagnostic.code, Object.keys(DIAGNOSTIC_MESSAGES));
      const locationIndex = diagnostic.location_index;
      if (
        locationIndex !== null &&
        (!Number.isSafeInteger(locationIndex) || typeof locationIndex !== "number" || locationIndex < 0)
      ) {
        throw new StudioEvidenceError("INVALID_VALUE", "Diagnostic location must be a non-negative integer or null.");
      }
      return Object.freeze({ code, message: DIAGNOSTIC_MESSAGES[code], locationIndex });
    }),
  );
}

function enforceVerdictSemantics(
  verdict: StudioEvidenceVerdict,
  diagnostics: readonly StudioEvidenceDiagnostic[],
): void {
  if (verdict === "VALID" && diagnostics.length !== 0) {
    throw new StudioEvidenceError("SEMANTIC_MISMATCH", "VALID evidence cannot contain diagnostics.");
  }
  if (verdict === "INVALID" && (diagnostics.length === 0 || diagnostics.some((item) => !INVALID_CODES.has(item.code)))) {
    throw new StudioEvidenceError("SEMANTIC_MISMATCH", "INVALID evidence requires only invalidating diagnostics.");
  }
  if (
    verdict === "INCONCLUSIVE" &&
    (diagnostics.length === 0 || diagnostics.some((item) => !INCONCLUSIVE_CODES.has(item.code)))
  ) {
    throw new StudioEvidenceError(
      "SEMANTIC_MISMATCH",
      "INCONCLUSIVE evidence requires only inconclusive diagnostics.",
    );
  }
}

function freezeModel(model: StudioEvidenceViewModel): StudioEvidenceViewModel {
  return Object.freeze(model);
}

function verdictCopy(verdict: StudioEvidenceVerdict): string {
  switch (verdict) {
    case "VALID":
      return "Validated within the declared bound";
    case "INVALID":
      return "Counterexample or contract violation";
    case "INCONCLUSIVE":
      return "Evidence is insufficient for a verdict";
  }
}

function requireRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new StudioEvidenceError("INVALID_VALUE", "Evidence field must be an object.");
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  allowMissing = false,
): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key))) {
    throw new StudioEvidenceError("UNKNOWN_FIELD", "Evidence contains a field outside the allowlist.");
  }
  if (!allowMissing && allowed.some((key) => !(key in value))) {
    throw new StudioEvidenceError("INVALID_VALUE", "Evidence is missing a required field.");
  }
}

function requireOneOf<T extends string>(value: unknown, allowed: readonly string[]): T {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw new StudioEvidenceError("INVALID_VALUE", "Evidence contains an unsupported enum value.");
  }
  return value as T;
}

function requireDigest(value: unknown): string {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw new StudioEvidenceError("INVALID_VALUE", "Evidence digest must be lowercase SHA-256.");
  }
  return value;
}
