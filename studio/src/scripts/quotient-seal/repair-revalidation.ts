import { replayScenario, sha256Hex } from "./adversarial-lab.ts";

export const REPAIR_COMPARISON_SCHEMA =
  "quotient-seal.studio.repair-revalidation.v1";
export const REPAIR_EVIDENCE_ORIGIN = "SOFTWARE_FIXTURE";
export const REPAIR_HARDWARE_STATUS = "NOT_VERIFIED";

export type RepairFixtureId =
  | "FUEL_PAD_PASS"
  | "UTILITY_REGRESSION"
  | "PERFORMANCE_BUDGET_FAIL"
  | "REVALIDATION_UNRESOLVED";
export type TriStateVerdict = "VALID" | "INVALID" | "INCONCLUSIVE";
export type PerformanceVerdict = "PASS" | "FAIL" | "INCONCLUSIVE";
export type ResourceAxis =
  | "OPCODE"
  | "BRANCH"
  | "MEMORY_ADDRESS"
  | "IMPORT"
  | "FUEL"
  | "MEMORY_PAGES";
export type NormalizationKind =
  | "PUBLIC_NO_OP"
  | "BOUNDED_LOOP"
  | "BRANCH_FUEL"
  | "FIXED_SCRATCH"
  | "FAILURE_RETURN_PATH";
export type PadSide = "LEFT" | "RIGHT" | "BOTH";

export interface RepairFixtureDefinition {
  readonly id: RepairFixtureId;
  readonly title: string;
  readonly summary: string;
  readonly securityMode: "NORMALIZED" | "UTILITY_CHANGED" | "UNRESOLVED";
  readonly performanceMode: "PASS" | "FAIL" | "INCONCLUSIVE";
  readonly normalizationKind: NormalizationKind;
}

export interface ResourceTraceComparison {
  readonly index: number;
  readonly axis: ResourceAxis;
  readonly leftBefore: number;
  readonly rightBefore: number;
  readonly leftAfter: number | null;
  readonly rightAfter: number | null;
  readonly beforeEqual: boolean;
  readonly afterEqual: boolean | null;
}

export interface QuotientPadOperation {
  readonly pair: readonly [number, number];
  readonly eventIndex: number;
  readonly axis: ResourceAxis;
  readonly kind: NormalizationKind;
  readonly side: PadSide;
  readonly amount: number;
}

export interface NormalizationOverhead {
  readonly operationCount: number;
  readonly addedInstructions: number;
  readonly addedFuel: number;
  readonly boundedLoopIterations: number;
  readonly fixedScratchBytes: number;
}

export interface QuotientPadCandidate {
  readonly version: 1;
  readonly operations: readonly QuotientPadOperation[];
  readonly overhead: NormalizationOverhead;
  readonly sha256: string;
}

export interface SecurityRevalidation {
  readonly verdict: TriStateVerdict;
  readonly reason:
    | "RESOURCE_TRACE_NORMALIZED"
    | "NORMALIZATION_CHANGED_UTILITY"
    | "REVALIDATION_RESOURCE_BOUND";
  readonly relation: TriStateVerdict;
  readonly context: TriStateVerdict;
  readonly resource: "NORMALIZED" | "COUNTEREXAMPLE" | "INCONCLUSIVE";
  readonly utilityPreserved: boolean | null;
  readonly deadlinesPreserved: boolean | null;
  readonly securityInterpretation: "BOUNDED_SECURITY_EVIDENCE";
  readonly sha256: string;
}

export interface PerformanceGateEvidence {
  readonly verdict: PerformanceVerdict;
  readonly metric: "WALL_CLOCK_TIME";
  readonly unit: "NANOSECONDS";
  readonly statistic: "P95";
  readonly baselineValue: number;
  readonly candidateValue: number | null;
  readonly relativeLimitMillionths: number;
  readonly observedRatioMillionths: number | null;
  readonly baselineSamples: number;
  readonly candidateSamples: number;
  readonly securityInterpretation: "NOT_A_SECURITY_VERDICT";
  readonly evidenceOrigin: "PERFORMANCE_BUDGET_GATE";
  readonly hardwareStatus: typeof REPAIR_HARDWARE_STATUS;
  readonly baselineStatisticsSha256: string;
  readonly candidateStatisticsSha256: string;
  readonly gateSha256: string;
}

export interface RepairArtifactLink {
  readonly role:
    | "ATTACK_FIXTURE"
    | "COUNTEREXAMPLE"
    | "QUOTIENT_PAD"
    | "REVALIDATION"
    | "BASELINE_STATISTICS"
    | "CANDIDATE_STATISTICS"
    | "PERFORMANCE_GATE"
    | "REPAIR_BUNDLE";
  readonly sha256: string;
  readonly dependsOn: readonly string[];
}

export interface RepairComparison {
  readonly schema: typeof REPAIR_COMPARISON_SCHEMA;
  readonly fixtureId: RepairFixtureId;
  readonly title: string;
  readonly summary: string;
  readonly attackVerdict: "INVALID";
  readonly trace: readonly ResourceTraceComparison[];
  readonly candidate: QuotientPadCandidate;
  readonly security: SecurityRevalidation;
  readonly performance: PerformanceGateEvidence;
  readonly artifacts: readonly RepairArtifactLink[];
  readonly evidenceOrigin: typeof REPAIR_EVIDENCE_ORIGIN;
  readonly hardwareStatus: typeof REPAIR_HARDWARE_STATUS;
  readonly claimBoundary: readonly string[];
}

export const RESOURCE_AXES: readonly ResourceAxis[] = Object.freeze([
  "OPCODE",
  "BRANCH",
  "MEMORY_ADDRESS",
  "IMPORT",
  "FUEL",
  "MEMORY_PAGES",
]);

export const REPAIR_FIXTURES: readonly RepairFixtureDefinition[] = Object.freeze([
  Object.freeze({
    id: "FUEL_PAD_PASS",
    title: "Fuel pad / dual pass",
    summary: "resource traceをequalizeし、security再検証と性能budgetが独立に通る。",
    securityMode: "NORMALIZED",
    performanceMode: "PASS",
    normalizationKind: "BRANCH_FUEL",
  }),
  Object.freeze({
    id: "UTILITY_REGRESSION",
    title: "Utility regression",
    summary: "性能はPASSするがutility保存に失敗し、securityはINVALIDのまま。",
    securityMode: "UTILITY_CHANGED",
    performanceMode: "PASS",
    normalizationKind: "FAILURE_RETURN_PATH",
  }),
  Object.freeze({
    id: "PERFORMANCE_BUDGET_FAIL",
    title: "Budget regression",
    summary: "securityはVALIDでも、performance budget超過を独立にFAILとする。",
    securityMode: "NORMALIZED",
    performanceMode: "FAIL",
    normalizationKind: "BOUNDED_LOOP",
  }),
  Object.freeze({
    id: "REVALIDATION_UNRESOLVED",
    title: "Bounded unresolved",
    summary: "再検証と測定の証拠不足を成功へ昇格せずINCONCLUSIVEに保つ。",
    securityMode: "UNRESOLVED",
    performanceMode: "INCONCLUSIVE",
    normalizationKind: "FIXED_SCRATCH",
  }),
]);

function fixtureDefinition(fixtureId: RepairFixtureId): RepairFixtureDefinition {
  const fixture = REPAIR_FIXTURES.find((candidate) => candidate.id === fixtureId);
  if (!fixture) throw new RangeError(`unknown repair fixture: ${String(fixtureId)}`);
  return fixture;
}

function createTrace(unresolved: boolean): readonly ResourceTraceComparison[] {
  const beforeValues: Readonly<Record<ResourceAxis, readonly [number, number]>> = {
    OPCODE: [40, 40],
    BRANCH: [8, 8],
    MEMORY_ADDRESS: [10, 10],
    IMPORT: [1, 1],
    FUEL: [12, 20],
    MEMORY_PAGES: [1, 1],
  };
  return Object.freeze(
    RESOURCE_AXES.map((axis, index) => {
      const [leftBefore, rightBefore] = beforeValues[axis];
      const leftAfter = unresolved ? null : axis === "FUEL" ? 20 : leftBefore;
      const rightAfter = unresolved ? null : rightBefore;
      return Object.freeze({
        index,
        axis,
        leftBefore,
        rightBefore,
        leftAfter,
        rightAfter,
        beforeEqual: leftBefore === rightBefore,
        afterEqual:
          leftAfter === null || rightAfter === null ? null : leftAfter === rightAfter,
      });
    }),
  );
}

function createCandidate(
  fixture: RepairFixtureDefinition,
  counterexampleSha256: string,
): QuotientPadCandidate {
  const operation: QuotientPadOperation = Object.freeze({
    pair: Object.freeze([0, 1]) as readonly [number, number],
    eventIndex: 4,
    axis: "FUEL",
    kind: fixture.normalizationKind,
    side: "LEFT",
    amount: 8,
  });
  const overhead: NormalizationOverhead = Object.freeze({
    operationCount: 1,
    addedInstructions: fixture.performanceMode === "FAIL" ? 26 : 8,
    addedFuel: fixture.performanceMode === "FAIL" ? 28 : 8,
    boundedLoopIterations: fixture.normalizationKind === "BOUNDED_LOOP" ? 4 : 0,
    fixedScratchBytes: fixture.normalizationKind === "FIXED_SCRATCH" ? 64 : 0,
  });
  const sha256 = sha256Hex(
    `quotient-seal/resource/quotient-pad/v1|${counterexampleSha256}|${operation.pair.join(":")}|${operation.eventIndex}|${operation.axis}|${operation.kind}|${operation.side}|${operation.amount}|${Object.values(overhead).join(":")}`,
  );
  return Object.freeze({
    version: 1,
    operations: Object.freeze([operation]),
    overhead,
    sha256,
  });
}

function createSecurity(
  fixture: RepairFixtureDefinition,
  candidate: QuotientPadCandidate,
): SecurityRevalidation {
  const unresolved = fixture.securityMode === "UNRESOLVED";
  const utilityChanged = fixture.securityMode === "UTILITY_CHANGED";
  const verdict: TriStateVerdict = unresolved
    ? "INCONCLUSIVE"
    : utilityChanged
      ? "INVALID"
      : "VALID";
  const reason = unresolved
    ? "REVALIDATION_RESOURCE_BOUND"
    : utilityChanged
      ? "NORMALIZATION_CHANGED_UTILITY"
      : "RESOURCE_TRACE_NORMALIZED";
  const relation: TriStateVerdict = unresolved ? "INCONCLUSIVE" : "VALID";
  const context: TriStateVerdict = unresolved ? "INCONCLUSIVE" : "VALID";
  const resource = unresolved
    ? "INCONCLUSIVE"
    : utilityChanged
      ? "COUNTEREXAMPLE"
      : "NORMALIZED";
  const utilityPreserved = unresolved ? null : !utilityChanged;
  const deadlinesPreserved = unresolved ? null : true;
  const sha256 = sha256Hex(
    `${REPAIR_COMPARISON_SCHEMA}|security|${candidate.sha256}|${verdict}|${reason}|${relation}|${context}|${resource}|${String(utilityPreserved)}|${String(deadlinesPreserved)}`,
  );
  return Object.freeze({
    verdict,
    reason,
    relation,
    context,
    resource,
    utilityPreserved,
    deadlinesPreserved,
    securityInterpretation: "BOUNDED_SECURITY_EVIDENCE",
    sha256,
  });
}

function createPerformance(
  fixture: RepairFixtureDefinition,
  candidate: QuotientPadCandidate,
): PerformanceGateEvidence {
  const baselineValue = 100_000;
  const candidateValue =
    fixture.performanceMode === "INCONCLUSIVE"
      ? null
      : fixture.performanceMode === "FAIL"
        ? 138_000
        : 112_000;
  const relativeLimitMillionths = 1_250_000;
  const observedRatioMillionths =
    candidateValue === null ? null : Math.floor((candidateValue * 1_000_000) / baselineValue);
  const baselineSamples = 64;
  const candidateSamples = fixture.performanceMode === "INCONCLUSIVE" ? 2 : 64;
  const baselineStatisticsSha256 = sha256Hex(
    `${REPAIR_COMPARISON_SCHEMA}|baseline-statistics|P95|${baselineValue}|${baselineSamples}`,
  );
  const candidateStatisticsSha256 = sha256Hex(
    `${REPAIR_COMPARISON_SCHEMA}|candidate-statistics|${candidate.sha256}|P95|${String(candidateValue)}|${candidateSamples}`,
  );
  const gateSha256 = sha256Hex(
    `${REPAIR_COMPARISON_SCHEMA}|performance-gate|${baselineStatisticsSha256}|${candidateStatisticsSha256}|${relativeLimitMillionths}|${fixture.performanceMode}`,
  );
  return Object.freeze({
    verdict: fixture.performanceMode,
    metric: "WALL_CLOCK_TIME",
    unit: "NANOSECONDS",
    statistic: "P95",
    baselineValue,
    candidateValue,
    relativeLimitMillionths,
    observedRatioMillionths,
    baselineSamples,
    candidateSamples,
    securityInterpretation: "NOT_A_SECURITY_VERDICT",
    evidenceOrigin: "PERFORMANCE_BUDGET_GATE",
    hardwareStatus: REPAIR_HARDWARE_STATUS,
    baselineStatisticsSha256,
    candidateStatisticsSha256,
    gateSha256,
  });
}

function createArtifacts(
  fixtureSha256: string,
  counterexampleSha256: string,
  candidate: QuotientPadCandidate,
  security: SecurityRevalidation,
  performance: PerformanceGateEvidence,
): readonly RepairArtifactLink[] {
  const bundleSha256 = sha256Hex(
    `${REPAIR_COMPARISON_SCHEMA}|bundle|${fixtureSha256}|${counterexampleSha256}|${candidate.sha256}|${security.sha256}|${performance.gateSha256}`,
  );
  return Object.freeze([
    Object.freeze({ role: "ATTACK_FIXTURE", sha256: fixtureSha256, dependsOn: Object.freeze([]) }),
    Object.freeze({
      role: "COUNTEREXAMPLE",
      sha256: counterexampleSha256,
      dependsOn: Object.freeze([fixtureSha256]),
    }),
    Object.freeze({
      role: "QUOTIENT_PAD",
      sha256: candidate.sha256,
      dependsOn: Object.freeze([counterexampleSha256]),
    }),
    Object.freeze({
      role: "REVALIDATION",
      sha256: security.sha256,
      dependsOn: Object.freeze([candidate.sha256]),
    }),
    Object.freeze({
      role: "BASELINE_STATISTICS",
      sha256: performance.baselineStatisticsSha256,
      dependsOn: Object.freeze([fixtureSha256]),
    }),
    Object.freeze({
      role: "CANDIDATE_STATISTICS",
      sha256: performance.candidateStatisticsSha256,
      dependsOn: Object.freeze([candidate.sha256]),
    }),
    Object.freeze({
      role: "PERFORMANCE_GATE",
      sha256: performance.gateSha256,
      dependsOn: Object.freeze([
        performance.baselineStatisticsSha256,
        performance.candidateStatisticsSha256,
      ]),
    }),
    Object.freeze({
      role: "REPAIR_BUNDLE",
      sha256: bundleSha256,
      dependsOn: Object.freeze([security.sha256, performance.gateSha256]),
    }),
  ]);
}

export function createRepairComparison(fixtureId: RepairFixtureId): RepairComparison {
  const fixture = fixtureDefinition(fixtureId);
  const attack = replayScenario("RESOURCE_ONLY_LEAK", [
    "MALFORMED",
    "TICK",
    "FUTURE_SLOT",
    "REPEAT",
  ]);
  const attackFixture = attack.artifactLinks.find((artifact) => artifact.role === "FIXTURE");
  const counterexample = attack.artifactLinks.find(
    (artifact) => artifact.role === "COUNTEREXAMPLE",
  );
  if (!attackFixture || !counterexample || attack.verdict !== "INVALID") {
    throw new Error("resource attack fixture is not reproducible");
  }
  const candidate = createCandidate(fixture, counterexample.sha256);
  const security = createSecurity(fixture, candidate);
  const performance = createPerformance(fixture, candidate);
  const artifacts = createArtifacts(
    attackFixture.sha256,
    counterexample.sha256,
    candidate,
    security,
    performance,
  );
  return Object.freeze({
    schema: REPAIR_COMPARISON_SCHEMA,
    fixtureId,
    title: fixture.title,
    summary: fixture.summary,
    attackVerdict: "INVALID",
    trace: createTrace(fixture.securityMode === "UNRESOLVED"),
    candidate,
    security,
    performance,
    artifacts,
    evidenceOrigin: REPAIR_EVIDENCE_ORIGIN,
    hardwareStatus: REPAIR_HARDWARE_STATUS,
    claimBoundary: Object.freeze([
      "performance gateはsecurity verdictではない",
      "再検証は固定software fixtureに限定される",
      "Polar Verity Sense実機での性能とsecurityは未検証である",
    ]),
  });
}
