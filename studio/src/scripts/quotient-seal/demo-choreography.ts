import { replayScenario, sha256Hex, type ScenarioId } from "./adversarial-lab.ts";
import {
  createRepairComparison,
  type PerformanceVerdict,
  type RepairFixtureId,
  type TriStateVerdict,
} from "./repair-revalidation.ts";

export const WISS_DEMO_SCHEMA = "quotient-seal.wiss-demo-export.v1";
export const WISS_DEMO_DURATION_SECONDS = 90;
export const WISS_DEMO_MAX_EXPORT_BYTES = 64 * 1024;
export const WISS_DEMO_HARDWARE_STATUS = "NOT_VERIFIED";

export type DemoStepId =
  | "CAPSULE"
  | "ATTACK"
  | "MICROSCOPE"
  | "REPAIR"
  | "BOUNDARY";

export interface DemoStep {
  readonly id: DemoStepId;
  readonly index: number;
  readonly startSecond: number;
  readonly endSecond: number;
  readonly title: string;
  readonly cue: string;
  readonly target: string;
}

export interface DemoAttackSummary {
  readonly scenarioId: ScenarioId;
  readonly seed: number;
  readonly verdict: "INVALID";
  readonly observer: "API" | "CONTROL" | "RESOURCE";
  readonly mutation: string;
  readonly oneMinimal: true;
  readonly counterexampleSha256: string;
  readonly replaySha256: string;
}

export interface DemoRepairSummary {
  readonly fixtureId: RepairFixtureId;
  readonly attackVerdict: "INVALID";
  readonly securityVerdict: TriStateVerdict;
  readonly performanceVerdict: PerformanceVerdict;
  readonly quotientPadSha256: string;
  readonly revalidationSha256: string;
  readonly performanceGateSha256: string;
  readonly bundleSha256: string;
}

export interface WissDemoExport {
  readonly schema: typeof WISS_DEMO_SCHEMA;
  readonly title: "QuotientSeal Studio WISS Demo";
  readonly durationSeconds: typeof WISS_DEMO_DURATION_SECONDS;
  readonly interactionBudgetToFirstAttack: 2;
  readonly choreography: readonly DemoStep[];
  readonly capsule: {
    readonly verdict: "INCONCLUSIVE";
    readonly reason: "NATIVE_SEMANTIC_CHECK_REQUIRED";
    readonly capsuleSha256: string;
  };
  readonly attacks: readonly DemoAttackSummary[];
  readonly repairs: readonly DemoRepairSummary[];
  readonly evidenceOrigin: "SOFTWARE_FIXTURE";
  readonly hardwareStatus: typeof WISS_DEMO_HARDWARE_STATUS;
  readonly claimBoundary: readonly string[];
  readonly exportSha256: string;
}

export const WISS_DEMO_STEPS: readonly DemoStep[] = Object.freeze([
  Object.freeze({
    id: "CAPSULE",
    index: 0,
    startSecond: 0,
    endSecond: 12,
    title: "What may cross?",
    cue: "capsule、certificate、ABI graphを見せ、private TCB-only境界を固定する。",
    target: "qsm-observatory",
  }),
  Object.freeze({
    id: "ATTACK",
    index: 1,
    startSecond: 12,
    endSecond: 32,
    title: "Break the quotient",
    cue: "同じaction semanticsでもrelease traceを区別できる反例を再生する。",
    target: "#adversarial-lab",
  }),
  Object.freeze({
    id: "MICROSCOPE",
    index: 2,
    startSecond: 32,
    endSecond: 50,
    title: "Find first divergence",
    cue: "API、control、memory、resourceのどこで初めて分岐したかを追う。",
    target: "#relational-trace",
  }),
  Object.freeze({
    id: "REPAIR",
    index: 3,
    startSecond: 50,
    endSecond: 72,
    title: "Repair, then doubt again",
    cue: "QuotientPad候補を適用し、securityとperformanceを独立に再検証する。",
    target: "#repair-revalidation",
  }),
  Object.freeze({
    id: "BOUNDARY",
    index: 4,
    startSecond: 72,
    endSecond: 90,
    title: "Export only what is allowed",
    cue: "digest-linked summaryとclaim boundaryだけを共有し、未検証事項を残す。",
    target: "wiss-demo-director",
  }),
]);

export const WISS_ATTACK_SCENARIOS: readonly ScenarioId[] = Object.freeze([
  "EXTRA_HOST_CALL",
  "PRIVATE_TRAP",
  "RESOURCE_ONLY_LEAK",
]);

const WISS_REPAIR_FIXTURES: readonly RepairFixtureId[] = Object.freeze([
  "FUEL_PAD_PASS",
  "UTILITY_REGRESSION",
  "PERFORMANCE_BUDGET_FAIL",
  "REVALIDATION_UNRESOLVED",
]);

function requiredArtifact(
  artifacts: readonly { readonly role: string; readonly sha256: string }[],
  role: string,
): string {
  const artifact = artifacts.find((candidate) => candidate.role === role);
  if (!artifact) throw new Error(`missing demo artifact: ${role}`);
  return artifact.sha256;
}

function createAttackSummaries(): readonly DemoAttackSummary[] {
  const actions: Readonly<Record<ScenarioId, readonly ("TICK" | "RESET" | "HANDOFF" | "MALFORMED" | "REPEAT" | "FUTURE_SLOT")[]>> = {
    EXTRA_HOST_CALL: ["RESET", "TICK", "HANDOFF"],
    PRIVATE_TRAP: ["HANDOFF", "RESET", "TICK"],
    RESOURCE_ONLY_LEAK: ["MALFORMED", "TICK", "FUTURE_SLOT", "REPEAT"],
    ENGINE_DISAGREEMENT: ["RESET"],
  };
  return Object.freeze(
    WISS_ATTACK_SCENARIOS.map((scenarioId) => {
      const result = replayScenario(scenarioId, actions[scenarioId]);
      if (result.verdict !== "INVALID" || !result.oneMinimal) {
        throw new Error(`demo attack is not reproducible: ${scenarioId}`);
      }
      return Object.freeze({
        scenarioId,
        seed: result.seed,
        verdict: "INVALID" as const,
        observer: result.observer,
        mutation: result.mutation,
        oneMinimal: true as const,
        counterexampleSha256: requiredArtifact(result.artifactLinks, "COUNTEREXAMPLE"),
        replaySha256: requiredArtifact(result.artifactLinks, "REPLAY"),
      });
    }),
  );
}

function createRepairSummaries(): readonly DemoRepairSummary[] {
  return Object.freeze(
    WISS_REPAIR_FIXTURES.map((fixtureId) => {
      const result = createRepairComparison(fixtureId);
      return Object.freeze({
        fixtureId,
        attackVerdict: result.attackVerdict,
        securityVerdict: result.security.verdict,
        performanceVerdict: result.performance.verdict,
        quotientPadSha256: result.candidate.sha256,
        revalidationSha256: result.security.sha256,
        performanceGateSha256: result.performance.gateSha256,
        bundleSha256: requiredArtifact(result.artifacts, "REPAIR_BUNDLE"),
      });
    }),
  );
}

export function createWissDemoExport(): WissDemoExport {
  const capsuleSha256 = sha256Hex(
    `${WISS_DEMO_SCHEMA}|QSEALCAP|NATIVE_SEMANTIC_CHECK_REQUIRED|${WISS_DEMO_HARDWARE_STATUS}`,
  );
  const attacks = createAttackSummaries();
  const repairs = createRepairSummaries();
  const claimBoundary = Object.freeze([
    "固定software fixtureに対する有界なsecurity evidenceである",
    "performance PASSはsecurity verdictではない",
    "private biosignal、secret key、stable identifierをexportしない",
    "Polar Verity Sense実機での動作はNOT_VERIFIEDである",
    "candidate new primitiveでありworld-firstを断定しない",
  ]);
  const unsigned: Omit<WissDemoExport, "exportSha256"> = {
    schema: WISS_DEMO_SCHEMA,
    title: "QuotientSeal Studio WISS Demo" as const,
    durationSeconds: WISS_DEMO_DURATION_SECONDS,
    interactionBudgetToFirstAttack: 2 as const,
    choreography: WISS_DEMO_STEPS,
    capsule: Object.freeze({
      verdict: "INCONCLUSIVE" as const,
      reason: "NATIVE_SEMANTIC_CHECK_REQUIRED" as const,
      capsuleSha256,
    }),
    attacks,
    repairs,
    evidenceOrigin: "SOFTWARE_FIXTURE" as const,
    hardwareStatus: WISS_DEMO_HARDWARE_STATUS,
    claimBoundary,
  };
  const exportSha256 = sha256Hex(JSON.stringify(unsigned));
  return Object.freeze({ ...unsigned, exportSha256 });
}

export function encodeWissDemoExport(value: WissDemoExport = createWissDemoExport()): string {
  const encoded = `${JSON.stringify(value, null, 2)}\n`;
  if (new TextEncoder().encode(encoded).byteLength > WISS_DEMO_MAX_EXPORT_BYTES) {
    throw new RangeError("WISS demo export exceeds its byte bound");
  }
  return encoded;
}
