export const ADVERSARIAL_SCENARIO_SCHEMA =
  "quotient-seal.studio.adversarial-scenario.v1";
export const MAX_SCENARIO_ACTIONS = 16;
export const EVIDENCE_ORIGIN = "INJECTED_TEST_FIXTURE";
export const HARDWARE_STATUS = "NOT_VERIFIED";
export const SECURITY_INTERPRETATION = "BOUNDED_SECURITY_EVIDENCE";

export type ScenarioId =
  | "EXTRA_HOST_CALL"
  | "PRIVATE_TRAP"
  | "RESOURCE_ONLY_LEAK"
  | "ENGINE_DISAGREEMENT";

export type PublicActionKind =
  | "TICK"
  | "RESET"
  | "HANDOFF"
  | "MALFORMED"
  | "REPEAT"
  | "STALE_SLOT"
  | "FUTURE_SLOT"
  | "FAULT"
  | "RECONNECT"
  | "SERVICE_SWITCH";

export type MutationOperator =
  | "extra_host_call"
  | "private_dependent_trap"
  | "opcode_cost_inflate"
  | "address_trace_alias";

export type ObserverSurface = "API" | "CONTROL" | "RESOURCE";
export type ScenarioVerdict = "VALID" | "INVALID" | "INCONCLUSIVE";
export type ReplayEngine = "REFERENCE_REPLAY" | "INDEPENDENT_REPLAY";
export type ReplayFinding =
  | "COUNTEREXAMPLE"
  | "NO_COUNTEREXAMPLE"
  | "UNRESOLVED";

export interface ScenarioDefinition {
  readonly id: ScenarioId;
  readonly title: string;
  readonly summary: string;
  readonly seed: number;
  readonly mutation: MutationOperator;
  readonly observer: ObserverSurface;
  readonly cause: string;
  readonly defaultActions: readonly PublicActionKind[];
  readonly requiredActions: readonly PublicActionKind[];
  readonly sourceEffect: string;
  readonly targetEffect: string;
}

export interface ReplayEvidence {
  readonly engine: ReplayEngine;
  readonly finding: ReplayFinding;
  readonly sourceEffect: string;
  readonly targetEffect: string;
  readonly firstDivergenceStep: number | null;
}

export interface ArtifactLink {
  readonly role: "FIXTURE" | "MUTANT" | "COUNTEREXAMPLE" | "REPLAY";
  readonly sha256: string;
  readonly dependsOn: readonly string[];
}

export interface ScenarioReplayResult {
  readonly schema: typeof ADVERSARIAL_SCENARIO_SCHEMA;
  readonly scenarioId: ScenarioId;
  readonly title: string;
  readonly seed: number;
  readonly mutation: MutationOperator;
  readonly observer: ObserverSurface;
  readonly cause: string;
  readonly actions: readonly PublicActionKind[];
  readonly minimizedActions: readonly PublicActionKind[];
  readonly oneMinimal: boolean;
  readonly verdict: ScenarioVerdict;
  readonly reason:
    | "COUNTEREXAMPLE_REPRODUCED"
    | "COUNTEREXAMPLE_NOT_REPRODUCED"
    | "ENGINE_DISAGREEMENT";
  readonly replayAgreement: boolean;
  readonly replays: readonly ReplayEvidence[];
  readonly firstDivergenceStep: number | null;
  readonly artifactLinks: readonly ArtifactLink[];
  readonly evidenceOrigin: typeof EVIDENCE_ORIGIN;
  readonly hardwareStatus: typeof HARDWARE_STATUS;
  readonly securityInterpretation: typeof SECURITY_INTERPRETATION;
  readonly claimBoundary: readonly string[];
}

export const PUBLIC_ACTION_PALETTE: readonly PublicActionKind[] = Object.freeze([
  "TICK",
  "RESET",
  "HANDOFF",
  "MALFORMED",
  "REPEAT",
  "STALE_SLOT",
  "FUTURE_SLOT",
  "FAULT",
  "RECONNECT",
  "SERVICE_SWITCH",
]);

const ACTION_SET = new Set<string>(PUBLIC_ACTION_PALETTE);

export const SCENARIO_CATALOG: readonly ScenarioDefinition[] = Object.freeze([
  Object.freeze({
    id: "EXTRA_HOST_CALL",
    title: "Extra host call",
    summary: "同じactionに対してmutantだけが追加host callを公開する。",
    seed: 4_110_017,
    mutation: "extra_host_call",
    observer: "API",
    cause: "許可されたaction境界を越える2回目のhost call",
    defaultActions: Object.freeze<PublicActionKind[]>(["RESET", "TICK", "HANDOFF"]),
    requiredActions: Object.freeze<PublicActionKind[]>(["TICK"]),
    sourceEffect: "host_call_count=1",
    targetEffect: "host_call_count=2",
  }),
  Object.freeze({
    id: "PRIVATE_TRAP",
    title: "Private-dependent trap",
    summary: "public actionは同じまま、mutantだけがprivate-dependent pathでtrapする。",
    seed: 4_110_029,
    mutation: "private_dependent_trap",
    observer: "CONTROL",
    cause: "非公開状態に依存したtermination差",
    defaultActions: Object.freeze<PublicActionKind[]>([
      "HANDOFF",
      "RESET",
      "TICK",
      "RECONNECT",
    ]),
    requiredActions: Object.freeze<PublicActionKind[]>(["RESET", "TICK"]),
    sourceEffect: "termination=CONTINUE",
    targetEffect: "termination=TRAP_PRIVATE_PATH",
  }),
  Object.freeze({
    id: "RESOURCE_ONLY_LEAK",
    title: "Resource-only leak",
    summary: "API traceは一致するがmutantのfuel消費だけがprivate pathを露出する。",
    seed: 4_110_043,
    mutation: "opcode_cost_inflate",
    observer: "RESOURCE",
    cause: "action-equivalent execution間のresource trace差",
    defaultActions: Object.freeze<PublicActionKind[]>([
      "MALFORMED",
      "TICK",
      "FUTURE_SLOT",
      "REPEAT",
    ]),
    requiredActions: Object.freeze<PublicActionKind[]>(["TICK", "FUTURE_SLOT"]),
    sourceEffect: "api=ALLOW, fuel=12",
    targetEffect: "api=ALLOW, fuel=20",
  }),
  Object.freeze({
    id: "ENGINE_DISAGREEMENT",
    title: "Engine disagreement",
    summary: "2系統のreplay結果が一致しないため、攻撃成功へ昇格しない。",
    seed: 4_110_059,
    mutation: "address_trace_alias",
    observer: "CONTROL",
    cause: "reference replayとindependent replayの解釈不一致",
    defaultActions: Object.freeze<PublicActionKind[]>(["RESET", "FAULT", "RECONNECT"]),
    requiredActions: Object.freeze<PublicActionKind[]>(["FAULT"]),
    sourceEffect: "reference=TRAP",
    targetEffect: "independent=CONTINUE",
  }),
]);

const SHA256_CONSTANTS = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotateRight(value: number, shift: number): number {
  return (value >>> shift) | (value << (32 - shift));
}

export function sha256Hex(input: string): string {
  const inputBytes = new TextEncoder().encode(input);
  const paddedLength = Math.ceil((inputBytes.length + 9) / 64) * 64;
  const bytes = new Uint8Array(paddedLength);
  bytes.set(inputBytes);
  bytes[inputBytes.length] = 0x80;
  const bitLength = inputBytes.length * 8;
  const view = new DataView(bytes.buffer);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x1_0000_0000), false);
  view.setUint32(paddedLength - 4, bitLength >>> 0, false);

  const hash = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const words = new Uint32Array(64);

  for (let offset = 0; offset < bytes.length; offset += 64) {
    for (let index = 0; index < 16; index += 1) {
      words[index] = view.getUint32(offset + index * 4, false);
    }
    for (let index = 16; index < 64; index += 1) {
      const s0 =
        rotateRight(words[index - 15], 7) ^
        rotateRight(words[index - 15], 18) ^
        (words[index - 15] >>> 3);
      const s1 =
        rotateRight(words[index - 2], 17) ^
        rotateRight(words[index - 2], 19) ^
        (words[index - 2] >>> 10);
      words[index] =
        (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = hash;
    for (let index = 0; index < 64; index += 1) {
      const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temporary1 = (h + sum1 + choice + SHA256_CONSTANTS[index] + words[index]) >>> 0;
      const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temporary2 = (sum0 + majority) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temporary1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temporary1 + temporary2) >>> 0;
    }
    hash[0] = (hash[0] + a) >>> 0;
    hash[1] = (hash[1] + b) >>> 0;
    hash[2] = (hash[2] + c) >>> 0;
    hash[3] = (hash[3] + d) >>> 0;
    hash[4] = (hash[4] + e) >>> 0;
    hash[5] = (hash[5] + f) >>> 0;
    hash[6] = (hash[6] + g) >>> 0;
    hash[7] = (hash[7] + h) >>> 0;
  }

  return Array.from(hash, (value) => value.toString(16).padStart(8, "0")).join("");
}

function getScenario(scenarioId: ScenarioId): ScenarioDefinition {
  const scenario = SCENARIO_CATALOG.find((candidate) => candidate.id === scenarioId);
  if (!scenario) {
    throw new RangeError(`unknown scenario: ${String(scenarioId)}`);
  }
  return scenario;
}

function validateActions(actions: readonly PublicActionKind[]): void {
  if (actions.length === 0 || actions.length > MAX_SCENARIO_ACTIONS) {
    throw new RangeError(`actions must contain 1..${MAX_SCENARIO_ACTIONS} entries`);
  }
  for (const action of actions) {
    if (!ACTION_SET.has(action)) {
      throw new RangeError(`unknown public action: ${String(action)}`);
    }
  }
}

function containsOrderedSequence(
  actions: readonly PublicActionKind[],
  required: readonly PublicActionKind[],
): boolean {
  let requiredIndex = 0;
  for (const action of actions) {
    if (action === required[requiredIndex]) {
      requiredIndex += 1;
    }
  }
  return requiredIndex === required.length;
}

export function minimizeScenarioActions(
  scenarioId: ScenarioId,
  actions: readonly PublicActionKind[],
): readonly PublicActionKind[] {
  const scenario = getScenario(scenarioId);
  validateActions(actions);
  let minimized = [...actions];
  let index = 0;
  while (index < minimized.length) {
    const candidate = minimized.filter((_, candidateIndex) => candidateIndex !== index);
    if (candidate.length > 0 && containsOrderedSequence(candidate, scenario.requiredActions)) {
      minimized = candidate;
    } else {
      index += 1;
    }
  }
  return Object.freeze(minimized);
}

function createReplays(
  scenario: ScenarioDefinition,
  reproduced: boolean,
  divergenceStep: number | null,
): readonly ReplayEvidence[] {
  if (scenario.id === "ENGINE_DISAGREEMENT" && reproduced) {
    return Object.freeze([
      Object.freeze({
        engine: "REFERENCE_REPLAY",
        finding: "COUNTEREXAMPLE",
        sourceEffect: scenario.sourceEffect,
        targetEffect: scenario.targetEffect,
        firstDivergenceStep: divergenceStep,
      }),
      Object.freeze({
        engine: "INDEPENDENT_REPLAY",
        finding: "NO_COUNTEREXAMPLE",
        sourceEffect: "termination=CONTINUE",
        targetEffect: "termination=CONTINUE",
        firstDivergenceStep: null,
      }),
    ]);
  }
  const finding: ReplayFinding = reproduced ? "COUNTEREXAMPLE" : "NO_COUNTEREXAMPLE";
  return Object.freeze(
    (["REFERENCE_REPLAY", "INDEPENDENT_REPLAY"] as const).map((engine) =>
      Object.freeze({
        engine,
        finding,
        sourceEffect: scenario.sourceEffect,
        targetEffect: reproduced ? scenario.targetEffect : scenario.sourceEffect,
        firstDivergenceStep: reproduced ? divergenceStep : null,
      }),
    ),
  );
}

function createArtifactLinks(
  scenario: ScenarioDefinition,
  actions: readonly PublicActionKind[],
  minimizedActions: readonly PublicActionKind[],
  replays: readonly ReplayEvidence[],
): readonly ArtifactLink[] {
  const fixture = sha256Hex(
    `${ADVERSARIAL_SCENARIO_SCHEMA}|fixture|${scenario.id}|${scenario.seed}|${actions.join(",")}`,
  );
  const mutant = sha256Hex(
    `${ADVERSARIAL_SCENARIO_SCHEMA}|mutant|${scenario.mutation}|${fixture}`,
  );
  const counterexample = sha256Hex(
    `${ADVERSARIAL_SCENARIO_SCHEMA}|counterexample|${fixture}|${mutant}|${minimizedActions.join(",")}`,
  );
  const replay = sha256Hex(
    `${ADVERSARIAL_SCENARIO_SCHEMA}|replay|${counterexample}|${replays
      .map((item) => `${item.engine}:${item.finding}`)
      .join(",")}`,
  );
  return Object.freeze([
    Object.freeze({ role: "FIXTURE", sha256: fixture, dependsOn: Object.freeze([]) }),
    Object.freeze({ role: "MUTANT", sha256: mutant, dependsOn: Object.freeze([fixture]) }),
    Object.freeze({
      role: "COUNTEREXAMPLE",
      sha256: counterexample,
      dependsOn: Object.freeze([fixture, mutant]),
    }),
    Object.freeze({ role: "REPLAY", sha256: replay, dependsOn: Object.freeze([counterexample]) }),
  ]);
}

export function replayScenario(
  scenarioId: ScenarioId,
  actions: readonly PublicActionKind[],
): ScenarioReplayResult {
  const scenario = getScenario(scenarioId);
  validateActions(actions);
  const frozenActions = Object.freeze([...actions]);
  const reproduced = containsOrderedSequence(frozenActions, scenario.requiredActions);
  const minimizedActions = reproduced
    ? minimizeScenarioActions(scenarioId, frozenActions)
    : frozenActions;
  const firstDivergenceStep = reproduced
    ? frozenActions.findIndex(
        (action) => action === scenario.requiredActions[scenario.requiredActions.length - 1],
      )
    : null;
  const replays = createReplays(scenario, reproduced, firstDivergenceStep);
  const replayAgreement = replays[0]?.finding === replays[1]?.finding;
  const engineDisagreement = scenario.id === "ENGINE_DISAGREEMENT" && reproduced;
  const oneMinimal =
    reproduced &&
    !engineDisagreement &&
    minimizedActions.every((_, index) => {
      const candidate = minimizedActions.filter((__, candidateIndex) => candidateIndex !== index);
      return !containsOrderedSequence(candidate, scenario.requiredActions);
    });
  const verdict: ScenarioVerdict = engineDisagreement
    ? "INCONCLUSIVE"
    : reproduced && replayAgreement
      ? "INVALID"
      : "INCONCLUSIVE";
  const reason = engineDisagreement
    ? "ENGINE_DISAGREEMENT"
    : reproduced && replayAgreement
      ? "COUNTEREXAMPLE_REPRODUCED"
      : "COUNTEREXAMPLE_NOT_REPRODUCED";
  const artifactLinks = createArtifactLinks(
    scenario,
    frozenActions,
    minimizedActions,
    replays,
  );

  return Object.freeze({
    schema: ADVERSARIAL_SCENARIO_SCHEMA,
    scenarioId,
    title: scenario.title,
    seed: scenario.seed,
    mutation: scenario.mutation,
    observer: scenario.observer,
    cause: scenario.cause,
    actions: frozenActions,
    minimizedActions,
    oneMinimal,
    verdict,
    reason,
    replayAgreement,
    replays,
    firstDivergenceStep,
    artifactLinks,
    evidenceOrigin: EVIDENCE_ORIGIN,
    hardwareStatus: HARDWARE_STATUS,
    securityInterpretation: SECURITY_INTERPRETATION,
    claimBoundary: Object.freeze([
      "固定software fixtureに対する有界なcounterexample evidenceである",
      "engine不一致を攻撃成功として扱わない",
      "実機Polar Verity Senseでの成立は検証していない",
    ]),
  });
}
