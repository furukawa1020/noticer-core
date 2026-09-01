export const MAX_RELATIONAL_TRACE_STEPS = 10_000;
export const MAX_RENDERED_TRACE_STEPS = 9;

export type TraceVerdict = "VALID" | "INVALID" | "INCONCLUSIVE";
export type RelationStatus = "MATCH" | "STUTTER" | "DIVERGED";
export type ObserverChannel = "API" | "CONTROL" | "INSTRUCTION" | "MEMORY" | "RESOURCE";
export type TraceTermination =
  | "COMPLETE"
  | "RESOURCE_BOUND"
  | "UNSUPPORTED"
  | "ENGINE_DISAGREEMENT";

export interface RelationalTraceStep {
  readonly index: number;
  readonly sourceState: number;
  readonly sourceTransition: "TICK" | "RESET" | "HANDOFF" | "STATUS" | "INTERNAL";
  readonly targetPc: string;
  readonly targetOpcode: string;
  readonly relationRecord: number;
  readonly relationStatus: RelationStatus;
  readonly observations: Readonly<Record<ObserverChannel, string | null>>;
}

export interface RelationalTrace {
  readonly schema: "quotient-seal.studio-relational-trace.v1";
  readonly termination: TraceTermination;
  readonly steps: readonly RelationalTraceStep[];
  readonly firstDivergenceIndex: number | null;
  readonly verdict: TraceVerdict;
  readonly verdictReason: string;
}

export interface ProjectedTraceStep extends RelationalTraceStep {
  readonly visibleObservations: readonly Readonly<{
    channel: ObserverChannel;
    value: string;
  }>[];
}

export interface TraceWindow {
  readonly center: number;
  readonly total: number;
  readonly omittedBefore: number;
  readonly omittedAfter: number;
  readonly steps: readonly RelationalTraceStep[];
}

const CHANNELS: readonly ObserverChannel[] = Object.freeze([
  "API",
  "CONTROL",
  "INSTRUCTION",
  "MEMORY",
  "RESOURCE",
]);

export function createRelationalTraceFixture(options: {
  readonly length?: number;
  readonly divergenceAt?: number | null;
  readonly termination?: TraceTermination;
} = {}): RelationalTrace {
  const length = options.length ?? 96;
  const divergenceAt = options.divergenceAt ?? null;
  const termination = options.termination ?? "COMPLETE";
  if (
    !Number.isSafeInteger(length) ||
    length < 1 ||
    length > MAX_RELATIONAL_TRACE_STEPS ||
    (divergenceAt !== null &&
      (!Number.isSafeInteger(divergenceAt) || divergenceAt < 0 || divergenceAt >= length))
  ) {
    throw new RangeError("Relational trace fixture is outside its hard bound.");
  }
  const steps = Array.from({ length }, (_, index) => freezeStep(makeStep(index, divergenceAt)));
  return freezeTrace(steps, termination);
}

export function windowRelationalTrace(
  trace: RelationalTrace,
  requestedCenter: number,
): TraceWindow {
  const center = Math.max(0, Math.min(trace.steps.length - 1, Math.trunc(requestedCenter)));
  const radius = Math.floor(MAX_RENDERED_TRACE_STEPS / 2);
  let start = Math.max(0, center - radius);
  let end = Math.min(trace.steps.length, start + MAX_RENDERED_TRACE_STEPS);
  start = Math.max(0, end - MAX_RENDERED_TRACE_STEPS);
  const steps = trace.steps.slice(start, end);
  return Object.freeze({
    center,
    total: trace.steps.length,
    omittedBefore: start,
    omittedAfter: trace.steps.length - end,
    steps: Object.freeze(steps),
  });
}

export function projectTraceStep(
  step: RelationalTraceStep,
  requestedChannels: readonly ObserverChannel[],
): ProjectedTraceStep {
  const selected = new Set(requestedChannels);
  const visibleObservations = CHANNELS.filter((channel) => selected.has(channel))
    .map((channel) => {
      const value = step.observations[channel];
      return value === null ? null : Object.freeze({ channel, value });
    })
    .filter((entry): entry is Readonly<{ channel: ObserverChannel; value: string }> => entry !== null);
  return Object.freeze({ ...step, visibleObservations: Object.freeze(visibleObservations) });
}

function makeStep(index: number, divergenceAt: number | null): RelationalTraceStep {
  const sourceTransition = transitionFor(index);
  const sourceState = Math.floor(index / 5) % 7;
  const diverged = index === divergenceAt;
  const relationStatus: RelationStatus = diverged
    ? "DIVERGED"
    : index % 4 === 2
      ? "STUTTER"
      : "MATCH";
  const remainingFuel = Math.max(0, 20_000 - index * 3 - (diverged ? 17 : 0));
  return {
    index,
    sourceState,
    sourceTransition,
    targetPc: `f${Math.floor(index / 64)}:i${index % 64}`,
    targetOpcode: `0x${(0x20 + (index % 0x59)).toString(16).padStart(2, "0")}`,
    relationRecord: sourceState,
    relationStatus,
    observations: {
      API: index % 8 === 0 ? `qseal.public.${sourceTransition.toLowerCase()}()` : null,
      CONTROL: index % 5 === 0 ? `enter relation record ${sourceState}` : null,
      INSTRUCTION: `execute opcode 0x${(0x20 + (index % 0x59)).toString(16).padStart(2, "0")}`,
      MEMORY: index % 7 === 0 ? `LOAD public-region +${(index * 4) % 128} / 4 bytes` : null,
      RESOURCE: diverged
        ? `host-call ordinal +1 / fuel ${remainingFuel}`
        : `instruction fuel -3 / remaining ${remainingFuel}`,
    },
  };
}

function transitionFor(index: number): RelationalTraceStep["sourceTransition"] {
  if (index % 29 === 0) return "HANDOFF";
  if (index % 23 === 0) return "RESET";
  if (index % 11 === 0) return "STATUS";
  if (index % 5 === 0) return "TICK";
  return "INTERNAL";
}

function freezeStep(step: RelationalTraceStep): RelationalTraceStep {
  return Object.freeze({ ...step, observations: Object.freeze({ ...step.observations }) });
}

function freezeTrace(steps: readonly RelationalTraceStep[], termination: TraceTermination): RelationalTrace {
  const firstDivergenceIndex = steps.findIndex((step) => step.relationStatus === "DIVERGED");
  const divergence = firstDivergenceIndex === -1 ? null : firstDivergenceIndex;
  const [verdict, verdictReason]: readonly [TraceVerdict, string] =
    divergence !== null
      ? ["INVALID", "Source and target leave the declared relation."]
      : termination === "COMPLETE"
        ? ["VALID", "The complete fixture remains related through its declared bound."]
        : ["INCONCLUSIVE", terminationReason(termination)];
  return Object.freeze({
    schema: "quotient-seal.studio-relational-trace.v1",
    termination,
    steps: Object.freeze([...steps]),
    firstDivergenceIndex: divergence,
    verdict,
    verdictReason,
  });
}

function terminationReason(termination: Exclude<TraceTermination, "COMPLETE">): string {
  switch (termination) {
    case "RESOURCE_BOUND":
      return "Trace ended at its declared resource bound.";
    case "UNSUPPORTED":
      return "Trace contains a target operation outside the supported fragment.";
    case "ENGINE_DISAGREEMENT":
      return "Independent engines disagree; no security verdict is assigned.";
  }
}
