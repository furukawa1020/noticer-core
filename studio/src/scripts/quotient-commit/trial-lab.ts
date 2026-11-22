export type TrialAttack = "identity" | "traffic" | "drift";
export type TrialMetric = "latency" | "leakage" | "utility" | "detection";
export type TrialAblation = "full" | "no-cause" | "no-remedy" | "no-sentinel" | "no-replay";

export const ATTACKS = Object.freeze([
  { id: "identity", label: "IDENTITY INFERENCE" },
  { id: "traffic", label: "TRAFFIC ANALYSIS" },
  { id: "drift", label: "MODEL DRIFT" },
]);
export const METRICS = Object.freeze([
  { id: "latency", label: "P95 LATENCY", unit: "ms", lower: true },
  { id: "leakage", label: "ATTACK ADVANTAGE", unit: "ppm", lower: true },
  { id: "utility", label: "ACTION MATCH", unit: "%", lower: false },
  { id: "detection", label: "DETECTION DELAY", unit: "slots", lower: true },
]);
export const ABLATIONS = Object.freeze([
  { id: "full", label: "FULL STACK" },
  { id: "no-cause", label: "− CAUSE" },
  { id: "no-remedy", label: "− REMEDY" },
  { id: "no-sentinel", label: "− SENTINEL" },
  { id: "no-replay", label: "− DUAL REPLAY" },
]);

const FIXTURES: Readonly<Record<TrialAttack, Readonly<Record<TrialMetric, readonly number[]>>>> = {
  identity: { latency: [4, 10, 14, 19], leakage: [410000, 180000, 90000, 12000], utility: [100, 94, 97, 98], detection: [0, 0, 0, 3] },
  traffic: { latency: [4, 12, 16, 21], leakage: [520000, 210000, 70000, 18000], utility: [100, 92, 96, 98], detection: [0, 0, 0, 2] },
  drift: { latency: [4, 10, 15, 20], leakage: [360000, 170000, 80000, 15000], utility: [100, 94, 96, 98], detection: [0, 0, 0, 4] },
};

const SYSTEMS = Object.freeze(["IMMEDIATE", "FIXED RATE", "PADDING", "QUOTIENT STACK"]);

export function runTrialFixture(
  attack: string = "identity",
  metric: string = "leakage",
  ablation: string = "full",
) {
  if (!ATTACKS.some((item) => item.id === attack)) throw new TypeError(`unknown attack: ${attack}`);
  if (!METRICS.some((item) => item.id === metric)) throw new TypeError(`unknown metric: ${metric}`);
  if (!ABLATIONS.some((item) => item.id === ablation)) throw new TypeError(`unknown ablation: ${ablation}`);

  const typedAttack = attack as TrialAttack;
  const typedMetric = metric as TrialMetric;
  const values = [...FIXTURES[typedAttack][typedMetric]];
  const penalty: Readonly<Record<TrialAblation, number>> = {
    full: 0,
    "no-cause": typedMetric === "leakage" ? 45000 : 1,
    "no-remedy": typedMetric === "utility" ? -8 : 2,
    "no-sentinel": typedMetric === "detection" ? 12 : 1,
    "no-replay": typedMetric === "latency" ? -3 : typedMetric === "leakage" ? 25000 : 0,
  };
  values[3] = Math.max(0, values[3] + penalty[ablation as TrialAblation]);

  const metricMeta = METRICS.find((item) => item.id === typedMetric)!;
  const fullValue = values[3];
  const baseline = values[2];
  const effect = fullValue - baseline;
  const halfWidth = Math.max(1, Math.round(Math.abs(effect) * 0.16));
  const claimPass = ablation === "full"
    && (metricMeta.lower ? fullValue < baseline : fullValue >= baseline)
    && !(typedMetric === "detection" && typedAttack !== "drift");

  return {
    fixtureOnly: true,
    systems: SYSTEMS.map((name, index) => ({ name, value: values[index] })),
    metric: metricMeta,
    attack: typedAttack,
    ablation,
    effect,
    interval: { lower: effect - halfWidth, upper: effect + halfWidth },
    gates: [
      { name: "PAIRED DESIGN", pass: true },
      { name: "95% INTERVAL", pass: effect - halfWidth > 0 || effect + halfWidth < 0 },
      { name: "NON-INFERIORITY", pass: typedMetric !== "utility" || fullValue >= 95 },
      { name: "HOLM CONTROL", pass: true },
      { name: "CLAIM BOUNDARY", pass: claimPass },
    ],
    claimPass,
  };
}

