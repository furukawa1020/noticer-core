export type SentinelScenarioId =
  | "healthy"
  | "privacy-drift"
  | "semantics-drift"
  | "lease-expired"
  | "monitor-suppressed"
  | "split-view"
  | "sample-replay"
  | "alarm-flood";

export interface SentinelScenario {
  id: SentinelScenarioId;
  label: string;
  fault: string | null;
  verdict: "healthy" | "violated" | "inconclusive" | "invalid";
  response: "monitor" | "quarantine" | "rollback";
}

export const SENTINEL_SCENARIOS: readonly SentinelScenario[] = Object.freeze([
  { id: "healthy", label: "HEALTHY", fault: null, verdict: "healthy", response: "monitor" },
  { id: "privacy-drift", label: "PRIVACY DRIFT", fault: "PRIVACY", verdict: "violated", response: "rollback" },
  { id: "semantics-drift", label: "SEMANTICS DRIFT", fault: "SEMANTICS", verdict: "violated", response: "rollback" },
  { id: "lease-expired", label: "LEASE EXPIRED", fault: "FRESHNESS", verdict: "inconclusive", response: "quarantine" },
  { id: "monitor-suppressed", label: "MONITOR OFFLINE", fault: "INGEST", verdict: "inconclusive", response: "quarantine" },
  { id: "split-view", label: "SPLIT VIEW", fault: "FUSION", verdict: "invalid", response: "quarantine" },
  { id: "sample-replay", label: "SAMPLE REPLAY", fault: "REPLAY GUARD", verdict: "invalid", response: "quarantine" },
  { id: "alarm-flood", label: "ALARM FLOOD", fault: "DEBOUNCE", verdict: "invalid", response: "quarantine" },
]);

export const SENTINEL_STAGES = Object.freeze([
  "DEPLOYMENT BINDING",
  "INGEST",
  "REPLAY GUARD",
  "FRESHNESS",
  "SUPPORT",
  "SEMANTICS",
  "SAFETY",
  "LIVENESS",
  "PRIVACY",
  "FUSION",
  "DEBOUNCE",
  "RESPONSE",
]);

const DETAILS: Readonly<Record<string, string>> = Object.freeze({
  "DEPLOYMENT BINDING": "K17 repair certificate bound",
  INGEST: "sequence 284 / slot 91",
  "REPLAY GUARD": "nonce + sequence accepted",
  FRESHNESS: "lease 1.8s remaining",
  SUPPORT: "inside certified support",
  SEMANTICS: "action class unchanged",
  SAFETY: "removed failure absent",
  LIVENESS: "progress within 4 slots",
  PRIVACY: "1 distinction / bound 1",
  FUSION: "no active alarm",
  DEBOUNCE: "0 duplicates retained",
  RESPONSE: "permit remains active",
});

export function runSentinelScenario(id: string = "healthy") {
  const scenario = SENTINEL_SCENARIOS.find((item) => item.id === id);
  if (!scenario) throw new TypeError(`unknown sentinel scenario: ${id}`);

  let stopped = false;
  const stages = SENTINEL_STAGES.map((name) => {
    if (stopped) return { name, status: "withheld", detail: "upstream assurance unavailable" };
    if (scenario.fault === name) {
      stopped = true;
      const status = scenario.verdict === "violated" ? "violated" : scenario.verdict;
      return { name, status, detail: faultDetail(scenario.id) };
    }
    return { name, status: "verified", detail: DETAILS[name] };
  });

  return {
    scenario,
    stages,
    permitActive: scenario.verdict === "healthy",
    revocationIssued: scenario.verdict === "violated",
    quarantine: scenario.response !== "monitor",
    timeline: buildTimeline(scenario),
    capsule: {
      verdict: scenario.verdict,
      response: scenario.response,
      deployment: "deploy:5a81…0d2c",
      evidence: scenario.verdict === "healthy" ? "window:8f20…1a93" : "incident:c041…7b9e",
      sequence: "284",
      disclosure: "public trace only",
    },
  };
}

function faultDetail(id: SentinelScenarioId): string {
  const details: Readonly<Record<SentinelScenarioId, string>> = {
    healthy: "no fault",
    "privacy-drift": "new within-action distinction",
    "semantics-drift": "action class changed",
    "lease-expired": "evidence lease expired",
    "monitor-suppressed": "sample stream missing",
    "split-view": "independent monitors disagree",
    "sample-replay": "sequence 281 replayed",
    "alarm-flood": "duplicate digest burst",
  };
  return details[id];
}

function buildTimeline(scenario: SentinelScenario) {
  const base = [
    { slot: 88, state: "ACTIVE", note: "permit valid" },
    { slot: 89, state: "ACTIVE", note: "window verified" },
    { slot: 90, state: "ACTIVE", note: "lease renewed" },
  ];
  if (scenario.verdict === "healthy") {
    return [...base, { slot: 91, state: "ACTIVE", note: "continue monitoring" }];
  }
  return [
    ...base,
    { slot: 91, state: "DETECTED", note: faultDetail(scenario.id) },
    { slot: 92, state: "QUARANTINED", note: "release withheld" },
    { slot: 93, state: scenario.response === "rollback" ? "ROLLBACK" : "REVIEW", note: scenario.response },
  ];
}

