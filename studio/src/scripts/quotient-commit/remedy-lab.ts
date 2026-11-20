export type RemedyScenarioId =
  | "clean"
  | "semantic-drift"
  | "privacy-regression"
  | "deny-all"
  | "budget-limit"
  | "certificate-mutation"
  | "replay-split";

export interface RemedyScenario {
  id: RemedyScenarioId;
  label: string;
  fault: string | null;
}

export const REMEDY_SCENARIOS: readonly RemedyScenario[] = Object.freeze([
  { id: "clean", label: "CLEAN REPAIR", fault: null },
  { id: "semantic-drift", label: "SEMANTIC DRIFT", fault: "ACTION EQUIVALENCE" },
  { id: "privacy-regression", label: "PRIVACY REGRESSION", fault: "PRIVACY" },
  { id: "deny-all", label: "DENY-ALL PATCH", fault: "LIVENESS" },
  { id: "budget-limit", label: "BUDGET LIMIT", fault: "SEARCH" },
  { id: "certificate-mutation", label: "CERT MUTATION", fault: "AUTH" },
  { id: "replay-split", label: "REPLAY SPLIT", fault: "DUAL REPLAY" },
]);

export const REMEDY_STAGES = Object.freeze([
  "CAUSE BINDING",
  "CANDIDATES",
  "SEARCH",
  "COUNTERFACTUAL",
  "SAFETY",
  "ACTION EQUIVALENCE",
  "LIVENESS",
  "PRIVACY",
  "MINIMALITY",
  "DUAL REPLAY",
  "AUTH",
  "DEPLOYMENT",
]);

const PATCHES: Readonly<Record<RemedyScenarioId, readonly string[]>> = Object.freeze({
  clean: ["delay(release_gate,+1)", "clamp(notify,0..1)"],
  "semantic-drift": ["substitute(action,2)"],
  "privacy-regression": ["disable(padding)", "delay(release_gate,+1)"],
  "deny-all": ["disable(release_gate)"],
  "budget-limit": [],
  "certificate-mutation": ["delay(release_gate,+1)"],
  "replay-split": ["clamp(notify,0..1)"],
});

export function runRemedyScenario(id: string = "clean") {
  const scenario = REMEDY_SCENARIOS.find((item) => item.id === id);
  if (!scenario) throw new TypeError(`unknown remedy scenario: ${id}`);
  const scenarioId = scenario.id;

  const stages = [];
  let blocked = false;
  for (const name of REMEDY_STAGES) {
    if (blocked) {
      stages.push({ name, status: "withheld", detail: "upstream proof unavailable" });
      continue;
    }
    if (scenario.fault === name) {
      const inconclusive = name === "SEARCH";
      stages.push({
        name,
        status: inconclusive ? "inconclusive" : "blocked",
        detail: inconclusive ? "node limit reached" : `${name.toLowerCase()} rejected`,
      });
      blocked = true;
      continue;
    }
    stages.push({ name, status: "verified", detail: stageDetail(name) });
  }

  const verdict = scenario.fault === "SEARCH"
    ? "inconclusive"
    : scenario.fault
      ? "unrepairable"
      : "repaired";
  return {
    scenario,
    verdict,
    deployable: verdict === "repaired",
    patches: PATCHES[scenarioId],
    stages,
    capsule: {
      verdict,
      patchLabel: verdict === "repaired" ? "minimal-2-edit" : "withheld",
      causeDigest: "cause:7d2c…91af",
      modelDigest: "model:01a9…d44e",
      certificateDigest: verdict === "repaired" ? "repair:ce51…087b" : "withheld",
      checks: verdict === "repaired" ? "5/5 + dual replay" : "not issued",
    },
  };
}

function stageDetail(name: string): string {
  const details: Readonly<Record<string, string>> = {
    "CAUSE BINDING": "K16 certificate authenticated",
    CANDIDATES: "8 canonical patches",
    SEARCH: "23 nodes / 11 worlds",
    COUNTERFACTUAL: "patched world isolated",
    SAFETY: "failure absent",
    "ACTION EQUIVALENCE": "allowed action preserved",
    LIVENESS: "2 eligible releases progress",
    PRIVACY: "0 new distinctions",
    MINIMALITY: "all single removals fail",
    "DUAL REPLAY": "primary = independent",
    AUTH: "domain tag verified",
    DEPLOYMENT: "permit issued",
  };
  return details[name];
}

