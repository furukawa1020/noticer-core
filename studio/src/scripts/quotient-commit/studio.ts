export type CommitScenario = "nominal" | "relation" | "budget" | "substitution";
export type CommitState =
  | "PREPARED"
  | "MONITOR_ACCEPTED"
  | "BUDGET_RESERVED"
  | "COMMITTED"
  | "REJECTED"
  | "ABORTED";

export interface CommitFrame {
  state: CommitState;
  monitor: "PENDING" | "ACCEPT" | "REJECT";
  budget: "PENDING" | "RESERVED" | "REJECT";
  output: "SEALED" | "RELEASED";
  event: string;
}

export interface CommitRun {
  scenario: CommitScenario;
  transactionId: string;
  certificate: string;
  relation: string;
  profile: string;
  frames: CommitFrame[];
  releasePermit: boolean;
}

export type RecoveryScenario = "normal" | "tamper" | "replay" | "split-brain";
export interface RecoveryGate { id: string; label: string; passed: boolean; detail: string }
export interface RecoveryDrill { scenario: RecoveryScenario; ready: boolean; attackDetected: boolean; privacyBudget: number; artifact: string; gates: RecoveryGate[] }

export function simulateRecoveryDrill(scenario: RecoveryScenario): RecoveryDrill {
  const failures: Partial<Record<RecoveryScenario, string>> = { tamper: "proof", replay: "replay", "split-brain": "lease" };
  const definitions = [["proof", "PROOF", "bundle authenticator"], ["quorum", "QUORUM", "2 / 3 verifiers"], ["lease", "FENCE", "token 0042"], ["replay", "NONCE", "epoch 0007"], ["privacy", "AETP", "bucket delta 0"], ["audit", "AUDIT", "causal head bound"]];
  const gates = definitions.map(([id, label, detail]) => ({ id, label, detail, passed: id !== failures[scenario] }));
  const ready = gates.every((gate) => gate.passed);
  return { scenario, ready, attackDetected: scenario !== "normal" && !ready, privacyBudget: scenario === "tamper" ? 18 : scenario === "normal" ? 12 : 14, artifact: digest(`recovery|${scenario}|epoch:7|seed:24301`), gates };
}

export interface ResilienceStep { label: string; state: "passed" | "detected" | "blocked" }
export function simulateResilienceTimeline(fault: string): ResilienceStep[] {
  const labels = ["BOOT", "PROOF", "QUORUM", "LEASE", "HANDOFF", "AUDIT", "ATTEST"];
  const faultIndex: Record<string, number> = { proof: 1, quorum: 2, lease: 3, handoff: 4, audit: 5 };
  const index = faultIndex[fault] ?? -1;
  return labels.map((label, step) => ({ label, state: index < 0 || step < index ? "passed" : step === index ? "detected" : "blocked" }));
}

export interface MissionStage { label: string; status: "verified" | "intercepted" | "withheld" }
export function simulateMissionControl(threat: string): MissionStage[] {
  const labels = ["PROVENANCE", "TIME", "OPERATORS", "REGION", "PRIVACY", "LOG", "CANARY", "ATTEST"];
  const intercept: Record<string, number> = { clock: 1, collusion: 2, region: 3, privacy: 4, canary: 6 };
  const stop = intercept[threat] ?? -1;
  return labels.map((label, index) => ({ label, status: stop < 0 || index < stop ? "verified" : index === stop ? "intercepted" : "withheld" }));
}

export type FlightThreat = "clean" | "rollback" | "custody" | "fork" | "restore" | "liveness" | "export";
export interface FlightStage { label: string; status: "verified" | "intercepted" | "withheld"; evidence: string }
export function simulateRecoveryFlightDeck(threat: FlightThreat): FlightStage[] {
  const stages = [
    ["POLICY", "epoch monotonic"], ["CUSTODY", "share quorum"], ["BREAK-GLASS", "bounded permit"],
    ["REGIONS", "checkpoint gossip"], ["RESTORE", "ordered execution"], ["WATCHDOG", "heartbeat fresh"],
    ["SAFE MODE", "reauthorization"], ["WAVES", "progress chain"], ["EXPORT", "field permit"],
  ];
  const intercept: Record<Exclude<FlightThreat, "clean">, number> = {
    rollback: 0, custody: 1, fork: 3, restore: 4, liveness: 5, export: 8,
  };
  const stop = threat === "clean" ? -1 : intercept[threat];
  return stages.map(([label, evidence], index) => ({
    label,
    evidence,
    status: stop < 0 || index < stop ? "verified" : index === stop ? "intercepted" : "withheld",
  }));
}

export type ControlThreat = "clean" | "escalation" | "delegation" | "monoculture" | "evidence" | "fork" | "rollback" | "replay";
export interface ControlStage { label: string; status: "proven" | "intercepted" | "withheld"; proof: string }
export function simulateProofControlPlane(threat: ControlThreat): ControlStage[] {
  const definitions = [["AUTHORITY", "lattice"], ["DELEGATION", "chain"], ["QUORUM", "diversity"], ["CLOSURE", "evidence DAG"], ["CAUSAL CUT", "region frontier"], ["ROLLBACK", "witness"], ["CHALLENGE", "nonce ledger"], ["COMMITMENT", "bounded view"], ["PROOF CHAIN", "continuous"]];
  const intercept: Record<Exclude<ControlThreat, "clean">, number> = { escalation: 0, delegation: 1, monoculture: 2, evidence: 3, fork: 4, rollback: 5, replay: 6 };
  const stop = threat === "clean" ? -1 : intercept[threat];
  return definitions.map(([label, proof], index) => ({ label, proof, status: stop < 0 || index < stop ? "proven" : index === stop ? "intercepted" : "withheld" }));
}

export type FabricThreat = "clean" | "collusion" | "clock" | "domain" | "fragment" | "cache";
export interface FabricStage { label: string; status: "verified" | "detected" | "blocked"; evidence: string }
export function simulateProofFabric(threat: FabricThreat): FabricStage[] {
  const definitions = [["PRODUCERS", "independent quorum"], ["TIME", "uncertainty cut"], ["DOMAINS", "fault diversity"], ["FRAGMENTS", "root-bound recovery"], ["AGGREGATE", "manifest complete"], ["LEASE", "fresh proof"], ["QUARANTINE", "contradictions zero"], ["AUDIT", "append-only"], ["CACHE", "context bound"]];
  const intercept: Record<Exclude<FabricThreat, "clean">, number> = { collusion: 0, clock: 1, domain: 2, fragment: 3, cache: 8 };
  const stop = threat === "clean" ? -1 : intercept[threat];
  return definitions.map(([label, evidence], index) => ({ label, evidence, status: stop < 0 || index < stop ? "verified" : index === stop ? "detected" : "blocked" }));
}

function digest(value: string): string {
  let hash = 2166136261;
  for (const char of value) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

export function simulateCommit(scenario: CommitScenario): CommitRun {
  const certificate = "CAQT:91d6a1f2";
  const relation = "AQREL:3c07e442";
  const profile = "AQPP:fe2a60b9";
  const transactionId = digest([certificate, relation, profile, "trace:07", "epoch:9"].join("|"));
  const prepared: CommitFrame = {
    state: "PREPARED",
    monitor: "PENDING",
    budget: "PENDING",
    output: "SEALED",
    event: "canonical bindings frozen into transaction",
  };
  const monitored: CommitFrame = {
    state: "MONITOR_ACCEPTED",
    monitor: "ACCEPT",
    budget: "PENDING",
    output: "SEALED",
    event: "online action-equivalence relation accepted",
  };
  let frames: CommitFrame[];

  if (scenario === "relation") {
    frames = [
      prepared,
      {
        state: "REJECTED",
        monitor: "REJECT",
        budget: "PENDING",
        output: "SEALED",
        event: "relation divergence closed the transaction",
      },
    ];
  } else if (scenario === "budget") {
    frames = [
      prepared,
      monitored,
      {
        state: "REJECTED",
        monitor: "ACCEPT",
        budget: "REJECT",
        output: "SEALED",
        event: "privacy filter rejected before release",
      },
    ];
  } else if (scenario === "substitution") {
    frames = [
      prepared,
      monitored,
      {
        state: "ABORTED",
        monitor: "ACCEPT",
        budget: "REJECT",
        output: "SEALED",
        event: "cross-transaction profile binding mismatch",
      },
    ];
  } else {
    frames = [
      prepared,
      monitored,
      {
        state: "BUDGET_RESERVED",
        monitor: "ACCEPT",
        budget: "RESERVED",
        output: "SEALED",
        event: "privacy spend durably reserved",
      },
      {
        state: "COMMITTED",
        monitor: "ACCEPT",
        budget: "RESERVED",
        output: "RELEASED",
        event: "single public release permit issued",
      },
    ];
  }

  return {
    scenario,
    transactionId,
    certificate,
    relation,
    profile,
    frames,
    releasePermit: frames.at(-1)?.state === "COMMITTED",
  };
}

export function validateCommitRun(run: CommitRun): boolean {
  const allowed: Record<CommitState, CommitState[]> = {
    PREPARED: ["MONITOR_ACCEPTED", "REJECTED", "ABORTED"],
    MONITOR_ACCEPTED: ["BUDGET_RESERVED", "REJECTED", "ABORTED"],
    BUDGET_RESERVED: ["COMMITTED", "REJECTED", "ABORTED"],
    COMMITTED: [],
    REJECTED: [],
    ABORTED: [],
  };
  if (run.frames[0]?.state !== "PREPARED") return false;
  for (let index = 1; index < run.frames.length; index += 1) {
    if (!allowed[run.frames[index - 1].state].includes(run.frames[index].state)) return false;
  }
  const released = run.frames.filter((frame) => frame.output === "RELEASED");
  const committed = run.frames.at(-1)?.state === "COMMITTED";
  return released.length === (committed ? 1 : 0) && run.releasePermit === committed;
}

export type OracleThreat = "clean" | "invalid-input" | "node-limit" | "depth-limit" | "replay-disagreement" | "state-mutation";
export type OracleStageStatus = "verified" | "invalid" | "inconclusive" | "blocked";
export type OracleStage = { label: string; status: OracleStageStatus; evidence: string };

export function simulateMinimalOracleLab(threat: OracleThreat): OracleStage[] {
  const labels = ["INPUT", "BFS", "PREDECESSOR", "TRACE", "REPLAY A", "REPLAY B", "MINIMALITY", "ARTIFACT", "VERDICT"];
  const evidence = ["canonical symbols", "ordered frontier", "first parent only", "slot + input + L/R", "independent engine A", "independent engine B", "1-minimal fixed point", "authenticated schema", "promotion gate"];
  const failures: Partial<Record<OracleThreat, { index: number; status: Exclude<OracleStageStatus, "verified" | "blocked">; detail: string }>> = {
    "invalid-input": { index: 0, status: "invalid", detail: "invalid / domain" },
    "node-limit": { index: 1, status: "inconclusive", detail: "inconclusive / node-limit" },
    "depth-limit": { index: 1, status: "inconclusive", detail: "inconclusive / depth-limit" },
    "replay-disagreement": { index: 5, status: "inconclusive", detail: "inconclusive / replay-disagreement" },
    "state-mutation": { index: 7, status: "invalid", detail: "invalid / authentication" },
  };
  const failure = failures[threat];
  return labels.map((label, index) => {
    if (!failure || index < failure.index) return { label, status: "verified", evidence: evidence[index] };
    if (index === failure.index) return { label, status: failure.status, evidence: failure.detail };
    return { label, status: "blocked", evidence: "no verified promotion" };
  });
}

export type CauseThreat = "clean" | "non-cause" | "actual-mismatch" | "node-limit" | "replay-split" | "certificate-mutation" | "inadmissible";
export type CauseStageStatus = "verified" | "causal" | "non-causal" | "invalid" | "inconclusive" | "blocked";
export type CauseStage = { label: string; status: CauseStageStatus; evidence: string };

export function simulateCausalityLab(threat: CauseThreat): CauseStage[] {
  const labels = ["MODEL", "ACTUAL", "CONE", "INTERVENTION", "COUNTERFACTUAL", "ACTUALITY", "DEPENDENCE", "MINIMALITY", "DUAL REPLAY", "PUBLIC CAPSULE"];
  const evidence = ["equation DAG bound", "actual world authenticated", "irrelevant atoms pruned", "policy admissible", "do-world evaluated", "AC1 holds", "AC2 holds", "AC3 holds", "independent engines agree", "redacted cause only"];
  const failures: Partial<Record<CauseThreat, { index: number; status: Exclude<CauseStageStatus, "verified" | "causal" | "blocked">; detail: string }>> = {
    "non-cause": { index: 6, status: "non-causal", detail: "outcome does not depend on candidate" },
    "actual-mismatch": { index: 1, status: "invalid", detail: "actual world binding mismatch" },
    "node-limit": { index: 2, status: "inconclusive", detail: "causal cone node limit" },
    "replay-split": { index: 8, status: "inconclusive", detail: "independent replay disagreement" },
    "certificate-mutation": { index: 9, status: "invalid", detail: "certificate authentication failed" },
    inadmissible: { index: 3, status: "invalid", detail: "intervention outside policy" },
  };
  const failure = failures[threat];
  return labels.map((label, index) => {
    if (!failure) return { label, status: index === labels.length - 1 ? "causal" : "verified", evidence: evidence[index] };
    if (index < failure.index) return { label, status: "verified", evidence: evidence[index] };
    if (index === failure.index) return { label, status: failure.status, evidence: failure.detail };
    return { label, status: "blocked", evidence: "causal promotion withheld" };
  });
}

export function bootstrapCommitStudio(root: HTMLElement): void {
  const get = <T extends HTMLElement>(id: string): T => {
    const node = root.querySelector<T>(`#${id}`);
    if (!node) throw new Error(`missing QuotientCommit element: ${id}`);
    return node;
  };
  const scrubber = get<HTMLInputElement>("qc-scrubber");
  let run = simulateCommit("nominal");
  let timer: ReturnType<typeof setInterval> | undefined;

  const render = (index: number): void => {
    const frame = run.frames[Math.min(index, run.frames.length - 1)];
    get("qc-state").textContent = frame.state;
    get("qc-state").className = `qc-state ${frame.state.toLowerCase()}`;
    get("qc-event").textContent = frame.event;
    get("qc-monitor").textContent = frame.monitor;
    get("qc-budget").textContent = frame.budget;
    get("qc-output").textContent = frame.output;
    get("qc-position").textContent = `${index + 1} / ${run.frames.length}`;
    get("qc-permit").textContent = frame.state === "COMMITTED" ? "PERMIT ISSUED" : "NO PERMIT";
    get("qc-permit").className = frame.state === "COMMITTED" ? "qc-permit live" : "qc-permit";
    get("qc-flow").innerHTML = run.frames
      .map(
        (item, itemIndex) =>
          `<button data-step="${itemIndex}" class="${itemIndex === index ? "active" : ""} ${item.state.toLowerCase()}"><i></i><span>${item.state.replace("_", " ")}</span></button>`,
      )
      .join("");
    root.querySelectorAll<HTMLButtonElement>("[data-step]").forEach((button) =>
      button.addEventListener("click", () => {
        scrubber.value = button.dataset.step ?? "0";
        render(Number(scrubber.value));
      }),
    );
  };

  const select = (scenario: CommitScenario): void => {
    if (timer) clearInterval(timer);
    run = simulateCommit(scenario);
    scrubber.max = String(run.frames.length - 1);
    scrubber.value = "0";
    get("qc-transaction").textContent = run.transactionId;
    get("qc-certificate").textContent = run.certificate;
    get("qc-relation").textContent = run.relation;
    get("qc-profile").textContent = run.profile;
    get("qc-integrity").textContent = validateCommitRun(run) ? "TRACE VALID" : "TRACE INVALID";
    root.querySelectorAll<HTMLElement>("[data-scenario]").forEach((node) =>
      node.classList.toggle("active", node.dataset.scenario === scenario),
    );
    render(0);
  };

  root.querySelectorAll<HTMLButtonElement>("[data-scenario]").forEach((button) =>
    button.addEventListener("click", () => select(button.dataset.scenario as CommitScenario)),
  );
  scrubber.addEventListener("input", () => render(Number(scrubber.value)));
  get("qc-play").addEventListener("click", () => {
    if (timer) clearInterval(timer);
    scrubber.value = "0";
    render(0);
    timer = setInterval(() => {
      const next = Number(scrubber.value) + 1;
      if (next >= run.frames.length) {
        if (timer) clearInterval(timer);
        timer = undefined;
        return;
      }
      scrubber.value = String(next);
      render(next);
    }, 650);
  });
  select("nominal");

  let recoveryScenario: RecoveryScenario = "normal";
  const renderRecovery = (): void => {
    const drill = simulateRecoveryDrill(recoveryScenario);
    get("qc-recovery-verdict").textContent = drill.ready ? "DEPLOY READY" : "DEPLOY BLOCKED";
    get("qc-recovery-verdict").className = `qc-recovery-verdict ${drill.ready ? "ready" : "blocked"}`;
    get("qc-recovery-signal").textContent = drill.ready ? "All six recovery gates agree. Release authority may resume." : `${drill.gates.find((gate) => !gate.passed)?.label} caught ${recoveryScenario.toUpperCase()}. No authority escaped.`;
    get("qc-recovery-artifact").textContent = `DRILL:${drill.artifact}`;
    get("qc-privacy-fill").style.width = `${drill.privacyBudget}%`;
    get("qc-privacy-value").textContent = `${drill.privacyBudget} / 100`;
    get("qc-recovery-gates").innerHTML = drill.gates.map((gate, index) => `<div class="qc-gate ${gate.passed ? "passed" : "blocked"}" style="--gate-delay:${index * 55}ms"><small>0${index + 1}</small><b>${gate.label}</b><span>${gate.passed ? "VERIFIED" : "REJECTED"}</span><code>${gate.detail}</code></div>`).join("");
    root.querySelectorAll<HTMLElement>("[data-recovery-scenario]").forEach((node) => node.classList.toggle("active", node.dataset.recoveryScenario === recoveryScenario));
  };
  root.querySelectorAll<HTMLButtonElement>("[data-recovery-scenario]").forEach((button) => button.addEventListener("click", () => { recoveryScenario = button.dataset.recoveryScenario as RecoveryScenario; renderRecovery(); }));
  get("qc-run-drill").addEventListener("click", () => requestAnimationFrame(renderRecovery));
  renderRecovery();

  const renderCampaign = (fault: string): void => {
    const timeline = simulateResilienceTimeline(fault);
    get("qc-campaign-timeline").innerHTML = timeline.map((step, index) => `<div class="${step.state}"><i>${String(index + 1).padStart(2, "0")}</i><b>${step.label}</b><span>${step.state.toUpperCase()}</span></div>`).join("");
    const detected = timeline.some((step) => step.state === "detected");
    get("qc-campaign-result").textContent = detected ? "ATTACK CONTAINED / NO ATTESTATION" : "CLEAN RUN / ATTESTED";
    root.querySelectorAll<HTMLElement>("[data-campaign-fault]").forEach((node) => node.classList.toggle("active", node.dataset.campaignFault === fault));
  };
  root.querySelectorAll<HTMLButtonElement>("[data-campaign-fault]").forEach((button) => button.addEventListener("click", () => renderCampaign(button.dataset.campaignFault ?? "clean")));
  renderCampaign("clean");

  const renderMission = (threat: string): void => {
    const stages = simulateMissionControl(threat);
    get("qc-mission-rail").innerHTML = stages.map((stage) => `<div class="${stage.status}"><b>${stage.label}</b><span>${stage.status.toUpperCase()}</span></div>`).join("");
    const stopped = stages.find((stage) => stage.status === "intercepted");
    get("qc-mission-verdict").textContent = stopped ? `${stopped.label} INTERCEPTED / RELEASE WITHHELD` : "ALL SYSTEMS COHERENT / RELEASE ATTESTED";
    get("qc-mission-export").textContent = `MISSION:${digest(stages.map((stage) => `${stage.label}:${stage.status}`).join("|"))}`;
    root.querySelectorAll<HTMLElement>("[data-mission-threat]").forEach((node) => node.classList.toggle("active", node.dataset.missionThreat === threat));
  };
  root.querySelectorAll<HTMLButtonElement>("[data-mission-threat]").forEach((button) => button.addEventListener("click", () => renderMission(button.dataset.missionThreat ?? "clean")));
  renderMission("clean");

  const renderFlightDeck = (threat: FlightThreat): void => {
    const stages = simulateRecoveryFlightDeck(threat);
    get("qc-flight-grid").innerHTML = stages.map((stage, index) => `<div class="${stage.status}" style="--flight-delay:${index * 45}ms"><small>${String(index + 1).padStart(2, "0")}</small><b>${stage.label}</b><span>${stage.status.toUpperCase()}</span><code>${stage.evidence}</code></div>`).join("");
    const stopped = stages.find((stage) => stage.status === "intercepted");
    get("qc-flight-verdict").textContent = stopped ? `${stopped.label} CONTAINED THE ATTACK` : "RECOVERY CLEARED FOR CONTROLLED RELEASE";
    get("qc-flight-proof").textContent = `FLIGHT:${digest(stages.map((stage) => `${stage.label}:${stage.status}`).join("|"))}`;
    root.querySelectorAll<HTMLElement>("[data-flight-threat]").forEach((node) => node.classList.toggle("active", node.dataset.flightThreat === threat));
  };
  root.querySelectorAll<HTMLButtonElement>("[data-flight-threat]").forEach((button) => button.addEventListener("click", () => renderFlightDeck((button.dataset.flightThreat ?? "clean") as FlightThreat)));
  renderFlightDeck("clean");

  const renderControlPlane = (threat: ControlThreat): void => {
    const stages = simulateProofControlPlane(threat);
    get("qc-control-rail").innerHTML = stages.map((stage, index) => `<div class="${stage.status}" style="--control-delay:${index * 45}ms"><small>${String(index + 1).padStart(2, "0")}</small><b>${stage.label}</b><span>${stage.status.toUpperCase()}</span><code>${stage.proof}</code></div>`).join("");
    const stopped = stages.find((stage) => stage.status === "intercepted");
    get("qc-control-verdict").textContent = stopped ? `${stopped.label} REJECTED / AUTHORITY WITHHELD` : "PROOF CHAIN COMPLETE / RELEASE REPRODUCIBLE";
    get("qc-control-proof").textContent = `CONTROL:${digest(stages.map((stage) => `${stage.label}:${stage.status}`).join("|"))}`;
    root.querySelectorAll<HTMLElement>("[data-control-threat]").forEach((node) => node.classList.toggle("active", node.dataset.controlThreat === threat));
  };
  root.querySelectorAll<HTMLButtonElement>("[data-control-threat]").forEach((button) => button.addEventListener("click", () => renderControlPlane((button.dataset.controlThreat ?? "clean") as ControlThreat)));
  renderControlPlane("clean");

  const renderFabric = (threat: FabricThreat): void => {
    const stages = simulateProofFabric(threat);
    get("qc-fabric-rail").innerHTML = stages.map((stage, index) => `<div class="${stage.status}" style="--fabric-delay:${index * 45}ms"><small>${String(index + 1).padStart(2, "0")}</small><b>${stage.label}</b><span>${stage.status.toUpperCase()}</span><code>${stage.evidence}</code></div>`).join("");
    const stopped = stages.find((stage) => stage.status === "detected");
    get("qc-fabric-verdict").textContent = stopped ? `${stopped.label} DETECTED / FABRIC SEALED` : "DIVERSE PROOFS AGREE / RELEASE ELIGIBLE";
    get("qc-fabric-proof").textContent = `FABRIC:${digest(stages.map((stage) => `${stage.label}:${stage.status}`).join("|"))}`;
    root.querySelectorAll<HTMLElement>("[data-fabric-threat]").forEach((node) => node.classList.toggle("active", node.dataset.fabricThreat === threat));
  };
  root.querySelectorAll<HTMLButtonElement>("[data-fabric-threat]").forEach((button) => button.addEventListener("click", () => renderFabric((button.dataset.fabricThreat ?? "clean") as FabricThreat)));
  renderFabric("clean");

  const renderOracleLab = (threat: OracleThreat): void => {
    const stages = simulateMinimalOracleLab(threat);
    get("qc-oracle-rail").innerHTML = stages.map((stage, index) => `<div class="${stage.status}" style="--oracle-delay:${index * 45}ms"><small>${String(index + 1).padStart(2, "0")}</small><b>${stage.label}</b><span>${stage.status.toUpperCase()}</span><code>${stage.evidence}</code></div>`).join("");
    const terminal = stages.find((stage) => stage.status === "invalid" || stage.status === "inconclusive");
    get("qc-oracle-verdict").textContent = terminal ? `${terminal.status.toUpperCase()} / VERIFIED PROMOTION BLOCKED` : "VERIFIED / MINIMAL TRACE CERTIFIED";
    get("qc-oracle-artifact").textContent = `ORACLE:${digest(stages.map((stage) => `${stage.label}:${stage.status}:${stage.evidence}`).join("|"))}`;
    root.querySelectorAll<HTMLElement>("[data-oracle-threat]").forEach((node) => node.classList.toggle("active", node.dataset.oracleThreat === threat));
  };
  root.querySelectorAll<HTMLButtonElement>("[data-oracle-threat]").forEach((button) => button.addEventListener("click", () => renderOracleLab((button.dataset.oracleThreat ?? "clean") as OracleThreat)));
  renderOracleLab("clean");

  const renderCauseLab = (threat: CauseThreat): void => {
    const stages = simulateCausalityLab(threat);
    get("qc-cause-rail").innerHTML = stages.map((stage, index) => `<div class="${stage.status}" style="--cause-delay:${index * 45}ms"><small>${String(index + 1).padStart(2, "0")}</small><b>${stage.label}</b><span>${stage.status.toUpperCase()}</span><code>${stage.evidence}</code></div>`).join("");
    const terminal = stages.find((stage) => ["non-causal", "invalid", "inconclusive"].includes(stage.status));
    get("qc-cause-verdict").textContent = terminal ? `${terminal.status.toUpperCase()} / CAUSAL CLAIM WITHHELD` : "CAUSAL / PROOF-CARRYING EXPLANATION";
    get("qc-cause-capsule").textContent = `CAUSE:${digest(stages.map((stage) => `${stage.label}:${stage.status}:${stage.evidence}`).join("|"))}`;
    root.querySelectorAll<HTMLElement>("[data-cause-threat]").forEach((node) => node.classList.toggle("active", node.dataset.causeThreat === threat));
  };
  root.querySelectorAll<HTMLButtonElement>("[data-cause-threat]").forEach((button) => button.addEventListener("click", () => renderCauseLab((button.dataset.causeThreat ?? "clean") as CauseThreat)));
  renderCauseLab("clean");
}
