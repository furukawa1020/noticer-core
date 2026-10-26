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
}
