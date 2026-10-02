export type Scenario = "nominal" | "coalition" | "crash" | "invalidation";
export type Decision = "RELEASE" | "REJECT" | "RECOVER";

export interface OdometerFrame {
  index: number;
  action: string;
  service: string;
  coalition: string;
  decision: Decision;
  cost: number;
  spent: number;
  durableSpent: number;
  profile: "VALID" | "INVALIDATED";
  event: string;
  receipt: string;
  previousReceipt: string;
}

export interface OdometerRun {
  scenario: Scenario;
  budget: number;
  frames: OdometerFrame[];
  released: number;
  rejected: number;
  finalReceipt: string;
}

const ACTIONS = ["notify", "open", "defer", "escalate", "render", "ack", "handoff", "notify", "open", "render", "ack", "defer"];
const COSTS = [7, 9, 4, 15, 8, 6, 11, 7, 9, 8, 6, 4];

function digest(value: string): string {
  let hash = 2166136261;
  for (const char of value) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

export function simulateOdometer(scenario: Scenario): OdometerRun {
  const budget = 72;
  let spent = 0;
  let durableSpent = 0;
  let previousReceipt = "GENESIS";
  let profile: OdometerFrame["profile"] = "VALID";
  const frames: OdometerFrame[] = [];

  ACTIONS.forEach((action, index) => {
    const service = `svc-${(index % 4) + 1}`;
    const coalition = scenario === "coalition" && index >= 4 ? "C:{1,2,4}" : `C:{${(index % 3) + 1}}`;
    let event = "conditional profile composed";
    let decision: Decision = "RELEASE";
    let cost = COSTS[index];

    if (scenario === "coalition" && index >= 4) cost += 5;
    if (scenario === "invalidation" && index === 5) {
      profile = "INVALIDATED";
      event = "policy epoch changed; profile invalidated";
    }
    if (scenario === "crash" && index === 6) {
      decision = "RECOVER";
      cost = 0;
      spent = durableSpent;
      event = "crash recovery restored durable ledger";
    } else if (profile === "INVALIDATED" || spent + cost > budget) {
      decision = "REJECT";
      cost = 0;
      event = profile === "INVALIDATED" ? "fail closed: recertification required" : "pre-release filter blocked budget excess";
    } else {
      spent += cost;
      durableSpent = spent;
    }

    const previous = previousReceipt;
    const receipt = digest([index, action, service, coalition, decision, spent, durableSpent, profile, previous].join("|"));
    previousReceipt = receipt;
    frames.push({ index, action, service, coalition, decision, cost, spent, durableSpent, profile, event, receipt, previousReceipt: previous });
  });

  return {
    scenario,
    budget,
    frames,
    released: frames.filter((frame) => frame.decision === "RELEASE").length,
    rejected: frames.filter((frame) => frame.decision === "REJECT").length,
    finalReceipt: previousReceipt,
  };
}

export function verifyReceiptChain(run: OdometerRun): boolean {
  let previous = "GENESIS";
  for (const frame of run.frames) {
    if (frame.previousReceipt !== previous) return false;
    const expected = digest([frame.index, frame.action, frame.service, frame.coalition, frame.decision, frame.spent, frame.durableSpent, frame.profile, previous].join("|"));
    if (frame.receipt !== expected) return false;
    previous = frame.receipt;
  }
  return previous === run.finalReceipt;
}

export function bootstrapOdometerStudio(root: HTMLElement): void {
  const get = <T extends HTMLElement>(id: string): T => {
    const node = root.querySelector<T>(`#${id}`);
    if (!node) throw new Error(`missing Odometer Studio element: ${id}`);
    return node;
  };
  const scrubber = get<HTMLInputElement>("qo-scrubber");
  let run = simulateOdometer("nominal");
  let timer: ReturnType<typeof setInterval> | undefined;

  const render = (index: number): void => {
    const frame = run.frames[Math.min(index, run.frames.length - 1)];
    const percent = Math.round((frame.spent / run.budget) * 100);
    get("qo-position").textContent = `${frame.index + 1} / ${run.frames.length}`;
    get("qo-spent").textContent = `${frame.spent}`;
    get("qo-budget").textContent = `${run.budget}`;
    get("qo-budget-fill").setAttribute("style", `--fill:${Math.min(percent, 100)}%`);
    get("qo-decision").textContent = frame.decision;
    get("qo-decision").className = `qo-decision ${frame.decision.toLowerCase()}`;
    get("qo-action").textContent = frame.action.toUpperCase();
    get("qo-service").textContent = frame.service;
    get("qo-coalition").textContent = frame.coalition;
    get("qo-profile").textContent = frame.profile;
    get("qo-profile").className = frame.profile === "VALID" ? "valid" : "invalid";
    get("qo-event").textContent = frame.event;
    get("qo-receipt").textContent = frame.receipt;
    get("qo-previous").textContent = frame.previousReceipt;
    get("qo-chain-status").textContent = verifyReceiptChain(run) ? "CHAIN VERIFIED" : "CHAIN BROKEN";
    get("qo-timeline").innerHTML = run.frames.map((item) => `<button class="qo-tick ${item.decision.toLowerCase()} ${item.index === frame.index ? "active" : ""}" data-step="${item.index}" title="${item.action}: ${item.decision}"><i></i><span>${item.index + 1}</span></button>`).join("");
    root.querySelectorAll<HTMLButtonElement>("[data-step]").forEach((button) => button.addEventListener("click", () => { scrubber.value = button.dataset.step ?? "0"; render(Number(scrubber.value)); }));
  };

  const selectScenario = (scenario: Scenario): void => {
    if (timer) clearInterval(timer);
    run = simulateOdometer(scenario);
    scrubber.max = String(run.frames.length - 1);
    scrubber.value = "0";
    root.querySelectorAll("[data-scenario]").forEach((node) => node.classList.toggle("active", (node as HTMLElement).dataset.scenario === scenario));
    get("qo-release-count").textContent = String(run.released);
    get("qo-reject-count").textContent = String(run.rejected);
    render(0);
  };

  root.querySelectorAll<HTMLButtonElement>("[data-scenario]").forEach((button) => button.addEventListener("click", () => selectScenario(button.dataset.scenario as Scenario)));
  scrubber.addEventListener("input", () => render(Number(scrubber.value)));
  get("qo-play").addEventListener("click", () => {
    if (timer) clearInterval(timer);
    scrubber.value = "0";
    render(0);
    timer = setInterval(() => {
      const next = Number(scrubber.value) + 1;
      if (next >= run.frames.length) { if (timer) clearInterval(timer); timer = undefined; return; }
      scrubber.value = String(next);
      render(next);
    }, 430);
  });
  selectScenario("nominal");
}
