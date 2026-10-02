export type GuardScenario = "nominal" | "drift" | "reorder" | "reconnect" | "binding";
export type GuardState = "MONITORING" | "HOLD" | "SAFE_SINK" | "RECOVERED";
export type Relation = "EQUIVALENT" | "DIVERGED" | "NOT_COMPARED";

export interface PublicGuardFrame {
  slot: number;
  publicAction: string;
  relation: Relation;
  state: GuardState;
  event: string;
  capsuleEpoch: number;
  capsuleDigest: string;
  previousCapsule: string;
  firstDivergence: number | null;
}

export interface GuardRun {
  scenario: GuardScenario;
  frames: PublicGuardFrame[];
  finalState: GuardState;
  firstDivergence: number | null;
}

const ACTIONS = ["cover", "notify", "cover", "defer", "open", "cover", "ack", "cover", "handoff", "cover"];

function hash(value: string): string {
  let result = 2166136261;
  for (const character of value) {
    result ^= character.charCodeAt(0);
    result = Math.imul(result, 16777619);
  }
  return (result >>> 0).toString(16).padStart(8, "0");
}

export function simulateGuard(scenario: GuardScenario): GuardRun {
  let state: GuardState = "MONITORING";
  let firstDivergence: number | null = null;
  let epoch = 7;
  let previousCapsule = "QG-GENESIS";
  const frames: PublicGuardFrame[] = [];

  ACTIONS.forEach((action, slot) => {
    let relation: Relation = state === "SAFE_SINK" ? "NOT_COMPARED" : "EQUIVALENT";
    let event = "public projections remain action-equivalent";
    let publicAction = action;

    if (scenario === "drift" && slot === 4 && state !== "SAFE_SINK") {
      relation = "DIVERGED";
      state = "SAFE_SINK";
      firstDivergence = slot;
      publicAction = "NO_RELEASE";
      event = "first public projection divergence; sticky witness sealed";
    } else if (scenario === "reorder" && slot === 3 && state !== "SAFE_SINK") {
      relation = "NOT_COMPARED";
      state = "SAFE_SINK";
      firstDivergence = slot;
      publicAction = "NO_RELEASE";
      event = "non-consecutive slot rejected; sequence sink entered";
    } else if (scenario === "binding" && slot === 2 && state !== "SAFE_SINK") {
      relation = "NOT_COMPARED";
      state = "SAFE_SINK";
      publicAction = "NO_RELEASE";
      event = "certificate/runtime digest mismatch; binding rejected";
    } else if (scenario === "reconnect" && slot === 3) {
      relation = "NOT_COMPARED";
      state = "HOLD";
      publicAction = "NO_RELEASE";
      event = "disconnect; bounded hold with no release";
    } else if (scenario === "reconnect" && slot === 5) {
      epoch += 1;
      state = "RECOVERED";
      event = "verified capsule + monotone epoch + public reset";
    } else if (scenario === "reconnect" && slot === 6) {
      state = "MONITORING";
      event = "new public sequence monitored";
    } else if (state === "SAFE_SINK") {
      publicAction = "NO_RELEASE";
      event = "sticky safe sink suppresses observable release";
    } else if (state === "HOLD") {
      relation = "NOT_COMPARED";
      publicAction = "NO_RELEASE";
      event = "awaiting explicit public recovery ceremony";
    }

    const capsuleDigest = hash([slot, epoch, relation, state, publicAction, previousCapsule].join("|"));
    frames.push({ slot, publicAction, relation, state, event, capsuleEpoch: epoch, capsuleDigest, previousCapsule, firstDivergence });
    previousCapsule = capsuleDigest;
  });
  return { scenario, frames, finalState: state, firstDivergence };
}

export function verifyPublicCapsuleChain(run: GuardRun): boolean {
  let previous = "QG-GENESIS";
  for (const frame of run.frames) {
    if (frame.previousCapsule !== previous) return false;
    const expected = hash([frame.slot, frame.capsuleEpoch, frame.relation, frame.state, frame.publicAction, previous].join("|"));
    if (expected !== frame.capsuleDigest) return false;
    previous = frame.capsuleDigest;
  }
  return true;
}

export function bootstrapGuardObservatory(root: HTMLElement): void {
  const get = <T extends HTMLElement>(id: string): T => {
    const node = root.querySelector<T>(`#${id}`);
    if (!node) throw new Error(`missing Guard Observatory element: ${id}`);
    return node;
  };
  const scrubber = get<HTMLInputElement>("qg-scrubber");
  let run = simulateGuard("nominal");
  let timer: ReturnType<typeof setInterval> | undefined;

  const render = (position: number): void => {
    const frame = run.frames[Math.min(position, run.frames.length - 1)];
    get("qg-step").textContent = `${frame.slot + 1} / ${run.frames.length}`;
    get("qg-action").textContent = frame.publicAction;
    get("qg-relation").textContent = frame.relation;
    get("qg-relation").className = `relation ${frame.relation.toLowerCase()}`;
    get("qg-state").textContent = frame.state;
    get("qg-state").className = `guard-state ${frame.state.toLowerCase()}`;
    get("qg-event").textContent = frame.event;
    get("qg-epoch").textContent = String(frame.capsuleEpoch);
    get("qg-capsule").textContent = frame.capsuleDigest;
    get("qg-previous").textContent = frame.previousCapsule;
    get("qg-divergence").textContent = frame.firstDivergence === null ? "NONE" : `SLOT ${frame.firstDivergence}`;
    get("qg-chain").textContent = verifyPublicCapsuleChain(run) ? "VERIFIED" : "BROKEN";
    get("qg-trace").innerHTML = run.frames.map((item) => `<button data-slot="${item.slot}" class="trace-node ${item.state.toLowerCase()} ${item.slot === frame.slot ? "active" : ""}"><i></i><b>${item.slot}</b><span>${item.publicAction}</span></button>`).join("");
    root.querySelectorAll<HTMLButtonElement>("[data-slot]").forEach((button) => button.addEventListener("click", () => { scrubber.value = button.dataset.slot ?? "0"; render(Number(scrubber.value)); }));
  };

  const load = (scenario: GuardScenario): void => {
    if (timer) clearInterval(timer);
    run = simulateGuard(scenario);
    scrubber.value = "0";
    root.querySelectorAll<HTMLElement>("[data-scenario]").forEach((node) => node.classList.toggle("active", node.dataset.scenario === scenario));
    render(0);
  };
  root.querySelectorAll<HTMLButtonElement>("[data-scenario]").forEach((button) => button.addEventListener("click", () => load(button.dataset.scenario as GuardScenario)));
  scrubber.addEventListener("input", () => render(Number(scrubber.value)));
  get("qg-play").addEventListener("click", () => {
    if (timer) clearInterval(timer);
    scrubber.value = "0"; render(0);
    timer = setInterval(() => { const next = Number(scrubber.value) + 1; if (next >= run.frames.length) { if (timer) clearInterval(timer); timer = undefined; return; } scrubber.value = String(next); render(next); }, 480);
  });
  load("nominal");
}
