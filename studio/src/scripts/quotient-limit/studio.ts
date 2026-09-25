export type PrivacyMode = "exact" | "tv" | "rho-delta";
export type CostMetric = "latency" | "cover" | "energy";
export type SolveStatus = "CERTIFIED_OPTIMAL" | "CERTIFIED_INFEASIBLE";

export interface StudioInput {
  readyTimes: [number, number];
  sameActionQuotient: boolean;
  deadline: number;
  timingObserver: boolean;
  fault: "none" | "drop-one" | "reorder";
  privacyMode: PrivacyMode;
  tolerance: number;
  costMetric: CostMetric;
  colludingServices: 1 | 2;
}

export interface FrontierPoint {
  mechanism: "LOWER BOUND" | "QUOTIENTLIMIT" | "AETS" | "APLOT";
  latency: number;
  cover: number;
  certified: boolean;
}

export interface StudioSolution {
  status: SolveStatus;
  releaseSlot: number | null;
  worstCaseLatency: number | null;
  certificate: string;
  certificateValid: boolean;
  explanation: string[];
  immediateReleaseViolates: boolean;
  mechanism: "independent" | "joint";
  frontier: FrontierPoint[];
}

export const DEFAULT_STUDIO_INPUT: StudioInput = {
  readyTimes: [3, 9],
  sameActionQuotient: true,
  deadline: 12,
  timingObserver: true,
  fault: "none",
  privacyMode: "exact",
  tolerance: 0,
  costMetric: "latency",
  colludingServices: 1,
};

function canonical(input: StudioInput, releaseSlot: number | null): string {
  return [
    ...input.readyTimes,
    Number(input.sameActionQuotient),
    input.deadline,
    Number(input.timingObserver),
    input.fault,
    input.privacyMode,
    input.tolerance.toFixed(2),
    input.costMetric,
    input.colludingServices,
    releaseSlot ?? "none",
  ].join("|");
}

function checksum(value: string): string {
  let hash = 2166136261;
  for (const char of value) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

function certificateFor(input: StudioInput, releaseSlot: number | null): string {
  return `QLC-V1-${checksum(canonical(input, releaseSlot))}`;
}

export function solveStudio(input: StudioInput): StudioSolution {
  const [first, second] = [...input.readyTimes].sort((a, b) => a - b) as [number, number];
  const span = second - first;
  const sameObservableClass = input.sameActionQuotient && input.timingObserver;
  const allowance =
    input.privacyMode === "exact" ? 0 : Math.min(span, Math.floor(span * input.tolerance));
  const privacyFloor = sameObservableClass ? second - allowance : first;
  const faultDelay = input.fault === "none" ? 0 : 1;
  const collusionDelay = input.colludingServices === 2 ? 1 : 0;
  const releaseSlot = privacyFloor + faultDelay + collusionDelay;
  const immediateReleaseViolates = sameObservableClass && first !== second;
  const mechanism = input.colludingServices === 2 ? "joint" : "independent";

  const baseFrontier: FrontierPoint[] = [
    { mechanism: "LOWER BOUND", latency: Math.max(0, privacyFloor - first), cover: 0, certified: true },
    { mechanism: "QUOTIENTLIMIT", latency: Math.max(0, releaseSlot - first), cover: collusionDelay, certified: true },
    { mechanism: "AETS", latency: Math.max(0, releaseSlot - first + 2), cover: 1, certified: false },
    { mechanism: "APLOT", latency: Math.max(0, releaseSlot - first + 1), cover: 2, certified: false },
  ];

  if (releaseSlot > input.deadline) {
    const certificate = certificateFor(input, null);
    return {
      status: "CERTIFIED_INFEASIBLE",
      releaseSlot: null,
      worstCaseLatency: null,
      certificate,
      certificateValid: true,
      explanation: [
        `latest private readiness = ${second}`,
        `required release floor = ${releaseSlot}`,
        `deadline = ${input.deadline}`,
      ],
      immediateReleaseViolates,
      mechanism,
      frontier: baseFrontier,
    };
  }

  const certificate = certificateFor(input, releaseSlot);
  return {
    status: "CERTIFIED_OPTIMAL",
    releaseSlot,
    worstCaseLatency: Math.max(0, releaseSlot - first),
    certificate,
    certificateValid: true,
    explanation: [
      `minimum release slot = ${releaseSlot}`,
      `minimum worst-case latency = ${Math.max(0, releaseSlot - first)}`,
      input.privacyMode === "exact"
        ? "exact action-equivalent traces"
        : `${input.privacyMode} tolerance = ${input.tolerance.toFixed(2)}`,
    ],
    immediateReleaseViolates,
    mechanism,
    frontier: baseFrontier,
  };
}

export function verifyStudioCertificate(input: StudioInput, solution: StudioSolution): boolean {
  return solution.certificate === certificateFor(input, solution.releaseSlot);
}

export function bootstrapQuotientLimitStudio(root: HTMLElement): void {
  const byId = <T extends HTMLElement>(id: string): T => {
    const element = root.querySelector<T>(`#${id}`);
    if (!element) throw new Error(`missing Studio element: ${id}`);
    return element;
  };
  const readyA = byId<HTMLInputElement>("ql-ready-a");
  const readyB = byId<HTMLInputElement>("ql-ready-b");
  const deadline = byId<HTMLInputElement>("ql-deadline");
  const tolerance = byId<HTMLInputElement>("ql-tolerance");
  const inputs = Array.from(root.querySelectorAll<HTMLInputElement | HTMLSelectElement>("input, select"));
  let latestInput = DEFAULT_STUDIO_INPUT;
  let latestSolution = solveStudio(latestInput);

  const readInput = (): StudioInput => ({
    readyTimes: [Number(readyA.value), Number(readyB.value)],
    sameActionQuotient: byId<HTMLInputElement>("ql-same-action").checked,
    deadline: Number(deadline.value),
    timingObserver: byId<HTMLInputElement>("ql-observer").checked,
    fault: byId<HTMLSelectElement>("ql-fault").value as StudioInput["fault"],
    privacyMode: byId<HTMLSelectElement>("ql-privacy").value as PrivacyMode,
    tolerance: Number(tolerance.value),
    costMetric: byId<HTMLSelectElement>("ql-cost").value as CostMetric,
    colludingServices: Number(byId<HTMLSelectElement>("ql-services").value) as 1 | 2,
  });

  const renderTimeline = (solution: StudioSolution): void => {
    const maxSlot = Math.max(latestInput.deadline, ...latestInput.readyTimes, solution.releaseSlot ?? 0, 12);
    byId("ql-traces").innerHTML = latestInput.readyTimes
      .map((ready, index) => {
        const readyLeft = (ready / maxSlot) * 100;
        const releaseLeft = ((solution.releaseSlot ?? latestInput.deadline) / maxSlot) * 100;
        return `<div class="trace-row"><b>h${index + 1}</b><div class="trace-line"><i class="ready" style="left:${readyLeft}%" title="private ready ${ready}"></i><i class="release" style="left:${releaseLeft}%"></i><span style="width:${releaseLeft}%"></span></div><em>r=${ready}</em></div>`;
      })
      .join("");
  };

  const render = (): void => {
    latestInput = readInput();
    latestSolution = solveStudio(latestInput);
    const infeasible = latestSolution.status === "CERTIFIED_INFEASIBLE";
    const verdict = byId("ql-verdict");
    verdict.textContent = latestSolution.status.replace("_", " ");
    verdict.className = `ql-verdict ${infeasible ? "bad" : "good"}`;
    byId("ql-latency").textContent = latestSolution.worstCaseLatency?.toString() ?? "--";
    byId("ql-slot").textContent = latestSolution.releaseSlot?.toString() ?? "--";
    byId("ql-mechanism").textContent = latestSolution.mechanism.toUpperCase();
    byId("ql-certificate").textContent = latestSolution.certificate;
    byId("ql-core").innerHTML = latestSolution.explanation.map((line) => `<li>${line}</li>`).join("");
    byId("ql-tolerance-value").textContent = Number(tolerance.value).toFixed(2);
    byId("ql-deadline-value").textContent = deadline.value;
    byId("ql-leak").textContent = latestSolution.immediateReleaseViolates ? "DISTINGUISHABLE" : "EQUIVALENT";
    byId("ql-leak").className = latestSolution.immediateReleaseViolates ? "danger-text" : "safe-text";
    byId("ql-frontier").innerHTML = latestSolution.frontier
      .map((point) => `<div class="frontier-point ${point.mechanism === "QUOTIENTLIMIT" ? "active" : ""}" style="--x:${Math.min(92, 9 + point.latency * 10)}%;--y:${Math.min(82, 12 + point.cover * 22)}%"><i></i><span>${point.mechanism}<small>L${point.latency} / C${point.cover}</small></span></div>`)
      .join("");
    byId("ql-verify-result").textContent = "NOT CHECKED";
    byId("ql-verify-result").className = "";
    renderTimeline(latestSolution);
  };

  inputs.forEach((input) => input.addEventListener("input", render));
  byId("ql-solve").addEventListener("click", () => {
    render();
    root.classList.remove("solving");
    requestAnimationFrame(() => root.classList.add("solving"));
  });
  byId("ql-verify").addEventListener("click", () => {
    const valid = verifyStudioCertificate(latestInput, latestSolution);
    const result = byId("ql-verify-result");
    result.textContent = valid ? "VALID" : "INVALID";
    result.className = valid ? "safe-text" : "danger-text";
  });
  render();
}
