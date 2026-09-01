import {
  createRelationalTraceFixture,
  projectTraceStep,
  windowRelationalTrace,
  type ObserverChannel,
  type RelationalTrace,
  type RelationalTraceStep,
} from "./relational-trace";

const selectedObservers = new Set<ObserverChannel>(["API", "MEMORY", "RESOURCE"]);
let trace: RelationalTrace = createRelationalTraceFixture({ length: 96, divergenceAt: 37 });
let selectedIndex = trace.firstDivergenceIndex ?? 0;

function node<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing Relational Trace element: ${id}`);
  return value as T;
}

function render(): void {
  const verdict = node("trace-verdict");
  verdict.textContent = trace.verdict;
  verdict.className = `trace-verdict ${trace.verdict.toLowerCase()}`;
  node("trace-reason").textContent = trace.verdictReason;
  node("trace-termination").textContent = trace.termination;
  node("trace-total").textContent = trace.steps.length.toLocaleString();
  node("trace-divergence").textContent =
    trace.firstDivergenceIndex === null ? "none" : `step ${trace.firstDivergenceIndex}`;
  const scrubber = node<HTMLInputElement>("trace-scrubber");
  scrubber.max = String(trace.steps.length - 1);
  scrubber.value = String(selectedIndex);
  node("trace-position").textContent = `${selectedIndex + 1} / ${trace.steps.length}`;
  node<HTMLButtonElement>("trace-jump-divergence").disabled = trace.firstDivergenceIndex === null;

  const window = windowRelationalTrace(trace, selectedIndex);
  const timeline = node("trace-window");
  timeline.replaceChildren();
  if (window.omittedBefore > 0) timeline.append(omission(`${window.omittedBefore} earlier steps omitted`));
  for (const step of window.steps) timeline.append(traceRow(step));
  if (window.omittedAfter > 0) timeline.append(omission(`${window.omittedAfter} later steps omitted`));
  const selected = trace.steps[selectedIndex];
  if (selected) renderDetail(selected);
}

function traceRow(step: RelationalTraceStep): HTMLElement {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `trace-row relation-${step.relationStatus.toLowerCase()}`;
  button.setAttribute("aria-pressed", String(step.index === selectedIndex));
  const index = document.createElement("span");
  index.className = "trace-row-index";
  index.textContent = String(step.index).padStart(4, "0");
  const source = document.createElement("span");
  source.className = "trace-row-world";
  source.append(copy("SOURCE", `state ${step.sourceState}`, step.sourceTransition));
  const relation = document.createElement("span");
  relation.className = "trace-row-relation";
  relation.textContent = step.relationStatus === "MATCH" ? "≈" : step.relationStatus === "STUTTER" ? "…" : "≠";
  relation.setAttribute("aria-label", step.relationStatus.toLowerCase());
  const target = document.createElement("span");
  target.className = "trace-row-world";
  target.append(copy("TARGET WASM", step.targetPc, step.targetOpcode));
  const observation = document.createElement("span");
  observation.className = "trace-row-observation";
  const projected = projectTraceStep(step, [...selectedObservers]);
  observation.textContent = projected.visibleObservations.length
    ? projected.visibleObservations.map((item) => `${item.channel}: ${item.value}`).join(" / ")
    : "No selected observer event";
  button.append(index, source, relation, target, observation);
  button.addEventListener("click", () => {
    selectedIndex = step.index;
    render();
  });
  return button;
}

function copy(kicker: string, title: string, detail: string): DocumentFragment {
  const fragment = document.createDocumentFragment();
  const small = document.createElement("small");
  small.textContent = kicker;
  const strong = document.createElement("strong");
  strong.textContent = title;
  const code = document.createElement("code");
  code.textContent = detail;
  fragment.append(small, strong, code);
  return fragment;
}

function omission(text: string): HTMLElement {
  const item = document.createElement("div");
  item.className = "trace-omission";
  item.textContent = text;
  return item;
}

function renderDetail(step: RelationalTraceStep): void {
  node("trace-source-state").textContent = `S${step.sourceState} / ${step.sourceTransition}`;
  node("trace-target-pc").textContent = `${step.targetPc} / ${step.targetOpcode}`;
  node("trace-relation-record").textContent = `record ${step.relationRecord} / ${step.relationStatus}`;
  const events = node("trace-observer-events");
  events.replaceChildren();
  const projected = projectTraceStep(step, [...selectedObservers]);
  if (projected.visibleObservations.length === 0) {
    events.append(omission("No event reaches the selected observer projection at this step."));
  } else {
    for (const item of projected.visibleObservations) {
      const row = document.createElement("div");
      const channel = document.createElement("b");
      channel.textContent = item.channel;
      const value = document.createElement("span");
      value.textContent = item.value;
      row.append(channel, value);
      events.append(row);
    }
  }
}

node<HTMLInputElement>("trace-scrubber").addEventListener("input", (event) => {
  selectedIndex = Number.parseInt((event.currentTarget as HTMLInputElement).value, 10);
  render();
});
node<HTMLButtonElement>("trace-jump-divergence").addEventListener("click", () => {
  selectedIndex = trace.firstDivergenceIndex ?? selectedIndex;
  render();
});
node<HTMLButtonElement>("trace-load-valid").addEventListener("click", () => {
  trace = createRelationalTraceFixture({ length: 96 });
  selectedIndex = 0;
  render();
});
node<HTMLButtonElement>("trace-load-divergence").addEventListener("click", () => {
  trace = createRelationalTraceFixture({ length: 96, divergenceAt: 37 });
  selectedIndex = trace.firstDivergenceIndex ?? 0;
  render();
});
document.querySelectorAll<HTMLInputElement>("[data-trace-observer]").forEach((input) => {
  input.addEventListener("change", () => {
    const channel = input.dataset.traceObserver as ObserverChannel | undefined;
    if (!channel) return;
    if (input.checked) selectedObservers.add(channel);
    else selectedObservers.delete(channel);
    render();
  });
});

render();
