import * as monaco from "monaco-editor";
import EditorWorker from "./editor.worker?worker";
import "./quotient-seal/qsm-observatory";
import "./quotient-seal/relational-trace-microscope";

type MonacoHost = typeof globalThis & {
  MonacoEnvironment?: { getWorker: () => Worker };
};

(globalThis as MonacoHost).MonacoEnvironment = {
  getWorker: () => new EditorWorker(),
};

const FLAGS = {
  visiblePrivate: 1 << 0,
  fixedCadence: 1 << 1,
  authorizedAction: 1 << 2,
  deadlineMet: 1 << 3,
  recoveryPresent: 1 << 4,
  transitionsTotal: 1 << 5,
} as const;

interface QuotientForgeExports extends WebAssembly.Exports {
  qf_version: () => number;
  qf_check: (flags: number) => number;
  qf_repair: (flags: number) => number;
  qf_cost: (flags: number) => number;
  qf_frontier_cost: (index: number) => number;
  qf_verify_certificate: (actual: number, expected: number) => number;
}

interface VerdictCopy {
  seal: string;
  title: string;
  detail: string;
  kind: string;
  slot: string;
}

const VERDICTS: Record<number, VerdictCopy> = {
  0: {
    seal: "VALID",
    title: "Bounded model is trace-congruent",
    detail: "No observable divergence or action-utility violation was found within the browser bound.",
    kind: "bounded valid",
    slot: "none",
  },
  1: {
    seal: "CEX",
    title: "Private cadence reaches the observer",
    detail: "Action-equivalent worlds release at distinguishable cadence, so the observer separates them.",
    kind: "security divergence",
    slot: "0",
  },
  2: {
    seal: "CEX",
    title: "Action lacks an EvidencePermit",
    detail: "The release asks Menfugu to act without an authorized obligation in the public contract.",
    kind: "unauthorized action",
    slot: "1",
  },
  3: {
    seal: "CEX",
    title: "Authorized action misses its window",
    detail: "The action is permitted but does not occur before the declared public deadline.",
    kind: "missed deadline",
    slot: "3",
  },
  4: {
    seal: "CEX",
    title: "Recoverable fault has no public recovery",
    detail: "A bounded public fault is accepted without its required recovery action.",
    kind: "recovery absent",
    slot: "2",
  },
  5: {
    seal: "CEX",
    title: "Transition relation is partial",
    detail: "At least one public input has no release transition, so bounded verification cannot proceed.",
    kind: "partial transition",
    slot: "0",
  },
};

const DEFAULT_SPEC = `# Deliberately violating Studio example
contract pulse_notice {
  horizon 4
  observer network sees [presence, slot, payload]
  release cadence private
  action notify unauthorized
  deadline missed
  recovery absent
  transition total
}`;

const REQUIRED_CLAUSES = [
  "horizon ",
  "observer ",
  "release cadence ",
  "action ",
  "deadline ",
  "recovery ",
  "transition ",
] as const;

const LINE_RULES = [
  /^#.*$/,
  /^contract [a-z][a-z0-9_]* \{$/,
  /^horizon [1-8]$/,
  /^observer [a-z][a-z0-9_]* sees \[(presence|slot|payload)(, (presence|slot|payload))*\]$/,
  /^release cadence (private|fixed)$/,
  /^action [a-z][a-z0-9_]* (authorized|unauthorized)$/,
  /^deadline (met|missed)$/,
  /^recovery (present|absent)$/,
  /^transition (total|partial)$/,
  /^\}$/,
] as const;

let wasm: QuotientForgeExports | null = null;
let repairedSpec = "";
let repairedFlags = 0;
let certificateExpected = 0;
let certificateTampered = false;
let selectedFrontier = 0;

function element<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) {
    throw new Error(`Missing Studio element: ${id}`);
  }
  return node as T;
}

monaco.languages.register({ id: "quotient-forge" });
monaco.languages.setMonarchTokensProvider("quotient-forge", {
  tokenizer: {
    root: [
      [/#.*$/, "comment"],
      [/\b(contract|horizon|observer|sees|release|cadence|action|deadline|recovery|transition)\b/, "keyword"],
      [/\b(private|unauthorized|missed|absent|partial)\b/, "invalid"],
      [/\b(fixed|authorized|met|present|total)\b/, "valid"],
      [/\b[0-9]+\b/, "number"],
      [/[{}\[\],]/, "delimiter"],
      [/[a-z_][a-z0-9_]*/, "identifier"],
    ],
  },
});
monaco.editor.defineTheme("quotient-forge-paper", {
  base: "vs-dark",
  inherit: true,
  rules: [
    { token: "comment", foreground: "7F93A3", fontStyle: "italic" },
    { token: "keyword", foreground: "70C4D3", fontStyle: "bold" },
    { token: "invalid", foreground: "FF765F" },
    { token: "valid", foreground: "8FD4A9" },
    { token: "number", foreground: "F3CC75" },
    { token: "identifier", foreground: "E9EEE9" },
  ],
  colors: {
    "editor.background": "#101923",
    "editor.foreground": "#E9EEE9",
    "editorLineNumber.foreground": "#587080",
    "editorLineNumber.activeForeground": "#F3CC75",
    "editorCursor.foreground": "#FF765F",
    "editor.selectionBackground": "#24527499",
    "editorError.foreground": "#FF765F",
  },
});

const editor = monaco.editor.create(element<HTMLDivElement>("editor"), {
  value: DEFAULT_SPEC,
  language: "quotient-forge",
  theme: "quotient-forge-paper",
  automaticLayout: true,
  fontFamily: '"Cascadia Code", "IBM Plex Mono", monospace',
  fontSize: 13,
  lineHeight: 22,
  minimap: { enabled: false },
  padding: { top: 18, bottom: 18 },
  renderLineHighlight: "gutter",
  roundedSelection: false,
  scrollBeyondLastLine: false,
  tabSize: 2,
  wordWrap: "on",
});

function syntaxMarkers(source: string): monaco.editor.IMarkerData[] {
  const lines = source.split("\n");
  const markers: monaco.editor.IMarkerData[] = [];
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed || LINE_RULES.some((rule) => rule.test(trimmed))) {
      return;
    }
    markers.push({
      severity: monaco.MarkerSeverity.Error,
      message: "Unknown QuotientForge small-model clause",
      startLineNumber: index + 1,
      startColumn: Math.max(1, line.indexOf(trimmed) + 1),
      endLineNumber: index + 1,
      endColumn: Math.max(2, line.length + 1),
    });
  });

  if (!lines.some((line) => /^contract [a-z][a-z0-9_]* \{$/.test(line.trim()))) {
    markers.push(missingClauseMarker(lines, "contract <name> {"));
  }
  if (!lines.some((line) => line.trim() === "}")) {
    markers.push(missingClauseMarker(lines, "closing }"));
  }
  for (const clause of REQUIRED_CLAUSES) {
    if (!lines.some((line) => line.trim().startsWith(clause))) {
      markers.push(missingClauseMarker(lines, clause.trim()));
    }
  }
  return markers;
}

function missingClauseMarker(lines: string[], clause: string): monaco.editor.IMarkerData {
  const lineNumber = Math.max(1, lines.length);
  const line = lines[lineNumber - 1] ?? "";
  return {
    severity: monaco.MarkerSeverity.Error,
    message: `Missing required clause: ${clause}`,
    startLineNumber: lineNumber,
    startColumn: 1,
    endLineNumber: lineNumber,
    endColumn: Math.max(2, line.length + 1),
  };
}

function updateSyntaxDiagnostics(): monaco.editor.IMarkerData[] {
  const model = editor.getModel();
  const markers = syntaxMarkers(editor.getValue());
  if (model) {
    monaco.editor.setModelMarkers(model, "quotient-forge-studio", markers);
  }
  element("syntax-count").textContent = `${markers.length} ${markers.length === 1 ? "error" : "errors"}`;
  return markers;
}

function compileFlags(source: string): number {
  let flags = 0;
  if (/release cadence private/.test(source)) flags |= FLAGS.visiblePrivate;
  if (/release cadence fixed/.test(source)) flags |= FLAGS.fixedCadence;
  if (/action [a-z][a-z0-9_]* authorized/.test(source)) flags |= FLAGS.authorizedAction;
  if (/deadline met/.test(source)) flags |= FLAGS.deadlineMet;
  if (/recovery present/.test(source)) flags |= FLAGS.recoveryPresent;
  if (/transition total/.test(source)) flags |= FLAGS.transitionsTotal;
  return flags;
}

function horizon(source: string): number {
  return Number.parseInt(source.match(/horizon ([1-8])/)?.[1] ?? "1", 10);
}

function renderVerdict(code: number): void {
  const copy = VERDICTS[code] ?? VERDICTS[5];
  const valid = code === 0;
  const seal = element("verdict-seal");
  seal.textContent = copy.seal;
  seal.className = `verdict-seal ${valid ? "valid" : "invalid"}`;
  element("verdict-title").textContent = copy.title;
  element("verdict-detail").textContent = copy.detail;
  element("witness-kind").textContent = copy.kind;
  element("witness-kind").className = `tag ${valid ? "valid" : "danger"}`;
  element("causal-slot").textContent = copy.slot;
  element("pair-count").textContent = String(horizon(editor.getValue()) * 6);
  renderGraph(code);
}

function renderSyntaxError(): void {
  const seal = element("verdict-seal");
  seal.textContent = "PARSE";
  seal.className = "verdict-seal invalid";
  element("verdict-title").textContent = "Specification has syntax errors";
  element("verdict-detail").textContent =
    "Fix the underlined clauses before the Rust small-model checker receives a model.";
  element("witness-kind").textContent = "syntax diagnostic";
  element("witness-kind").className = "tag danger";
  element("counterexample-graph").innerHTML =
    '<div class="graph-empty">No semantic witness is emitted for an invalid syntax tree.</div>';
}

function renderGraph(code: number): void {
  const graph = element("counterexample-graph");
  if (code === 0) {
    graph.innerHTML = `
      <div class="trace-pair">
        <div class="trace-world"><strong>World L</strong><span>action: notify</span><code>trace = [fixed, fixed]</code></div>
        <div class="trace-edge"></div>
        <div class="trace-world"><strong>World R</strong><span>action: notify</span><code>trace = [fixed, fixed]</code></div>
        <div class="causal-callout" style="background:#247957">Observer projections remain equal through the bound.</div>
      </div>`;
    return;
  }
  const leftTrace = code === 1 ? "trace = [emit@0, idle]" : "trace = [public input, action]";
  const rightTrace = code === 1 ? "trace = [idle, emit@1]" : "trace = [public input, violation]";
  graph.innerHTML = `
    <div class="trace-pair">
      <div class="trace-world"><strong>World L</strong><span>same allowed action</span><code>${leftTrace}</code></div>
      <div class="trace-edge"></div>
      <div class="trace-world"><strong>World R</strong><span>same allowed action</span><code>${rightTrace}</code></div>
      <div class="causal-callout">First causal difference: ${VERDICTS[code]?.kind ?? "model violation"}</div>
    </div>`;
}

function repairSource(source: string): string {
  return source
    .replace(/release cadence (private|fixed)/, "release cadence fixed")
    .replace(/action ([a-z][a-z0-9_]*) (authorized|unauthorized)/, "action $1 authorized")
    .replace(/deadline (met|missed)/, "deadline met")
    .replace(/recovery (present|absent)/, "recovery present")
    .replace(/transition (total|partial)/, "transition total");
}

function runCheck(): void {
  if (!wasm) return;
  if (updateSyntaxDiagnostics().length > 0) {
    renderSyntaxError();
    return;
  }
  const flags = compileFlags(editor.getValue());
  renderVerdict(wasm.qf_check(flags));
  element<HTMLButtonElement>("synthesize-repair").disabled = false;
}

function synthesizeRepair(): void {
  if (!wasm || updateSyntaxDiagnostics().length > 0) return;
  const source = editor.getValue();
  const sourceFlags = compileFlags(source);
  repairedFlags = wasm.qf_repair(sourceFlags);
  repairedSpec = repairSource(source);
  element("before-code").textContent = source;
  element("after-code").textContent = repairedSpec;
  renderFrontier();
  renderRustPreview(selectedFrontier);
  issueCertificate();
}

function renderFrontier(): void {
  if (!wasm) return;
  document.querySelectorAll<HTMLButtonElement>("[data-frontier]").forEach((card) => {
    const index = Number.parseInt(card.dataset.frontier ?? "0", 10);
    const cost = card.querySelector<HTMLElement>("[data-cost]");
    if (cost) cost.textContent = String(wasm?.qf_frontier_cost(index) ?? "--");
    card.classList.toggle("selected", index === selectedFrontier);
  });
}

function renderRustPreview(frontierIndex: number): void {
  if (!wasm || !repairedSpec) return;
  const cost = wasm.qf_frontier_cost(frontierIndex);
  const width = [32, 48, 64][frontierIndex] ?? 32;
  const states = [2, 2, 1][frontierIndex] ?? 2;
  element("rust-preview").textContent = `#![no_std]

pub const STATE_COUNT: usize = ${states};
pub const FRAME_BYTES: usize = ${width};
pub const CERTIFIED_COST: u32 = ${cost};

#[derive(Clone, Copy)]
pub struct ReleasePlan {
    pub next_state: u8,
    pub emit_fixed_frame: bool,
    pub authorized_action: Option<u8>,
}

pub const PLAN: [ReleasePlan; STATE_COUNT] = [
    ReleasePlan {
        next_state: ${states > 1 ? 1 : 0},
        emit_fixed_frame: true,
        authorized_action: None,
    },${states > 1 ? `
    ReleasePlan {
        next_state: 1,
        emit_fixed_frame: true,
        authorized_action: Some(1),
    },` : ""}
];

// Preview only. Native CAQT verification gates real codegen.`;
}

function fnv1a(value: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function issueCertificate(): void {
  if (!wasm || !repairedSpec) return;
  certificateExpected = fnv1a(`${repairedSpec}\nflags=${repairedFlags}\ncost=${wasm.qf_cost(repairedFlags)}`);
  certificateTampered = false;
  element<HTMLButtonElement>("tamper-certificate").disabled = false;
  renderCertificate();
}

function renderCertificate(): void {
  if (!wasm || certificateExpected === 0) return;
  const actual = certificateTampered ? certificateExpected ^ 1 : certificateExpected;
  const accepted = wasm.qf_verify_certificate(actual, certificateExpected) === 1;
  element("certificate-digest").textContent = actual.toString(16).padStart(8, "0").toUpperCase();
  const status = element("certificate-status");
  status.textContent = accepted ? "accepted" : "rejected / tampered";
  status.className = `tag ${accepted ? "valid" : "danger"}`;
  element<HTMLButtonElement>("tamper-certificate").textContent = certificateTampered
    ? "Restore certificate"
    : "Tamper one bit";
  element("tamper-note").textContent = accepted
    ? "The Studio checksum matches. Independent native CAQT verification is still required."
    : "Rust WASM rejected the modified value before a generated plan could be trusted.";
}

async function loadWasm(): Promise<QuotientForgeExports> {
  const base = import.meta.env.BASE_URL.endsWith("/")
    ? import.meta.env.BASE_URL
    : `${import.meta.env.BASE_URL}/`;
  const response = await fetch(`${base}wasm/quotient_forge_studio_wasm.wasm`);
  if (!response.ok) {
    throw new Error(`WASM fetch failed: ${response.status}`);
  }
  const bytes = await response.arrayBuffer();
  const result = await WebAssembly.instantiate(bytes, {});
  const exports = result.instance.exports as QuotientForgeExports;
  for (const name of [
    "qf_version",
    "qf_check",
    "qf_repair",
    "qf_cost",
    "qf_frontier_cost",
    "qf_verify_certificate",
  ] as const) {
    if (typeof exports[name] !== "function") {
      throw new Error(`WASM export missing: ${name}`);
    }
  }
  return exports;
}

function clearDerivedState(): void {
  repairedSpec = "";
  repairedFlags = 0;
  certificateExpected = 0;
  certificateTampered = false;
  element("before-code").textContent = "No witness selected.";
  element("after-code").textContent = "No repair synthesized.";
  element("rust-preview").textContent = "// Synthesize a repair to preview generated Rust.";
  element("certificate-digest").textContent = "--------";
  element("certificate-status").textContent = "not issued";
  element("certificate-status").className = "tag neutral";
  element<HTMLButtonElement>("tamper-certificate").disabled = true;
  document.querySelectorAll("[data-cost]").forEach((node) => {
    node.textContent = "--";
  });
}

editor.onDidChangeModelContent(() => {
  updateSyntaxDiagnostics();
  clearDerivedState();
});

element<HTMLButtonElement>("run-check").addEventListener("click", runCheck);
element<HTMLButtonElement>("synthesize-repair").addEventListener("click", synthesizeRepair);
element<HTMLButtonElement>("reset-spec").addEventListener("click", () => {
  editor.setValue(DEFAULT_SPEC);
  runCheck();
});
element<HTMLButtonElement>("tamper-certificate").addEventListener("click", () => {
  certificateTampered = !certificateTampered;
  renderCertificate();
});
document.querySelectorAll<HTMLButtonElement>("[data-frontier]").forEach((card) => {
  card.addEventListener("click", () => {
    selectedFrontier = Number.parseInt(card.dataset.frontier ?? "0", 10);
    renderFrontier();
    renderRustPreview(selectedFrontier);
  });
});

updateSyntaxDiagnostics();
loadWasm()
  .then((exports) => {
    wasm = exports;
    element("wasm-status").textContent = "rust wasm ready";
    element("wasm-status").classList.remove("loading");
    element("kernel-version").textContent = `v${wasm.qf_version()}`;
    element<HTMLButtonElement>("run-check").disabled = false;
    element<HTMLButtonElement>("synthesize-repair").disabled = false;
    runCheck();
  })
  .catch((error: unknown) => {
    element("wasm-status").textContent = "wasm unavailable";
    element("wasm-status").classList.remove("loading");
    element("verdict-title").textContent = "Rust WASM kernel failed to load";
    element("verdict-detail").textContent =
      error instanceof Error ? error.message : "Unknown WebAssembly load failure";
  });
