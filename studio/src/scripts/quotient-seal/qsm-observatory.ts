import { auditQsmCapsule, buildQsmAuditFixture, tamperQsmSection, type QsmAuditResult } from "./qsm";

let sourceBytes = new Uint8Array();
let currentAudit: QsmAuditResult | null = null;

function node<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing QSM Observatory element: ${id}`);
  return value as T;
}

async function inspect(bytes: Uint8Array): Promise<void> {
  sourceBytes = bytes.slice();
  currentAudit = await auditQsmCapsule(sourceBytes);
  render(currentAudit);
}

function render(audit: QsmAuditResult): void {
  const verdict = node("qsm-verdict");
  verdict.textContent = audit.verdict;
  verdict.className = `qsm-verdict ${audit.verdict.toLowerCase()}`;
  node("qsm-reason").textContent = audit.reason;
  node("qsm-format").textContent = audit.formatVersion === null ? "--" : `v${audit.formatVersion}`;
  node("qsm-bytes").textContent = audit.totalBytes.toLocaleString();
  node("qsm-digest").textContent = audit.capsuleDigest?.slice(0, 16) ?? "not computed";
  const sectionMap = node("qsm-section-map");
  sectionMap.replaceChildren();
  audit.sections.forEach((section, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `qsm-section ${section.digestMatches ? "match" : "mismatch"}`;
    button.setAttribute("aria-pressed", String(index === audit.focusSectionIndex));
    const ordinal = document.createElement("span");
    ordinal.textContent = String(section.tag).padStart(2, "0");
    const copy = document.createElement("span");
    const strong = document.createElement("strong");
    strong.textContent = section.name;
    const small = document.createElement("small");
    small.textContent = `${section.length.toLocaleString()} bytes / ${section.digestMatches ? "digest match" : "DIGEST MISMATCH"}`;
    copy.append(strong, small);
    const status = document.createElement("b");
    status.textContent = section.digestMatches ? "OK" : "!";
    status.setAttribute("aria-label", section.digestMatches ? "digest matches" : "digest mismatch");
    button.append(ordinal, copy, status);
    button.addEventListener("click", () => renderSection(index));
    sectionMap.append(button);
  });
  renderSection(audit.focusSectionIndex ?? 0);
  renderAbi(audit);
  node<HTMLButtonElement>("qsm-tamper").disabled = audit.sections.length < 2;
}

function renderSection(index: number): void {
  if (!currentAudit) return;
  const section = currentAudit.sections[index];
  if (!section) {
    node("qsm-section-detail").textContent = "No bounded section detail is available.";
    return;
  }
  document.querySelectorAll<HTMLButtonElement>(".qsm-section").forEach((button, position) => {
    button.setAttribute("aria-pressed", String(position === index));
  });
  node("qsm-section-name").textContent = section.name;
  node("qsm-section-detail").textContent =
    `offset ${section.offset} / ${section.length} bytes / domain-separated SHA-256 ${section.digestMatches ? "matches" : "does not match"}`;
  node("qsm-declared-digest").textContent = section.declaredDigest;
  node("qsm-actual-digest").textContent = section.actualDigest;
  const source = currentAudit.sections[1];
  const wasm = currentAudit.sections[2];
  const abi = currentAudit.sections[3];
  node("qsm-chain-source").textContent = source ? source.declaredDigest.slice(0, 12) : "unavailable";
  node("qsm-chain-wasm").textContent = wasm ? wasm.declaredDigest.slice(0, 12) : "unavailable";
  node("qsm-chain-abi").textContent = abi ? abi.declaredDigest.slice(0, 12) : "unavailable";
}

function renderAbi(audit: QsmAuditResult): void {
  const graph = node("qsm-abi-graph");
  graph.replaceChildren();
  if (!audit.abi) {
    graph.textContent = "ABI graph unavailable until the manifest is structurally valid.";
    return;
  }
  const privateNode = capabilityNode(
    "PRIVATE / TCB ONLY",
    audit.abi.privateCapability,
    audit.abi.privatePolicy,
    "private",
  );
  const imports = capabilityNode(
    "HOST IMPORTS",
    `${audit.abi.hostImports.length} observable calls`,
    audit.abi.hostImports.join(" · "),
    "host",
  );
  const exports = capabilityNode(
    "PUBLIC CONTEXT",
    `${audit.abi.publicExports.length} public exports`,
    audit.abi.publicExports.join(" · "),
    "public",
  );
  graph.append(privateNode, edge("sealed admission"), exports, edge("emits through"), imports);
  node("qsm-abi-profile").textContent = audit.abi.profile;
}

function capabilityNode(label: string, title: string, detail: string, tone: string): HTMLElement {
  const item = document.createElement("div");
  item.className = `abi-node ${tone}`;
  const mark = document.createElement("span");
  mark.textContent = label;
  const strong = document.createElement("strong");
  strong.textContent = title;
  const small = document.createElement("small");
  small.textContent = detail;
  item.append(mark, strong, small);
  return item;
}

function edge(label: string): HTMLElement {
  const item = document.createElement("div");
  item.className = "abi-edge";
  item.textContent = label;
  return item;
}

node<HTMLButtonElement>("qsm-load-fixture").addEventListener("click", async () => {
  await inspect(await buildQsmAuditFixture());
});
node<HTMLButtonElement>("qsm-tamper").addEventListener("click", async () => {
  await inspect(tamperQsmSection(sourceBytes, 1));
});
node<HTMLInputElement>("qsm-file").addEventListener("change", async (event) => {
  const input = event.currentTarget as HTMLInputElement;
  const file = input.files?.[0];
  if (file) await inspect(new Uint8Array(await file.arrayBuffer()));
});

buildQsmAuditFixture().then(inspect).catch(() => {
  node("qsm-reason").textContent = "The deterministic QSM fixture could not be generated.";
});
