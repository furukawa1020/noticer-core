import {
  REPAIR_FIXTURES,
  createRepairComparison,
  type RepairComparison,
  type RepairFixtureId,
  type TriStateVerdict,
} from "./repair-revalidation";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function shortDigest(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-7)}`;
}

function triState(value: TriStateVerdict | boolean | null): string {
  if (value === true) return "VALID";
  if (value === false) return "INVALID";
  if (value === null) return "INCONCLUSIVE";
  return value;
}

class QuotientPadRevalidation extends HTMLElement {
  private fixtureId: RepairFixtureId = "FUEL_PAD_PASS";
  private comparison: RepairComparison = createRepairComparison(this.fixtureId);
  private phase: "BEFORE" | "AFTER" = "AFTER";
  private initialized = false;

  connectedCallback(): void {
    if (this.initialized) return;
    this.initialized = true;
    this.addEventListener("click", this.handleClick);
    this.render();
  }

  private readonly handleClick = (event: Event): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest<HTMLButtonElement>("button");
    if (!button) return;
    const fixtureId = button.dataset.fixture as RepairFixtureId | undefined;
    if (fixtureId) {
      if (!REPAIR_FIXTURES.some((fixture) => fixture.id === fixtureId)) return;
      this.fixtureId = fixtureId;
      this.comparison = createRepairComparison(this.fixtureId);
      this.phase = "AFTER";
      this.render();
      return;
    }
    const phase = button.dataset.phase as "BEFORE" | "AFTER" | undefined;
    if (phase) {
      this.phase = phase;
      this.render();
      return;
    }
    if (button.dataset.command === "revalidate") {
      this.comparison = createRepairComparison(this.fixtureId);
      this.phase = "AFTER";
      this.render();
      return;
    }
    if (button.dataset.command === "open-attack") {
      document.querySelector("#adversarial-lab")?.scrollIntoView({
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
          ? "auto"
          : "smooth",
        block: "start",
      });
    }
  };

  private render(): void {
    const result = this.comparison;
    const performance = result.performance;
    const ratio = performance.observedRatioMillionths;
    const securityClass = result.security.verdict.toLowerCase();
    const performanceClass = performance.verdict.toLowerCase();
    this.innerHTML = `
      <style>
        quotient-pad-revalidation { display: block; color: #171b1a; }
        .qpr-shell { overflow: hidden; border: 1px solid rgba(27,31,30,.17); border-radius: 28px; background: linear-gradient(135deg, #f6f0df 0%, #fffdf7 42%, #e8f1ed 100%); box-shadow: 0 30px 85px rgba(28,46,39,.13); }
        .qpr-top { padding: 1.35rem 1.5rem; color: #f8f5e9; background: radial-gradient(circle at 82% -10%, rgba(244,178,62,.38), transparent 34%), #172f28; }
        .qpr-topline { display: flex; justify-content: space-between; align-items: start; gap: 1rem; }
        .qpr-kicker { margin: 0 0 .35rem; color: #f3b34c; font: 700 .7rem/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .14em; text-transform: uppercase; }
        .qpr-top h3 { margin: 0; font: 650 clamp(1.4rem, 3vw, 2.3rem)/1 Georgia, "Times New Roman", serif; letter-spacing: -.04em; }
        .qpr-topnote { max-width: 26rem; margin: 0; color: #bdd0c8; font-size: .78rem; line-height: 1.55; }
        .qpr-fixtures { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: .55rem; margin-top: 1rem; }
        .qpr-fixture { min-height: 5.5rem; padding: .65rem .7rem; border: 1px solid rgba(255,255,255,.18); border-radius: 14px; color: #e7eee9; background: rgba(255,255,255,.055); text-align: left; cursor: pointer; }
        .qpr-fixture:hover, .qpr-fixture:focus-visible { border-color: #f3b34c; outline: none; }
        .qpr-fixture[aria-pressed="true"] { color: #172f28; border-color: #f3b34c; background: #f3b34c; }
        .qpr-fixture strong, .qpr-fixture span { display: block; }
        .qpr-fixture strong { font-size: .73rem; }
        .qpr-fixture span { margin-top: .3rem; opacity: .78; font-size: .64rem; line-height: 1.35; }
        .qpr-body { padding: 1.25rem 1.5rem 1.5rem; }
        .qpr-pipeline { display: grid; grid-template-columns: 1fr auto 1.25fr auto 1fr; gap: .55rem; align-items: stretch; }
        .qpr-stage { display: grid; align-content: center; min-height: 6.8rem; padding: .85rem; border: 1px solid rgba(23,47,40,.14); border-radius: 17px; background: rgba(255,255,255,.75); }
        .qpr-stage small, .qpr-stage strong, .qpr-stage code { display: block; }
        .qpr-stage small { color: #6c7773; font: 650 .6rem/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .08em; text-transform: uppercase; }
        .qpr-stage strong { margin: .35rem 0; font: 900 1rem/1.1 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .qpr-stage code { color: #8e5722; font-size: .65rem; overflow-wrap: anywhere; }
        .qpr-stage.invalid { border-left: 6px solid #b13a27; }
        .qpr-stage.valid { border-left: 6px solid #247254; }
        .qpr-stage.inconclusive { border-left: 6px solid #d69b28; }
        .qpr-stage.candidate { color: #f8f5e9; border-color: #173e31; background: #173e31; }
        .qpr-stage.candidate small { color: #9ec4b5; }
        .qpr-stage.candidate code { color: #f3b34c; }
        .qpr-flow { align-self: center; color: #d0642a; font: 900 1.15rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .qpr-grid { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(18rem, .85fr); gap: 1rem; margin-top: 1rem; }
        .qpr-panel { padding: 1rem; border: 1px solid rgba(23,47,40,.14); border-radius: 20px; background: rgba(255,255,255,.72); }
        .qpr-panel-head { display: flex; justify-content: space-between; align-items: center; gap: .75rem; margin-bottom: .7rem; }
        .qpr-panel h4 { margin: 0; font: 800 .72rem/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .1em; text-transform: uppercase; }
        .qpr-switch { display: flex; padding: .2rem; border-radius: 999px; background: #e6ece8; }
        .qpr-switch button { border: 0; border-radius: 999px; padding: .35rem .55rem; color: #68766f; background: transparent; font: 700 .61rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; cursor: pointer; }
        .qpr-switch button[aria-pressed="true"] { color: white; background: #274d40; }
        .qpr-trace { width: 100%; border-collapse: separate; border-spacing: 0 .35rem; font: .67rem/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .qpr-trace th { padding: .3rem .45rem; color: #718079; text-align: right; font-size: .58rem; text-transform: uppercase; }
        .qpr-trace th:first-child { text-align: left; }
        .qpr-trace td { padding: .55rem .45rem; background: rgba(23,62,49,.055); text-align: right; }
        .qpr-trace td:first-child { border-radius: 10px 0 0 10px; text-align: left; font-weight: 750; }
        .qpr-trace td:last-child { border-radius: 0 10px 10px 0; }
        .qpr-trace tr.diverged td { color: #8d321e; background: rgba(187,65,39,.11); }
        .qpr-trace tr.repaired td { color: #236549; background: rgba(42,127,91,.11); }
        .qpr-eq { display: inline-grid; place-items: center; width: 1.35rem; aspect-ratio: 1; border-radius: 50%; color: white; background: #247254; font-weight: 900; }
        .qpr-eq.no { background: #b13a27; }
        .qpr-eq.unknown { color: #2a291d; background: #e8ad36; border-radius: 4px; }
        .qpr-operation { display: grid; grid-template-columns: auto 1fr; gap: .7rem; align-items: center; padding: .75rem; border-radius: 14px; color: white; background: #24483d; }
        .qpr-op-mark { display: grid; place-items: center; width: 3rem; aspect-ratio: 1; border: 1px solid #f3b34c; border-radius: 50%; color: #f3b34c; font: 900 .8rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .qpr-operation strong, .qpr-operation code { display: block; }
        .qpr-operation strong { font-size: .78rem; }
        .qpr-operation code { margin-top: .25rem; color: #b8d0c6; font-size: .63rem; }
        .qpr-overhead { display: grid; grid-template-columns: repeat(2, 1fr); gap: .45rem; margin-top: .65rem; }
        .qpr-overhead div { padding: .55rem; border-radius: 11px; background: #eef2ed; }
        .qpr-overhead span, .qpr-overhead strong { display: block; }
        .qpr-overhead span { color: #718079; font-size: .58rem; text-transform: uppercase; }
        .qpr-overhead strong { margin-top: .18rem; font: 800 .75rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .qpr-gates { display: grid; grid-template-columns: repeat(5, 1fr); gap: .4rem; margin-top: .65rem; }
        .qpr-gate { padding: .55rem .35rem; border: 1px solid rgba(23,47,40,.12); border-radius: 10px; text-align: center; }
        .qpr-gate span, .qpr-gate strong { display: block; }
        .qpr-gate span { color: #718079; font-size: .52rem; text-transform: uppercase; }
        .qpr-gate strong { margin-top: .2rem; font: 800 .58rem/1.1 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .qpr-performance { margin-top: 1rem; padding: .85rem 1rem; border: 2px dashed rgba(23,47,40,.24); border-radius: 18px; background: rgba(255,255,255,.62); }
        .qpr-perf-head { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
        .qpr-perf-head h4 { margin: 0; font: 800 .72rem/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .08em; text-transform: uppercase; }
        .qpr-perf-verdict { padding: .35rem .55rem; border-radius: 7px; color: white; background: #247254; font: 900 .68rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .qpr-perf-verdict.fail { background: #b13a27; }
        .qpr-perf-verdict.inconclusive { color: #2a291d; background: #e8ad36; }
        .qpr-meter { position: relative; height: .7rem; margin: .75rem 0 .45rem; border-radius: 999px; background: #dce4df; }
        .qpr-meter::before { content: ""; position: absolute; inset: 0 auto 0 0; width: min(var(--ratio), 100%); border-radius: inherit; background: linear-gradient(90deg, #2c7b59, #e2a632 72%, #b13a27); }
        .qpr-limit { position: absolute; top: -.3rem; bottom: -.3rem; left: 83.33%; width: 2px; background: #172f28; }
        .qpr-perf-meta { display: flex; flex-wrap: wrap; justify-content: space-between; gap: .5rem; color: #627169; font: .62rem/1.35 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .qpr-warning { display: inline-block; margin-top: .55rem; padding: .35rem .5rem; border: 1px solid #b13a27; color: #8b2e1f; background: #fff4ef; font: 900 .62rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .05em; }
        .qpr-artifacts { display: flex; gap: .32rem; overflow-x: auto; margin-top: 1rem; padding: .55rem; border-radius: 14px; background: #172f28; }
        .qpr-artifact { flex: 0 0 auto; padding: .4rem .48rem; border: 1px solid rgba(255,255,255,.13); border-radius: 8px; color: #d7e5df; font: .54rem/1.35 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .qpr-artifact b { color: #f3b34c; font-weight: 700; }
        .qpr-arrow { align-self: center; color: #f3b34c; }
        .qpr-actions { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .8rem; }
        .qpr-actions button { border: 1px solid #274d40; border-radius: 999px; padding: .48rem .7rem; color: #274d40; background: transparent; font: 750 .65rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; cursor: pointer; }
        .qpr-actions button:first-child { color: white; background: #274d40; }
        .qpr-actions button:hover, .qpr-actions button:focus-visible { border-color: #d0642a; outline: 2px solid rgba(208,100,42,.16); outline-offset: 2px; }
        .qpr-boundary { margin: .75rem 0 0; color: #65736d; font: .6rem/1.5 ui-monospace, SFMono-Regular, Consolas, monospace; }
        @media (max-width: 940px) { .qpr-fixtures { grid-template-columns: 1fr 1fr; } .qpr-grid { grid-template-columns: 1fr; } }
        @media (max-width: 680px) { .qpr-topline { display: block; } .qpr-topnote { margin-top: .6rem; } .qpr-pipeline { grid-template-columns: 1fr; } .qpr-flow { justify-self: center; transform: rotate(90deg); } .qpr-gates { grid-template-columns: 1fr 1fr; } }
        @media (max-width: 520px) { .qpr-top, .qpr-body { padding-left: 1rem; padding-right: 1rem; } .qpr-fixtures { grid-template-columns: 1fr; } .qpr-overhead { grid-template-columns: 1fr; } .qpr-trace { font-size: .58rem; } }
      </style>
      <div class="qpr-shell">
        <header class="qpr-top">
          <div class="qpr-topline">
            <div><p class="qpr-kicker">K8-17e · repair is a hypothesis</p><h3>QuotientPad Revalidation Bay</h3></div>
            <p class="qpr-topnote">修復候補は自動的に安全になりません。relation、context、resource、utility、deadlineを再検証し、performance gateは別の判定として保持します。</p>
          </div>
          <nav class="qpr-fixtures" aria-label="修復fixture">
            ${REPAIR_FIXTURES.map(
              (fixture) => `<button class="qpr-fixture" type="button" data-fixture="${fixture.id}" aria-pressed="${fixture.id === this.fixtureId}"><strong>${escapeHtml(fixture.title)}</strong><span>${escapeHtml(fixture.summary)}</span></button>`,
            ).join("")}
          </nav>
        </header>
        <div class="qpr-body">
          <div class="qpr-pipeline" aria-label="attack to revalidation pipeline">
            <div class="qpr-stage invalid"><small>01 attack evidence</small><strong>INVALID ×</strong><code>RESOURCE_ONLY_LEAK</code></div>
            <span class="qpr-flow">→</span>
            <div class="qpr-stage candidate"><small>02 repair candidate</small><strong>QPAD v${result.candidate.version}</strong><code>${escapeHtml(result.candidate.operations[0]?.kind ?? "NONE")}</code></div>
            <span class="qpr-flow">→</span>
            <div class="qpr-stage ${securityClass}"><small>03 security revalidation</small><strong>${result.security.verdict} ${result.security.verdict === "VALID" ? "✓" : result.security.verdict === "INVALID" ? "×" : "?"}</strong><code>${escapeHtml(result.security.reason)}</code></div>
          </div>
          <div class="qpr-grid">
            <section class="qpr-panel">
              <div class="qpr-panel-head"><h4>Resource trace diff</h4><div class="qpr-switch"><button type="button" data-phase="BEFORE" aria-pressed="${this.phase === "BEFORE"}">BEFORE</button><button type="button" data-phase="AFTER" aria-pressed="${this.phase === "AFTER"}">AFTER</button></div></div>
              <table class="qpr-trace"><thead><tr><th>axis</th><th>left</th><th>right</th><th>relation</th></tr></thead><tbody>
                ${result.trace
                  .map((point) => {
                    const after = this.phase === "AFTER";
                    const left = after ? point.leftAfter : point.leftBefore;
                    const right = after ? point.rightAfter : point.rightBefore;
                    const equal = after ? point.afterEqual : point.beforeEqual;
                    const rowClass = equal === false ? "diverged" : after && equal ? "repaired" : "";
                    return `<tr class="${rowClass}"><td>${point.axis}</td><td>${left ?? "?"}</td><td>${right ?? "?"}</td><td><span class="qpr-eq ${equal === false ? "no" : equal === null ? "unknown" : ""}">${equal === true ? "=" : equal === false ? "≠" : "?"}</span></td></tr>`;
                  })
                  .join("")}
              </tbody></table>
            </section>
            <section class="qpr-panel">
              <div class="qpr-panel-head"><h4>Candidate & gates</h4><code>${shortDigest(result.candidate.sha256)}</code></div>
              <div class="qpr-operation"><span class="qpr-op-mark">+${result.candidate.operations[0]?.amount ?? 0}</span><div><strong>${result.candidate.operations[0]?.axis} · ${result.candidate.operations[0]?.side}</strong><code>${result.candidate.operations[0]?.kind} @ event ${result.candidate.operations[0]?.eventIndex}</code></div></div>
              <div class="qpr-overhead">
                <div><span>operations</span><strong>${result.candidate.overhead.operationCount}</strong></div><div><span>added instructions</span><strong>${result.candidate.overhead.addedInstructions}</strong></div><div><span>added fuel</span><strong>${result.candidate.overhead.addedFuel}</strong></div><div><span>scratch bytes</span><strong>${result.candidate.overhead.fixedScratchBytes}</strong></div>
              </div>
              <div class="qpr-gates">
                <div class="qpr-gate"><span>relation</span><strong>${result.security.relation}</strong></div><div class="qpr-gate"><span>context</span><strong>${result.security.context}</strong></div><div class="qpr-gate"><span>resource</span><strong>${result.security.resource}</strong></div><div class="qpr-gate"><span>utility</span><strong>${triState(result.security.utilityPreserved)}</strong></div><div class="qpr-gate"><span>deadline</span><strong>${triState(result.security.deadlinesPreserved)}</strong></div>
              </div>
            </section>
          </div>
          <section class="qpr-performance" aria-label="独立したperformance gate">
            <div class="qpr-perf-head"><h4>Independent performance budget gate</h4><span class="qpr-perf-verdict ${performanceClass}">${performance.verdict}</span></div>
            <div class="qpr-meter" style="--ratio: ${ratio === null ? 0 : Math.min(100, ratio / 15_000)}%"><span class="qpr-limit" title="125% limit"></span></div>
            <div class="qpr-perf-meta"><span>P95 baseline ${performance.baselineValue.toLocaleString()} ns</span><span>candidate ${performance.candidateValue?.toLocaleString() ?? "INSUFFICIENT"} ns</span><span>ratio ${ratio === null ? "N/A" : `${(ratio / 10_000).toFixed(1)}%`} / limit 125.0%</span><span>samples ${performance.baselineSamples}/${performance.candidateSamples}</span></div>
            <strong class="qpr-warning">NOT_A_SECURITY_VERDICT</strong>
          </section>
          <div class="qpr-artifacts" aria-label="repair artifact chain">
            ${result.artifacts
              .map((artifact, index) => `${index > 0 ? '<span class="qpr-arrow">→</span>' : ""}<span class="qpr-artifact"><b>${artifact.role}</b><br>${shortDigest(artifact.sha256)}</span>`)
              .join("")}
          </div>
          <div class="qpr-actions"><button type="button" data-command="revalidate">候補を再検証</button><button type="button" data-command="open-attack">元の攻撃反例へ戻る</button></div>
          <p class="qpr-boundary">${result.evidenceOrigin} · Polar Verity Sense ${result.hardwareStatus} · ${result.security.securityInterpretation} · performance ${performance.securityInterpretation}</p>
        </div>
      </div>`;
  }
}

if (!customElements.get("quotient-pad-revalidation")) {
  customElements.define("quotient-pad-revalidation", QuotientPadRevalidation);
}

