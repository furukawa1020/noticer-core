import {
  MAX_SCENARIO_ACTIONS,
  PUBLIC_ACTION_PALETTE,
  SCENARIO_CATALOG,
  replayScenario,
  type PublicActionKind,
  type ScenarioId,
  type ScenarioReplayResult,
} from "./adversarial-lab";

const ACTION_LABELS: Readonly<Record<PublicActionKind, string>> = Object.freeze({
  TICK: "Tick · slot+1",
  RESET: "Reset · epoch+1",
  HANDOFF: "Handoff · service 1",
  MALFORMED: "Malformed · tag 7",
  REPEAT: "Repeat · count 2",
  STALE_SLOT: "Stale slot · delta 1",
  FUTURE_SLOT: "Future slot · delta 2",
  FAULT: "Fault · code 1",
  RECONNECT: "Reconnect · service 0",
  SERVICE_SWITCH: "Service switch · 0→1",
});

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function shortDigest(value: string): string {
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

class AdversarialScenarioLab extends HTMLElement {
  private scenarioId: ScenarioId = "EXTRA_HOST_CALL";
  private actions: PublicActionKind[] = [...SCENARIO_CATALOG[0].defaultActions];
  private result: ScenarioReplayResult = replayScenario(this.scenarioId, this.actions);
  private initialized = false;

  connectedCallback(): void {
    if (this.initialized) return;
    this.initialized = true;
    this.addEventListener("click", this.handleClick);
    window.addEventListener("quotient-seal:demo-scenario", this.handleDemoScenario as EventListener);
    this.render();
  }

  disconnectedCallback(): void {
    window.removeEventListener("quotient-seal:demo-scenario", this.handleDemoScenario as EventListener);
  }

  private readonly handleDemoScenario = (event: CustomEvent<{ scenarioId?: ScenarioId }>): void => {
    const scenario = SCENARIO_CATALOG.find((item) => item.id === event.detail?.scenarioId);
    if (!scenario) return;
    this.scenarioId = scenario.id;
    this.actions = [...scenario.defaultActions];
    this.result = replayScenario(this.scenarioId, this.actions);
    this.render();
  };

  private readonly handleClick = (event: Event): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest<HTMLButtonElement>("button");
    if (!button) return;

    const selectedScenario = button.dataset.scenario as ScenarioId | undefined;
    if (selectedScenario) {
      const scenario = SCENARIO_CATALOG.find((item) => item.id === selectedScenario);
      if (!scenario) return;
      this.scenarioId = scenario.id;
      this.actions = [...scenario.defaultActions];
      this.result = replayScenario(this.scenarioId, this.actions);
      this.render();
      return;
    }

    const paletteAction = button.dataset.palette as PublicActionKind | undefined;
    if (paletteAction && this.actions.length < MAX_SCENARIO_ACTIONS) {
      this.actions = [...this.actions, paletteAction];
      this.result = replayScenario(this.scenarioId, this.actions);
      this.render();
      return;
    }

    const removeIndex = button.dataset.remove;
    if (removeIndex !== undefined && this.actions.length > 1) {
      this.actions = this.actions.filter((_, index) => index !== Number(removeIndex));
      this.result = replayScenario(this.scenarioId, this.actions);
      this.render();
      return;
    }

    if (button.dataset.command === "replay") {
      this.result = replayScenario(this.scenarioId, this.actions);
      this.render();
      return;
    }

    if (button.dataset.command === "minimize") {
      this.actions = [...this.result.minimizedActions];
      this.result = replayScenario(this.scenarioId, this.actions);
      this.render();
      return;
    }

    if (button.dataset.command === "open-trace") {
      window.dispatchEvent(
        new CustomEvent("quotient-seal:open-divergence", {
          detail: {
            scenarioId: this.scenarioId,
            index: this.result.firstDivergenceStep,
          },
        }),
      );
      document.querySelector("#relational-trace")?.scrollIntoView({
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
          ? "auto"
          : "smooth",
        block: "start",
      });
    }
  };

  private render(): void {
    const scenario = SCENARIO_CATALOG.find((item) => item.id === this.scenarioId);
    if (!scenario) return;
    const result = this.result;
    const verdictClass = result.verdict.toLowerCase();
    this.innerHTML = `
      <style>
        adversarial-scenario-lab { display: block; color: #15241f; }
        .asl-shell { position: relative; overflow: hidden; border: 1px solid rgba(21, 36, 31, .16); border-radius: 28px; background: radial-gradient(circle at 82% 4%, rgba(245, 181, 65, .2), transparent 30%), linear-gradient(145deg, #f8f4e8, #edf7ef 54%, #e6f0eb); box-shadow: 0 28px 80px rgba(24, 48, 39, .13); }
        .asl-shell::before { content: ""; position: absolute; inset: 0; pointer-events: none; opacity: .24; background-image: linear-gradient(rgba(20, 58, 46, .09) 1px, transparent 1px), linear-gradient(90deg, rgba(20, 58, 46, .09) 1px, transparent 1px); background-size: 24px 24px; mask-image: linear-gradient(to bottom, black, transparent 82%); }
        .asl-header, .asl-body { position: relative; z-index: 1; }
        .asl-header { display: flex; justify-content: space-between; gap: 1.5rem; align-items: end; padding: 1.4rem 1.5rem 1.1rem; border-bottom: 1px solid rgba(21, 36, 31, .12); }
        .asl-kicker { margin: 0 0 .35rem; color: #9a541d; font: 700 .72rem/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .14em; text-transform: uppercase; }
        .asl-header h3 { margin: 0; font: 650 clamp(1.35rem, 3vw, 2.2rem)/1.02 Georgia, "Times New Roman", serif; letter-spacing: -.035em; }
        .asl-boundary { max-width: 27rem; margin: 0; color: #52665e; font-size: .82rem; line-height: 1.55; }
        .asl-body { padding: 1.25rem 1.5rem 1.5rem; }
        .asl-scenarios { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .65rem; }
        .asl-scenario { min-height: 7rem; padding: .8rem; border: 1px solid rgba(21, 36, 31, .15); border-radius: 16px; color: inherit; background: rgba(255,255,255,.62); text-align: left; cursor: pointer; transition: transform .18s ease, border-color .18s ease, background .18s ease; }
        .asl-scenario:hover, .asl-scenario:focus-visible { transform: translateY(-2px); border-color: #d06a2d; outline: none; }
        .asl-scenario[aria-pressed="true"] { color: #fffaf0; border-color: #173e31; background: #173e31; }
        .asl-scenario strong, .asl-scenario span { display: block; }
        .asl-scenario strong { margin-bottom: .35rem; font-size: .83rem; }
        .asl-scenario span { opacity: .76; font-size: .7rem; line-height: 1.35; }
        .asl-workbench { display: grid; grid-template-columns: minmax(0, 1.08fr) minmax(19rem, .92fr); gap: 1rem; margin-top: 1rem; }
        .asl-panel { padding: 1rem; border: 1px solid rgba(21, 36, 31, .13); border-radius: 20px; background: rgba(255,255,255,.7); backdrop-filter: blur(12px); }
        .asl-panel-head { display: flex; align-items: center; justify-content: space-between; gap: .75rem; margin-bottom: .75rem; }
        .asl-panel h4 { margin: 0; font: 700 .74rem/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .1em; text-transform: uppercase; }
        .asl-count { color: #65766f; font: .7rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .asl-palette { display: flex; flex-wrap: wrap; gap: .4rem; }
        .asl-palette button, .asl-command { border: 1px solid rgba(21, 36, 31, .16); border-radius: 999px; padding: .47rem .65rem; color: #21473a; background: #f9fcf7; font: 650 .68rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; cursor: pointer; }
        .asl-palette button:hover, .asl-palette button:focus-visible, .asl-command:hover, .asl-command:focus-visible { border-color: #c85e26; color: #9b3c14; outline: 2px solid rgba(200, 94, 38, .15); outline-offset: 2px; }
        .asl-palette button:disabled { opacity: .4; cursor: not-allowed; }
        .asl-sequence { display: flex; gap: .35rem; overflow-x: auto; padding: .8rem 0 .35rem; scrollbar-color: #c85e26 transparent; }
        .asl-step { flex: 0 0 auto; display: grid; grid-template-columns: auto auto; gap: .4rem; align-items: center; border: 1px solid rgba(21, 36, 31, .15); border-radius: 12px; padding: .5rem .6rem; color: #203b32; background: #fff; font: .68rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .asl-step b { color: #b24f20; font-weight: 800; }
        .asl-step button { border: 0; padding: 0; color: #76847e; background: transparent; cursor: pointer; font: inherit; }
        .asl-actions { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .85rem; }
        .asl-command.primary { border-color: #173e31; color: white; background: #173e31; }
        .asl-verdict { display: grid; grid-template-columns: auto 1fr; gap: .75rem; align-items: center; padding: .8rem; border-radius: 15px; background: #f5f8f5; }
        .asl-verdict-mark { display: grid; place-items: center; width: 2.7rem; aspect-ratio: 1; border-radius: 50%; color: white; background: #66736e; font: 900 .75rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .asl-verdict.invalid .asl-verdict-mark { background: #b53823; clip-path: polygon(50% 0, 100% 25%, 91% 87%, 50% 100%, 9% 87%, 0 25%); }
        .asl-verdict.inconclusive .asl-verdict-mark { color: #2c2b20; background: #e9ad35; border-radius: 8px; transform: rotate(45deg); }
        .asl-verdict.inconclusive .asl-verdict-mark span { transform: rotate(-45deg); }
        .asl-verdict strong, .asl-verdict small { display: block; }
        .asl-verdict strong { font: 800 1rem/1.15 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .asl-verdict small { margin-top: .25rem; color: #63746d; font-size: .7rem; }
        .asl-meta { display: grid; grid-template-columns: repeat(3, 1fr); gap: .45rem; margin: .75rem 0; }
        .asl-meta div { min-width: 0; padding: .6rem; border-radius: 12px; background: rgba(23,62,49,.06); }
        .asl-meta span, .asl-meta strong { display: block; overflow-wrap: anywhere; }
        .asl-meta span { margin-bottom: .2rem; color: #6b7c74; font: .6rem/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; text-transform: uppercase; }
        .asl-meta strong { font-size: .72rem; }
        .asl-engines { display: grid; grid-template-columns: 1fr 1fr; gap: .5rem; }
        .asl-engine { padding: .65rem; border: 1px solid rgba(21,36,31,.12); border-radius: 12px; background: #fff; }
        .asl-engine code, .asl-engine strong, .asl-engine span { display: block; }
        .asl-engine code { color: #89601b; font-size: .62rem; }
        .asl-engine strong { margin: .3rem 0; font: 800 .7rem/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .asl-engine span { color: #63746d; font-size: .65rem; line-height: 1.4; }
        .asl-artifacts { display: flex; align-items: center; gap: .35rem; overflow-x: auto; margin-top: .75rem; padding-bottom: .2rem; }
        .asl-artifact { flex: 0 0 auto; padding: .45rem .55rem; border-radius: 9px; color: #315247; background: #e6eee9; font: .58rem/1.3 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .asl-arrow { color: #c85e26; }
        .asl-foot { display: flex; flex-wrap: wrap; justify-content: space-between; gap: .5rem; margin-top: .8rem; color: #5f7069; font: .62rem/1.4 ui-monospace, SFMono-Regular, Consolas, monospace; }
        @media (max-width: 920px) { .asl-scenarios { grid-template-columns: 1fr 1fr; } .asl-workbench { grid-template-columns: 1fr; } }
        @media (max-width: 560px) { .asl-header { display: block; } .asl-boundary { margin-top: .65rem; } .asl-body, .asl-header { padding-left: 1rem; padding-right: 1rem; } .asl-scenarios { grid-template-columns: 1fr; } .asl-meta { grid-template-columns: 1fr; } }
        @media (prefers-reduced-motion: reduce) { .asl-scenario { transition: none; } }
      </style>
      <div class="asl-shell">
        <header class="asl-header">
          <div>
            <p class="asl-kicker">K8-17d · fixed-seed counterexample bench</p>
            <h3>Adversarial Scenario Lab</h3>
          </div>
          <p class="asl-boundary">任意コードは実行しません。Rust側と同じpublic action paletteとmutation taxonomyだけを、有界なsoftware fixtureとして再生します。</p>
        </header>
        <div class="asl-body">
          <nav class="asl-scenarios" aria-label="攻撃シナリオ">
            ${SCENARIO_CATALOG.map(
              (item) => `
                <button class="asl-scenario" type="button" data-scenario="${item.id}" aria-pressed="${item.id === this.scenarioId}">
                  <strong>${escapeHtml(item.title)}</strong>
                  <span>${escapeHtml(item.summary)}</span>
                </button>`,
            ).join("")}
          </nav>
          <div class="asl-workbench">
            <section class="asl-panel" aria-label="bounded action editor">
              <div class="asl-panel-head">
                <h4>Bounded public context</h4>
                <span class="asl-count">${this.actions.length} / ${MAX_SCENARIO_ACTIONS}</span>
              </div>
              <div class="asl-palette">
                ${PUBLIC_ACTION_PALETTE.map(
                  (action) => `<button type="button" data-palette="${action}" ${this.actions.length >= MAX_SCENARIO_ACTIONS ? "disabled" : ""}>+ ${escapeHtml(ACTION_LABELS[action])}</button>`,
                ).join("")}
              </div>
              <div class="asl-sequence" aria-label="action sequence">
                ${this.actions
                  .map(
                    (action, index) => `<span class="asl-step"><b>${String(index).padStart(2, "0")}</b>${escapeHtml(action)}<button type="button" data-remove="${index}" aria-label="${escapeHtml(action)}を削除">×</button></span>`,
                  )
                  .join("")}
              </div>
              <div class="asl-actions">
                <button class="asl-command primary" type="button" data-command="replay">2系統でreplay</button>
                <button class="asl-command" type="button" data-command="minimize">1-minimalへ縮約</button>
                <button class="asl-command" type="button" data-command="open-trace">trace microscopeへ</button>
              </div>
              <div class="asl-foot">
                <span>mutation: ${escapeHtml(scenario.mutation)}</span>
                <span>seed: ${scenario.seed}</span>
                <span>evidence: ${result.evidenceOrigin}</span>
              </div>
            </section>
            <section class="asl-panel" aria-label="replay result">
              <div class="asl-verdict ${verdictClass}">
                <div class="asl-verdict-mark"><span>${result.verdict === "INVALID" ? "×" : result.verdict === "VALID" ? "✓" : "?"}</span></div>
                <div><strong>${result.verdict}</strong><small>${escapeHtml(result.reason)} · ${result.replayAgreement ? "REPLAYS AGREE" : "REPLAYS DISAGREE"}</small></div>
              </div>
              <div class="asl-meta">
                <div><span>observer</span><strong>${result.observer}</strong></div>
                <div><span>first divergence</span><strong>${result.firstDivergenceStep ?? "N/A"}</strong></div>
                <div><span>1-minimal</span><strong>${result.oneMinimal ? "YES" : "NO"}</strong></div>
              </div>
              <div class="asl-engines">
                ${result.replays
                  .map(
                    (replay) => `<article class="asl-engine"><code>${replay.engine}</code><strong>${replay.finding}</strong><span>${escapeHtml(replay.sourceEffect)}<br>${escapeHtml(replay.targetEffect)}</span></article>`,
                  )
                  .join("")}
              </div>
              <div class="asl-artifacts" aria-label="artifact digest chain">
                ${result.artifactLinks
                  .map(
                    (artifact, index) => `${index > 0 ? '<span class="asl-arrow">→</span>' : ""}<span class="asl-artifact" title="${artifact.sha256}">${artifact.role}<br>${shortDigest(artifact.sha256)}</span>`,
                  )
                  .join("")}
              </div>
              <div class="asl-foot">
                <span>${escapeHtml(result.cause)}</span>
                <span>${result.securityInterpretation}</span>
                <span>Polar Verity Sense: ${result.hardwareStatus}</span>
              </div>
            </section>
          </div>
        </div>
      </div>`;
  }
}

if (!customElements.get("adversarial-scenario-lab")) {
  customElements.define("adversarial-scenario-lab", AdversarialScenarioLab);
}

