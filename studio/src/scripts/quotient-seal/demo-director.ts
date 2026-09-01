import {
  WISS_ATTACK_SCENARIOS,
  WISS_DEMO_DURATION_SECONDS,
  WISS_DEMO_STEPS,
  createWissDemoExport,
  encodeWissDemoExport,
  type DemoStep,
} from "./demo-choreography";

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

class WissDemoDirector extends HTMLElement {
  private open = false;
  private running = false;
  private elapsedSeconds = 0;
  private stepIndex = 0;
  private startedAt = 0;
  private timer: number | null = null;
  private focusedTarget: Element | null = null;
  private initialized = false;

  connectedCallback(): void {
    if (this.initialized) return;
    this.initialized = true;
    this.addEventListener("click", this.handleClick);
    window.addEventListener("keydown", this.handleKeydown);
    this.render();
  }

  disconnectedCallback(): void {
    window.removeEventListener("keydown", this.handleKeydown);
    this.stopTimer();
    this.clearFocus();
  }

  private readonly handleKeydown = (event: KeyboardEvent): void => {
    if (!this.open) return;
    if (event.key === "Escape") {
      this.open = false;
      this.render();
    } else if (event.key === "ArrowRight") {
      event.preventDefault();
      this.goToStep(Math.min(this.stepIndex + 1, WISS_DEMO_STEPS.length - 1));
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      this.goToStep(Math.max(this.stepIndex - 1, 0));
    }
  };

  private readonly handleClick = (event: Event): void => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest<HTMLButtonElement>("button");
    if (!button) return;
    if (button.dataset.command === "open") {
      this.open = true;
      this.render();
      return;
    }
    if (button.dataset.command === "close") {
      this.open = false;
      this.render();
      return;
    }
    if (button.dataset.command === "start") {
      this.startGuidedMode();
      return;
    }
    if (button.dataset.command === "free") {
      this.running = false;
      this.stopTimer();
      this.clearFocus();
      this.render();
      return;
    }
    if (button.dataset.command === "next") {
      this.goToStep(Math.min(this.stepIndex + 1, WISS_DEMO_STEPS.length - 1));
      return;
    }
    if (button.dataset.command === "previous") {
      this.goToStep(Math.max(this.stepIndex - 1, 0));
      return;
    }
    if (button.dataset.command === "attack-now") {
      this.open = true;
      this.goToStep(1);
      this.selectAttack("EXTRA_HOST_CALL");
      return;
    }
    if (button.dataset.command === "export") {
      this.downloadExport();
      return;
    }
    const step = button.dataset.step;
    if (step !== undefined) {
      this.goToStep(Number(step));
      return;
    }
    const scenario = button.dataset.scenario;
    if (scenario && WISS_ATTACK_SCENARIOS.includes(scenario as (typeof WISS_ATTACK_SCENARIOS)[number])) {
      this.selectAttack(scenario);
      this.goToStep(1);
      return;
    }
    const repair = button.dataset.repair;
    if (repair) {
      window.dispatchEvent(
        new CustomEvent("quotient-seal:demo-repair", { detail: { fixtureId: repair } }),
      );
      this.goToStep(3);
    }
  };

  private startGuidedMode(): void {
    this.open = true;
    this.running = true;
    this.elapsedSeconds = 0;
    this.startedAt = performance.now();
    this.goToStep(0);
    this.stopTimer();
    this.timer = window.setInterval(() => {
      const elapsed = Math.min(
        WISS_DEMO_DURATION_SECONDS,
        Math.floor((performance.now() - this.startedAt) / 1000),
      );
      if (elapsed === this.elapsedSeconds) return;
      this.elapsedSeconds = elapsed;
      const timedStep = WISS_DEMO_STEPS.findLastIndex(
        (step) => step.startSecond <= this.elapsedSeconds,
      );
      if (timedStep > this.stepIndex) this.goToStep(timedStep, true, false);
      if (elapsed >= WISS_DEMO_DURATION_SECONDS) {
        this.running = false;
        this.stopTimer();
      }
      this.render();
    }, 250);
  }

  private stopTimer(): void {
    if (this.timer !== null) window.clearInterval(this.timer);
    this.timer = null;
  }

  private goToStep(index: number, scroll = true, render = true): void {
    const boundedIndex = Math.max(0, Math.min(index, WISS_DEMO_STEPS.length - 1));
    this.stepIndex = boundedIndex;
    const step = WISS_DEMO_STEPS[boundedIndex];
    if (step.id === "ATTACK") this.selectAttack("EXTRA_HOST_CALL");
    if (step.id === "REPAIR") {
      window.dispatchEvent(
        new CustomEvent("quotient-seal:demo-repair", {
          detail: { fixtureId: "FUEL_PAD_PASS" },
        }),
      );
    }
    if (scroll) this.focusStep(step);
    if (render) this.render();
  }

  private focusStep(step: DemoStep): void {
    this.clearFocus();
    const target = document.querySelector(step.target);
    if (!target || target === this) return;
    this.focusedTarget = target;
    target.classList.add("wiss-demo-focus");
    target.scrollIntoView({
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      block: "center",
    });
  }

  private clearFocus(): void {
    this.focusedTarget?.classList.remove("wiss-demo-focus");
    this.focusedTarget = null;
  }

  private selectAttack(scenarioId: string): void {
    window.dispatchEvent(
      new CustomEvent("quotient-seal:demo-scenario", { detail: { scenarioId } }),
    );
  }

  private downloadExport(): void {
    const artifact = createWissDemoExport();
    const blob = new Blob([encodeWissDemoExport(artifact)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `quotient-seal-wiss-demo-${artifact.exportSha256.slice(0, 12)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  private render(): void {
    const step = WISS_DEMO_STEPS[this.stepIndex];
    const artifact = createWissDemoExport();
    const progress = (this.elapsedSeconds / WISS_DEMO_DURATION_SECONDS) * 100;
    this.innerHTML = `
      <style>
        wiss-demo-director { position: fixed; right: max(1rem, env(safe-area-inset-right)); bottom: max(1rem, env(safe-area-inset-bottom)); z-index: 1200; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
        .wiss-demo-focus { position: relative; outline: 4px solid #ffb52e !important; outline-offset: 8px; animation: wiss-focus-pulse 1.4s ease-in-out infinite alternate; }
        @keyframes wiss-focus-pulse { to { outline-color: #db4d24; outline-offset: 13px; } }
        .wdd-launcher { display: flex; align-items: center; gap: .65rem; border: 1px solid #ffbd3f; border-radius: 999px; padding: .55rem .75rem .55rem .6rem; color: #fff8e6; background: #142a24; box-shadow: 0 18px 55px rgba(13,28,23,.3); cursor: pointer; }
        .wdd-launcher b { display: grid; place-items: center; width: 2.15rem; aspect-ratio: 1; border-radius: 50%; color: #172b25; background: #ffbd3f; font-size: .72rem; }
        .wdd-launcher span { font: 800 .68rem/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .08em; }
        .wdd-panel { width: min(27rem, calc(100vw - 2rem)); overflow: hidden; border: 1px solid rgba(255,189,63,.7); border-radius: 22px; color: #f7f0de; background: #142a24; box-shadow: 0 28px 90px rgba(10,24,19,.42); }
        .wdd-head { display: flex; justify-content: space-between; gap: 1rem; align-items: start; padding: .9rem 1rem .75rem; border-bottom: 1px solid rgba(255,255,255,.1); background: radial-gradient(circle at 82% 0, rgba(255,181,46,.28), transparent 38%); }
        .wdd-kicker { margin: 0 0 .2rem; color: #ffbd3f; font-size: .56rem; letter-spacing: .14em; text-transform: uppercase; }
        .wdd-head h2 { margin: 0; font: 800 .96rem/1.15 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .wdd-close { border: 1px solid rgba(255,255,255,.2); border-radius: 50%; width: 1.8rem; aspect-ratio: 1; color: white; background: transparent; cursor: pointer; }
        .wdd-progress { height: .35rem; background: rgba(255,255,255,.1); }
        .wdd-progress span { display: block; width: var(--progress); height: 100%; background: linear-gradient(90deg, #ffbd3f, #db4d24); transition: width .25s linear; }
        .wdd-body { padding: .9rem 1rem 1rem; }
        .wdd-clock { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; }
        .wdd-clock strong { font-size: 1.35rem; color: #ffbd3f; }
        .wdd-clock span { color: #9fb8ae; font-size: .58rem; }
        .wdd-timeline { display: grid; grid-template-columns: repeat(5, 1fr); gap: .28rem; margin: .65rem 0; }
        .wdd-step { position: relative; min-height: 2.7rem; border: 1px solid rgba(255,255,255,.13); border-radius: 9px; padding: .35rem; color: #a9bdb5; background: rgba(255,255,255,.035); font: 750 .52rem/1.25 ui-monospace, SFMono-Regular, Consolas, monospace; text-align: left; cursor: pointer; }
        .wdd-step[aria-current="step"] { color: #172b25; border-color: #ffbd3f; background: #ffbd3f; }
        .wdd-step b { display: block; margin-bottom: .18rem; font-size: .5rem; opacity: .7; }
        .wdd-cue { min-height: 5.1rem; padding: .75rem; border-radius: 13px; color: #172b25; background: #f4eddc; }
        .wdd-cue small, .wdd-cue strong, .wdd-cue span { display: block; }
        .wdd-cue small { color: #a14824; font-size: .54rem; letter-spacing: .08em; text-transform: uppercase; }
        .wdd-cue strong { margin: .3rem 0; font-size: .84rem; }
        .wdd-cue span { color: #53655e; font: .64rem/1.45 ui-monospace, SFMono-Regular, Consolas, monospace; }
        .wdd-row { display: flex; flex-wrap: wrap; gap: .4rem; margin-top: .65rem; }
        .wdd-button { border: 1px solid rgba(255,255,255,.2); border-radius: 999px; padding: .45rem .6rem; color: #e4eee9; background: transparent; font: 750 .58rem/1 ui-monospace, SFMono-Regular, Consolas, monospace; cursor: pointer; }
        .wdd-button.primary { border-color: #ffbd3f; color: #172b25; background: #ffbd3f; }
        .wdd-button.hot { border-color: #e15a31; color: white; background: #c94825; }
        .wdd-button:hover, .wdd-button:focus-visible, .wdd-close:focus-visible, .wdd-step:focus-visible { outline: 2px solid #ffbd3f; outline-offset: 2px; }
        .wdd-scenarios { display: grid; grid-template-columns: repeat(3, 1fr); gap: .35rem; margin-top: .65rem; }
        .wdd-scenarios button { min-height: 2.7rem; border: 1px solid rgba(255,255,255,.15); border-radius: 9px; padding: .35rem; color: #cbdad4; background: rgba(255,255,255,.04); font: 700 .52rem/1.25 ui-monospace, SFMono-Regular, Consolas, monospace; cursor: pointer; }
        .wdd-scenarios button:hover, .wdd-scenarios button:focus-visible { border-color: #ffbd3f; outline: none; }
        .wdd-export { display: grid; grid-template-columns: 1fr auto; gap: .6rem; align-items: center; margin-top: .65rem; padding: .55rem .65rem; border: 1px dashed rgba(255,255,255,.2); border-radius: 10px; color: #9fb8ae; font-size: .55rem; }
        .wdd-export code { color: #ffbd3f; }
        .wdd-boundary { margin: .65rem 0 0; color: #8ea69d; font: .5rem/1.45 ui-monospace, SFMono-Regular, Consolas, monospace; }
        @media (max-width: 540px) { wiss-demo-director { right: .6rem; bottom: .6rem; } .wdd-panel { width: calc(100vw - 1.2rem); max-height: calc(100vh - 1.2rem); overflow-y: auto; } .wdd-step { min-height: 2.3rem; padding: .25rem; font-size: .46rem; } }
        @media (prefers-reduced-motion: reduce) { .wiss-demo-focus { animation: none; } .wdd-progress span { transition: none; } }
      </style>
      ${
        this.open
          ? `<aside class="wdd-panel" role="dialog" aria-label="WISS demo director">
              <header class="wdd-head"><div><p class="wdd-kicker">WISS · software-only · 90 seconds</p><h2>QuotientSeal Demo Director</h2></div><button class="wdd-close" type="button" data-command="close" aria-label="閉じる">×</button></header>
              <div class="wdd-progress" style="--progress: ${progress}%"><span></span></div>
              <div class="wdd-body">
                <div class="wdd-clock"><strong>${String(Math.floor(this.elapsedSeconds / 60)).padStart(2, "0")}:${String(this.elapsedSeconds % 60).padStart(2, "0")}</strong><span>${this.running ? "GUIDED RUNNING" : "READY / FREE EXPLORE"}</span></div>
                <nav class="wdd-timeline" aria-label="demo steps">${WISS_DEMO_STEPS.map((item) => `<button class="wdd-step" type="button" data-step="${item.index}" aria-current="${item.index === this.stepIndex ? "step" : "false"}"><b>${String(item.startSecond).padStart(2, "0")}s</b>${escapeHtml(item.id)}</button>`).join("")}</nav>
                <section class="wdd-cue"><small>Act ${step.index + 1} / ${WISS_DEMO_STEPS.length}</small><strong>${escapeHtml(step.title)}</strong><span>${escapeHtml(step.cue)}</span></section>
                <div class="wdd-row"><button class="wdd-button primary" type="button" data-command="start">90秒guided開始</button><button class="wdd-button hot" type="button" data-command="attack-now">攻撃へ直行</button><button class="wdd-button" type="button" data-command="free">自由探索</button></div>
                <div class="wdd-row"><button class="wdd-button" type="button" data-command="previous">← 前</button><button class="wdd-button" type="button" data-command="next">次 →</button></div>
                <div class="wdd-scenarios"><button type="button" data-scenario="EXTRA_HOST_CALL">Extra<br>host call</button><button type="button" data-scenario="PRIVATE_TRAP">Private<br>trap</button><button type="button" data-scenario="RESOURCE_ONLY_LEAK">Resource-only<br>leak</button></div>
                <div class="wdd-export"><span>ALLOWLIST EXPORT<br><code>${shortDigest(artifact.exportSha256)}</code></span><button class="wdd-button" type="button" data-command="export">JSON保存</button></div>
                <p class="wdd-boundary">${artifact.evidenceOrigin} · Polar Verity Sense ${artifact.hardwareStatus} · private biosignal / secret key / stable identifierは出力しない</p>
              </div>
            </aside>`
          : `<button class="wdd-launcher" type="button" data-command="open"><b>90s</b><span>WISS DEMO<br>DIRECTOR</span></button>`
      }`;
  }
}

if (!customElements.get("wiss-demo-director")) {
  customElements.define("wiss-demo-director", WissDemoDirector);
}

