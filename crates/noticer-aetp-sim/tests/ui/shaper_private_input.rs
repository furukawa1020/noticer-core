use noticer_aetp::RandomTape;
use noticer_aetp_sim::PrivateHistory;
use noticer_trace_shaper::ActionEquivalentTraceShaper;

fn leak(history: &PrivateHistory) {
    let _ = ActionEquivalentTraceShaper::shape(history, history, &RandomTape([0; 32]));
}

fn main() {}
