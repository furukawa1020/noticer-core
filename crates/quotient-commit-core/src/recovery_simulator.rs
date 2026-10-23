//! Deterministic bounded simulation of recovery ceremony lifecycle events.

use crate::recovery_ceremony::CeremonyPhase;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimulationConfig {
    pub seed: u64,
    pub event_count: u32,
    pub maximum_backlog: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationEvent {
    CrashRestart,
    RotateKey,
    AddBacklog,
    DrainBacklog,
    AdvanceCeremony,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimulationStep {
    pub ordinal: u32,
    pub event: SimulationEvent,
    pub phase: CeremonyPhase,
    pub key_epoch: u64,
    pub backlog: u32,
    pub admission_halted: bool,
    pub restart_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationArtifact {
    pub config: SimulationConfig,
    pub steps: Vec<SimulationStep>,
    pub terminal: SimulationStep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationError {
    InvalidSeed,
    InvalidEventCount,
    InvalidBacklogLimit,
    UnsafeCompleteWithBacklog,
    UnsafeAdvanceWhileHalted,
}

pub fn run_simulation(config: SimulationConfig) -> Result<SimulationArtifact, SimulationError> {
    validate_config(config)?;
    let mut random = config.seed;
    let mut state = SimulationStep {
        ordinal: 0,
        event: SimulationEvent::CrashRestart,
        phase: CeremonyPhase::Initialized,
        key_epoch: 1,
        backlog: 0,
        admission_halted: false,
        restart_count: 0,
    };
    let mut steps = Vec::with_capacity(config.event_count as usize);
    for ordinal in 1..=config.event_count {
        random = xorshift64(random);
        let event = match random % 5 {
            0 => SimulationEvent::CrashRestart,
            1 => SimulationEvent::RotateKey,
            2 => SimulationEvent::AddBacklog,
            3 => SimulationEvent::DrainBacklog,
            _ => SimulationEvent::AdvanceCeremony,
        };
        apply(&mut state, event, config.maximum_backlog);
        state.ordinal = ordinal;
        state.event = event;
        steps.push(state);
    }
    oracle(&steps, state, config.maximum_backlog)?;
    Ok(SimulationArtifact {
        config,
        steps,
        terminal: state,
    })
}

pub fn verify_artifact(artifact: &SimulationArtifact) -> Result<(), SimulationError> {
    oracle(
        &artifact.steps,
        artifact.terminal,
        artifact.config.maximum_backlog,
    )
}

#[must_use]
pub fn canonical_json(artifact: &SimulationArtifact) -> String {
    let steps = artifact.steps.iter().map(|step| format!(
        "{{\"ordinal\":{},\"event\":\"{}\",\"phase\":{},\"key_epoch\":{},\"backlog\":{},\"admission_halted\":{},\"restart_count\":{}}}",
        step.ordinal, event_label(step.event), step.phase as u8, step.key_epoch,
        step.backlog, step.admission_halted, step.restart_count
    )).collect::<Vec<_>>().join(",");
    format!("{{\"schema\":\"noticer.recovery-simulation.v1\",\"seed\":{},\"event_count\":{},\"maximum_backlog\":{},\"steps\":[{}]}}",
        artifact.config.seed, artifact.config.event_count, artifact.config.maximum_backlog, steps)
}

fn apply(state: &mut SimulationStep, event: SimulationEvent, limit: u32) {
    match event {
        SimulationEvent::CrashRestart => state.restart_count += 1,
        SimulationEvent::RotateKey => {
            state.key_epoch += 1;
            state.phase = CeremonyPhase::Initialized;
        }
        SimulationEvent::AddBacklog => state.backlog = state.backlog.saturating_add(1),
        SimulationEvent::DrainBacklog => state.backlog = state.backlog.saturating_sub(1),
        SimulationEvent::AdvanceCeremony if !state.admission_halted => {
            state.phase = match state.phase {
                CeremonyPhase::Initialized => CeremonyPhase::SecurityAuthorized,
                CeremonyPhase::SecurityAuthorized => CeremonyPhase::AdmissionAuthorized,
                CeremonyPhase::AdmissionAuthorized => CeremonyPhase::RecoveryWitnessed,
                CeremonyPhase::RecoveryWitnessed | CeremonyPhase::Complete => {
                    CeremonyPhase::Complete
                }
            };
        }
        SimulationEvent::AdvanceCeremony => {}
    }
    state.admission_halted = state.backlog > limit;
    if state.admission_halted && state.phase == CeremonyPhase::Complete {
        state.phase = CeremonyPhase::AdmissionAuthorized;
    }
}

fn oracle(
    steps: &[SimulationStep],
    terminal: SimulationStep,
    limit: u32,
) -> Result<(), SimulationError> {
    if terminal.phase == CeremonyPhase::Complete && terminal.backlog > limit {
        return Err(SimulationError::UnsafeCompleteWithBacklog);
    }
    if steps.windows(2).any(|pair| {
        pair[0].admission_halted
            && pair[1].event == SimulationEvent::AdvanceCeremony
            && pair[1].phase > pair[0].phase
    }) {
        return Err(SimulationError::UnsafeAdvanceWhileHalted);
    }
    Ok(())
}

fn validate_config(config: SimulationConfig) -> Result<(), SimulationError> {
    if config.seed == 0 {
        return Err(SimulationError::InvalidSeed);
    }
    if config.event_count == 0 || config.event_count > 10_000 {
        return Err(SimulationError::InvalidEventCount);
    }
    if config.maximum_backlog == 0 {
        return Err(SimulationError::InvalidBacklogLimit);
    }
    Ok(())
}

fn xorshift64(mut value: u64) -> u64 {
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    value
}
fn event_label(event: SimulationEvent) -> &'static str {
    match event {
        SimulationEvent::CrashRestart => "crash_restart",
        SimulationEvent::RotateKey => "rotate_key",
        SimulationEvent::AddBacklog => "add_backlog",
        SimulationEvent::DrainBacklog => "drain_backlog",
        SimulationEvent::AdvanceCeremony => "advance_ceremony",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> SimulationConfig {
        SimulationConfig {
            seed: 0x5eed,
            event_count: 128,
            maximum_backlog: 3,
        }
    }

    #[test]
    fn identical_seed_is_byte_identical_and_bounded() {
        let first = run_simulation(config()).unwrap();
        let second = run_simulation(config()).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            canonical_json(&first).as_bytes(),
            canonical_json(&second).as_bytes()
        );
        assert_eq!(first.steps.len(), 128);
    }

    #[test]
    fn generated_trace_preserves_terminal_and_transition_invariants() {
        let artifact = run_simulation(config()).unwrap();
        assert_eq!(verify_artifact(&artifact), Ok(()));
        assert!(artifact.steps.iter().any(|step| step.restart_count > 0));
        assert!(artifact.steps.iter().any(|step| step.key_epoch > 1));
    }

    #[test]
    fn unsafe_terminal_is_rejected_with_reason() {
        let mut artifact = run_simulation(config()).unwrap();
        artifact.terminal.phase = CeremonyPhase::Complete;
        artifact.terminal.backlog = config().maximum_backlog + 1;
        assert_eq!(
            verify_artifact(&artifact),
            Err(SimulationError::UnsafeCompleteWithBacklog)
        );
    }
}
