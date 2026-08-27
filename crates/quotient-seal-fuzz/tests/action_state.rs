use quotient_seal_context::{CommandKind, ContextFamily};
use quotient_seal_fuzz::{
    apply_public_feedback, AdaptiveContextBounds, AdaptiveContextState, AdaptiveHostAction,
    AdaptiveHostProgram, AdaptiveProgramError, AdaptivePublicObservation,
};

fn bounds() -> AdaptiveContextBounds {
    AdaptiveContextBounds {
        max_steps: 32,
        max_service_alias: 8,
        max_repeat: 4,
        max_faults: 4,
        max_public_events: 128,
    }
}

fn observation(byte: u8) -> AdaptivePublicObservation {
    AdaptivePublicObservation {
        event_count: 2,
        action_count: 1,
        trap_count: 0,
        host_call_count: 1,
        resource_units: 3,
        public_trace_sha256: [byte; 32],
    }
}

#[test]
fn all_required_actions_map_to_existing_context_commands() {
    let state = AdaptiveContextState::initial(bounds()).unwrap();
    let cases = [
        (
            AdaptiveHostAction::Tick { public_slot: 3 },
            ContextFamily::Tick,
            CommandKind::PublicCall,
        ),
        (
            AdaptiveHostAction::Reset { epoch: 2 },
            ContextFamily::Reset,
            CommandKind::PublicReset,
        ),
        (
            AdaptiveHostAction::Handoff { service_alias: 2 },
            ContextFamily::Handoff,
            CommandKind::PublicHandoff,
        ),
        (
            AdaptiveHostAction::Malformed { payload_tag: 9 },
            ContextFamily::Malformed,
            CommandKind::PublicCall,
        ),
        (
            AdaptiveHostAction::Repeat { count: 2 },
            ContextFamily::Retry,
            CommandKind::PublicCall,
        ),
        (
            AdaptiveHostAction::StaleSlot { delta: 1 },
            ContextFamily::Deadline,
            CommandKind::PublicCall,
        ),
        (
            AdaptiveHostAction::FutureSlot { delta: 1 },
            ContextFamily::Deadline,
            CommandKind::PublicCall,
        ),
        (
            AdaptiveHostAction::Fault { code: 3 },
            ContextFamily::FaultTimeout,
            CommandKind::PublicFault,
        ),
        (
            AdaptiveHostAction::Reconnect { service_alias: 3 },
            ContextFamily::FaultReconnect,
            CommandKind::PublicFault,
        ),
        (
            AdaptiveHostAction::ServiceSwitch { from: 0, to: 4 },
            ContextFamily::ServiceCollusion,
            CommandKind::PublicCall,
        ),
    ];
    for (action, family, kind) in cases {
        let command = action.to_context_command(state).unwrap();
        assert_eq!(command.family, family);
        assert_eq!(command.kind, kind);
    }
}

#[test]
fn state_transition_depends_only_on_public_action_and_observation() {
    let state = AdaptiveContextState::initial(bounds()).unwrap();
    let action = AdaptiveHostAction::Handoff { service_alias: 3 };
    let first = apply_public_feedback(state, action, observation(7)).unwrap();
    let second = apply_public_feedback(state, action, observation(7)).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.after.service_alias, 3);
    assert_eq!(first.after.step, 1);
    assert_eq!(first.after.public_event_count, 2);
}

#[test]
fn invalid_actions_and_state_bounds_fail_closed() {
    let state = AdaptiveContextState::initial(bounds()).unwrap();
    assert_eq!(
        AdaptiveHostAction::Repeat { count: 0 }.to_context_command(state),
        Err(AdaptiveProgramError::ActionBound)
    );
    assert_eq!(
        AdaptiveHostAction::ServiceSwitch { from: 2, to: 2 }.to_context_command(state),
        Err(AdaptiveProgramError::ServiceBound)
    );

    let mut exhausted = state;
    exhausted.step = exhausted.bounds.max_steps;
    assert_eq!(
        apply_public_feedback(
            exhausted,
            AdaptiveHostAction::Tick { public_slot: 1 },
            observation(1)
        ),
        Err(AdaptiveProgramError::StateBound)
    );
}

#[test]
fn canonical_program_is_deterministic_and_tamper_evident() {
    let actions = vec![
        AdaptiveHostAction::Tick { public_slot: 1 },
        AdaptiveHostAction::Fault { code: 2 },
        AdaptiveHostAction::Reconnect { service_alias: 1 },
    ];
    let first = AdaptiveHostProgram::build(17, bounds(), actions.clone()).unwrap();
    let second = AdaptiveHostProgram::build(17, bounds(), actions).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.encode().unwrap(), second.encode().unwrap());
    assert_eq!(
        AdaptiveHostProgram::decode(&first.encode().unwrap()).unwrap(),
        first
    );

    let mut tampered = first.encode().unwrap();
    tampered[20] ^= 0xff;
    assert_eq!(
        AdaptiveHostProgram::decode(&tampered),
        Err(AdaptiveProgramError::Digest)
    );
    let mut trailing = second.encode().unwrap();
    trailing.push(0);
    assert_eq!(
        AdaptiveHostProgram::decode(&trailing),
        Err(AdaptiveProgramError::Length)
    );
}

#[test]
fn program_artifact_contains_no_private_observation_fields() {
    let program = AdaptiveHostProgram::build(
        23,
        bounds(),
        vec![AdaptiveHostAction::Malformed { payload_tag: 4 }],
    )
    .unwrap();
    let json = String::from_utf8(program.canonical_json().unwrap()).unwrap();
    assert!(json.contains("INJECTED_TEST_FIXTURE"));
    assert!(json.contains("NOT_VERIFIED"));
    for forbidden in [
        "private_observation",
        "private_trace",
        "secret",
        "stable_identifier",
    ] {
        assert!(!json.contains(forbidden));
    }
}
