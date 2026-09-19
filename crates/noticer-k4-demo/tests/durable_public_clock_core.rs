use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use noticer_aetp::{required_claim, ActionObligation, BucketId, ServiceBinding};
use noticer_crypto::CryptographicRootSecret;
use noticer_k4_demo::{public_clock::PublicClockError, CoreInitError, SoftwareCore};
use noticer_menfugu_core::ExecutionPolicy;
use noticer_menfugu_firmware::RuntimeEvent;
use noticer_token::{semantics_tag, TokenIssuer};
use noticer_trace_shaper::{NetworkFrame, PublicFrameIdentity};
use noticer_transport_core::TransportIdKey;
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use noticer_verifier::{KeyRegistry, PolicyAllowlist, RevocationSnapshot};

fn temporary_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "noticer-core-{label}-{}-{nonce}.bin",
        std::process::id()
    ))
}

fn policy() -> ExecutionPolicy {
    ExecutionPolicy {
        pump_ticks: 5,
        maximum_pump_ticks: 5,
        cooldown_slots: 1,
        execution_period_slots: 1,
        execution_offset_slots: 0,
    }
}

#[test]
fn rejected_token_still_persists_slot_before_verification() {
    let replay_path = temporary_path("replay-clock-integration");
    let clock_path = temporary_path("clock-integration");
    let service = ServiceBinding([3; 16]);
    let epoch = 5;
    let issuer =
        TokenIssuer::new(CryptographicRootSecret::new([9; 32]), epoch, &[service]).unwrap();
    let obligation = ActionObligation {
        service,
        action: ActionCode::MenfuguInflateSoft,
        public_bucket: BucketId(1),
        admission_cutoff: LogicalSlot(8),
        release_window_start: LogicalSlot(9),
        release_deadline: LogicalSlot(12),
        max_uses: 1,
        policy_hash: PolicyHash([4; 32]),
    };
    let claim = required_claim(obligation.action);
    let identity = PublicFrameIdentity {
        service,
        public_epoch: epoch,
        public_bucket: 1,
        slot_in_bucket: 1,
        sequence: 7,
        absolute_slot: LogicalSlot(10),
    };
    let mut token = issuer
        .issue_action_frame(identity, &obligation, claim)
        .unwrap();
    let last = token.0.len() - 1;
    token.0[last] ^= 1;
    let frame = NetworkFrame {
        identity,
        bytes: token.0.to_vec().into_boxed_slice(),
    };
    let make_core = |trusted_initial_slot| {
        let mut keys = KeyRegistry::default();
        keys.insert(issuer.verifier_material(service).unwrap())
            .unwrap();
        let mut policies = PolicyAllowlist::default();
        policies
            .allow(
                obligation.policy_hash,
                obligation.action,
                claim,
                semantics_tag(&obligation, claim),
            )
            .unwrap();
        SoftwareCore::<1, 4>::new_with_durable_state(
            keys,
            policies,
            RevocationSnapshot::default(),
            &replay_path,
            &clock_path,
            trusted_initial_slot,
            service,
            epoch,
            TransportIdKey::new([7; 32]),
            100,
            policy(),
        )
    };

    let mut first = make_core(9).unwrap();
    let report = first.ingest_frame(&frame).unwrap();
    assert!(report.events.contains(&RuntimeEvent::Rejected));
    assert!(!report.pump_enabled);
    drop(first);

    assert!(matches!(
        make_core(9),
        Err(CoreInitError::PublicClock(PublicClockError::Rollback))
    ));
    fs::remove_file(replay_path).unwrap();
    fs::remove_file(clock_path).unwrap();
}
