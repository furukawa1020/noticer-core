use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use noticer_aetp::{required_claim, ActionObligation, BucketId, ServiceBinding};
use noticer_crypto::CryptographicRootSecret;
use noticer_k4_demo::{CoreInitError, SoftwareCore};
use noticer_menfugu_core::ExecutionPolicy;
use noticer_menfugu_firmware::RuntimeEvent;
use noticer_token::{semantics_tag, TokenIssuer};
use noticer_trace_shaper::{NetworkFrame, PublicFrameIdentity};
use noticer_transport_core::TransportIdKey;
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use noticer_verifier::{FileReplayError, KeyRegistry, PolicyAllowlist, RevocationSnapshot};

fn temporary_path() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "noticer-core-replay-{}-{nonce}.bin",
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
fn restart_rejects_same_atv2_action_in_virtual_menfugu() {
    let path = temporary_path();
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
    // Lab-only token creation is confined to this integration test.
    let token = issuer
        .issue_action_frame(identity, &obligation, claim)
        .unwrap();
    let frame = NetworkFrame {
        identity,
        bytes: token.0.to_vec().into_boxed_slice(),
    };
    let make_core = || {
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
        SoftwareCore::<1, 4>::new_with_durable_replay(
            keys,
            policies,
            RevocationSnapshot::default(),
            &path,
            service,
            epoch,
            TransportIdKey::new([7; 32]),
            100,
            policy(),
        )
    };

    let mut first = make_core().unwrap();
    let report = first.ingest_frame(&frame).unwrap();
    assert!(report
        .events
        .contains(&RuntimeEvent::PumpStarted { duration_ticks: 5 }));
    drop(first);

    let mut restarted = make_core().unwrap();
    let report = restarted.ingest_frame(&frame).unwrap();
    assert!(report.events.contains(&RuntimeEvent::Rejected));
    assert!(!report.pump_enabled);
    drop(restarted);
    fs::remove_file(path).unwrap();
}

#[test]
fn invalid_policy_and_wrong_epoch_fail_before_runtime_starts() {
    let path = temporary_path();
    let service = ServiceBinding([3; 16]);
    let mut invalid = policy();
    invalid.pump_ticks = 0;
    let start = |epoch, execution_policy| {
        SoftwareCore::<1, 4>::new_with_durable_replay(
            KeyRegistry::default(),
            PolicyAllowlist::default(),
            RevocationSnapshot::default(),
            &path,
            service,
            epoch,
            TransportIdKey::new([7; 32]),
            100,
            execution_policy,
        )
    };
    assert!(matches!(
        start(5, invalid),
        Err(CoreInitError::Execution(_))
    ));
    assert!(!path.exists());
    let core = start(5, policy()).unwrap();
    drop(core);
    assert!(matches!(
        start(6, policy()),
        Err(CoreInitError::Replay(FileReplayError::EpochMismatch))
    ));
    fs::remove_file(path).unwrap();
}
