use noticer_aetp::{required_claim, ActionObligation, BucketId, ServiceBinding};
use noticer_crypto::CryptographicRootSecret;
use noticer_k4_demo::{
    authenticated_public_clock::{AuthenticatedClockError, PublicClockAuthKey},
    CoreInitError, SoftwareCore,
};
use noticer_menfugu_core::ExecutionPolicy;
use noticer_menfugu_firmware::RuntimeEvent;
use noticer_token::{semantics_tag, TokenIssuer};
use noticer_trace_shaper::{NetworkFrame, PublicFrameIdentity};
use noticer_transport_core::TransportIdKey;
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use noticer_verifier::{KeyRegistry, PolicyAllowlist, RevocationSnapshot};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-auth-core-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
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
fn rejected_token_advances_authenticated_watermark_before_verification() {
    let replay = path("replay");
    let clock = path("clock");
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
    let make = |slot, key| {
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
        SoftwareCore::<1, 4>::new_with_authenticated_durable_state(
            keys,
            policies,
            RevocationSnapshot::default(),
            &replay,
            &clock,
            PublicClockAuthKey::new(key),
            3,
            slot,
            service,
            epoch,
            TransportIdKey::new([7; 32]),
            100,
            policy(),
        )
    };
    let mut first = make(9, [0x5a; 32]).unwrap();
    let report = first.ingest_frame(&frame).unwrap();
    assert!(report.events.contains(&RuntimeEvent::Rejected));
    assert!(!report.pump_enabled);
    drop(first);
    assert!(matches!(
        make(9, [0x5a; 32]),
        Err(CoreInitError::AuthenticatedPublicClock(
            AuthenticatedClockError::Rollback
        ))
    ));
    assert!(matches!(
        make(10, [0x6b; 32]),
        Err(CoreInitError::AuthenticatedPublicClock(
            AuthenticatedClockError::Authentication
        ))
    ));
    fs::remove_file(replay).unwrap();
    fs::remove_file(clock).unwrap();
}
