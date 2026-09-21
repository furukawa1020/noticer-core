use noticer_aetp::{required_claim, ActionObligation, BucketId, ServiceBinding};
use noticer_crypto::CryptographicRootSecret;
use noticer_k4_demo::{
    authenticated_public_clock::{AuthenticatedClockError, PublicClockAuthKey},
    monotonic_anchor::{AnchorBinding, AnchoredClockError, MonotonicAnchor, MonotonicAnchorError},
    CoreError, CoreInitError, SoftwareCore,
};
use noticer_menfugu_core::ExecutionPolicy;
use noticer_token::{semantics_tag, TokenIssuer};
use noticer_trace_shaper::{NetworkFrame, PublicFrameIdentity};
use noticer_transport_core::TransportIdKey;
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use noticer_verifier::{KeyRegistry, PolicyAllowlist, RevocationSnapshot};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct SharedAnchor(Arc<Mutex<State>>);
struct State {
    binding: AnchorBinding,
    slot: u64,
    available: bool,
    fail: bool,
}
impl MonotonicAnchor for SharedAnchor {
    fn current(&mut self, b: AnchorBinding) -> Result<u64, MonotonicAnchorError> {
        let s = self.0.lock().unwrap();
        if !s.available {
            return Err(MonotonicAnchorError::Unavailable);
        }
        if s.binding != b {
            return Err(MonotonicAnchorError::BindingMismatch);
        }
        Ok(s.slot)
    }
    fn advance(&mut self, b: AnchorBinding, slot: u64) -> Result<(), MonotonicAnchorError> {
        let mut s = self.0.lock().unwrap();
        if s.binding != b {
            return Err(MonotonicAnchorError::BindingMismatch);
        }
        if s.fail {
            return Err(MonotonicAnchorError::UpdateFailed);
        }
        s.slot = slot;
        Ok(())
    }
}
fn path(l: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "noticer-core-anchor-{l}-{}-{}",
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
fn stale_valid_record_and_anchor_failure_never_reach_action() {
    let replay = path("replay");
    let clock = path("clock");
    let service = ServiceBinding([3; 16]);
    let epoch = 5;
    let binding = AnchorBinding {
        epoch,
        generation: 4,
    };
    let state = Arc::new(Mutex::new(State {
        binding,
        slot: 9,
        available: true,
        fail: false,
    }));
    let anchor = SharedAnchor(state.clone());
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
    let token = issuer
        .issue_action_frame(identity, &obligation, claim)
        .unwrap();
    let frame = NetworkFrame {
        identity,
        bytes: token.0.to_vec().into_boxed_slice(),
    };
    let make = |a: SharedAnchor| {
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
        SoftwareCore::<1, 4>::new_with_anchored_durable_state(
            keys,
            policies,
            RevocationSnapshot::default(),
            &replay,
            &clock,
            PublicClockAuthKey::new([77; 32]),
            4,
            a,
            service,
            epoch,
            TransportIdKey::new([7; 32]),
            100,
            policy(),
        )
    };
    let mut first = make(anchor.clone()).unwrap();
    let old = fs::read(&clock).unwrap();
    state.lock().unwrap().fail = true;
    assert_eq!(first.ingest_frame(&frame), Err(CoreError::DurableClock));
    assert!(!first.pump_enabled());
    drop(first);
    state.lock().unwrap().fail = false;
    fs::write(&clock, old).unwrap();
    state.lock().unwrap().slot = 10;
    assert!(matches!(
        make(anchor),
        Err(CoreInitError::AnchoredPublicClock(
            AnchoredClockError::Clock(AuthenticatedClockError::TrustedSlotMismatch)
        ))
    ));
    fs::remove_file(replay).unwrap();
    fs::remove_file(clock).unwrap();
}
