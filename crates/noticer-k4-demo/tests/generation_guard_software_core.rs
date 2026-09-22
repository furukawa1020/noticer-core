use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use noticer_aetp::{required_claim, ActionObligation, BucketId, ServiceBinding};
use noticer_crypto::{CryptographicRootSecret, StateAuthenticationKey};
use noticer_k4_demo::{
    authenticated_public_clock::{AuthenticatedDurablePublicClock, PublicClockAuthKey},
    durable_recovery_ledger::FileRecoveryLedger,
    monotonic_anchor::{AnchorBinding, MonotonicAnchor, MonotonicAnchorError},
    state_generation::{
        initial_generation_state, GenerationAnchor, GenerationAnchorError, GenerationAnchorState,
        StateSnapshot,
    },
    CoreError, CoreInitError, SoftwareCore,
};
use noticer_menfugu_core::ExecutionPolicy;
use noticer_menfugu_firmware::RuntimeEvent;
use noticer_token::{semantics_tag, TokenIssuer};
use noticer_trace_shaper::{NetworkFrame, PublicFrameIdentity};
use noticer_transport_core::TransportIdKey;
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use noticer_verifier::{KeyRegistry, PolicyAllowlist, RevocationSnapshot};

const EPOCH: u32 = 5;
const GENERATION: u64 = 7;
const INITIAL_SLOT: u64 = 9;

#[derive(Clone)]
struct SharedMonotonicAnchor(Arc<Mutex<u64>>);

impl MonotonicAnchor for SharedMonotonicAnchor {
    fn current(&mut self, _binding: AnchorBinding) -> Result<u64, MonotonicAnchorError> {
        Ok(*self.0.lock().unwrap())
    }

    fn advance(&mut self, _binding: AnchorBinding, next: u64) -> Result<(), MonotonicAnchorError> {
        let mut slot = self.0.lock().unwrap();
        if next < *slot {
            return Err(MonotonicAnchorError::UpdateFailed);
        }
        *slot = next;
        Ok(())
    }
}

struct GenerationState {
    value: GenerationAnchorState,
    fail_advance: bool,
}

#[derive(Clone)]
struct SharedGenerationAnchor(Arc<Mutex<GenerationState>>);

impl GenerationAnchor for SharedGenerationAnchor {
    fn current(
        &mut self,
        _binding: AnchorBinding,
    ) -> Result<GenerationAnchorState, GenerationAnchorError> {
        Ok(self.0.lock().unwrap().value)
    }

    fn advance(
        &mut self,
        _binding: AnchorBinding,
        expected_revision: u64,
        next: GenerationAnchorState,
    ) -> Result<(), GenerationAnchorError> {
        let mut state = self.0.lock().unwrap();
        if state.fail_advance {
            return Err(GenerationAnchorError::Unavailable);
        }
        if state.value.revision != expected_revision {
            return Err(GenerationAnchorError::BindingMismatch);
        }
        state.value = next;
        Ok(())
    }
}

struct Paths {
    replay: PathBuf,
    clock: PathBuf,
    ledger: PathBuf,
}

impl Paths {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "noticer-generation-guard-{label}-{}-{nonce}",
            std::process::id()
        ));
        Self {
            replay: base.with_extension("replay"),
            clock: base.with_extension("clock"),
            ledger: base.with_extension("ledger"),
        }
    }
}

impl Drop for Paths {
    fn drop(&mut self) {
        for path in [&self.replay, &self.clock, &self.ledger] {
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }
}

fn binding() -> AnchorBinding {
    AnchorBinding {
        epoch: EPOCH,
        generation: GENERATION,
    }
}

fn clock_key() -> PublicClockAuthKey {
    PublicClockAuthKey::new([51; 32])
}

fn ledger_key() -> StateAuthenticationKey {
    StateAuthenticationKey::new([52; 32])
}

fn generation_key() -> StateAuthenticationKey {
    StateAuthenticationKey::new([53; 32])
}

fn bootstrap(paths: &Paths) -> GenerationAnchorState {
    let clock = AuthenticatedDurablePublicClock::open(
        &paths.clock,
        EPOCH,
        GENERATION,
        INITIAL_SLOT,
        clock_key(),
    )
    .unwrap();
    drop(clock);
    let ledger = FileRecoveryLedger::open(&paths.ledger, EPOCH, GENERATION, ledger_key()).unwrap();
    let snapshot = StateSnapshot {
        binding: binding(),
        clock_slot: INITIAL_SLOT,
        anchor_slot: INITIAL_SLOT,
        recovery_ledger: ledger.head(),
    };
    drop(ledger);
    initial_generation_state(&snapshot, &generation_key())
}

fn protocol() -> (KeyRegistry, PolicyAllowlist, NetworkFrame, ServiceBinding) {
    let service = ServiceBinding([3; 16]);
    let issuer =
        TokenIssuer::new(CryptographicRootSecret::new([9; 32]), EPOCH, &[service]).unwrap();
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
        public_epoch: EPOCH,
        public_bucket: 1,
        slot_in_bucket: 1,
        sequence: 7,
        absolute_slot: LogicalSlot(10),
    };
    let token = issuer
        .issue_action_frame(identity, &obligation, claim)
        .unwrap();
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
    (
        keys,
        policies,
        NetworkFrame {
            identity,
            bytes: token.0.to_vec().into_boxed_slice(),
        },
        service,
    )
}

fn make_core(
    paths: &Paths,
    monotonic: SharedMonotonicAnchor,
    generation: SharedGenerationAnchor,
) -> Result<SoftwareCore<1, 4>, CoreInitError> {
    let (keys, policies, _, service) = protocol();
    SoftwareCore::new_with_generation_guarded_state(
        keys,
        policies,
        RevocationSnapshot::default(),
        &paths.replay,
        &paths.clock,
        clock_key(),
        &paths.ledger,
        ledger_key(),
        generation_key(),
        GENERATION,
        monotonic,
        generation,
        service,
        EPOCH,
        TransportIdKey::new([7; 32]),
        100,
        ExecutionPolicy {
            pump_ticks: 5,
            maximum_pump_ticks: 5,
            cooldown_slots: 1,
            execution_period_slots: 1,
            execution_offset_slots: 0,
        },
    )
}

fn anchors(
    initial: GenerationAnchorState,
    fail_advance: bool,
) -> (SharedMonotonicAnchor, SharedGenerationAnchor) {
    (
        SharedMonotonicAnchor(Arc::new(Mutex::new(INITIAL_SLOT))),
        SharedGenerationAnchor(Arc::new(Mutex::new(GenerationState {
            value: initial,
            fail_advance,
        }))),
    )
}

#[test]
fn action_runs_only_after_generation_commitment_advances() {
    let paths = Paths::new("success");
    let initial = bootstrap(&paths);
    let (monotonic, generation) = anchors(initial, false);
    let generation_view = generation.0.clone();
    let (_, _, frame, _) = protocol();
    let mut core = make_core(&paths, monotonic, generation).unwrap();

    let report = core.ingest_frame(&frame).unwrap();

    assert!(report
        .events
        .contains(&RuntimeEvent::PumpStarted { duration_ticks: 5 }));
    assert!(report.pump_enabled);
    assert_eq!(generation_view.lock().unwrap().value.revision, 1);
}

#[test]
fn generation_update_failure_prevents_action_execution() {
    let paths = Paths::new("failure");
    let initial = bootstrap(&paths);
    let (monotonic, generation) = anchors(initial, true);
    let (_, _, frame, _) = protocol();
    let mut core = make_core(&paths, monotonic, generation).unwrap();

    assert_eq!(core.ingest_frame(&frame), Err(CoreError::DurableClock));
    assert!(!core.pump_enabled());
}

#[test]
fn mismatched_generation_commitment_rejects_startup() {
    let paths = Paths::new("startup");
    let mut initial = bootstrap(&paths);
    initial.commitment[0] ^= 1;
    let (monotonic, generation) = anchors(initial, false);

    assert!(matches!(
        make_core(&paths, monotonic, generation),
        Err(CoreInitError::GenerationGuard(_))
    ));
    assert!(!paths.replay.exists());
}

#[test]
fn same_slot_timer_is_generation_idempotent() {
    let paths = Paths::new("idempotent");
    let initial = bootstrap(&paths);
    let (monotonic, generation) = anchors(initial, false);
    let generation_view = generation.0.clone();
    let mut core = make_core(&paths, monotonic, generation).unwrap();

    core.advance_public_time(INITIAL_SLOT as u32, 1).unwrap();
    assert_eq!(generation_view.lock().unwrap().value.revision, 0);

    core.advance_public_time(INITIAL_SLOT as u32 + 1, 2)
        .unwrap();
    assert_eq!(generation_view.lock().unwrap().value.revision, 1);

    core.advance_public_time(INITIAL_SLOT as u32 + 1, 3)
        .unwrap();
    assert_eq!(generation_view.lock().unwrap().value.revision, 1);
}
