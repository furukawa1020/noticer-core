#![forbid(unsafe_code)]

//! Software-only ATv2 to APLOT to virtual Menfugu integration boundary.
//! Local events are diagnostics, not an AETP-approved release surface.

pub mod authenticated_public_clock;
pub mod durable_recovery;
pub mod durable_recovery_ledger;
pub mod generation_guard;
pub mod monotonic_anchor;
pub mod public_clock;
pub mod recovery;
pub mod state_generation;

use authenticated_public_clock::{
    AuthenticatedClockError, AuthenticatedDurablePublicClock, PublicClockAuthKey,
};
use generation_guard::{GenerationGuardError, GenerationGuardedClock};
use monotonic_anchor::{
    AnchorBinding, AnchoredAuthenticatedClock, AnchoredClockError, MonotonicAnchor,
};
use public_clock::{DurablePublicClock, PublicClockError};
use state_generation::GenerationAnchor;

use noticer_aetp::ServiceBinding;
use noticer_ble_host::HostVerifierAdapter;
use noticer_menfugu_core::{ExecutionError, ExecutionPolicy};
use noticer_menfugu_firmware::{MenfuguRuntime, PumpOutput, RuntimeEvent};
use noticer_protocol::AtypicalityTokenEnvelope;
use noticer_trace_shaper::{NetworkFrame, NetworkTrace};
use noticer_transport_core::{
    derive_frame_id, fragment_envelope, TransportFrameIdentity, TransportIdKey,
    TOTAL_FRAGMENT_COUNT,
};
use noticer_verifier::{
    FileReplayError, FileReplayStore, KeyRegistry, PolicyAllowlist, RevocationSnapshot,
    TokenVerifier,
};
use std::{path::Path, sync::Arc};

#[derive(Default)]
pub struct VirtualPump {
    enabled: bool,
}

impl VirtualPump {
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

impl PumpOutput for VirtualPump {
    fn set_pump(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameReport {
    /// Local-only diagnostics; never publish as an AETP trace.
    pub events: Vec<RuntimeEvent>,
    pub pump_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreError {
    InvalidEnvelope,
    PublicBinding,
    ClockRegression,
    ClockOverflow,
    InvalidFaultMask,
    DurableClock,
}

#[derive(Debug)]
pub enum CoreInitError {
    Replay(FileReplayError),
    PublicClock(PublicClockError),
    AuthenticatedPublicClock(AuthenticatedClockError),
    AnchoredPublicClock(AnchoredClockError),
    GenerationGuard(GenerationGuardError),
    Execution(ExecutionError),
}
enum PublicClockState {
    Plaintext(DurablePublicClock),
    Authenticated(AuthenticatedDurablePublicClock),
    Anchored(AnchoredAuthenticatedClock<Box<dyn MonotonicAnchor>>),
    GenerationGuarded(Box<GenerationGuardedClock>),
}

impl PublicClockState {
    fn advance(&mut self, slot: u64) -> Result<(), ()> {
        match self {
            Self::Plaintext(clock) => clock.advance(slot).map_err(|_| ()),
            Self::Authenticated(clock) => clock.advance(slot).map_err(|_| ()),
            Self::Anchored(clock) => clock.advance(slot).map_err(|_| ()),
            Self::GenerationGuarded(clock) => clock.advance(slot).map_err(|_| ()),
        }
    }
}
pub struct SoftwareCore<const ACTIVE_FRAMES: usize, const CONSUMED_TOKENS: usize> {
    runtime: MenfuguRuntime<HostVerifierAdapter, VirtualPump, ACTIVE_FRAMES, CONSUMED_TOKENS>,
    transport_key: TransportIdKey,
    expected_service: ServiceBinding,
    expected_epoch: u32,
    public_clock: Option<PublicClockState>,
    last_slot: Option<u32>,
    next_tick: u64,
}

impl<const ACTIVE_FRAMES: usize, const CONSUMED_TOKENS: usize>
    SoftwareCore<ACTIVE_FRAMES, CONSUMED_TOKENS>
{
    pub fn new(
        verifier: TokenVerifier,
        service: ServiceBinding,
        epoch: u32,
        transport_key: TransportIdKey,
        reassembly_ttl_ticks: u64,
        execution_policy: ExecutionPolicy,
    ) -> Result<Self, ExecutionError> {
        let runtime = MenfuguRuntime::new(
            HostVerifierAdapter::new(verifier, service, epoch),
            VirtualPump::default(),
            reassembly_ttl_ticks,
            execution_policy,
        )?;
        Ok(Self {
            runtime,
            transport_key,
            expected_service: service,
            expected_epoch: epoch,
            public_clock: None,
            last_slot: None,
            next_tick: 0,
        })
    }

    /// Fail-closed startup: no in-memory fallback if durable replay is unavailable.
    // Keep service, epoch, policy and ledger bindings explicit at this trust boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_durable_replay(
        keys: KeyRegistry,
        policies: PolicyAllowlist,
        revocations: RevocationSnapshot,
        replay_path: impl AsRef<Path>,
        service: ServiceBinding,
        epoch: u32,
        transport_key: TransportIdKey,
        reassembly_ttl_ticks: u64,
        execution_policy: ExecutionPolicy,
    ) -> Result<Self, CoreInitError> {
        execution_policy
            .validate()
            .map_err(CoreInitError::Execution)?;
        let store =
            Arc::new(FileReplayStore::open(replay_path, epoch).map_err(CoreInitError::Replay)?);
        let verifier = TokenVerifier::new(keys, policies, revocations, store);
        Self::new(
            verifier,
            service,
            epoch,
            transport_key,
            reassembly_ttl_ticks,
            execution_policy,
        )
        .map_err(CoreInitError::Execution)
    }

    /// Restart-safe startup for both token replay and public-slot rollback.
    // The initial slot must come from a trusted public scheduler, not packet contents.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_durable_state(
        keys: KeyRegistry,
        policies: PolicyAllowlist,
        revocations: RevocationSnapshot,
        replay_path: impl AsRef<Path>,
        public_clock_path: impl AsRef<Path>,
        trusted_initial_slot: u32,
        service: ServiceBinding,
        epoch: u32,
        transport_key: TransportIdKey,
        reassembly_ttl_ticks: u64,
        execution_policy: ExecutionPolicy,
    ) -> Result<Self, CoreInitError> {
        execution_policy
            .validate()
            .map_err(CoreInitError::Execution)?;
        let public_clock =
            DurablePublicClock::open(public_clock_path, epoch, u64::from(trusted_initial_slot))
                .map_err(CoreInitError::PublicClock)?;
        let store =
            Arc::new(FileReplayStore::open(replay_path, epoch).map_err(CoreInitError::Replay)?);
        let verifier = TokenVerifier::new(keys, policies, revocations, store);
        let mut core = Self::new(
            verifier,
            service,
            epoch,
            transport_key,
            reassembly_ttl_ticks,
            execution_policy,
        )
        .map_err(CoreInitError::Execution)?;
        core.public_clock = Some(PublicClockState::Plaintext(public_clock));
        core.last_slot = Some(trusted_initial_slot);
        Ok(core)
    }

    /// Restart-safe startup with an authenticated public-clock record.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_authenticated_durable_state(
        keys: KeyRegistry,
        policies: PolicyAllowlist,
        revocations: RevocationSnapshot,
        replay_path: impl AsRef<Path>,
        public_clock_path: impl AsRef<Path>,
        public_clock_key: PublicClockAuthKey,
        state_generation: u64,
        trusted_initial_slot: u32,
        service: ServiceBinding,
        epoch: u32,
        transport_key: TransportIdKey,
        reassembly_ttl_ticks: u64,
        execution_policy: ExecutionPolicy,
    ) -> Result<Self, CoreInitError> {
        execution_policy
            .validate()
            .map_err(CoreInitError::Execution)?;
        let public_clock = AuthenticatedDurablePublicClock::open(
            public_clock_path,
            epoch,
            state_generation,
            u64::from(trusted_initial_slot),
            public_clock_key,
        )
        .map_err(CoreInitError::AuthenticatedPublicClock)?;
        let store =
            Arc::new(FileReplayStore::open(replay_path, epoch).map_err(CoreInitError::Replay)?);
        let verifier = TokenVerifier::new(keys, policies, revocations, store);
        let mut core = Self::new(
            verifier,
            service,
            epoch,
            transport_key,
            reassembly_ttl_ticks,
            execution_policy,
        )
        .map_err(CoreInitError::Execution)?;
        core.public_clock = Some(PublicClockState::Authenticated(public_clock));
        core.last_slot = Some(trusted_initial_slot);
        Ok(core)
    }
    /// Restart-safe startup with authenticated state and an external freshness anchor.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_anchored_durable_state<A: MonotonicAnchor + 'static>(
        keys: KeyRegistry,
        policies: PolicyAllowlist,
        revocations: RevocationSnapshot,
        replay_path: impl AsRef<Path>,
        public_clock_path: impl AsRef<Path>,
        public_clock_key: PublicClockAuthKey,
        state_generation: u64,
        anchor: A,
        service: ServiceBinding,
        epoch: u32,
        transport_key: TransportIdKey,
        reassembly_ttl_ticks: u64,
        execution_policy: ExecutionPolicy,
    ) -> Result<Self, CoreInitError> {
        execution_policy
            .validate()
            .map_err(CoreInitError::Execution)?;
        let public_clock = AnchoredAuthenticatedClock::open(
            public_clock_path,
            AnchorBinding {
                epoch,
                generation: state_generation,
            },
            public_clock_key,
            Box::new(anchor) as Box<dyn MonotonicAnchor>,
        )
        .map_err(CoreInitError::AnchoredPublicClock)?;
        let trusted_initial_slot = u32::try_from(public_clock.slot()).map_err(|_| {
            CoreInitError::AnchoredPublicClock(AnchoredClockError::Clock(
                AuthenticatedClockError::TrustedSlotMismatch,
            ))
        })?;
        let store =
            Arc::new(FileReplayStore::open(replay_path, epoch).map_err(CoreInitError::Replay)?);
        let verifier = TokenVerifier::new(keys, policies, revocations, store);
        let mut core = Self::new(
            verifier,
            service,
            epoch,
            transport_key,
            reassembly_ttl_ticks,
            execution_policy,
        )
        .map_err(CoreInitError::Execution)?;
        core.public_clock = Some(PublicClockState::Anchored(public_clock));
        core.last_slot = Some(trusted_initial_slot);
        Ok(core)
    }
    /// Strongest software-only startup: local durable state plus two external anchors.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_generation_guarded_state<
        M: MonotonicAnchor + 'static,
        G: GenerationAnchor + 'static,
    >(
        keys: KeyRegistry,
        policies: PolicyAllowlist,
        revocations: RevocationSnapshot,
        replay_path: impl AsRef<Path>,
        public_clock_path: impl AsRef<Path>,
        public_clock_key: PublicClockAuthKey,
        recovery_ledger_path: impl AsRef<Path>,
        recovery_ledger_key: noticer_crypto::StateAuthenticationKey,
        generation_key: noticer_crypto::StateAuthenticationKey,
        state_generation: u64,
        monotonic_anchor: M,
        generation_anchor: G,
        service: ServiceBinding,
        epoch: u32,
        transport_key: TransportIdKey,
        reassembly_ttl_ticks: u64,
        execution_policy: ExecutionPolicy,
    ) -> Result<Self, CoreInitError> {
        execution_policy
            .validate()
            .map_err(CoreInitError::Execution)?;
        let guarded = GenerationGuardedClock::open(
            public_clock_path,
            public_clock_key,
            recovery_ledger_path,
            recovery_ledger_key,
            generation_key,
            AnchorBinding {
                epoch,
                generation: state_generation,
            },
            Box::new(monotonic_anchor),
            Box::new(generation_anchor),
        )
        .map_err(CoreInitError::GenerationGuard)?;
        let initial_slot = u32::try_from(guarded.slot())
            .map_err(|_| CoreInitError::GenerationGuard(GenerationGuardError::SlotOverflow))?;
        let store =
            Arc::new(FileReplayStore::open(replay_path, epoch).map_err(CoreInitError::Replay)?);
        let verifier = TokenVerifier::new(keys, policies, revocations, store);
        let mut core = Self::new(
            verifier,
            service,
            epoch,
            transport_key,
            reassembly_ttl_ticks,
            execution_policy,
        )
        .map_err(CoreInitError::Execution)?;
        core.public_clock = Some(PublicClockState::GenerationGuarded(Box::new(guarded)));
        core.last_slot = Some(initial_slot);
        Ok(core)
    }
    pub fn pump_enabled(&self) -> bool {
        self.runtime.pump().enabled()
    }

    /// Ingests one already-shaped public frame without real BLE or hardware.
    pub fn ingest_frame(&mut self, frame: &NetworkFrame) -> Result<FrameReport, CoreError> {
        self.ingest_frame_with_public_loss(frame, 0)
    }

    /// The loss mask is public simulation input; all twenty time slots still elapse.
    pub fn ingest_frame_with_public_loss(
        &mut self,
        frame: &NetworkFrame,
        loss_mask: u32,
    ) -> Result<FrameReport, CoreError> {
        if loss_mask >> TOTAL_FRAGMENT_COUNT != 0 {
            return Err(CoreError::InvalidFaultMask);
        }
        let identity = frame.identity;
        let slot = u32::try_from(identity.absolute_slot.0).map_err(|_| CoreError::ClockOverflow)?;
        if self.last_slot.is_some_and(|last| slot < last) {
            return Err(CoreError::ClockRegression);
        }
        if identity.service != self.expected_service || identity.public_epoch != self.expected_epoch
        {
            return Err(CoreError::PublicBinding);
        }
        let envelope = AtypicalityTokenEnvelope::from_slice(&frame.bytes)
            .map_err(|_| CoreError::InvalidEnvelope)?;
        let outer = envelope.outer().map_err(|_| CoreError::InvalidEnvelope)?;
        if outer.public_epoch != identity.public_epoch
            || outer.public_bucket != identity.public_bucket
            || outer.sequence != identity.sequence
        {
            return Err(CoreError::PublicBinding);
        }
        if let Some(clock) = &mut self.public_clock {
            clock
                .advance(u64::from(slot))
                .map_err(|_| CoreError::DurableClock)?;
        }
        let end_tick = self
            .next_tick
            .checked_add(TOTAL_FRAGMENT_COUNT as u64)
            .ok_or(CoreError::ClockOverflow)?;
        let frame_id = derive_frame_id(
            &self.transport_key,
            TransportFrameIdentity {
                service_alias: outer.service_alias.0,
                public_epoch: outer.public_epoch,
                public_bucket: outer.public_bucket,
                sequence: outer.sequence,
            },
        );
        let fragments = fragment_envelope(envelope.as_bytes(), frame_id);
        let mut events = Vec::new();
        for (index, fragment) in fragments.iter().enumerate() {
            let tick = self.next_tick + index as u64;
            let timer_event = self.runtime.on_public_timer(tick, slot);
            if timer_event != RuntimeEvent::Pending {
                events.push(timer_event);
            }
            if loss_mask & (1_u32 << index) == 0 {
                let event = self.runtime.on_gatt_write(&fragment.encode(), tick, slot);
                if event != RuntimeEvent::Pending {
                    events.push(event);
                }
            }
        }
        self.last_slot = Some(slot);
        self.next_tick = end_tick;
        Ok(FrameReport {
            events,
            pump_enabled: self.pump_enabled(),
        })
    }

    /// Streaming operation: a later bad frame does not roll back prior actions.
    pub fn ingest_trace(&mut self, trace: &NetworkTrace) -> Result<Vec<FrameReport>, CoreError> {
        trace
            .frames
            .iter()
            .map(|frame| self.ingest_frame(frame))
            .collect()
    }

    /// The public timer must advance independently of incoming frames.
    pub fn advance_public_time(&mut self, slot: u32, tick: u64) -> Result<RuntimeEvent, CoreError> {
        if self.last_slot.is_some_and(|last| slot < last) || tick < self.next_tick {
            return Err(CoreError::ClockRegression);
        }
        if let Some(clock) = &mut self.public_clock {
            clock
                .advance(u64::from(slot))
                .map_err(|_| CoreError::DurableClock)?;
        }
        let event = self.runtime.on_public_timer(tick, slot);
        self.last_slot = Some(slot);
        self.next_tick = tick;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noticer_aetp::{required_claim, ActionObligation, BucketId};
    use noticer_crypto::CryptographicRootSecret;
    use noticer_protocol::ENVELOPE_SIZE;
    use noticer_token::{semantics_tag, TokenIssuer};
    use noticer_trace_shaper::PublicFrameIdentity;
    use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
    use noticer_verifier::{InMemoryReplayStore, KeyRegistry, PolicyAllowlist, RevocationSnapshot};
    use std::sync::Arc;

    fn fixture() -> (SoftwareCore<1, 4>, NetworkFrame, NetworkFrame) {
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
        let cover_identity = PublicFrameIdentity {
            service,
            public_epoch: epoch,
            public_bucket: 1,
            slot_in_bucket: 0,
            sequence: 6,
            absolute_slot: LogicalSlot(9),
        };
        let action_identity = PublicFrameIdentity {
            sequence: 7,
            slot_in_bucket: 1,
            absolute_slot: LogicalSlot(10),
            ..cover_identity
        };
        let cover = issuer.issue_cover_frame(cover_identity).unwrap();
        let action = issuer
            .issue_action_frame(action_identity, &obligation, claim)
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
        let verifier = TokenVerifier::new(
            keys,
            policies,
            RevocationSnapshot::default(),
            Arc::new(InMemoryReplayStore::default()),
        );
        let core = SoftwareCore::new(
            verifier,
            service,
            epoch,
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
        .unwrap();
        (
            core,
            NetworkFrame {
                identity: cover_identity,
                bytes: cover.0.to_vec().into_boxed_slice(),
            },
            NetworkFrame {
                identity: action_identity,
                bytes: action.0.to_vec().into_boxed_slice(),
            },
        )
    }

    #[test]
    fn cover_action_replay_and_timer_respect_virtual_pump() {
        let (mut core, cover, action) = fixture();
        let reports = core
            .ingest_trace(&NetworkTrace {
                frames: vec![cover, action.clone()],
            })
            .unwrap();
        assert!(reports[0].events.contains(&RuntimeEvent::Cover));
        assert!(!reports[0].pump_enabled);
        assert!(reports[1]
            .events
            .contains(&RuntimeEvent::PumpStarted { duration_ticks: 5 }));
        assert!(core.pump_enabled());
        assert_eq!(
            core.advance_public_time(10, 100).unwrap(),
            RuntimeEvent::PumpStopped
        );
        assert!(!core.pump_enabled());
        let replay = core.ingest_frame(&action).unwrap();
        assert!(!replay
            .events
            .iter()
            .any(|event| matches!(event, RuntimeEvent::PumpStarted { .. })));
    }

    #[test]
    fn binding_mutation_and_slot_rollback_never_start_pump() {
        let (mut core, cover, action) = fixture();
        let mut wrong_identity = action.clone();
        wrong_identity.identity.sequence += 1;
        assert_eq!(
            core.ingest_frame(&wrong_identity),
            Err(CoreError::PublicBinding)
        );
        let mut malformed = action.clone();
        malformed.bytes = vec![0; ENVELOPE_SIZE - 1].into_boxed_slice();
        assert_eq!(
            core.ingest_frame(&malformed),
            Err(CoreError::InvalidEnvelope)
        );
        assert!(!core.pump_enabled());
        core.ingest_frame(&action).unwrap();
        assert_eq!(core.ingest_frame(&cover), Err(CoreError::ClockRegression));
    }
    #[test]
    fn one_loss_per_parity_group_recovers_authorized_action() {
        let (mut core, _, action) = fixture();
        let report = core.ingest_frame_with_public_loss(&action, 0b1111).unwrap();
        assert!(report
            .events
            .contains(&RuntimeEvent::PumpStarted { duration_ticks: 5 }));
        assert!(report.pump_enabled);
    }

    #[test]
    fn two_losses_in_one_group_and_ciphertext_mutation_never_act() {
        let (mut core, _, action) = fixture();
        let report = core
            .ingest_frame_with_public_loss(&action, (1 << 0) | (1 << 4))
            .unwrap();
        assert!(!report
            .events
            .iter()
            .any(|event| matches!(event, RuntimeEvent::PumpStarted { .. })));
        assert!(!report.pump_enabled);

        let (mut core, _, mut action) = fixture();
        action.bytes[ENVELOPE_SIZE - 1] ^= 1;
        let report = core.ingest_frame(&action).unwrap();
        assert!(report.events.contains(&RuntimeEvent::Rejected));
        assert!(!report.pump_enabled);
    }

    #[test]
    fn invalid_public_loss_mask_is_rejected_before_sending() {
        let (mut core, _, action) = fixture();
        assert_eq!(
            core.ingest_frame_with_public_loss(&action, 1_u32 << TOTAL_FRAGMENT_COUNT),
            Err(CoreError::InvalidFaultMask)
        );
        assert!(!core.pump_enabled());
    }
}
