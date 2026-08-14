use std::{collections::BTreeSet, sync::Arc};

use noticer_acquisition_core::{
    AcquisitionSession, NegotiatedAccSettings, NegotiatedPpgSettings, PrivateAccBatch,
    PrivatePpgBatch, SessionConfig, SessionId, SessionPhase, SourceDescriptor,
};
use noticer_aetp::{
    required_claim, ActionObligation, ActionSemantics, BucketId, ChannelSchedule, ClaimBound,
    PublicContext, PublicNetworkTape, ScheduleRandomTape, ServiceBinding,
};
use noticer_baseline::{
    AnchorBaselineBuilder, BaselineConfig, BaselineRegistry, ContextKey, PrivateFeatureVector,
};
use noticer_ble_host::HostVerifierAdapter;
use noticer_crypto::CryptographicRootSecret;
use noticer_evidence::{
    ContextConfig, EngineConfig, EvidenceConfig, EvidenceEngine, PersistenceConfig,
};
use noticer_evidence_bridge::{EvidenceBridge, ProductionAdmission};
use noticer_menfugu_core::ExecutionPolicy;
use noticer_menfugu_firmware::{MenfuguRuntime, PumpOutput, RuntimeEvent};
use noticer_nepp::{
    ChallengeStore, ExpectedBindings, NeppClaims, PairwiseServiceAlias, ReferenceSoftwareAttester,
    VerifierChallenge, VerifierOnlyClaims,
};
use noticer_ppg_features::FeatureSchema;
use noticer_protocol::{AtypicalityTokenEnvelope, FrameKind, ENVELOPE_SIZE};
use noticer_provenance::{
    AssuranceProfile, BootStateAssurance, CollectorKeyAssurance, FreshnessAssurance,
    PipelineAssurance, PipelineMeasurementHash, SourceAssurance,
};
use noticer_provenance_lease::{
    validate_lease, ExpectedLeaseBindings, InMemoryLeaseReplayGuard, LeaseIssuancePolicy,
    LeaseNonce, LeaseSigningKey, ProvenanceLeaseIssuer, PublicLeaseSchedule,
    ValidatedProvenanceLease,
};
use noticer_provenance_verifier::{
    AppraisalRequest, PlatformEvidence, ProvenanceAppraiser, ReferenceValueStore, SourceEvidence,
};
use noticer_release::TokenPlan;
use noticer_token::{
    semantics_tag, ProductionBindings, ProductionGuardError, ProductionTokenIssuer, TokenIssuer,
};
use noticer_trace_shaper::{ActionEquivalentTraceShaper, FrameIssuer, PublicFrameIdentity};
use noticer_transport_core::{
    derive_frame_id, fragment_envelope, TransportFrameIdentity, TransportIdKey,
};
use noticer_transport_sim::{simulate, PublicLossTape};
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use noticer_verifier::{
    InMemoryReplayStore, KeyRegistry, PolicyAllowlist, RevocationSnapshot, TokenVerifier,
};
use rand_core::{impls, RngCore};

const SERVICE: ServiceBinding = ServiceBinding([0x31; 16]);
const SERVICE_ALIAS: PairwiseServiceAlias = PairwiseServiceAlias([0x32; 16]);
const PIPELINE: PipelineMeasurementHash = PipelineMeasurementHash([0x33; 32]);
const POLICY: PolicyHash = PolicyHash([0x42; 32]);
const EPOCH: u32 = 9;

struct FixedRng(u64);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.0
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        impls::fill_bytes_via_next(self, destination);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

fn profile() -> AssuranceProfile {
    AssuranceProfile {
        source: SourceAssurance::synthetic_replay(),
        collector_key: CollectorKeyAssurance::software(),
        boot_state: BootStateAssurance::unknown(),
        pipeline: PipelineAssurance::self_declared(),
        freshness: FreshnessAssurance::appraised_verifier_challenge(),
    }
}

fn token_key_id(root: [u8; 32]) -> [u8; 8] {
    TokenIssuer::new(CryptographicRootSecret::new(root), EPOCH, &[SERVICE])
        .unwrap()
        .verifier_material(SERVICE)
        .unwrap()
        .key_id()
        .0
}

fn validated_lease(atv2_key_id: [u8; 8], nonce_byte: u8) -> ValidatedProvenanceLease {
    let actual = profile();
    let attester = ReferenceSoftwareAttester::from_secret_bytes([7; 32]).unwrap();
    let challenge = VerifierChallenge::new([nonce_byte; 32]).unwrap();
    let verifier_only = VerifierOnlyClaims::new(b"k5-09-production".to_vec()).unwrap();
    let atv2_public_key_hash = [0x66; 32];
    let evidence = attester
        .sign(NeppClaims {
            challenge,
            service_alias: SERVICE_ALIAS,
            epoch: u64::from(EPOCH),
            pipeline: PIPELINE,
            assurance: actual.digest(),
            collector_session_public_key_hash: [0x44; 32],
            atv2_issuer_key_id: atv2_key_id,
            atv2_issuer_public_key_hash: atv2_public_key_hash,
            policy_hash: POLICY.0,
            created_public_slot: 96,
            expires_public_slot: 120,
            verifier_only_claims: verifier_only.digest(),
        })
        .unwrap();
    let expected = ExpectedBindings {
        challenge,
        service_alias: SERVICE_ALIAS,
        epoch: u64::from(EPOCH),
        pipeline: PIPELINE,
        atv2_issuer_key_id: atv2_key_id,
        atv2_issuer_public_key_hash: atv2_public_key_hash,
        policy_hash: POLICY.0,
        current_public_slot: 100,
    };
    let references = ReferenceValueStore::new(
        BTreeSet::from([attester.key_id()]),
        BTreeSet::new(),
        BTreeSet::from([PIPELINE]),
        BTreeSet::from([POLICY.0]),
        BTreeSet::new(),
        BTreeSet::from([(atv2_key_id, atv2_public_key_hash)]),
    )
    .unwrap();
    let mut challenges = ChallengeStore::new(4).unwrap();
    challenges.issue(challenge, 110).unwrap();
    let appraisal = ProvenanceAppraiser::new(references, challenges)
        .appraise(AppraisalRequest {
            evidence: &evidence,
            verifier_key: &attester.verifier(),
            expected: &expected,
            verifier_only_claims: &verifier_only,
            platform: PlatformEvidence::ReferenceSoftware,
            source: SourceEvidence::SyntheticReplay,
            minimum_assurance: actual,
        })
        .unwrap();
    let signing_key = LeaseSigningKey::from_secret_bytes([0x71; 32]);
    let verifier_key = signing_key.verifier_key();
    let issuer = ProvenanceLeaseIssuer::new(
        signing_key,
        LeaseIssuancePolicy {
            maximum_lifetime_slots: 15,
            schedule: PublicLeaseSchedule {
                period_slots: 10,
                phase_slot: 0,
            },
        },
    )
    .unwrap();
    let lease = issuer
        .issue(
            &appraisal,
            EPOCH,
            100,
            LeaseNonce::new([nonce_byte; 12]).unwrap(),
        )
        .unwrap();
    validate_lease(
        &lease,
        &verifier_key,
        ExpectedLeaseBindings {
            verifier_key_id: verifier_key.key_id(),
            service_alias: SERVICE_ALIAS,
            public_epoch: EPOCH,
            atv2_issuer_key_id: atv2_key_id,
            pipeline: PIPELINE,
            assurance: actual.digest(),
            policy_hash: POLICY.0,
            collector_session_public_key_hash: [0x44; 32],
            current_public_slot: 101,
        },
        &InMemoryLeaseReplayGuard::default(),
    )
    .unwrap()
}

fn private_feature(value: f64) -> PrivateFeatureVector {
    PrivateFeatureVector::new(vec![value; FeatureSchema::PpgAccV1.dimension()]).unwrap()
}

fn evidence_engine(context: ContextKey) -> EvidenceEngine {
    let mut builder = AnchorBaselineBuilder::new(BaselineConfig {
        minimum_reference_samples: 8,
        minimum_calibration_samples: 8,
        scale_floor: 1e-6,
        z_cap: 20.0,
    })
    .unwrap();
    for index in 0..8 {
        builder.add_reference(index, private_feature(index as f64 * 1e-7));
        builder.add_calibration(index + 100, private_feature(index as f64 * 1e-7));
    }
    let mut registry = BaselineRegistry::new(None);
    registry.insert(context, builder.build(1).unwrap());
    EvidenceEngine::new(
        EngineConfig {
            evidence: EvidenceConfig {
                alpha_total: 0.9,
                max_monitoring_steps: 64,
                power_epsilons: vec![0.1],
                power_weights: vec![1.0],
            },
            persistence: PersistenceConfig {
                window: 1,
                required_hits: 1,
                p_max: 1.0,
            },
            contexts: vec![ContextConfig {
                id: "monitoring".into(),
                alpha_weight: 1.0,
                fallback: false,
            }],
            permit_ttl_slots: 12,
        },
        registry,
        vec![(context, 1.0)],
        ActionCode::MenfuguInflateSoft,
        POLICY,
    )
    .unwrap()
}

fn acquisition(id: SessionId) -> AcquisitionSession {
    let ppg = NegotiatedPpgSettings::new(100, 22, 4).unwrap();
    let acc = NegotiatedAccSettings::new(100, 16, 3).unwrap();
    let mut session = AcquisitionSession::start(
        id,
        SessionPhase::Monitoring,
        SourceDescriptor::replay(),
        Some(ppg),
        Some(acc),
        SessionConfig::default(),
    )
    .unwrap();
    let ppg_samples = (0..2_000)
        .flat_map(|frame| {
            let value = ((frame % 25) - 12) * 2_000;
            [value, -value, value + 100, -value - 100]
        })
        .collect();
    let acc_samples = (0..2_000).flat_map(|_| [10, -10, 20]).collect();
    session
        .ingest_ppg(PrivatePpgBatch::new(1_000, 1_000, ppg.period_ns(), ppg, ppg_samples).unwrap())
        .unwrap();
    session
        .ingest_acc(PrivateAccBatch::new(1_000, 1_000, acc.period_ns(), acc, acc_samples).unwrap())
        .unwrap();
    session
}

fn admission(atv2_key_id: [u8; 8], nonce_byte: u8) -> ProductionAdmission {
    let id = SessionId::new([nonce_byte; 16]).unwrap();
    let context = ContextKey::opaque(b"k5-09-production");
    let mut bridge = EvidenceBridge::new(
        id,
        FeatureSchema::PpgAccV1.id(),
        context,
        104,
        evidence_engine(context),
    )
    .unwrap();
    let mut source = acquisition(id);
    let mut rng = FixedRng(7);
    for _ in 0..8 {
        let window = source.extract_next_feature_window().unwrap();
        let _ = bridge.process(window, &mut rng);
        if bridge.has_pending_internal_permit() {
            break;
        }
    }
    assert!(bridge.has_pending_internal_permit());
    bridge
        .take_production_admission(validated_lease(atv2_key_id, nonce_byte), profile())
        .unwrap()
}

fn bindings(minimum_assurance: AssuranceProfile) -> ProductionBindings {
    ProductionBindings {
        service: SERVICE,
        lease_service_alias: SERVICE_ALIAS,
        public_epoch: EPOCH,
        pipeline: PIPELINE,
        policy_hash: POLICY,
        minimum_assurance,
    }
}

fn issuer(root: [u8; 32], minimum: AssuranceProfile) -> ProductionTokenIssuer {
    ProductionTokenIssuer::new(CryptographicRootSecret::new(root), bindings(minimum)).unwrap()
}

fn obligation(deadline: u64) -> ActionObligation {
    ActionObligation {
        service: SERVICE,
        action: ActionCode::MenfuguInflateSoft,
        public_bucket: BucketId(1),
        admission_cutoff: LogicalSlot(103),
        release_window_start: LogicalSlot(104),
        release_deadline: LogicalSlot(deadline),
        max_uses: 1,
        policy_hash: POLICY,
    }
}

fn identity(sequence: u32, slot: u64) -> PublicFrameIdentity {
    PublicFrameIdentity {
        service: SERVICE,
        public_epoch: EPOCH,
        public_bucket: 1,
        slot_in_bucket: 1,
        sequence,
        absolute_slot: LogicalSlot(slot),
    }
}

fn kind(bytes: &[u8]) -> FrameKind {
    AtypicalityTokenEnvelope::from_slice(bytes)
        .unwrap()
        .outer()
        .unwrap()
        .kind
}

#[test]
fn valid_admission_emits_one_action_then_falls_back_to_cover() {
    let root = [0x55; 32];
    let issuer = issuer(root, AssuranceProfile::lab_reference());
    issuer.arm(admission(token_key_id(root), 1)).unwrap();
    let obligation = obligation(110);
    let claim = required_claim(obligation.action);
    let first = FrameIssuer::issue_action(&issuer, identity(1, 105), &obligation, claim).unwrap();
    let second = FrameIssuer::issue_action(&issuer, identity(2, 106), &obligation, claim).unwrap();
    assert_eq!(kind(&first), FrameKind::Action);
    assert_eq!(kind(&second), FrameKind::Cover);
}

#[test]
fn no_lease_expiry_wrong_key_and_downgrade_produce_zero_actions() {
    let obligation = obligation(120);
    let claim = required_claim(obligation.action);

    let no_lease = issuer([0x21; 32], AssuranceProfile::lab_reference());
    let frame = FrameIssuer::issue_action(&no_lease, identity(1, 105), &obligation, claim).unwrap();
    assert_eq!(kind(&frame), FrameKind::Cover);

    let root = [0x22; 32];
    let expired = issuer(root, AssuranceProfile::lab_reference());
    expired.arm(admission(token_key_id(root), 2)).unwrap();
    let frame = FrameIssuer::issue_action(&expired, identity(2, 116), &obligation, claim).unwrap();
    assert_eq!(kind(&frame), FrameKind::Cover);

    let wrong_key = issuer([0x23; 32], AssuranceProfile::lab_reference());
    assert_eq!(
        wrong_key.arm(admission(token_key_id([0x24; 32]), 3)),
        Err(ProductionGuardError::WrongAtv2Key)
    );
    let frame =
        FrameIssuer::issue_action(&wrong_key, identity(3, 105), &obligation, claim).unwrap();
    assert_eq!(kind(&frame), FrameKind::Cover);

    let root = [0x25; 32];
    let stronger_minimum = AssuranceProfile {
        source: SourceAssurance::paired_commercial_sensor(),
        ..AssuranceProfile::lab_reference()
    };
    let downgrade = issuer(root, stronger_minimum);
    assert_eq!(
        downgrade.arm(admission(token_key_id(root), 4)),
        Err(ProductionGuardError::AssuranceBelowMinimum)
    );
}

#[test]
fn rejected_action_keeps_the_complete_cover_schedule() {
    let issuer = issuer([0x31; 32], AssuranceProfile::lab_reference());
    let action = ActionObligation {
        public_bucket: BucketId(0),
        admission_cutoff: LogicalSlot(103),
        release_window_start: LogicalSlot(104),
        release_deadline: LogicalSlot(107),
        ..obligation(107)
    };
    let semantics = ActionSemantics::new(vec![action]).unwrap();
    let plan = TokenPlan::from_action_semantics(&semantics, vec![SERVICE]).unwrap();
    let context = PublicContext {
        schedule: ChannelSchedule {
            buckets: 1,
            slots_per_bucket: 4,
            frame_interval_ms: 250,
            fixed_plaintext_size: 160,
            fixed_ciphertext_size: ENVELOPE_SIZE as u16,
        },
        network: PublicNetworkTape {
            services: vec![SERVICE],
            public_epoch: EPOCH,
            start_slot: LogicalSlot(104),
        },
    };
    let trace =
        ActionEquivalentTraceShaper::shape(&plan, &context, &ScheduleRandomTape([7; 32]), &issuer)
            .unwrap();
    assert_eq!(trace.frames.len(), 4);
    assert!(trace
        .frames
        .iter()
        .all(|frame| kind(&frame.bytes) == FrameKind::Cover));
}

#[derive(Default)]
struct RecordingPump {
    enabled: bool,
    starts: u32,
}

impl PumpOutput for RecordingPump {
    fn set_pump(&mut self, enabled: bool) {
        if enabled && !self.enabled {
            self.starts += 1;
        }
        self.enabled = enabled;
    }
}

#[test]
fn valid_production_action_crosses_ble_reassembly_and_menfugu_once() {
    let root = [0x61; 32];
    let issuer = issuer(root, AssuranceProfile::lab_reference());
    issuer.arm(admission(token_key_id(root), 5)).unwrap();
    let obligation = obligation(110);
    let claim: ClaimBound = required_claim(obligation.action);
    let bytes = FrameIssuer::issue_action(&issuer, identity(7, 105), &obligation, claim).unwrap();
    assert_eq!(kind(&bytes), FrameKind::Action);
    let envelope = AtypicalityTokenEnvelope::from_slice(&bytes).unwrap();
    let outer = envelope.outer().unwrap();
    let transport_identity = TransportFrameIdentity {
        service_alias: outer.service_alias.0,
        public_epoch: outer.public_epoch,
        public_bucket: outer.public_bucket,
        sequence: outer.sequence,
    };
    let frame_id = derive_frame_id(&TransportIdKey::new([0x77; 32]), transport_identity);
    let fragments = fragment_envelope(envelope.as_bytes(), frame_id);
    let trace = simulate(
        &fragments,
        0,
        1,
        &PublicLossTape::from_indices(&[]).unwrap(),
    );

    let mut registry = KeyRegistry::default();
    registry
        .insert(issuer.verifier_material().unwrap())
        .unwrap();
    let mut policies = PolicyAllowlist::default();
    policies
        .allow(
            POLICY,
            obligation.action,
            claim,
            semantics_tag(&obligation, claim),
        )
        .unwrap();
    let verifier = TokenVerifier::new(
        registry,
        policies,
        RevocationSnapshot::default(),
        Arc::new(InMemoryReplayStore::default()),
    );
    let adapter = HostVerifierAdapter::new(verifier, SERVICE, EPOCH);
    let mut runtime = MenfuguRuntime::<_, _, 4, 16>::new(
        adapter,
        RecordingPump::default(),
        100,
        ExecutionPolicy {
            pump_ticks: 3,
            maximum_pump_ticks: 10,
            cooldown_slots: 1,
            execution_period_slots: 1,
            execution_offset_slots: 0,
        },
    )
    .unwrap();
    let mut starts = 0;
    for observation in &trace.observations {
        if matches!(
            runtime.on_gatt_write(&observation.wire, observation.scheduled_tick, 105),
            RuntimeEvent::PumpStarted { .. }
        ) {
            starts += 1;
        }
    }
    assert_eq!(starts, 1);
    assert_eq!(runtime.pump().starts, 1);
}
