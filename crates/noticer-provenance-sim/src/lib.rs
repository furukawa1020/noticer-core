#![forbid(unsafe_code)]

//! Deterministic counterfactual simulator for action- and
//! provenance-equivalent private acquisition histories.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
};

use noticer_acquisition_core::{
    AcquisitionSession, NegotiatedAccSettings, NegotiatedPpgSettings, PrivateAccBatch,
    PrivatePpgBatch, SessionConfig, SessionId, SessionPhase, SourceDescriptor,
};
use noticer_aetp::{
    ActionObligation, ActionSemantics, BucketId, ChannelSchedule, ClaimBound, PublicContext,
    PublicNetworkTape, ScheduleRandomTape, ServiceBinding,
};
use noticer_baseline::{
    AnchorBaselineBuilder, BaselineConfig, BaselineRegistry, ContextKey, PrivateFeatureVector,
};
use noticer_crypto::CryptographicRootSecret;
use noticer_evidence::{
    ContextConfig, EngineConfig, EvidenceConfig, EvidenceEngine, PersistenceConfig,
};
use noticer_evidence_bridge::{EvidenceBridge, ProductionAdmission};
use noticer_nepp::{
    ChallengeStore, ExpectedBindings, NeppClaims, PairwiseServiceAlias, ReferenceSoftwareAttester,
    VerifierChallenge, VerifierOnlyClaims,
};
use noticer_ppg_features::FeatureSchema;
use noticer_protocol::{AtypicalityTokenEnvelope, ENVELOPE_SIZE};
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
    AppraisalRequest, AppraisedProvenance, PlatformEvidence, ProvenanceAppraiser,
    ReferenceValueStore, SourceEvidence,
};
use noticer_release::TokenPlan;
use noticer_token::{ProductionBindings, ProductionTokenIssuer};
use noticer_trace_shaper::{
    ActionEquivalentTraceShaper, FrameIssueError, FrameIssuer, NetworkTrace, PublicFrameIdentity,
};
use noticer_transport_core::{
    derive_frame_id, fragment_envelope, TransportFrameIdentity, TransportIdKey,
};
use noticer_transport_sim::{observer_traces_are_equal, simulate, PublicLossTape};
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use rand_core::{impls, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SIMULATION_SCHEMA: &str = "noticer-aepa-counterfactual-v1";
pub const FAMILY_COUNT: usize = 6;
pub const DEFAULT_PUBLIC_EPOCHS: [u32; 4] = [1, 4, 16, 64];
const PIPELINE: PipelineMeasurementHash = PipelineMeasurementHash([0x33; 32]);
const ACTION_SLOT_START: u64 = 200;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CounterfactualFamily {
    P0EarlySlow,
    P1HighNearThreshold,
    P2RawMorphology,
    P3ExactSampleCount,
    P4ExactAcquisitionTiming,
    P5PrivateContextPath,
}

impl CounterfactualFamily {
    pub const ALL: [Self; FAMILY_COUNT] = [
        Self::P0EarlySlow,
        Self::P1HighNearThreshold,
        Self::P2RawMorphology,
        Self::P3ExactSampleCount,
        Self::P4ExactAcquisitionTiming,
        Self::P5PrivateContextPath,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::P0EarlySlow => "P0",
            Self::P1HighNearThreshold => "P1",
            Self::P2RawMorphology => "P2",
            Self::P3ExactSampleCount => "P3",
            Self::P4ExactAcquisitionTiming => "P4",
            Self::P5PrivateContextPath => "P5",
        }
    }

    const fn ordinal(self) -> u8 {
        match self {
            Self::P0EarlySlow => 0,
            Self::P1HighNearThreshold => 1,
            Self::P2RawMorphology => 2,
            Self::P3ExactSampleCount => 3,
            Self::P4ExactAcquisitionTiming => 4,
            Self::P5PrivateContextPath => 5,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationConfig {
    pub seed: u64,
    pub services: Vec<ServiceBinding>,
    pub public_epochs: Vec<u32>,
}

impl SimulationConfig {
    pub fn full(seed: u64) -> Self {
        Self {
            seed,
            services: vec![
                ServiceBinding([0x11; 16]),
                ServiceBinding([0x22; 16]),
                ServiceBinding([0x33; 16]),
            ],
            public_epochs: DEFAULT_PUBLIC_EPOCHS.to_vec(),
        }
    }

    fn validate(&self) -> Result<(), SimulationError> {
        let services: BTreeSet<_> = self.services.iter().copied().collect();
        let epochs: BTreeSet<_> = self.public_epochs.iter().copied().collect();
        if self.services.is_empty()
            || self.public_epochs.is_empty()
            || services.len() != self.services.len()
            || epochs.len() != self.public_epochs.len()
            || self.public_epochs.contains(&0)
        {
            return Err(SimulationError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CongruenceRates {
    pub pointwise_provenance: f64,
    pub lease: f64,
    pub atv2_trace: f64,
    pub k4_trace: f64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CounterfactualWitness {
    pub family: &'static str,
    pub public_epoch: u32,
    pub service_count: usize,
    pub private_inputs_distinct: bool,
    pub pointwise_provenance_congruent: bool,
    pub lease_equal: bool,
    pub atv2_trace_equal: bool,
    pub k4_trace_equal: bool,
    pub provenance_sha256: String,
    pub lease_sha256: String,
    pub atv2_trace_sha256: String,
    pub k4_trace_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SimulationReport {
    pub schema: &'static str,
    pub seed: u64,
    pub families: usize,
    pub service_count: usize,
    pub public_epochs: Vec<u32>,
    pub case_count: usize,
    pub all_private_inputs_distinct: bool,
    pub all_congruent: bool,
    pub rates: CongruenceRates,
    pub witnesses: Vec<CounterfactualWitness>,
}

impl SimulationReport {
    pub fn write_artifacts(&self, output: &Path) -> Result<(), SimulationError> {
        fs::create_dir_all(output)?;
        fs::write(
            output.join("summary.json"),
            serde_json::to_vec_pretty(self)?,
        )?;
        let mut writer = csv::Writer::from_path(output.join("witnesses.csv"))?;
        for witness in &self.witnesses {
            writer.serialize(witness)?;
        }
        writer.flush()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PrivateHistory {
    evidence_slot_base: u64,
    amplitude: i32,
    morphology: u8,
    sample_count: usize,
    acquisition_clock: u64,
    context_path: u8,
}

impl fmt::Debug for PrivateHistory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateHistory(REDACTED)")
    }
}

#[derive(Clone, Copy)]
struct PrivatePair {
    left: PrivateHistory,
    right: PrivateHistory,
}

impl PrivatePair {
    fn is_distinct(self) -> bool {
        self.left != self.right
    }
}

pub fn run(config: &SimulationConfig) -> Result<SimulationReport, SimulationError> {
    config.validate()?;
    let mut witnesses = Vec::with_capacity(FAMILY_COUNT * config.public_epochs.len());
    for family in CounterfactualFamily::ALL {
        let pair = private_pair(family);
        for public_epoch in &config.public_epochs {
            witnesses.push(run_case(
                config.seed,
                family,
                pair,
                *public_epoch,
                &config.services,
            )?);
        }
    }
    let case_count = witnesses.len();
    let rate = |predicate: fn(&CounterfactualWitness) -> bool| -> f64 {
        witnesses
            .iter()
            .filter(|witness| predicate(witness))
            .count() as f64
            / case_count as f64
    };
    let all_private_inputs_distinct = witnesses
        .iter()
        .all(|witness| witness.private_inputs_distinct);
    let all_congruent = witnesses.iter().all(|witness| {
        witness.pointwise_provenance_congruent
            && witness.lease_equal
            && witness.atv2_trace_equal
            && witness.k4_trace_equal
    });
    Ok(SimulationReport {
        schema: SIMULATION_SCHEMA,
        seed: config.seed,
        families: FAMILY_COUNT,
        service_count: config.services.len(),
        public_epochs: config.public_epochs.clone(),
        case_count,
        all_private_inputs_distinct,
        all_congruent,
        rates: CongruenceRates {
            pointwise_provenance: rate(|witness| witness.pointwise_provenance_congruent),
            lease: rate(|witness| witness.lease_equal),
            atv2_trace: rate(|witness| witness.atv2_trace_equal),
            k4_trace: rate(|witness| witness.k4_trace_equal),
        },
        witnesses,
    })
}

fn run_case(
    seed: u64,
    family: CounterfactualFamily,
    pair: PrivatePair,
    public_epoch: u32,
    services: &[ServiceBinding],
) -> Result<CounterfactualWitness, SimulationError> {
    let actual_assurance = simulation_profile();
    let mut left_issuers = BTreeMap::new();
    let mut right_issuers = BTreeMap::new();
    let mut obligations = Vec::with_capacity(services.len());
    let mut provenance_hasher = Sha256::new();
    provenance_hasher.update(b"NOTICER_AEPA_PROVENANCE_WITNESS_V1");
    let mut lease_hasher = Sha256::new();
    lease_hasher.update(b"NOTICER_AEPA_LEASE_WITNESS_V1");
    let mut pointwise_provenance_congruent = true;
    let mut lease_equal = true;

    for (service_index, service) in services.iter().copied().enumerate() {
        let root = root_secret(seed, family, public_epoch, service_index);
        let bindings = production_bindings(service, service_index, public_epoch);
        let left_issuer = ProductionTokenIssuer::new(CryptographicRootSecret::new(root), bindings)
            .map_err(pipeline_error)?;
        let right_issuer = ProductionTokenIssuer::new(CryptographicRootSecret::new(root), bindings)
            .map_err(pipeline_error)?;
        let atv2_key_id = left_issuer
            .verifier_material()
            .ok_or_else(|| SimulationError::Pipeline("missing ATv2 verifier material".into()))?
            .key_id()
            .0;
        if right_issuer
            .verifier_material()
            .ok_or_else(|| SimulationError::Pipeline("missing ATv2 verifier material".into()))?
            .key_id()
            .0
            != atv2_key_id
        {
            return Err(SimulationError::Pipeline(
                "coupled ATv2 keys diverged".into(),
            ));
        }
        let left_provenance = build_provenance(
            seed,
            family,
            service_index,
            public_epoch,
            atv2_key_id,
            bindings,
            actual_assurance,
        )?;
        let right_provenance = build_provenance(
            seed,
            family,
            service_index,
            public_epoch,
            atv2_key_id,
            bindings,
            actual_assurance,
        )?;
        pointwise_provenance_congruent &= left_provenance.nepp == right_provenance.nepp
            && left_provenance.appraisal == right_provenance.appraisal;
        lease_equal &= left_provenance.lease == right_provenance.lease;
        provenance_hasher.update(&left_provenance.nepp);
        provenance_hasher.update(left_provenance.appraisal);
        lease_hasher.update(&left_provenance.lease);

        let left_admission = build_admission(
            pair.left,
            service,
            service_index,
            public_epoch,
            bindings.policy_hash,
            left_provenance.validated,
            actual_assurance,
        )?;
        let right_admission = build_admission(
            pair.right,
            service,
            service_index,
            public_epoch,
            bindings.policy_hash,
            right_provenance.validated,
            actual_assurance,
        )?;
        left_issuer.arm(left_admission).map_err(pipeline_error)?;
        right_issuer.arm(right_admission).map_err(pipeline_error)?;
        left_issuers.insert(service, left_issuer);
        right_issuers.insert(service, right_issuer);
        obligations.push(ActionObligation {
            service,
            action: ActionCode::MenfuguInflateSoft,
            public_bucket: BucketId(0),
            admission_cutoff: LogicalSlot(ACTION_SLOT_START - 1),
            release_window_start: LogicalSlot(ACTION_SLOT_START),
            release_deadline: LogicalSlot(ACTION_SLOT_START + 3),
            max_uses: 1,
            policy_hash: bindings.policy_hash,
        });
    }

    let semantics = ActionSemantics::new(obligations).map_err(pipeline_error)?;
    let plan =
        TokenPlan::from_action_semantics(&semantics, services.to_vec()).map_err(pipeline_error)?;
    let context = public_context(public_epoch, services);
    let schedule_tape = ScheduleRandomTape(schedule_secret(seed, family, public_epoch));
    let left_trace = ActionEquivalentTraceShaper::shape(
        &plan,
        &context,
        &schedule_tape,
        &MultiServiceIssuer(left_issuers),
    )
    .map_err(pipeline_error)?;
    let right_trace = ActionEquivalentTraceShaper::shape(
        &plan,
        &context,
        &schedule_tape,
        &MultiServiceIssuer(right_issuers),
    )
    .map_err(pipeline_error)?;
    let atv2_trace_equal = left_trace == right_trace;
    let atv2_trace_sha256 = hex(&left_trace.digest());
    let (k4_trace_equal, k4_trace_sha256) =
        transport_witness(seed, public_epoch, &left_trace, &right_trace)?;

    Ok(CounterfactualWitness {
        family: family.code(),
        public_epoch,
        service_count: services.len(),
        private_inputs_distinct: pair.is_distinct(),
        pointwise_provenance_congruent,
        lease_equal,
        atv2_trace_equal,
        k4_trace_equal,
        provenance_sha256: hex(&provenance_hasher.finalize()),
        lease_sha256: hex(&lease_hasher.finalize()),
        atv2_trace_sha256,
        k4_trace_sha256,
    })
}

struct ProvenanceRun {
    nepp: Vec<u8>,
    appraisal: [u8; 32],
    lease: Vec<u8>,
    validated: ValidatedProvenanceLease,
}

#[allow(clippy::too_many_arguments)]
fn build_provenance(
    seed: u64,
    family: CounterfactualFamily,
    service_index: usize,
    public_epoch: u32,
    atv2_key_id: [u8; 8],
    bindings: ProductionBindings,
    actual_assurance: AssuranceProfile,
) -> Result<ProvenanceRun, SimulationError> {
    let material = public_material_byte(seed, family, public_epoch, service_index);
    let attester =
        ReferenceSoftwareAttester::from_secret_bytes([material; 32]).map_err(pipeline_error)?;
    let challenge =
        VerifierChallenge::new([material.wrapping_add(1); 32]).map_err(pipeline_error)?;
    let verifier_only =
        VerifierOnlyClaims::new(b"aepa-counterfactual-v1".to_vec()).map_err(pipeline_error)?;
    let atv2_public_key_hash = public_hash(
        b"NOTICER_AEPA_SIM_ATV2_PUBLIC_KEY",
        &[
            &atv2_key_id,
            &public_epoch.to_be_bytes(),
            &[service_index as u8],
        ],
    );
    let collector_session_public_key_hash = public_hash(
        b"NOTICER_AEPA_SIM_COLLECTOR_SESSION",
        &[
            &public_epoch.to_be_bytes(),
            &[service_index as u8],
            &seed.to_be_bytes(),
        ],
    );
    let evidence = attester
        .sign(NeppClaims {
            challenge,
            service_alias: bindings.lease_service_alias,
            epoch: u64::from(public_epoch),
            pipeline: bindings.pipeline,
            assurance: actual_assurance.digest(),
            collector_session_public_key_hash,
            atv2_issuer_key_id: atv2_key_id,
            atv2_issuer_public_key_hash: atv2_public_key_hash,
            policy_hash: bindings.policy_hash.0,
            created_public_slot: 180,
            expires_public_slot: 230,
            verifier_only_claims: verifier_only.digest(),
        })
        .map_err(pipeline_error)?;
    let expected = ExpectedBindings {
        challenge,
        service_alias: bindings.lease_service_alias,
        epoch: u64::from(public_epoch),
        pipeline: bindings.pipeline,
        atv2_issuer_key_id: atv2_key_id,
        atv2_issuer_public_key_hash: atv2_public_key_hash,
        policy_hash: bindings.policy_hash.0,
        current_public_slot: 190,
    };
    let references = ReferenceValueStore::new(
        BTreeSet::from([attester.key_id()]),
        BTreeSet::new(),
        BTreeSet::from([bindings.pipeline]),
        BTreeSet::from([bindings.policy_hash.0]),
        BTreeSet::new(),
        BTreeSet::from([(atv2_key_id, atv2_public_key_hash)]),
    )
    .map_err(pipeline_error)?;
    let mut challenges = ChallengeStore::new(4).map_err(pipeline_error)?;
    challenges.issue(challenge, 200).map_err(pipeline_error)?;
    let appraisal = ProvenanceAppraiser::new(references, challenges)
        .appraise(AppraisalRequest {
            evidence: &evidence,
            verifier_key: &attester.verifier(),
            expected: &expected,
            verifier_only_claims: &verifier_only,
            platform: PlatformEvidence::ReferenceSoftware,
            source: SourceEvidence::SyntheticReplay,
            minimum_assurance: actual_assurance,
        })
        .map_err(pipeline_error)?;
    let appraisal_digest = appraised_digest(&appraisal);
    let lease_signing_key = LeaseSigningKey::from_secret_bytes([material.wrapping_add(2); 32]);
    let lease_verifier_key = lease_signing_key.verifier_key();
    let lease_issuer = ProvenanceLeaseIssuer::new(
        lease_signing_key,
        LeaseIssuancePolicy {
            maximum_lifetime_slots: 30,
            schedule: PublicLeaseSchedule {
                period_slots: 10,
                phase_slot: 0,
            },
        },
    )
    .map_err(pipeline_error)?;
    let lease = lease_issuer
        .issue(
            &appraisal,
            public_epoch,
            190,
            LeaseNonce::new([material.wrapping_add(3); 12]).map_err(pipeline_error)?,
        )
        .map_err(pipeline_error)?;
    let lease_bytes = lease.as_bytes().to_vec();
    let validated = validate_lease(
        &lease,
        &lease_verifier_key,
        ExpectedLeaseBindings {
            verifier_key_id: lease_verifier_key.key_id(),
            service_alias: bindings.lease_service_alias,
            public_epoch,
            atv2_issuer_key_id: atv2_key_id,
            pipeline: bindings.pipeline,
            assurance: actual_assurance.digest(),
            policy_hash: bindings.policy_hash.0,
            collector_session_public_key_hash,
            current_public_slot: 191,
        },
        &InMemoryLeaseReplayGuard::default(),
    )
    .map_err(pipeline_error)?;
    Ok(ProvenanceRun {
        nepp: evidence.as_bytes().to_vec(),
        appraisal: appraisal_digest,
        lease: lease_bytes,
        validated,
    })
}

fn appraised_digest(appraisal: &AppraisedProvenance) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"NOTICER_AEPA_APPRAISAL_WITNESS_V1");
    digest.update(appraisal.profile().digest().0);
    digest.update(appraisal.collector_key_id().as_bytes());
    digest.update(appraisal.pipeline().0);
    digest.update(appraisal.service_alias().0);
    digest.update(appraisal.epoch().to_be_bytes());
    digest.update(appraisal.atv2_issuer_key_id());
    digest.update(appraisal.collector_session_public_key_hash());
    digest.update(appraisal.policy_hash());
    digest.update(appraisal.created_public_slot().to_be_bytes());
    digest.update(appraisal.expires_public_slot().to_be_bytes());
    digest.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn build_admission(
    history: PrivateHistory,
    service: ServiceBinding,
    service_index: usize,
    public_epoch: u32,
    policy_hash: PolicyHash,
    lease: ValidatedProvenanceLease,
    actual_assurance: AssuranceProfile,
) -> Result<ProductionAdmission, SimulationError> {
    let session_id = private_session_id(history, service, public_epoch)?;
    let context = private_context(history, service_index);
    let mut bridge = EvidenceBridge::new(
        session_id,
        FeatureSchema::PpgAccV1.id(),
        context,
        history.evidence_slot_base,
        evidence_engine(context, policy_hash)?,
    )
    .map_err(pipeline_error)?;
    let mut source = acquisition(history, session_id)?;
    let mut rng = FixedRng(7);
    for _ in 0..8 {
        let window = source
            .extract_next_feature_window()
            .map_err(pipeline_error)?;
        let _ = bridge.process(window, &mut rng);
        if bridge.has_pending_internal_permit() {
            break;
        }
    }
    if !bridge.has_pending_internal_permit() {
        return Err(SimulationError::Pipeline(
            "counterfactual history did not yield a K1 permit".into(),
        ));
    }
    bridge
        .take_production_admission(lease, actual_assurance)
        .map_err(pipeline_error)
}

fn evidence_engine(
    context: ContextKey,
    policy_hash: PolicyHash,
) -> Result<EvidenceEngine, SimulationError> {
    let mut builder = AnchorBaselineBuilder::new(BaselineConfig {
        minimum_reference_samples: 8,
        minimum_calibration_samples: 8,
        scale_floor: 1e-6,
        z_cap: 20.0,
    })
    .map_err(pipeline_error)?;
    for index in 0..8 {
        let value = index as f64 * 1e-7;
        builder.add_reference(index, private_feature(value)?);
        builder.add_calibration(index + 100, private_feature(value)?);
    }
    let mut registry = BaselineRegistry::new(None);
    registry.insert(context, builder.build(1).map_err(pipeline_error)?);
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
            permit_ttl_slots: 64,
        },
        registry,
        vec![(context, 1.0)],
        ActionCode::MenfuguInflateSoft,
        policy_hash,
    )
    .map_err(pipeline_error)
}

fn private_feature(value: f64) -> Result<PrivateFeatureVector, SimulationError> {
    PrivateFeatureVector::new(vec![value; FeatureSchema::PpgAccV1.dimension()])
        .map_err(pipeline_error)
}

fn acquisition(
    history: PrivateHistory,
    session_id: SessionId,
) -> Result<AcquisitionSession, SimulationError> {
    let ppg = NegotiatedPpgSettings::new(100, 22, 4).map_err(pipeline_error)?;
    let acc = NegotiatedAccSettings::new(100, 16, 3).map_err(pipeline_error)?;
    let mut session = AcquisitionSession::start(
        session_id,
        SessionPhase::Monitoring,
        SourceDescriptor::replay(),
        Some(ppg),
        Some(acc),
        SessionConfig::default(),
    )
    .map_err(pipeline_error)?;
    let ppg_samples = (0..history.sample_count)
        .flat_map(|frame| {
            let phase = i32::try_from(frame % 25).unwrap_or(0) - 12;
            let value = if history.morphology == 0 {
                phase.saturating_mul(history.amplitude)
            } else if phase < 0 {
                history.amplitude.saturating_mul(-10)
            } else {
                history.amplitude.saturating_mul(10)
            };
            [value, -value, value + 100, -value - 100]
        })
        .collect();
    let acc_samples = (0..history.sample_count)
        .flat_map(|_| [10, -10, 20])
        .collect();
    session
        .ingest_ppg(
            PrivatePpgBatch::new(
                history.acquisition_clock,
                history.acquisition_clock,
                ppg.period_ns(),
                ppg,
                ppg_samples,
            )
            .map_err(pipeline_error)?,
        )
        .map_err(pipeline_error)?;
    session
        .ingest_acc(
            PrivateAccBatch::new(
                history.acquisition_clock,
                history.acquisition_clock,
                acc.period_ns(),
                acc,
                acc_samples,
            )
            .map_err(pipeline_error)?,
        )
        .map_err(pipeline_error)?;
    Ok(session)
}

fn private_pair(family: CounterfactualFamily) -> PrivatePair {
    let base = PrivateHistory {
        evidence_slot_base: 180,
        amplitude: 2_000,
        morphology: 0,
        sample_count: 2_000,
        acquisition_clock: 1_000,
        context_path: 1,
    };
    let mut left = base;
    let mut right = base;
    match family {
        CounterfactualFamily::P0EarlySlow => right.evidence_slot_base = 184,
        CounterfactualFamily::P1HighNearThreshold => right.amplitude = 900,
        CounterfactualFamily::P2RawMorphology => right.morphology = 1,
        CounterfactualFamily::P3ExactSampleCount => right.sample_count = 2_200,
        CounterfactualFamily::P4ExactAcquisitionTiming => right.acquisition_clock = 900_000,
        CounterfactualFamily::P5PrivateContextPath => {
            left.context_path = 7;
            right.context_path = 19;
        }
    }
    PrivatePair { left, right }
}

fn simulation_profile() -> AssuranceProfile {
    AssuranceProfile {
        source: SourceAssurance::synthetic_replay(),
        collector_key: CollectorKeyAssurance::software(),
        boot_state: BootStateAssurance::unknown(),
        pipeline: PipelineAssurance::self_declared(),
        freshness: FreshnessAssurance::appraised_verifier_challenge(),
    }
}

fn production_bindings(
    service: ServiceBinding,
    service_index: usize,
    public_epoch: u32,
) -> ProductionBindings {
    ProductionBindings {
        service,
        lease_service_alias: PairwiseServiceAlias([0x41 + service_index as u8; 16]),
        public_epoch,
        pipeline: PIPELINE,
        policy_hash: PolicyHash([0x51 + service_index as u8; 32]),
        minimum_assurance: AssuranceProfile::lab_reference(),
    }
}

fn public_context(public_epoch: u32, services: &[ServiceBinding]) -> PublicContext {
    PublicContext {
        schedule: ChannelSchedule {
            buckets: 2,
            slots_per_bucket: 4,
            frame_interval_ms: 250,
            fixed_plaintext_size: 160,
            fixed_ciphertext_size: ENVELOPE_SIZE as u16,
        },
        network: PublicNetworkTape {
            services: services.to_vec(),
            public_epoch,
            start_slot: LogicalSlot(ACTION_SLOT_START),
        },
    }
}

struct MultiServiceIssuer(BTreeMap<ServiceBinding, ProductionTokenIssuer>);

impl FrameIssuer for MultiServiceIssuer {
    fn frame_length(&self) -> usize {
        ENVELOPE_SIZE
    }

    fn issue_cover(&self, identity: PublicFrameIdentity) -> Result<Vec<u8>, FrameIssueError> {
        self.0
            .get(&identity.service)
            .ok_or(FrameIssueError)
            .and_then(|issuer| FrameIssuer::issue_cover(issuer, identity))
    }

    fn issue_action(
        &self,
        identity: PublicFrameIdentity,
        obligation: &ActionObligation,
        claim_bound: ClaimBound,
    ) -> Result<Vec<u8>, FrameIssueError> {
        self.0
            .get(&identity.service)
            .ok_or(FrameIssueError)
            .and_then(|issuer| FrameIssuer::issue_action(issuer, identity, obligation, claim_bound))
    }
}

fn transport_witness(
    seed: u64,
    public_epoch: u32,
    left: &NetworkTrace,
    right: &NetworkTrace,
) -> Result<(bool, String), SimulationError> {
    let loss = PublicLossTape::from_indices(&[2, 7]).map_err(pipeline_error)?;
    let id_key = TransportIdKey::new(public_hash(
        b"NOTICER_AEPA_SIM_TRANSPORT_KEY",
        &[&seed.to_be_bytes(), &public_epoch.to_be_bytes()],
    ));
    let mut digest = Sha256::new();
    digest.update(b"NOTICER_AEPA_K4_TRACE_WITNESS_V1");
    let mut equal = left.frames.len() == right.frames.len();
    for (ordinal, (left_frame, right_frame)) in left.frames.iter().zip(&right.frames).enumerate() {
        let left_envelope =
            AtypicalityTokenEnvelope::from_slice(&left_frame.bytes).map_err(pipeline_error)?;
        let right_envelope =
            AtypicalityTokenEnvelope::from_slice(&right_frame.bytes).map_err(pipeline_error)?;
        let left_outer = left_envelope.outer().map_err(pipeline_error)?;
        let right_outer = right_envelope.outer().map_err(pipeline_error)?;
        let left_id = derive_frame_id(
            &id_key,
            TransportFrameIdentity {
                service_alias: left_outer.service_alias.0,
                public_epoch: left_outer.public_epoch,
                public_bucket: left_outer.public_bucket,
                sequence: left_outer.sequence,
            },
        );
        let right_id = derive_frame_id(
            &id_key,
            TransportFrameIdentity {
                service_alias: right_outer.service_alias.0,
                public_epoch: right_outer.public_epoch,
                public_bucket: right_outer.public_bucket,
                sequence: right_outer.sequence,
            },
        );
        let left_fragments = fragment_envelope(left_envelope.as_bytes(), left_id);
        let right_fragments = fragment_envelope(right_envelope.as_bytes(), right_id);
        let start_tick = u64::try_from(ordinal)
            .unwrap_or(u64::MAX)
            .saturating_mul(100);
        let left_transport = simulate(&left_fragments, start_tick, 2, &loss);
        let right_transport = simulate(&right_fragments, start_tick, 2, &loss);
        equal &= observer_traces_are_equal(&left_transport, &right_transport);
        for observation in &left_transport.observations {
            digest.update([observation.ordinal]);
            digest.update(observation.scheduled_tick.to_be_bytes());
            digest.update(observation.frame_id);
            digest.update([observation.fragment_index, u8::from(observation.delivered)]);
            digest.update(observation.wire);
        }
    }
    Ok((equal, hex(&digest.finalize())))
}

fn private_session_id(
    history: PrivateHistory,
    service: ServiceBinding,
    public_epoch: u32,
) -> Result<SessionId, SimulationError> {
    let mut digest = Sha256::new();
    digest.update(b"NOTICER_AEPA_PRIVATE_SESSION_ID_V1");
    digest.update(history.evidence_slot_base.to_be_bytes());
    digest.update(history.amplitude.to_be_bytes());
    digest.update([history.morphology]);
    digest.update(history.sample_count.to_be_bytes());
    digest.update(history.acquisition_clock.to_be_bytes());
    digest.update([history.context_path]);
    digest.update(service.0);
    digest.update(public_epoch.to_be_bytes());
    let output = digest.finalize();
    SessionId::new(output[..16].try_into().expect("fixed digest prefix")).map_err(pipeline_error)
}

fn private_context(history: PrivateHistory, service_index: usize) -> ContextKey {
    ContextKey::opaque(&[
        b'K',
        b'5',
        history.context_path,
        u8::try_from(service_index).unwrap_or(u8::MAX),
    ])
}

fn root_secret(
    seed: u64,
    family: CounterfactualFamily,
    public_epoch: u32,
    service_index: usize,
) -> [u8; 32] {
    public_hash(
        b"NOTICER_AEPA_SIM_TOKEN_ROOT",
        &[
            &seed.to_be_bytes(),
            &[family.ordinal()],
            &public_epoch.to_be_bytes(),
            &[service_index as u8],
        ],
    )
}

fn schedule_secret(seed: u64, family: CounterfactualFamily, public_epoch: u32) -> [u8; 32] {
    public_hash(
        b"NOTICER_AEPA_SIM_SCHEDULE",
        &[
            &seed.to_be_bytes(),
            &[family.ordinal()],
            &public_epoch.to_be_bytes(),
        ],
    )
}

fn public_material_byte(
    seed: u64,
    family: CounterfactualFamily,
    public_epoch: u32,
    service_index: usize,
) -> u8 {
    1 + ((seed
        .wrapping_add(u64::from(family.ordinal()) * 7)
        .wrapping_add(u64::from(public_epoch))
        .wrapping_add(service_index as u64 * 11))
        % 60) as u8
}

fn public_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn pipeline_error(error: impl fmt::Debug) -> SimulationError {
    SimulationError::Pipeline(format!("{error:?}"))
}

#[derive(Debug, Error)]
pub enum SimulationError {
    #[error("simulation services and public epochs must be non-empty, unique, and non-zero")]
    InvalidConfig,
    #[error("counterfactual pipeline failed: {0}")]
    Pipeline(String),
    #[error("artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("CSV artifact encoding failed: {0}")]
    Csv(#[from] csv::Error),
    #[error("JSON artifact encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_families_epochs_and_services_are_pointwise_congruent() {
        let report = run(&SimulationConfig::full(2026)).unwrap();
        assert_eq!(report.case_count, 24);
        assert_eq!(report.service_count, 3);
        assert!(report.all_private_inputs_distinct);
        assert!(report.all_congruent);
        assert_eq!(report.rates.pointwise_provenance, 1.0);
        assert_eq!(report.rates.lease, 1.0);
        assert_eq!(report.rates.atv2_trace, 1.0);
        assert_eq!(report.rates.k4_trace, 1.0);
    }

    #[test]
    fn same_seed_is_reproducible() {
        let config = SimulationConfig {
            seed: 77,
            services: vec![ServiceBinding([0x11; 16])],
            public_epochs: vec![4],
        };
        assert_eq!(run(&config).unwrap(), run(&config).unwrap());
    }

    #[test]
    fn artifact_schema_excludes_private_acquisition_values() {
        let report = run(&SimulationConfig {
            seed: 88,
            services: vec![ServiceBinding([0x11; 16])],
            public_epochs: vec![1],
        })
        .unwrap();
        let artifact = serde_json::to_string(&report).unwrap().to_ascii_lowercase();
        for forbidden in [
            "raw_ppg",
            "raw_acc",
            "sample_count",
            "acquisition_clock",
            "context_path",
            "private_history",
            "private_baseline",
        ] {
            assert!(!artifact.contains(forbidden));
        }
    }
}
