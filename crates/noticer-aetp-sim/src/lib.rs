#![forbid(unsafe_code)]

use std::fmt;

use noticer_aetp::{
    ActionObligation, ActionSemantics, BucketId, PublicContext, RandomTape, ServiceBinding,
};
use noticer_trace_shaper::{
    trace_hash, ActionEquivalentTraceShaper, DecodedFrameKind, ShapedTrace, ShaperError,
};
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone)]
pub struct PrivatePermitCandidate {
    private_ready_slot: LogicalSlot,
    action: ActionCode,
    service: ServiceBinding,
    policy_hash: PolicyHash,
    valid: bool,
}

impl PrivatePermitCandidate {
    pub fn synthetic(
        private_ready_slot: LogicalSlot,
        action: ActionCode,
        service: ServiceBinding,
        policy_hash: PolicyHash,
    ) -> Self {
        Self {
            private_ready_slot,
            action,
            service,
            policy_hash,
            valid: true,
        }
    }

    pub fn invalid_for_test(mut self) -> Self {
        self.valid = false;
        self
    }
}

impl fmt::Debug for PrivatePermitCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivatePermitCandidate")
            .field("private_values", &"REDACTED")
            .finish()
    }
}

pub struct PrivateHistory {
    candidates: Vec<PrivatePermitCandidate>,
    evidence_trajectory: Vec<f64>,
    hidden_identity_signature: [u8; 16],
    private_context_trajectory: Vec<u8>,
    private_confidence: f64,
    public_epoch_expectation: u64,
}

impl PrivateHistory {
    pub fn synthetic(
        candidates: Vec<PrivatePermitCandidate>,
        evidence_trajectory: Vec<f64>,
        hidden_identity_signature: [u8; 16],
        private_context_trajectory: Vec<u8>,
        private_confidence: f64,
        public_epoch_expectation: u64,
    ) -> Self {
        Self {
            candidates,
            evidence_trajectory,
            hidden_identity_signature,
            private_context_trajectory,
            private_confidence,
            public_epoch_expectation,
        }
    }

    pub fn perturb_private_profile(
        &mut self,
        evidence_scale: f64,
        identity: [u8; 16],
        context: Vec<u8>,
        confidence: f64,
    ) {
        for value in &mut self.evidence_trajectory {
            *value *= evidence_scale;
        }
        self.hidden_identity_signature = identity;
        self.private_context_trajectory = context;
        self.private_confidence = confidence;
    }
}

impl fmt::Debug for PrivateHistory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateHistory")
            .field("private_values", &"REDACTED")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionTemplate {
    pub obligation: ActionObligation,
}

#[derive(Debug)]
pub struct AdmittedAction {
    semantics: ActionObligation,
}

impl AdmittedAction {
    pub fn into_semantics(self) -> ActionObligation {
        self.semantics
    }
}

pub fn admit(
    candidate: PrivatePermitCandidate,
    template: &ActionTemplate,
    current_slot: LogicalSlot,
) -> Result<AdmittedAction, AdmissionError> {
    if !candidate.valid
        || candidate.action != template.obligation.action
        || candidate.service != template.obligation.service
        || candidate.policy_hash != template.obligation.policy_hash
    {
        return Err(AdmissionError::InvalidCandidate);
    }
    if candidate.private_ready_slot.0 > template.obligation.admission_cutoff.0
        || current_slot.0 > template.obligation.admission_cutoff.0
    {
        return Err(AdmissionError::AfterCutoff);
    }
    Ok(AdmittedAction {
        semantics: template.obligation.clone(),
    })
}

#[derive(Clone, Debug)]
pub struct AdmissionPolicy {
    pub templates: Vec<ActionTemplate>,
}

impl AdmissionPolicy {
    pub fn from_semantics(semantics: &ActionSemantics) -> Self {
        Self {
            templates: semantics
                .obligations
                .iter()
                .cloned()
                .map(|obligation| ActionTemplate { obligation })
                .collect(),
        }
    }
}

fn admit_history(
    history: &PrivateHistory,
    policy: &AdmissionPolicy,
    public_context: &PublicContext,
) -> Result<ActionSemantics, EquivalenceError> {
    if history.public_epoch_expectation != public_context.public_epoch {
        return Err(EquivalenceError::PublicContextMismatch);
    }
    if history.candidates.len() != policy.templates.len() {
        return Err(EquivalenceError::NotEquivalent);
    }
    let mut obligations = Vec::with_capacity(policy.templates.len());
    for (candidate, template) in history.candidates.iter().cloned().zip(&policy.templates) {
        let admitted = admit(candidate, template, template.obligation.admission_cutoff)
            .map_err(|_| EquivalenceError::NotEquivalent)?;
        obligations.push(admitted.into_semantics());
    }
    let semantics = ActionSemantics { obligations };
    semantics
        .validate(public_context.channel_schedule)
        .map_err(|_| EquivalenceError::NotJointlyFeasible)?;
    Ok(semantics)
}

pub fn action_equivalent(
    h0: &PrivateHistory,
    h1: &PrivateHistory,
    policy: &AdmissionPolicy,
    public_context: &PublicContext,
) -> Result<ActionSemantics, EquivalenceError> {
    let left = admit_history(h0, policy, public_context)?;
    let right = admit_history(h1, policy, public_context)?;
    if left != right {
        return Err(EquivalenceError::NotEquivalent);
    }
    Ok(left)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PairFamily {
    EarlySpikeVsSlowDrift,
    HighMarginVsLowMargin,
    HiddenIdentitySignature,
    PrivateContextTrajectory,
    EvidenceDuration,
    MultiServiceCorrelatedEvidence,
}

impl PairFamily {
    pub const ALL: [Self; 6] = [
        Self::EarlySpikeVsSlowDrift,
        Self::HighMarginVsLowMargin,
        Self::HiddenIdentitySignature,
        Self::PrivateContextTrajectory,
        Self::EvidenceDuration,
        Self::MultiServiceCorrelatedEvidence,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EarlySpikeVsSlowDrift => "early_spike_vs_slow_drift",
            Self::HighMarginVsLowMargin => "high_margin_vs_low_margin",
            Self::HiddenIdentitySignature => "hidden_identity_signature",
            Self::PrivateContextTrajectory => "private_context_trajectory",
            Self::EvidenceDuration => "evidence_duration",
            Self::MultiServiceCorrelatedEvidence => "multi_service_correlated_evidence",
        }
    }
}

pub struct ActionEquivalentPair {
    pub pair_id: u64,
    pub family: PairFamily,
    pub h0: PrivateHistory,
    pub h1: PrivateHistory,
    pub shared_semantics: ActionSemantics,
    pub public_context: PublicContext,
    pub random_tape: RandomTape,
}

pub fn generate_action_equivalent_pairs(
    count: usize,
    services: usize,
    context: &PublicContext,
    seed: u64,
) -> Result<Vec<ActionEquivalentPair>, GeneratorError> {
    if count == 0 || services == 0 || services > 32 {
        return Err(GeneratorError::InvalidConfiguration);
    }
    let mut pairs = Vec::with_capacity(count);
    for pair_id in 0..count {
        let family = PairFamily::ALL[pair_id % PairFamily::ALL.len()];
        let semantics = semantics_for_context(services, context, pair_id as u64)?;
        let policy = AdmissionPolicy::from_semantics(&semantics);
        let (h0, h1) =
            histories_for_family(family, &semantics, context.public_epoch, pair_id as u64);
        action_equivalent(&h0, &h1, &policy, context)
            .map_err(|_| GeneratorError::PairNotEquivalent)?;
        let mut hash = Sha256::new();
        hash.update(b"NOTICER_AETP_PAIR_TAPE_V1");
        hash.update(seed.to_be_bytes());
        hash.update((pair_id as u64).to_be_bytes());
        pairs.push(ActionEquivalentPair {
            pair_id: pair_id as u64,
            family,
            h0,
            h1,
            shared_semantics: semantics,
            public_context: context.clone(),
            random_tape: RandomTape(hash.finalize().into()),
        });
    }
    Ok(pairs)
}

fn semantics_for_context(
    services: usize,
    context: &PublicContext,
    pair_id: u64,
) -> Result<ActionSemantics, GeneratorError> {
    let mut obligations = Vec::new();
    let slots = u64::from(context.channel_schedule.slots_per_bucket);
    for bucket in 0..u64::from(context.channel_schedule.buckets) {
        let bucket_start = bucket * slots;
        for service in 0..services {
            obligations.push(ActionObligation {
                service: ServiceBinding::from_u64(service as u64 + 1),
                action: match (pair_id + service as u64) % 3 {
                    0 => ActionCode::MenfuguInflateSoft,
                    1 => ActionCode::RenderAmbientPulse,
                    _ => ActionCode::RenderReviewPrompt,
                },
                public_bucket: BucketId(bucket),
                admission_cutoff: LogicalSlot(bucket_start + 7),
                release_window_start: LogicalSlot(bucket_start + 8),
                release_deadline: LogicalSlot(bucket_start + slots - 1),
                max_uses: 1,
                policy_hash: PolicyHash([(pair_id % 251) as u8; 32]),
            });
        }
    }
    let semantics = ActionSemantics { obligations };
    semantics
        .validate(context.channel_schedule)
        .map_err(|_| GeneratorError::InvalidConfiguration)?;
    Ok(semantics)
}

fn histories_for_family(
    family: PairFamily,
    semantics: &ActionSemantics,
    epoch: u64,
    pair_id: u64,
) -> (PrivateHistory, PrivateHistory) {
    let make_candidates = |late: bool| {
        semantics
            .obligations
            .iter()
            .map(|obligation| {
                let ready = if late {
                    obligation.admission_cutoff
                } else {
                    LogicalSlot(obligation.admission_cutoff.0.saturating_sub(6))
                };
                PrivatePermitCandidate::synthetic(
                    ready,
                    obligation.action,
                    obligation.service,
                    obligation.policy_hash,
                )
            })
            .collect()
    };
    let late = matches!(
        family,
        PairFamily::EarlySpikeVsSlowDrift | PairFamily::MultiServiceCorrelatedEvidence
    );
    let left = PrivateHistory::synthetic(
        make_candidates(false),
        vec![0.1, 1.0, 8.0],
        [pair_id as u8; 16],
        vec![1, 1, 2],
        0.99,
        epoch,
    );
    let right = PrivateHistory::synthetic(
        make_candidates(late),
        match family {
            PairFamily::EvidenceDuration => vec![0.2; 32],
            PairFamily::HighMarginVsLowMargin => vec![0.49, 0.51],
            _ => vec![0.1, 0.2, 0.4, 0.8],
        },
        [(pair_id as u8).wrapping_add(113); 16],
        vec![9, 7, 5, 3],
        0.51,
        epoch,
    );
    (left, right)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoupledTraceWitness {
    pub semantics_hash: [u8; 32],
    pub trace_hash_h0: [u8; 32],
    pub trace_hash_h1: [u8; 32],
    pub byte_identical: bool,
    pub service_identical: bool,
    pub collusion_identical: bool,
}

pub fn coupled_trace_witness(
    pair: &ActionEquivalentPair,
) -> Result<CoupledTraceWitness, AetpViolation> {
    let policy = AdmissionPolicy::from_semantics(&pair.shared_semantics);
    let semantics = action_equivalent(&pair.h0, &pair.h1, &policy, &pair.public_context)?;
    let left =
        ActionEquivalentTraceShaper::shape(&semantics, &pair.public_context, &pair.random_tape)?;
    let right =
        ActionEquivalentTraceShaper::shape(&semantics, &pair.public_context, &pair.random_tape)?;
    Ok(witness(&semantics, &left, &right))
}

fn witness(
    semantics: &ActionSemantics,
    left: &ShapedTrace,
    right: &ShapedTrace,
) -> CoupledTraceWitness {
    CoupledTraceWitness {
        semantics_hash: semantics.canonical_hash(),
        trace_hash_h0: trace_hash(&left.network),
        trace_hash_h1: trace_hash(&right.network),
        byte_identical: left.network == right.network,
        service_identical: left.services == right.services,
        collusion_identical: left.collusion == right.collusion,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LongitudinalWitness {
    pub buckets: usize,
    pub services: usize,
    pub total_frames: usize,
    pub trace_hash_h0: [u8; 32],
    pub trace_hash_h1: [u8; 32],
    pub byte_identical: bool,
}

pub fn verify_longitudinal_composition(
    pair: &ActionEquivalentPair,
) -> Result<LongitudinalWitness, AetpViolation> {
    let coupled = coupled_trace_witness(pair)?;
    let services = pair
        .shared_semantics
        .obligations
        .iter()
        .map(|obligation| obligation.service)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    Ok(LongitudinalWitness {
        buckets: usize::from(pair.public_context.channel_schedule.buckets),
        services,
        total_frames: usize::from(pair.public_context.channel_schedule.buckets)
            * usize::from(pair.public_context.channel_schedule.slots_per_bucket)
            * services,
        trace_hash_h0: coupled.trace_hash_h0,
        trace_hash_h1: coupled.trace_hash_h1,
        byte_identical: coupled.byte_identical,
    })
}

pub fn utility_counts(trace: &ShapedTrace) -> (usize, usize, usize) {
    let actions = trace
        .services
        .iter()
        .flat_map(|service| &service.frames)
        .filter(|frame| matches!(frame.decoded_kind, DecodedFrameKind::AuthorizedAction(_)))
        .count();
    (actions, 0, 0)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AdmissionError {
    #[error("private permit candidate is invalid")]
    InvalidCandidate,
    #[error("private permit candidate missed admission cutoff")]
    AfterCutoff,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EquivalenceError {
    #[error("histories do not induce the same action semantics")]
    NotEquivalent,
    #[error("shared action semantics are not jointly feasible")]
    NotJointlyFeasible,
    #[error("history and public context mismatch")]
    PublicContextMismatch,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GeneratorError {
    #[error("invalid pair generator configuration")]
    InvalidConfiguration,
    #[error("generated pair is not action-equivalent")]
    PairNotEquivalent,
}

#[derive(Debug, Error)]
pub enum AetpViolation {
    #[error(transparent)]
    Equivalence(#[from] EquivalenceError),
    #[error(transparent)]
    Shaper(#[from] ShaperError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use noticer_aetp::{ChannelSchedule, PublicNetworkTape};
    use noticer_trace_shaper::{FIXED_CIPHERTEXT_SIZE, FIXED_PLAINTEXT_SIZE};
    use proptest::prelude::*;

    fn context(buckets: u16) -> PublicContext {
        PublicContext {
            protocol_version: 1,
            public_epoch: 44,
            channel_schedule: ChannelSchedule {
                buckets,
                slots_per_bucket: 32,
                frame_interval_ms: 1_000,
                fixed_plaintext_size: FIXED_PLAINTEXT_SIZE as u16,
                fixed_ciphertext_size: FIXED_CIPHERTEXT_SIZE as u16,
            },
            public_network_tape: PublicNetworkTape { statuses: vec![] },
        }
    }

    proptest! {
        #[test]
        fn all_private_pair_families_have_identical_traces(seed in any::<u64>()) {
            let pairs = generate_action_equivalent_pairs(6, 4, &context(1), seed).unwrap();
            for pair in pairs {
                let witness = coupled_trace_witness(&pair).unwrap();
                prop_assert!(witness.byte_identical && witness.service_identical && witness.collusion_identical);
            }
        }
    }

    #[test]
    fn sixty_four_bucket_four_service_trace_is_identical_and_useful() {
        let pair = generate_action_equivalent_pairs(1, 4, &context(64), 7)
            .unwrap()
            .remove(0);
        let witness = verify_longitudinal_composition(&pair).unwrap();
        assert!(witness.byte_identical);
        assert_eq!(witness.buckets, 64);
        assert_eq!(witness.services, 4);
    }

    #[test]
    fn action_change_is_not_equivalent() {
        let mut pair = generate_action_equivalent_pairs(1, 1, &context(1), 8)
            .unwrap()
            .remove(0);
        pair.h1.candidates[0].action = ActionCode::RenderAmbientPulse;
        let policy = AdmissionPolicy::from_semantics(&pair.shared_semantics);
        assert_eq!(
            action_equivalent(&pair.h0, &pair.h1, &policy, &pair.public_context),
            Err(EquivalenceError::NotEquivalent)
        );
    }

    #[test]
    fn late_and_invalid_candidates_fail_closed() {
        let pair = generate_action_equivalent_pairs(1, 1, &context(1), 9)
            .unwrap()
            .remove(0);
        let template = ActionTemplate {
            obligation: pair.shared_semantics.obligations[0].clone(),
        };
        let late = PrivatePermitCandidate::synthetic(
            LogicalSlot(template.obligation.admission_cutoff.0 + 1),
            template.obligation.action,
            template.obligation.service,
            template.obligation.policy_hash,
        );
        assert_eq!(
            admit(late, &template, template.obligation.admission_cutoff).unwrap_err(),
            AdmissionError::AfterCutoff
        );
    }

    #[test]
    fn compile_fail_private_boundary_contracts() {
        let tests = trybuild::TestCases::new();
        tests.compile_fail("tests/ui/*.rs");
    }
}
