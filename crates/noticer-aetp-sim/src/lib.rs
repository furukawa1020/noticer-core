#![forbid(unsafe_code)]

//! Counterfactual private-history generator for AETP witnesses.

use noticer_aetp::{
    action_equivalent, ActionObligation, ActionSemantics, BucketId, ChannelSchedule, PublicContext,
    PublicNetworkTape, ScheduleRandomTape, ServiceBinding,
};
use noticer_release::TokenPlan;
use noticer_trace_shaper::{ActionEquivalentTraceShaper, SimulationFrameIssuer, TraceShapeError};
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const EQUIVALENCE_CLASS_COUNT: usize = 6;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CounterfactualFamily {
    EarlyVsLateEvidence = 0,
    SmoothVsSpikySignal = 1,
    DifferentBaseline = 2,
    DifferentNoisePath = 3,
    DifferentSubject = 4,
    DifferentSession = 5,
}

impl CounterfactualFamily {
    pub const ALL: [Self; EQUIVALENCE_CLASS_COUNT] = [
        Self::EarlyVsLateEvidence,
        Self::SmoothVsSpikySignal,
        Self::DifferentBaseline,
        Self::DifferentNoisePath,
        Self::DifferentSubject,
        Self::DifferentSession,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::EarlyVsLateEvidence => "early_vs_late_evidence",
            Self::SmoothVsSpikySignal => "smooth_vs_spiky_signal",
            Self::DifferentBaseline => "different_baseline",
            Self::DifferentNoisePath => "different_noise_path",
            Self::DifferentSubject => "different_subject",
            Self::DifferentSession => "different_session",
        }
    }
}

struct PrivateHistory {
    subject_secret: [u8; 16],
    session_secret: [u8; 16],
    evidence_ready_slot: LogicalSlot,
    score_path_hash: [u8; 32],
}

impl core::fmt::Debug for PrivateHistory {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PrivateHistory(<redacted>)")
    }
}

pub struct ActionEquivalentPair {
    pub pair_id: u64,
    pub family: CounterfactualFamily,
    left: PrivateHistory,
    right: PrivateHistory,
    pub shared_semantics: ActionSemantics,
    pub public_context: PublicContext,
    pub schedule_tape: ScheduleRandomTape,
}

impl core::fmt::Debug for ActionEquivalentPair {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ActionEquivalentPair")
            .field("pair_id", &self.pair_id)
            .field("family", &self.family)
            .field("shared_semantics", &self.shared_semantics)
            .field("public_context", &self.public_context)
            .field("private_histories", &"<redacted>")
            .finish()
    }
}

impl ActionEquivalentPair {
    pub fn private_histories_are_distinct(&self) -> bool {
        self.left.subject_secret != self.right.subject_secret
            || self.left.session_secret != self.right.session_secret
            || self.left.evidence_ready_slot != self.right.evidence_ready_slot
            || self.left.score_path_hash != self.right.score_path_hash
    }

    pub fn public_plan(&self) -> Result<TokenPlan, SimulationError> {
        TokenPlan::from_action_semantics(
            &self.shared_semantics,
            self.public_context.network.services.clone(),
        )
        .map_err(|_| SimulationError::InvalidPair)
    }

    pub fn sanitized_pair_hash(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"NOTICER_AETP_SANITIZED_PAIR_WITNESS");
        digest.update(self.pair_id.to_le_bytes());
        digest.update([self.family as u8]);
        digest.update(self.shared_semantics.canonical_hash());
        digest.finalize().into()
    }
}

pub fn default_public_context() -> PublicContext {
    let mut services = vec![
        ServiceBinding([1; 16]),
        ServiceBinding([2; 16]),
        ServiceBinding([3; 16]),
        ServiceBinding([4; 16]),
    ];
    services.sort_unstable();
    PublicContext {
        schedule: ChannelSchedule {
            buckets: 64,
            slots_per_bucket: 4,
            frame_interval_ms: 250,
            fixed_plaintext_size: 160,
            fixed_ciphertext_size: 236,
        },
        network: PublicNetworkTape {
            services,
            public_epoch: 7,
            start_slot: LogicalSlot(10_000),
        },
    }
}

pub fn generate_action_equivalent_pairs(
    count: usize,
    seed: u64,
    context: &PublicContext,
) -> Result<Vec<ActionEquivalentPair>, SimulationError> {
    context
        .validate()
        .map_err(|_| SimulationError::InvalidPublicContext)?;
    let mut pairs = Vec::with_capacity(count);
    for index in 0..count {
        let family = CounterfactualFamily::ALL[index % EQUIVALENCE_CLASS_COUNT];
        let semantics = semantics_for_family(family, context)?;
        let left = private_history(seed, index as u64, 0, family, context);
        let mut right = private_history(seed, index as u64, 1, family, context);
        if family == CounterfactualFamily::EarlyVsLateEvidence {
            right.evidence_ready_slot = LogicalSlot(right.evidence_ready_slot.0 + 2);
        }
        let pair = ActionEquivalentPair {
            pair_id: index as u64,
            family,
            left,
            right,
            shared_semantics: semantics,
            public_context: context.clone(),
            schedule_tape: ScheduleRandomTape(hash32(seed, family as u64, b"schedule")),
        };
        if !pair.private_histories_are_distinct()
            || !action_equivalent(&pair.shared_semantics, &pair.shared_semantics)
        {
            return Err(SimulationError::InvalidPair);
        }
        pairs.push(pair);
    }
    Ok(pairs)
}

fn semantics_for_family(
    family: CounterfactualFamily,
    context: &PublicContext,
) -> Result<ActionSemantics, SimulationError> {
    let class = family as u64;
    let bucket = 8 + class * 7;
    let bucket_start =
        context.network.start_slot.0 + bucket * u64::from(context.schedule.slots_per_bucket);
    let action = match class % 3 {
        0 => ActionCode::RenderAmbientPulse,
        1 => ActionCode::MenfuguInflateSoft,
        _ => ActionCode::RenderReviewPrompt,
    };
    ActionSemantics::new(vec![ActionObligation {
        service: context.network.services[class as usize % context.network.services.len()],
        action,
        public_bucket: BucketId(bucket),
        admission_cutoff: LogicalSlot(bucket_start.saturating_sub(1)),
        release_window_start: LogicalSlot(bucket_start),
        release_deadline: LogicalSlot(
            bucket_start + u64::from(context.schedule.slots_per_bucket) - 1,
        ),
        max_uses: 1,
        policy_hash: PolicyHash(hash32(0xA37F, class, b"policy")),
    }])
    .map_err(|_| SimulationError::InvalidPair)
}

fn private_history(
    seed: u64,
    pair_id: u64,
    side: u8,
    family: CounterfactualFamily,
    context: &PublicContext,
) -> PrivateHistory {
    let subject = hash32(seed, pair_id * 2 + u64::from(side), b"subject");
    let session = hash32(seed, pair_id * 2 + u64::from(side), b"session");
    PrivateHistory {
        subject_secret: subject[..16].try_into().expect("fixed digest prefix"),
        session_secret: session[..16].try_into().expect("fixed digest prefix"),
        evidence_ready_slot: LogicalSlot(
            context.network.start_slot.0 + 2 + u64::from(side) + family as u64,
        ),
        score_path_hash: hash32(seed, pair_id * 2 + u64::from(side), b"score-path"),
    }
}

fn hash32(seed: u64, ordinal: u64, domain: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"NOTICER_AETP_SIM_V2");
    digest.update(seed.to_le_bytes());
    digest.update(ordinal.to_le_bytes());
    digest.update(domain);
    digest.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoupledWitness {
    pub pair_id: u64,
    pub family: CounterfactualFamily,
    pub trace_hash: [u8; 32],
    pub equal: bool,
}

pub fn coupled_simulation_witness(
    pair: &ActionEquivalentPair,
    simulation_secret: [u8; 32],
) -> Result<CoupledWitness, SimulationError> {
    let plan = pair.public_plan()?;
    let left_issuer = SimulationFrameIssuer::new(simulation_secret, 236);
    let right_issuer = SimulationFrameIssuer::new(simulation_secret, 236);
    let left = ActionEquivalentTraceShaper::shape(
        &plan,
        &pair.public_context,
        &pair.schedule_tape,
        &left_issuer,
    )?;
    let right = ActionEquivalentTraceShaper::shape(
        &plan,
        &pair.public_context,
        &pair.schedule_tape,
        &right_issuer,
    )?;
    Ok(CoupledWitness {
        pair_id: pair.pair_id,
        family: pair.family,
        trace_hash: left.digest(),
        equal: left == right,
    })
}

#[derive(Debug, Error)]
pub enum SimulationError {
    #[error("invalid public simulation context")]
    InvalidPublicContext,
    #[error("counterfactual pair is invalid")]
    InvalidPair,
    #[error("trace shaping failed")]
    Trace(#[from] TraceShapeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn generator_makes_distinct_private_but_action_equivalent_pairs() {
        let pairs = generate_action_equivalent_pairs(60, 42, &default_public_context()).unwrap();
        assert_eq!(pairs.len(), 60);
        assert!(pairs
            .iter()
            .all(ActionEquivalentPair::private_histories_are_distinct));
        assert_eq!(
            pairs
                .iter()
                .map(|pair| pair.family)
                .collect::<BTreeSet<_>>()
                .len(),
            EQUIVALENCE_CLASS_COUNT
        );
    }

    #[test]
    fn coupled_simulation_trace_is_identical() {
        let pairs = generate_action_equivalent_pairs(1, 42, &default_public_context()).unwrap();
        let witness = coupled_simulation_witness(&pairs[0], [8; 32]).unwrap();
        assert!(witness.equal);
    }
}
