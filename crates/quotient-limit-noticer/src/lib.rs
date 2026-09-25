#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;
use quotient_limit_rational::{Rational, RationalError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    Aets,
    Atv2Scheduler,
    AplotSuperframe,
    AepaLease,
    MenfuguExecutionSlot,
    QuotientForgeTransducer,
    QuotientSealManifest,
}

pub const REQUIRED_ADAPTERS: [SourceKind; 7] = [
    SourceKind::Aets,
    SourceKind::Atv2Scheduler,
    SourceKind::AplotSuperframe,
    SourceKind::AepaLease,
    SourceKind::MenfuguExecutionSlot,
    SourceKind::QuotientForgeTransducer,
    SourceKind::QuotientSealManifest,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceField {
    PublicState,
    PublicInput,
    PublicFault,
    ActionQuotient,
    ReleaseSymbol,
    PublicSlot,
    CoverCost,
    LatencyCost,
    PrivatePpg,
    PersonalBaseline,
    RawBiosignal,
    PrivateHistory,
}

impl SourceField {
    pub const fn is_private(self) -> bool {
        matches!(
            self,
            Self::PrivatePpg | Self::PersonalBaseline | Self::RawBiosignal | Self::PrivateHistory
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicTransition {
    pub from_state: u32,
    pub action_quotient: u16,
    pub public_input: u16,
    pub fault_input: u16,
    pub slot: u16,
    pub output_symbol: u16,
    pub to_state: u32,
    pub cover_cost: u32,
    pub latency_cost: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicAdapterInput {
    pub kind: SourceKind,
    pub source_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub horizon: u16,
    pub state_count: u32,
    pub quotient_inputs: u16,
    pub public_inputs: u16,
    pub fault_inputs: u16,
    pub declared_fields: Vec<SourceField>,
    pub transitions: Vec<PublicTransition>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AqrpCandidate {
    pub source_kind: SourceKind,
    pub source_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub horizon: u16,
    pub state_count: u32,
    pub quotient_inputs: u16,
    pub public_inputs: u16,
    pub fault_inputs: u16,
    pub transitions: Vec<PublicTransition>,
}

pub fn adapt_public_source(input: PublicAdapterInput) -> Result<AqrpCandidate, AdapterError> {
    if input.source_digest == [0; 32] || input.policy_digest == [0; 32] {
        return Err(AdapterError::MissingDigestBinding);
    }
    if input.horizon == 0
        || input.state_count == 0
        || input.quotient_inputs == 0
        || input.public_inputs == 0
        || input.fault_inputs == 0
    {
        return Err(AdapterError::EmptyPublicAxis);
    }
    if let Some(field) = input
        .declared_fields
        .iter()
        .copied()
        .find(|field| field.is_private())
    {
        return Err(AdapterError::PrivateField(field));
    }
    if input.transitions.is_empty() {
        return Err(AdapterError::EmptyTransitionSet);
    }
    let mut previous = None;
    for transition in &input.transitions {
        if previous.is_some_and(|prior| prior >= *transition) {
            return Err(AdapterError::NonCanonicalTransitionOrder);
        }
        if transition.from_state >= input.state_count
            || transition.to_state >= input.state_count
            || transition.action_quotient >= input.quotient_inputs
            || transition.public_input >= input.public_inputs
            || transition.fault_input >= input.fault_inputs
            || transition.slot >= input.horizon
        {
            return Err(AdapterError::TransitionOutsidePublicModel);
        }
        previous = Some(*transition);
    }
    Ok(AqrpCandidate {
        source_kind: input.kind,
        source_digest: input.source_digest,
        policy_digest: input.policy_digest,
        horizon: input.horizon,
        state_count: input.state_count,
        quotient_inputs: input.quotient_inputs,
        public_inputs: input.public_inputs,
        fault_inputs: input.fault_inputs,
        transitions: input.transitions,
    })
}

macro_rules! adapter {
    ($name:ident, $kind:expr) => {
        pub fn $name(mut input: PublicAdapterInput) -> Result<AqrpCandidate, AdapterError> {
            input.kind = $kind;
            adapt_public_source(input)
        }
    };
}

adapter!(adapt_aets, SourceKind::Aets);
adapter!(adapt_atv2_scheduler, SourceKind::Atv2Scheduler);
adapter!(adapt_aplot, SourceKind::AplotSuperframe);
adapter!(adapt_aepa, SourceKind::AepaLease);
adapter!(adapt_menfugu, SourceKind::MenfuguExecutionSlot);
adapter!(adapt_quotient_forge, SourceKind::QuotientForgeTransducer);
adapter!(adapt_quotient_seal, SourceKind::QuotientSealManifest);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComparisonMechanism {
    ImmediateRelease,
    FixedBucket,
    RandomDelay,
    FullFixedCadence,
    HandwrittenAets,
    HandwrittenAplot,
    QuotientForgeCandidate,
    QuotientLimitOptimal,
}

pub const REQUIRED_COMPARISONS: [ComparisonMechanism; 8] = [
    ComparisonMechanism::ImmediateRelease,
    ComparisonMechanism::FixedBucket,
    ComparisonMechanism::RandomDelay,
    ComparisonMechanism::FullFixedCadence,
    ComparisonMechanism::HandwrittenAets,
    ComparisonMechanism::HandwrittenAplot,
    ComparisonMechanism::QuotientForgeCandidate,
    ComparisonMechanism::QuotientLimitOptimal,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CostComparison {
    pub actual_cost: Rational,
    pub certified_lower_bound: Rational,
    pub optimality_gap: Rational,
    pub relative_gap: Rational,
    pub scale: Rational,
}

pub fn compare_cost(
    actual_cost: Rational,
    certified_lower_bound: Rational,
    scale_floor: Rational,
) -> Result<CostComparison, AdapterError> {
    if actual_cost.is_negative()
        || certified_lower_bound.is_negative()
        || scale_floor.checked_cmp(Rational::ZERO)? != Ordering::Greater
    {
        return Err(AdapterError::InvalidCost);
    }
    if actual_cost.checked_cmp(certified_lower_bound)? == Ordering::Less {
        return Err(AdapterError::CandidateBelowCertifiedLowerBound);
    }
    let gap = actual_cost.checked_add(certified_lower_bound.checked_neg()?)?;
    let scale = if certified_lower_bound.checked_cmp(scale_floor)? == Ordering::Greater {
        certified_lower_bound
    } else {
        scale_floor
    };
    let relative_gap = divide(gap, scale)?;
    Ok(CostComparison {
        actual_cost,
        certified_lower_bound,
        optimality_gap: gap,
        relative_gap,
        scale,
    })
}

fn divide(numerator: Rational, denominator: Rational) -> Result<Rational, AdapterError> {
    if denominator == Rational::ZERO {
        return Err(AdapterError::InvalidCost);
    }
    let top = numerator
        .numerator()
        .checked_mul(denominator.denominator())
        .ok_or(AdapterError::ArithmeticOverflow)?;
    let bottom = numerator
        .denominator()
        .checked_mul(denominator.numerator())
        .ok_or(AdapterError::ArithmeticOverflow)?;
    Ok(Rational::new(top, bottom)?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    MissingDigestBinding,
    EmptyPublicAxis,
    PrivateField(SourceField),
    EmptyTransitionSet,
    NonCanonicalTransitionOrder,
    TransitionOutsidePublicModel,
    InvalidCost,
    CandidateBelowCertifiedLowerBound,
    ArithmeticOverflow,
    Rational(RationalError),
}

impl From<RationalError> for AdapterError {
    fn from(value: RationalError) -> Self {
        Self::Rational(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn public_input() -> PublicAdapterInput {
        PublicAdapterInput {
            kind: SourceKind::Aets,
            source_digest: [1; 32],
            policy_digest: [2; 32],
            horizon: 8,
            state_count: 2,
            quotient_inputs: 2,
            public_inputs: 2,
            fault_inputs: 2,
            declared_fields: vec![
                SourceField::PublicState,
                SourceField::ActionQuotient,
                SourceField::PublicInput,
                SourceField::PublicFault,
            ],
            transitions: vec![PublicTransition {
                from_state: 0,
                action_quotient: 0,
                public_input: 0,
                fault_input: 0,
                slot: 1,
                output_symbol: 1,
                to_state: 1,
                cover_cost: 2,
                latency_cost: 1,
            }],
        }
    }

    #[test]
    fn all_required_adapters_produce_bound_aqrp_candidates() {
        let adapters: [fn(PublicAdapterInput) -> Result<AqrpCandidate, AdapterError>; 7] = [
            adapt_aets,
            adapt_atv2_scheduler,
            adapt_aplot,
            adapt_aepa,
            adapt_menfugu,
            adapt_quotient_forge,
            adapt_quotient_seal,
        ];
        for (index, adapter) in adapters.into_iter().enumerate() {
            let candidate = adapter(public_input()).unwrap();
            assert_eq!(candidate.source_kind, REQUIRED_ADAPTERS[index]);
            assert_eq!(candidate.source_digest, [1; 32]);
            assert_eq!(candidate.policy_digest, [2; 32]);
        }
    }

    #[test]
    fn rejects_ppg_baseline_and_private_history_at_boundary() {
        for field in [
            SourceField::PrivatePpg,
            SourceField::PersonalBaseline,
            SourceField::RawBiosignal,
            SourceField::PrivateHistory,
        ] {
            let mut input = public_input();
            input.declared_fields.push(field);
            assert_eq!(adapt_aets(input), Err(AdapterError::PrivateField(field)));
        }
    }

    #[test]
    fn rejects_noncanonical_or_out_of_model_transition() {
        let mut duplicate = public_input();
        duplicate.transitions.push(duplicate.transitions[0]);
        assert_eq!(
            adapt_aplot(duplicate),
            Err(AdapterError::NonCanonicalTransitionOrder)
        );
        let mut outside = public_input();
        outside.transitions[0].slot = 8;
        assert_eq!(
            adapt_quotient_forge(outside),
            Err(AdapterError::TransitionOutsidePublicModel)
        );
    }

    #[test]
    fn computes_exact_absolute_and_relative_optimality_gap() {
        let comparison = compare_cost(r(7, 2), r(3, 1), r(1, 10)).unwrap();
        assert_eq!(comparison.optimality_gap, r(1, 2));
        assert_eq!(comparison.relative_gap, r(1, 6));
        assert_eq!(comparison.scale, r(3, 1));
    }

    #[test]
    fn scale_floor_handles_zero_lower_bound() {
        let comparison = compare_cost(r(1, 4), Rational::ZERO, r(1, 2)).unwrap();
        assert_eq!(comparison.relative_gap, r(1, 2));
        assert_eq!(REQUIRED_COMPARISONS.len(), 8);
    }

    fn r(numerator: i128, denominator: i128) -> Rational {
        Rational::new(numerator, denominator).unwrap()
    }
}
