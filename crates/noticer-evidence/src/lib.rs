#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::marker::PhantomData;

use noticer_baseline::{
    AnchorBaseline, BaselineError, BaselineRegistry, ContextKey, PrivateObservation,
    ShadowBaseline, ShadowConfig, SignalQuality,
};
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use rand_core::RngCore;
use serde::Deserialize;
use thiserror::Error;

pub trait GuaranteeMarker: private::Sealed + 'static {
    const NAME: &'static str;
}

mod private {
    pub trait Sealed {}
}

pub struct ExchangeabilityAssumed;
pub struct EmpiricalOnly;
impl private::Sealed for ExchangeabilityAssumed {}
impl private::Sealed for EmpiricalOnly {}
impl GuaranteeMarker for ExchangeabilityAssumed {
    const NAME: &'static str = "exchangeability_assumed";
}
impl GuaranteeMarker for EmpiricalOnly {
    const NAME: &'static str = "empirical_only";
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceEpochId(pub u64);

#[must_use]
pub struct EvidencePermit<G: GuaranteeMarker> {
    action: ActionCode,
    policy_hash: PolicyHash,
    issued_slot: LogicalSlot,
    expires_slot: LogicalSlot,
    evidence_epoch: EvidenceEpochId,
    marker: PhantomData<G>,
}

impl<G: GuaranteeMarker> EvidencePermit<G> {
    fn new(
        action: ActionCode,
        policy_hash: PolicyHash,
        issued_slot: LogicalSlot,
        expires_slot: LogicalSlot,
        evidence_epoch: EvidenceEpochId,
    ) -> Self {
        Self {
            action,
            policy_hash,
            issued_slot,
            expires_slot,
            evidence_epoch,
            marker: PhantomData,
        }
    }

    pub fn consume(self) -> PermitAuthority {
        PermitAuthority {
            action: self.action,
            policy_hash: self.policy_hash,
            issued_slot: self.issued_slot,
            expires_slot: self.expires_slot,
            evidence_epoch: self.evidence_epoch,
            guarantee: G::NAME,
        }
    }
}

impl<G: GuaranteeMarker> fmt::Debug for EvidencePermit<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidencePermit")
            .field("action", &self.action)
            .field("issued_slot", &self.issued_slot)
            .field("expires_slot", &self.expires_slot)
            .field("evidence_epoch", &self.evidence_epoch)
            .field("private_evidence", &"REDACTED")
            .finish()
    }
}

pub struct PermitAuthority {
    pub action: ActionCode,
    pub policy_hash: PolicyHash,
    pub issued_slot: LogicalSlot,
    pub expires_slot: LogicalSlot,
    pub evidence_epoch: EvidenceEpochId,
    pub guarantee: &'static str,
}

#[derive(Clone, Deserialize)]
pub struct EvidenceConfig {
    pub alpha_total: f64,
    pub max_monitoring_steps: usize,
    pub power_epsilons: Vec<f64>,
    pub power_weights: Vec<f64>,
}

#[derive(Clone, Deserialize)]
pub struct PersistenceConfig {
    pub window: usize,
    pub required_hits: usize,
    pub p_max: f64,
}

#[derive(Clone, Deserialize)]
pub struct ContextConfig {
    pub id: String,
    pub alpha_weight: f64,
    pub fallback: bool,
}

#[derive(Clone)]
pub struct EngineConfig {
    pub evidence: EvidenceConfig,
    pub persistence: PersistenceConfig,
    pub contexts: Vec<ContextConfig>,
    pub permit_ttl_slots: u64,
}

impl EngineConfig {
    pub fn validate(self) -> Result<Self, EvidenceViolation> {
        if !(0.0 < self.evidence.alpha_total && self.evidence.alpha_total < 1.0)
            || self.evidence.max_monitoring_steps == 0
            || self.evidence.power_epsilons.is_empty()
            || self.evidence.power_epsilons.len() != self.evidence.power_weights.len()
            || self.persistence.window == 0
            || self.persistence.required_hits == 0
            || self.persistence.required_hits > self.persistence.window
            || !(0.0 < self.persistence.p_max && self.persistence.p_max <= 1.0)
            || self.permit_ttl_slots == 0
        {
            return Err(EvidenceViolation::InvalidConfig);
        }
        if self
            .evidence
            .power_epsilons
            .iter()
            .any(|epsilon| !epsilon.is_finite() || *epsilon <= 0.0 || *epsilon >= 1.0)
        {
            return Err(EvidenceViolation::InvalidConfig);
        }
        let mut sorted = self.evidence.power_epsilons.clone();
        sorted.sort_by(f64::total_cmp);
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EvidenceViolation::InvalidConfig);
        }
        let weight_sum: f64 = self.evidence.power_weights.iter().sum();
        let context_sum: f64 = self
            .contexts
            .iter()
            .map(|context| context.alpha_weight)
            .sum();
        if self
            .evidence
            .power_weights
            .iter()
            .any(|weight| *weight <= 0.0)
            || (weight_sum - 1.0).abs() > 1e-9
            || context_sum > 1.0 + 1e-12
            || self.contexts.iter().any(|context| {
                context.id.is_empty()
                    || context.alpha_weight <= 0.0
                    || !context.alpha_weight.is_finite()
            })
        {
            return Err(EvidenceViolation::InvalidAlphaBudget);
        }
        Ok(self)
    }
}

pub fn epoch_alpha(
    alpha_total: f64,
    context_weight: f64,
    epoch: u64,
) -> Result<f64, EvidenceViolation> {
    if epoch == 0 || !(0.0 < alpha_total && alpha_total < 1.0) || context_weight <= 0.0 {
        return Err(EvidenceViolation::InvalidAlphaBudget);
    }
    let epoch = epoch as f64;
    let alpha = alpha_total * context_weight * 6.0 / (std::f64::consts::PI.powi(2) * epoch.powi(2));
    if alpha.is_finite() && alpha > 0.0 {
        Ok(alpha)
    } else {
        Err(EvidenceViolation::ArithmeticViolation)
    }
}

pub fn randomized_rank_p_value<R: RngCore>(
    history: &[f64],
    current: f64,
    rng: &mut R,
) -> Result<f64, EvidenceViolation> {
    if history
        .iter()
        .chain([&current])
        .any(|value| !value.is_finite())
    {
        return Err(EvidenceViolation::ArithmeticViolation);
    }
    let greater = history.iter().filter(|value| **value > current).count();
    let equal = history.iter().filter(|value| **value == current).count() + 1;
    let mantissa = rng.next_u64() >> 11;
    let uniform = (mantissa as f64 + 1.0) / ((1_u64 << 53) as f64 + 1.0);
    let p_value = (greater as f64 + uniform * equal as f64) / (history.len() + 1) as f64;
    if p_value.is_finite() && p_value > 0.0 && p_value <= 1.0 {
        Ok(p_value)
    } else {
        Err(EvidenceViolation::ArithmeticViolation)
    }
}

#[derive(Debug, PartialEq)]
pub enum NoPermitReason {
    QualityInsufficient,
    BaselineUnavailable,
    EvidenceBelowThreshold,
    PersistenceInsufficient,
    EpochExhausted,
    QuarantineActive,
    ContextUnavailable,
    AlreadyIssued,
}

#[derive(Debug, Error, PartialEq)]
pub enum EvidenceViolation {
    #[error("logical time rolled back")]
    TimeRollback,
    #[error("feature dimension mismatch")]
    DimensionMismatch,
    #[error("feature contains non-finite value")]
    NonFiniteFeature,
    #[error("invalid evidence state")]
    InvalidState,
    #[error("numerical arithmetic violation")]
    ArithmeticViolation,
    #[error("invalid alpha budget")]
    InvalidAlphaBudget,
    #[error("invalid evidence configuration")]
    InvalidConfig,
}

pub enum EvidenceDecision {
    NoPermit(NoPermitReason),
    AssumptionBoundPermit(EvidencePermit<ExchangeabilityAssumed>),
    EmpiricalPermit(EvidencePermit<EmpiricalOnly>),
    Reject(EvidenceViolation),
}

struct ContextState {
    epoch: u64,
    monitoring_steps: usize,
    rank_history: Vec<f64>,
    log_components: Vec<f64>,
    persistence: VecDeque<bool>,
    issued: bool,
}

impl ContextState {
    fn new(anchor: &AnchorBaseline, components: usize) -> Self {
        Self {
            epoch: 1,
            monitoring_steps: 0,
            rank_history: anchor.calibration_scores().to_vec(),
            log_components: vec![0.0; components],
            persistence: VecDeque::new(),
            issued: false,
        }
    }
}

pub struct EvidenceEngine {
    config: EngineConfig,
    registry: BaselineRegistry,
    states: HashMap<ContextKey, ContextState>,
    context_weights: HashMap<ContextKey, f64>,
    last_slot: Option<LogicalSlot>,
    action: ActionCode,
    policy_hash: PolicyHash,
}

impl EvidenceEngine {
    pub fn new(
        config: EngineConfig,
        registry: BaselineRegistry,
        contexts: Vec<(ContextKey, f64)>,
        action: ActionCode,
        policy_hash: PolicyHash,
    ) -> Result<Self, EvidenceViolation> {
        let config = config.validate()?;
        let sum: f64 = contexts.iter().map(|entry| entry.1).sum();
        if sum > 1.0 + 1e-12 || contexts.iter().any(|entry| entry.1 <= 0.0) {
            return Err(EvidenceViolation::InvalidAlphaBudget);
        }
        Ok(Self {
            config,
            registry,
            states: HashMap::new(),
            context_weights: contexts.into_iter().collect(),
            last_slot: None,
            action,
            policy_hash,
        })
    }

    pub fn process<R: RngCore>(
        &mut self,
        observation: &PrivateObservation,
        rng: &mut R,
    ) -> EvidenceDecision {
        let slot = observation.logical_slot();
        if self.last_slot.is_some_and(|previous| slot.0 <= previous.0) {
            return EvidenceDecision::Reject(EvidenceViolation::TimeRollback);
        }
        self.last_slot = Some(slot);
        if observation.quality() < SignalQuality::Usable {
            return EvidenceDecision::NoPermit(NoPermitReason::QualityInsufficient);
        }
        let context = observation.context();
        let Some(&weight) = self.context_weights.get(&context) else {
            return EvidenceDecision::NoPermit(NoPermitReason::ContextUnavailable);
        };
        let (anchor, used_fallback) = match self.registry.resolve(context) {
            Ok(value) => value,
            Err(_) => return EvidenceDecision::NoPermit(NoPermitReason::BaselineUnavailable),
        };
        let score = match anchor.score_observation(observation) {
            Ok(value) => value,
            Err(BaselineError::DimensionMismatch) => {
                return EvidenceDecision::Reject(EvidenceViolation::DimensionMismatch)
            }
            Err(_) => return EvidenceDecision::Reject(EvidenceViolation::NonFiniteFeature),
        };
        let state = self.states.entry(context).or_insert_with(|| {
            ContextState::new(anchor, self.config.evidence.power_epsilons.len())
        });
        if state.monitoring_steps >= self.config.evidence.max_monitoring_steps {
            return EvidenceDecision::NoPermit(NoPermitReason::EpochExhausted);
        }
        let p_value = match randomized_rank_p_value(&state.rank_history, score, rng) {
            Ok(value) => value,
            Err(error) => return EvidenceDecision::Reject(error),
        };
        for (index, epsilon) in self.config.evidence.power_epsilons.iter().enumerate() {
            let log_factor = epsilon.ln() + (epsilon - 1.0) * p_value.ln();
            state.log_components[index] += log_factor;
            if !state.log_components[index].is_finite() {
                return EvidenceDecision::Reject(EvidenceViolation::ArithmeticViolation);
            }
        }
        let log_e =
            log_sum_exp_weighted(&state.log_components, &self.config.evidence.power_weights);
        if !log_e.is_finite() {
            return EvidenceDecision::Reject(EvidenceViolation::ArithmeticViolation);
        }
        state
            .persistence
            .push_back(p_value <= self.config.persistence.p_max);
        if state.persistence.len() > self.config.persistence.window {
            state.persistence.pop_front();
        }
        state.rank_history.push(score);
        state.monitoring_steps += 1;
        if state.issued {
            return EvidenceDecision::NoPermit(NoPermitReason::AlreadyIssued);
        }
        let alpha = match epoch_alpha(self.config.evidence.alpha_total, weight, state.epoch) {
            Ok(value) => value,
            Err(error) => return EvidenceDecision::Reject(error),
        };
        if log_e < (1.0 / alpha).ln() {
            return EvidenceDecision::NoPermit(NoPermitReason::EvidenceBelowThreshold);
        }
        if state.persistence.iter().filter(|hit| **hit).count()
            < self.config.persistence.required_hits
        {
            return EvidenceDecision::NoPermit(NoPermitReason::PersistenceInsufficient);
        }
        let Some(expires) = slot.0.checked_add(self.config.permit_ttl_slots) else {
            return EvidenceDecision::Reject(EvidenceViolation::ArithmeticViolation);
        };
        state.issued = true;
        if used_fallback {
            EvidenceDecision::EmpiricalPermit(EvidencePermit::new(
                self.action,
                self.policy_hash,
                slot,
                LogicalSlot(expires),
                EvidenceEpochId(state.epoch),
            ))
        } else {
            EvidenceDecision::AssumptionBoundPermit(EvidencePermit::new(
                self.action,
                self.policy_hash,
                slot,
                LogicalSlot(expires),
                EvidenceEpochId(state.epoch),
            ))
        }
    }

    pub fn bounded_history_lengths(&self) -> impl Iterator<Item = usize> + '_ {
        self.states.values().map(|state| state.monitoring_steps)
    }

    pub fn restart_context_epoch(
        &mut self,
        context: ContextKey,
        predetermined_epoch: u64,
    ) -> Result<(), EvidenceViolation> {
        let (anchor, _) = self
            .registry
            .resolve(context)
            .map_err(|_| EvidenceViolation::InvalidState)?;
        let current = self.states.get(&context).map_or(0, |state| state.epoch);
        if predetermined_epoch != current.saturating_add(1) {
            return Err(EvidenceViolation::InvalidAlphaBudget);
        }
        let mut state = ContextState::new(anchor, self.config.evidence.power_epsilons.len());
        state.epoch = predetermined_epoch;
        self.states.insert(context, state);
        Ok(())
    }
}

fn log_sum_exp_weighted(log_values: &[f64], weights: &[f64]) -> f64 {
    let maximum = log_values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    maximum
        + log_values
            .iter()
            .zip(weights)
            .map(|(&value, &weight)| weight * (value - maximum).exp())
            .sum::<f64>()
            .ln()
}

pub struct ShadowUpdateGate {
    pub config: ShadowConfig,
    pub minimum_quality: SignalQuality,
    pub evidence_update_ceiling: f64,
    pub quarantine_until: Option<LogicalSlot>,
}

impl ShadowUpdateGate {
    pub fn update_after_decision(
        &self,
        decision_is_permit: bool,
        private_log_e: f64,
        observation: &PrivateObservation,
        shadow: &mut ShadowBaseline,
        anchor: &AnchorBaseline,
    ) -> Result<Option<f64>, BaselineError> {
        if decision_is_permit
            || observation.quality() < self.minimum_quality
            || private_log_e >= self.evidence_update_ceiling
            || self
                .quarantine_until
                .is_some_and(|until| observation.logical_slot().0 <= until.0)
        {
            return Ok(None);
        }
        shadow
            .update_observation(observation, anchor, self.config)
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_core::impls;

    struct FixedRng(u64);
    impl rand_core::RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            impls::fill_bytes_via_next(self, dest)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    proptest! {
        #[test]
        fn p_value_is_bounded(history in prop::collection::vec(-1000.0f64..1000.0, 0..100), current in -1000.0f64..1000.0, seed in any::<u64>()) {
            let p = randomized_rank_p_value(&history, current, &mut FixedRng(seed)).unwrap();
            prop_assert!(p > 0.0 && p <= 1.0);
        }
    }

    #[test]
    fn alpha_spending_is_bounded() {
        let sum: f64 = (1..100_000)
            .map(|epoch| epoch_alpha(0.05, 1.0, epoch).unwrap())
            .sum();
        assert!(sum <= 0.05 + 1e-8);
    }

    #[test]
    fn randomized_rank_is_deterministic_for_rng_state() {
        let history = [0.1, 0.2, 0.3, 0.3];
        let first = randomized_rank_p_value(&history, 0.3, &mut FixedRng(77)).unwrap();
        let second = randomized_rank_p_value(&history, 0.3, &mut FixedRng(77)).unwrap();
        assert_eq!(first.to_bits(), second.to_bits());
    }

    #[test]
    fn larger_score_has_no_larger_rank_p_value() {
        let history = [0.1, 0.2, 0.3, 0.4];
        let lower = randomized_rank_p_value(&history, 0.15, &mut FixedRng(9)).unwrap();
        let higher = randomized_rank_p_value(&history, 0.35, &mut FixedRng(9)).unwrap();
        assert!(higher <= lower);
    }

    #[test]
    fn invalid_mixture_weights_are_rejected() {
        let result = EngineConfig {
            evidence: EvidenceConfig {
                alpha_total: 0.05,
                max_monitoring_steps: 10,
                power_epsilons: vec![0.3, 0.7],
                power_weights: vec![0.4, 0.4],
            },
            persistence: PersistenceConfig {
                window: 5,
                required_hits: 3,
                p_max: 0.1,
            },
            contexts: vec![ContextConfig {
                id: "opaque".into(),
                alpha_weight: 1.0,
                fallback: false,
            }],
            permit_ttl_slots: 3,
        }
        .validate();
        assert!(matches!(result, Err(EvidenceViolation::InvalidAlphaBudget)));
    }

    #[test]
    fn compile_fail_high_side_and_permit_contracts() {
        let tests = trybuild::TestCases::new();
        tests.compile_fail("../../tests/ui/*.rs");
    }
}
