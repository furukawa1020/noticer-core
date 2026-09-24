#![forbid(unsafe_code)]

//! Explicit `p[history, trace]` LP used as the small-model semantics oracle.

use quotient_limit_model::{ModelError, ModelLimits, ObserverId, PrivateHistoryId, PrivateHistoryModel};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const DOMAIN_MATRIX: &[u8] = b"QUOTIENT_LIMIT_MATRIX_V1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TraceId(pub u16);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObservationId(pub u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObserverObservation {
    pub observer: ObserverId,
    pub observation: ObservationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceCandidate {
    pub id: TraceId,
    pub release_slot: u16,
    pub action_count: u16,
    pub action_code: quotient_limit_model::ActionCode,
    pub service: quotient_limit_model::ServiceId,
    pub observations: Vec<ObserverObservation>,
    pub cost: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceVariable { pub history: PrivateHistoryId, pub trace: TraceId }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinearTerm { pub variable: u32, pub coefficient: i64 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EqualityKind {
    Normalization { history: PrivateHistoryId },
    ExactAetp { left: PrivateHistoryId, right: PrivateHistoryId, observer: ObserverId, observation: ObservationId },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Equality { pub kind: EqualityKind, pub terms: Vec<LinearTerm>, pub rhs: i64 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitTraceLp { pub variables: Vec<TraceVariable>, pub equalities: Vec<Equality>, pub objective: Vec<LinearTerm> }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceLpLimits { pub max_traces: usize, pub max_variables: usize, pub max_constraints: usize }
impl Default for TraceLpLimits {
    fn default() -> Self { Self { max_traces: 65_536, max_variables: 10_000_000, max_constraints: 20_000_000 } }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TraceLpError {
    #[error("invalid model: {0}")] InvalidModel(#[from] ModelError),
    #[error("trace catalog is empty, oversized, or non-canonical")] InvalidTraceCatalog,
    #[error("trace observations do not exactly cover declared observers")] InvalidObservationProjection,
    #[error("history {history:?} has no utility-feasible trace")] NoUtilityFeasibleTrace { history: PrivateHistoryId },
    #[error("explicit LP exceeds a frozen resource limit")] ResourceLimit,
}

pub fn build_exact_trace_lp(
    model: &PrivateHistoryModel,
    traces: &[TraceCandidate],
    model_limits: ModelLimits,
    limits: TraceLpLimits,
) -> Result<ExplicitTraceLp, TraceLpError> {
    model.validate(model_limits)?;
    validate_traces(model, traces, limits)?;
    let partition: BTreeMap<_, _> = model.action_quotient.class_of_history.iter().map(|x| (x.history, x.class)).collect();
    let classes: BTreeMap<_, _> = model.action_quotient.classes.iter().map(|x| (x.id, &x.semantics)).collect();
    let readiness: BTreeMap<_, _> = model.readiness.entries.iter().map(|x| (x.history, x.ready_slot)).collect();
    let trace_by_id: BTreeMap<_, _> = traces.iter().map(|x| (x.id, x)).collect();

    let mut variables = Vec::new();
    let mut objective = Vec::new();
    for history in &model.histories {
        let semantics = classes[&partition[history]];
        for trace in traces {
            let authorized = trace.action_count == 1
                && semantics.action_sequence.as_slice() == [trace.action_code]
                && trace.service == semantics.service;
            let timely = trace.release_slot >= readiness[history]
                && trace.release_slot >= semantics.release_window_start
                && trace.release_slot <= semantics.release_deadline;
            if authorized && timely {
                let index = u32::try_from(variables.len()).map_err(|_| TraceLpError::ResourceLimit)?;
                variables.push(TraceVariable { history: *history, trace: trace.id });
                objective.push(LinearTerm { variable: index, coefficient: i64::try_from(trace.cost).map_err(|_| TraceLpError::ResourceLimit)? });
            }
        }
        if !variables.iter().any(|x| x.history == *history) {
            return Err(TraceLpError::NoUtilityFeasibleTrace { history: *history });
        }
    }
    if variables.len() > limits.max_variables { return Err(TraceLpError::ResourceLimit); }

    let mut equalities = Vec::new();
    for history in &model.histories {
        equalities.push(Equality { kind: EqualityKind::Normalization { history: *history }, terms: select_terms(&variables, |x| x.history == *history, 1), rhs: 1 });
    }
    for class in &model.action_quotient.classes {
        let members: Vec<_> = model.action_quotient.class_of_history.iter().filter(|x| x.class == class.id).map(|x| x.history).collect();
        let Some(left) = members.first().copied() else { continue };
        for right in members.into_iter().skip(1) {
            for observer in &model.observers.observers {
                let observations: BTreeSet<_> = traces.iter().map(|trace| observation(trace, observer.id)).collect();
                for observed in observations {
                    let mut terms = select_terms(&variables, |x| x.history == left && observation(trace_by_id[&x.trace], observer.id) == observed, 1);
                    terms.extend(select_terms(&variables, |x| x.history == right && observation(trace_by_id[&x.trace], observer.id) == observed, -1));
                    terms.sort_by_key(|x| x.variable);
                    equalities.push(Equality { kind: EqualityKind::ExactAetp { left, right, observer: observer.id, observation: observed }, terms, rhs: 0 });
                }
            }
        }
    }
    if equalities.len() > limits.max_constraints { return Err(TraceLpError::ResourceLimit); }
    Ok(ExplicitTraceLp { variables, equalities, objective })
}

fn validate_traces(model: &PrivateHistoryModel, traces: &[TraceCandidate], limits: TraceLpLimits) -> Result<(), TraceLpError> {
    if traces.is_empty() || traces.len() > limits.max_traces || !traces.windows(2).all(|x| x[0].id < x[1].id) { return Err(TraceLpError::InvalidTraceCatalog); }
    let expected: Vec<_> = model.observers.observers.iter().map(|x| x.id).collect();
    if traces.iter().any(|trace| trace.observations.iter().map(|x| x.observer).ne(expected.iter().copied())) { return Err(TraceLpError::InvalidObservationProjection); }
    Ok(())
}

fn observation(trace: &TraceCandidate, observer: ObserverId) -> ObservationId {
    trace.observations.iter().find(|x| x.observer == observer).expect("validated observer projection").observation
}

fn select_terms(variables: &[TraceVariable], include: impl Fn(&TraceVariable) -> bool, coefficient: i64) -> Vec<LinearTerm> {
    variables.iter().enumerate().filter(|(_, x)| include(x)).map(|(i, _)| LinearTerm { variable: i as u32, coefficient }).collect()
}

impl ExplicitTraceLp {
    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut d = Sha256::new();
        d.update(DOMAIN_MATRIX); d.update([0]);
        d.update((self.variables.len() as u64).to_le_bytes());
        for x in &self.variables { d.update(x.history.0.to_le_bytes()); d.update(x.trace.0.to_le_bytes()); }
        d.update((self.equalities.len() as u64).to_le_bytes());
        for row in &self.equalities { d.update((row.terms.len() as u64).to_le_bytes()); for x in &row.terms { d.update(x.variable.to_le_bytes()); d.update(x.coefficient.to_le_bytes()); } d.update(row.rhs.to_le_bytes()); }
        for x in &self.objective { d.update(x.variable.to_le_bytes()); d.update(x.coefficient.to_le_bytes()); }
        d.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quotient_limit_model::*;

    fn fixture() -> PrivateHistoryModel {
        PrivateHistoryModel {
            histories: vec![PrivateHistoryId(0), PrivateHistoryId(1)],
            action_quotient: ActionQuotient { classes: vec![ActionQuotientClass { id: ActionQuotientClassId(0), semantics: AuthorizedActionSemantics { action_sequence: vec![ActionCode(1)], service: ServiceId(0), policy: PolicyId(0), admission_cutoff: 3, release_window_start: 4, release_deadline: 6, public_fault_contract: 0 } }], class_of_history: vec![HistoryClass { history: PrivateHistoryId(0), class: ActionQuotientClassId(0) }, HistoryClass { history: PrivateHistoryId(1), class: ActionQuotientClassId(0) }] },
            information_tree: InformationTree { information_sets: vec![InformationSet { id: InformationSetId(0), time: 0, public_prefix: PublicPrefixId(0), admitted_quotient_prefix: QuotientPrefixId(0), fault_prefix: FaultPrefixId(0) }] },
            readiness: ReadinessModel { entries: vec![ReadinessEntry { history: PrivateHistoryId(0), ready_slot: 1 }, ReadinessEntry { history: PrivateHistoryId(1), ready_slot: 3 }] },
            public_inputs: PublicInputModel { horizon: 6, public_prefix_count: 1, quotient_prefix_count: 1, fault_prefix_count: 1 },
            observers: ObserverFamily { observers: vec![Observer { id: ObserverId(0), projection: ObserverProjection::Timing }] },
        }
    }
    fn traces() -> Vec<TraceCandidate> { vec![4, 6].into_iter().enumerate().map(|(id, slot)| TraceCandidate { id: TraceId(id as u16), release_slot: slot, action_count: 1, action_code: ActionCode(1), service: ServiceId(0), observations: vec![ObserverObservation { observer: ObserverId(0), observation: ObservationId(slot) }], cost: slot.into() }).collect() }

    #[test]
    fn exact_rows_bind_each_observable_trace() {
        let lp = build_exact_trace_lp(&fixture(), &traces(), ModelLimits::default(), TraceLpLimits::default()).unwrap();
        assert_eq!(lp.variables.len(), 4);
        assert_eq!(lp.equalities.len(), 4);
        assert_ne!(lp.canonical_digest(), [0; 32]);
    }
    #[test]
    fn unauthorized_action_never_becomes_a_variable() {
        let mut traces = traces();
        traces.push(TraceCandidate { id: TraceId(2), action_code: ActionCode(9), ..traces[0].clone() });
        let lp = build_exact_trace_lp(&fixture(), &traces, ModelLimits::default(), TraceLpLimits::default()).unwrap();
        assert!(lp.variables.iter().all(|x| x.trace != TraceId(2)));
    }
    #[test]
    fn incomplete_projection_is_rejected() {
        let mut traces = traces(); traces[0].observations.clear();
        assert_eq!(build_exact_trace_lp(&fixture(), &traces, ModelLimits::default(), TraceLpLimits::default()), Err(TraceLpError::InvalidObservationProjection));
    }
}
