use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::counterexample::{
    CausalField, Counterexample, CounterexampleKind, Observation, RepairCandidate, Side, TraceStep,
};
use crate::model::{ActionEmission, EnvironmentInput, ObligationRef, Release};

pub const COUNTEREXAMPLE_SIGNATURE_SCHEMA_V1: &str =
    "noticer.quotient_forge.counterexample_signature.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalSide {
    Left,
    Right,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalObligation {
    Authorized { obligation: String },
    Recovery { fault: String, triggered_at: u32 },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAction {
    pub obligation: CanonicalObligation,
    pub action: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalCounterexampleKind {
    SecurityDivergence,
    UnauthorizedAction {
        side: CanonicalSide,
        action: String,
        obligation: CanonicalObligation,
    },
    DuplicateAction {
        side: CanonicalSide,
        action: String,
        obligation: CanonicalObligation,
    },
    MissedDeadline {
        side: CanonicalSide,
        action: String,
        obligation: CanonicalObligation,
    },
    RecoverableFaultViolation {
        side: CanonicalSide,
        action: String,
        obligation: CanonicalObligation,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalCausalField {
    ReleasePresence,
    Field { field: String },
    Actions,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalRepairCandidate {
    EqualizeReleasePresence,
    NormalizeField { field: String },
    HideField { observer: String, field: String },
    NormalizeObservedActions,
    BindAuthorizedAction { obligation: CanonicalObligation },
    SuppressDuplicateAction { obligation: CanonicalObligation },
    ScheduleBeforeDeadline { obligation: CanonicalObligation },
    AddRecoveryTransition { obligation: CanonicalObligation },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalObservation {
    pub emitted: bool,
    pub fields: Vec<String>,
    pub actions: Vec<CanonicalAction>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRelease {
    pub emitted: bool,
    pub fields: Vec<String>,
    pub actions: Vec<CanonicalAction>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEnvironmentInput {
    pub id: String,
    pub public_symbol: String,
    pub fault: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTraceStep {
    pub slot: u32,
    pub input: CanonicalEnvironmentInput,
    pub left_release: CanonicalRelease,
    pub right_release: CanonicalRelease,
}

/// Public, value-redacted representation used for duplicate and prefix checks.
///
/// Release field values, private-history identifiers, and combined checker state
/// identifiers are intentionally absent from this type.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCounterexample {
    pub kind: CanonicalCounterexampleKind,
    pub slot: u32,
    pub observer: Option<String>,
    pub left_observation: Option<CanonicalObservation>,
    pub right_observation: Option<CanonicalObservation>,
    pub causal_field: Option<CanonicalCausalField>,
    pub trace: Vec<CanonicalTraceStep>,
    pub repair_candidates: Vec<CanonicalRepairCandidate>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CounterexampleSignature {
    pub schema_version: String,
    pub digest_sha256: String,
    pub counterexample: CanonicalCounterexample,
}

impl CounterexampleSignature {
    pub fn from_counterexample(counterexample: &Counterexample) -> Result<Self, serde_json::Error> {
        let canonical = CanonicalCounterexample::from(counterexample);
        let digest_sha256 = digest(&serde_json::to_vec(&canonical)?);
        Ok(Self {
            schema_version: COUNTEREXAMPLE_SIGNATURE_SCHEMA_V1.to_owned(),
            digest_sha256,
            counterexample: canonical,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn validate_digest(&self) -> Result<bool, serde_json::Error> {
        if self.schema_version != COUNTEREXAMPLE_SIGNATURE_SCHEMA_V1 {
            return Ok(false);
        }
        Ok(self.digest_sha256 == digest(&serde_json::to_vec(&self.counterexample)?))
    }

    #[must_use]
    pub fn is_exact_duplicate(&self, other: &Self) -> bool {
        self.counterexample == other.counterexample
    }

    #[must_use]
    pub fn is_strict_prefix_of(&self, other: &Self) -> bool {
        self.same_violation_context(other)
            && self.counterexample.slot <= other.counterexample.slot
            && self.counterexample.trace.len() < other.counterexample.trace.len()
            && other
                .counterexample
                .trace
                .starts_with(&self.counterexample.trace)
    }

    #[must_use]
    pub fn subsumes(&self, other: &Self) -> bool {
        self.is_exact_duplicate(other) || self.is_strict_prefix_of(other)
    }

    fn same_violation_context(&self, other: &Self) -> bool {
        self.counterexample.kind == other.counterexample.kind
            && self.counterexample.observer == other.counterexample.observer
            && self.counterexample.left_observation == other.counterexample.left_observation
            && self.counterexample.right_observation == other.counterexample.right_observation
            && self.counterexample.causal_field == other.counterexample.causal_field
            && self.counterexample.repair_candidates == other.counterexample.repair_candidates
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogInsert {
    Inserted { removed_subsumed: usize },
    ExactDuplicate,
    SubsumedByExisting,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CounterexampleCatalog {
    entries: Vec<CounterexampleSignature>,
}

impl CounterexampleCatalog {
    #[must_use]
    pub fn entries(&self) -> &[CounterexampleSignature] {
        &self.entries
    }

    pub fn insert(&mut self, signature: CounterexampleSignature) -> CatalogInsert {
        if self
            .entries
            .iter()
            .any(|existing| existing.is_exact_duplicate(&signature))
        {
            return CatalogInsert::ExactDuplicate;
        }
        if self
            .entries
            .iter()
            .any(|existing| existing.subsumes(&signature))
        {
            return CatalogInsert::SubsumedByExisting;
        }
        let before = self.entries.len();
        self.entries
            .retain(|existing| !signature.subsumes(existing));
        let removed_subsumed = before - self.entries.len();
        self.entries.push(signature);
        self.entries
            .sort_by(|left, right| left.counterexample.cmp(&right.counterexample));
        CatalogInsert::Inserted { removed_subsumed }
    }

    pub fn insert_counterexample(
        &mut self,
        counterexample: &Counterexample,
    ) -> Result<CatalogInsert, serde_json::Error> {
        Ok(self.insert(CounterexampleSignature::from_counterexample(
            counterexample,
        )?))
    }
}

impl From<&Counterexample> for CanonicalCounterexample {
    fn from(value: &Counterexample) -> Self {
        let mut repair_candidates = value
            .repair_candidates
            .iter()
            .map(canonical_repair)
            .collect::<Vec<_>>();
        repair_candidates.sort();
        repair_candidates.dedup();
        Self {
            kind: canonical_kind(&value.kind),
            slot: value.slot,
            observer: value
                .observer
                .as_ref()
                .map(|observer| observer.as_str().to_owned()),
            left_observation: value.left_observation.as_ref().map(canonical_observation),
            right_observation: value.right_observation.as_ref().map(canonical_observation),
            causal_field: value.causal_field.as_ref().map(canonical_causal_field),
            trace: value.trace.iter().map(canonical_trace_step).collect(),
            repair_candidates,
        }
    }
}

fn canonical_kind(value: &CounterexampleKind) -> CanonicalCounterexampleKind {
    match value {
        CounterexampleKind::SecurityDivergence => CanonicalCounterexampleKind::SecurityDivergence,
        CounterexampleKind::UnauthorizedAction {
            side,
            action,
            obligation,
        } => CanonicalCounterexampleKind::UnauthorizedAction {
            side: canonical_side(*side),
            action: action.as_str().to_owned(),
            obligation: canonical_obligation(obligation),
        },
        CounterexampleKind::DuplicateAction {
            side,
            action,
            obligation,
        } => CanonicalCounterexampleKind::DuplicateAction {
            side: canonical_side(*side),
            action: action.as_str().to_owned(),
            obligation: canonical_obligation(obligation),
        },
        CounterexampleKind::MissedDeadline {
            side,
            action,
            obligation,
        } => CanonicalCounterexampleKind::MissedDeadline {
            side: canonical_side(*side),
            action: action.as_str().to_owned(),
            obligation: canonical_obligation(obligation),
        },
        CounterexampleKind::RecoverableFaultViolation {
            side,
            action,
            obligation,
        } => CanonicalCounterexampleKind::RecoverableFaultViolation {
            side: canonical_side(*side),
            action: action.as_str().to_owned(),
            obligation: canonical_obligation(obligation),
        },
    }
}

const fn canonical_side(value: Side) -> CanonicalSide {
    match value {
        Side::Left => CanonicalSide::Left,
        Side::Right => CanonicalSide::Right,
    }
}

fn canonical_obligation(value: &ObligationRef) -> CanonicalObligation {
    match value {
        ObligationRef::Authorized(obligation) => CanonicalObligation::Authorized {
            obligation: obligation.as_str().to_owned(),
        },
        ObligationRef::Recovery {
            fault,
            triggered_at,
        } => CanonicalObligation::Recovery {
            fault: fault.as_str().to_owned(),
            triggered_at: *triggered_at,
        },
    }
}

fn canonical_causal_field(value: &CausalField) -> CanonicalCausalField {
    match value {
        CausalField::ReleasePresence => CanonicalCausalField::ReleasePresence,
        CausalField::Field(field) => CanonicalCausalField::Field {
            field: field.as_str().to_owned(),
        },
        CausalField::Actions => CanonicalCausalField::Actions,
    }
}

fn canonical_repair(value: &RepairCandidate) -> CanonicalRepairCandidate {
    match value {
        RepairCandidate::EqualizeReleasePresence => {
            CanonicalRepairCandidate::EqualizeReleasePresence
        }
        RepairCandidate::NormalizeField(field) => CanonicalRepairCandidate::NormalizeField {
            field: field.as_str().to_owned(),
        },
        RepairCandidate::HideField { observer, field } => CanonicalRepairCandidate::HideField {
            observer: observer.as_str().to_owned(),
            field: field.as_str().to_owned(),
        },
        RepairCandidate::NormalizeObservedActions => {
            CanonicalRepairCandidate::NormalizeObservedActions
        }
        RepairCandidate::BindAuthorizedAction(obligation) => {
            CanonicalRepairCandidate::BindAuthorizedAction {
                obligation: canonical_obligation(obligation),
            }
        }
        RepairCandidate::SuppressDuplicateAction(obligation) => {
            CanonicalRepairCandidate::SuppressDuplicateAction {
                obligation: canonical_obligation(obligation),
            }
        }
        RepairCandidate::ScheduleBeforeDeadline(obligation) => {
            CanonicalRepairCandidate::ScheduleBeforeDeadline {
                obligation: canonical_obligation(obligation),
            }
        }
        RepairCandidate::AddRecoveryTransition(obligation) => {
            CanonicalRepairCandidate::AddRecoveryTransition {
                obligation: canonical_obligation(obligation),
            }
        }
    }
}

fn canonical_observation(value: &Observation) -> CanonicalObservation {
    CanonicalObservation {
        emitted: value.emitted,
        fields: value
            .fields
            .keys()
            .map(|field| field.as_str().to_owned())
            .collect(),
        actions: canonical_actions(&value.actions),
    }
}

fn canonical_release(value: &Release) -> CanonicalRelease {
    CanonicalRelease {
        emitted: value.emitted,
        fields: value
            .fields
            .keys()
            .map(|field| field.as_str().to_owned())
            .collect(),
        actions: canonical_actions(&value.actions),
    }
}

fn canonical_actions(values: &[ActionEmission]) -> Vec<CanonicalAction> {
    let mut actions = values
        .iter()
        .map(|value| CanonicalAction {
            obligation: canonical_obligation(&value.obligation),
            action: value.action.as_str().to_owned(),
        })
        .collect::<Vec<_>>();
    actions.sort();
    actions
}

fn canonical_input(value: &EnvironmentInput) -> CanonicalEnvironmentInput {
    CanonicalEnvironmentInput {
        id: value.id.as_str().to_owned(),
        public_symbol: value.public_symbol.clone(),
        fault: value.fault.as_ref().map(|fault| fault.as_str().to_owned()),
    }
}

fn canonical_trace_step(value: &TraceStep) -> CanonicalTraceStep {
    CanonicalTraceStep {
        slot: value.slot,
        input: canonical_input(&value.input),
        left_release: canonical_release(&value.left_release),
        right_release: canonical_release(&value.right_release),
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
