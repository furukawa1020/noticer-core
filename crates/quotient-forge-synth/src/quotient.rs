//! Canonical action-semantics quotient partitions.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const ACTION_SEMANTICS_SCHEMA_V1: &str = "noticer.quotient_forge.action_semantics.v1";
pub const QUOTIENT_PARTITION_SCHEMA_V1: &str = "noticer.quotient_forge.quotient_partition.v1";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ActionSemanticAtom {
    pub observation_sha256: String,
    pub authorized_action_sha256: String,
}

impl ActionSemanticAtom {
    pub fn new(
        observation_sha256: impl Into<String>,
        authorized_action_sha256: impl Into<String>,
    ) -> Result<Self, QuotientError> {
        let atom = Self {
            observation_sha256: observation_sha256.into(),
            authorized_action_sha256: authorized_action_sha256.into(),
        };
        atom.validate()?;
        Ok(atom)
    }

    fn validate(&self) -> Result<(), QuotientError> {
        require_sha256("observation_sha256", &self.observation_sha256)?;
        require_sha256("authorized_action_sha256", &self.authorized_action_sha256)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActionSemantics {
    pub schema_version: String,
    pub atoms: Vec<ActionSemanticAtom>,
    pub semantics_sha256: String,
}

impl ActionSemantics {
    pub fn new(mut atoms: Vec<ActionSemanticAtom>) -> Result<Self, QuotientError> {
        if atoms.is_empty() {
            return Err(QuotientError::EmptyActionSemantics);
        }
        for atom in &atoms {
            atom.validate()?;
        }
        atoms.sort();
        if atoms.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(QuotientError::DuplicateActionSemanticAtom);
        }
        let mut semantics = Self {
            schema_version: ACTION_SEMANTICS_SCHEMA_V1.to_owned(),
            atoms,
            semantics_sha256: String::new(),
        };
        semantics.semantics_sha256 = semantics.digest()?;
        semantics.validate()?;
        Ok(semantics)
    }

    pub fn validate(&self) -> Result<(), QuotientError> {
        if self.schema_version != ACTION_SEMANTICS_SCHEMA_V1 {
            return Err(QuotientError::SchemaVersion);
        }
        if self.atoms.is_empty() || self.atoms.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(QuotientError::NonCanonicalActionSemantics);
        }
        for atom in &self.atoms {
            atom.validate()?;
        }
        require_sha256("semantics_sha256", &self.semantics_sha256)?;
        if self.digest()? != self.semantics_sha256 {
            return Err(QuotientError::DigestMismatch("semantics_sha256"));
        }
        Ok(())
    }

    fn digest(&self) -> Result<String, QuotientError> {
        let mut payload = self.clone();
        payload.semantics_sha256.clear();
        canonical_json_sha256(&payload)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientState {
    source_index: u32,
    _private_history_label: String,
    action_semantics: ActionSemantics,
}

impl QuotientState {
    pub fn new(
        source_index: u32,
        private_history_label: impl Into<String>,
        action_semantics: ActionSemantics,
    ) -> Result<Self, QuotientError> {
        let private_history_label = private_history_label.into();
        if private_history_label.is_empty() {
            return Err(QuotientError::EmptyPrivateHistoryLabel);
        }
        action_semantics.validate()?;
        Ok(Self {
            source_index,
            _private_history_label: private_history_label,
            action_semantics,
        })
    }

    pub const fn source_index(&self) -> u32 {
        self.source_index
    }

    pub fn action_semantics(&self) -> &ActionSemantics {
        &self.action_semantics
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RelationEdge {
    pub left_source_index: u32,
    pub right_source_index: u32,
}

impl RelationEdge {
    pub const fn new(left_source_index: u32, right_source_index: u32) -> Self {
        Self {
            left_source_index,
            right_source_index,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalQuotientClass {
    pub class_id: u32,
    pub action_semantics_sha256: String,
    pub member_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalQuotientArtifact {
    pub schema_version: String,
    pub problem_sha256: String,
    pub source_state_count: u32,
    pub relation_pair_count: u64,
    pub classes: Vec<CanonicalQuotientClass>,
    pub private_labels_included: bool,
    pub artifact_sha256: String,
}

impl CanonicalQuotientArtifact {
    pub fn validate(&self) -> Result<(), QuotientError> {
        if self.schema_version != QUOTIENT_PARTITION_SCHEMA_V1 {
            return Err(QuotientError::SchemaVersion);
        }
        require_sha256("problem_sha256", &self.problem_sha256)?;
        require_sha256("artifact_sha256", &self.artifact_sha256)?;
        if self.private_labels_included || self.source_state_count == 0 || self.classes.is_empty() {
            return Err(QuotientError::InvalidArtifact);
        }
        let mut member_total = 0_u32;
        let mut relation_total = 0_u64;
        for (index, class) in self.classes.iter().enumerate() {
            if class.class_id != index as u32 || class.member_count == 0 {
                return Err(QuotientError::NonCanonicalClasses);
            }
            require_sha256("action_semantics_sha256", &class.action_semantics_sha256)?;
            if index > 0
                && self.classes[index - 1].action_semantics_sha256 >= class.action_semantics_sha256
            {
                return Err(QuotientError::NonCanonicalClasses);
            }
            member_total = member_total
                .checked_add(class.member_count)
                .ok_or(QuotientError::ModelTooLarge)?;
            let count = u64::from(class.member_count);
            relation_total = relation_total
                .checked_add(
                    count
                        .checked_mul(count)
                        .ok_or(QuotientError::ModelTooLarge)?,
                )
                .ok_or(QuotientError::ModelTooLarge)?;
        }
        if member_total != self.source_state_count || relation_total != self.relation_pair_count {
            return Err(QuotientError::InvalidArtifact);
        }
        let mut payload = self.clone();
        payload.artifact_sha256.clear();
        if canonical_json_sha256(&payload)? != self.artifact_sha256 {
            return Err(QuotientError::DigestMismatch("artifact_sha256"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientPartition {
    pub artifact: CanonicalQuotientArtifact,
    state_to_class: BTreeMap<u32, u32>,
}

impl QuotientPartition {
    pub fn class_for_source_index(&self, source_index: u32) -> Option<u32> {
        self.state_to_class.get(&source_index).copied()
    }

    pub fn mapped_state_count(&self) -> usize {
        self.state_to_class.len()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum QuotientError {
    #[error("{0} must be a lowercase SHA-256 digest")]
    InvalidSha256(&'static str),
    #[error("action semantics must contain at least one atom")]
    EmptyActionSemantics,
    #[error("action semantics contains a duplicate atom")]
    DuplicateActionSemanticAtom,
    #[error("action semantics is not canonical")]
    NonCanonicalActionSemantics,
    #[error("private history label must be non-empty")]
    EmptyPrivateHistoryLabel,
    #[error("quotient requires at least one source state")]
    EmptyStateSet,
    #[error("source index is duplicated")]
    DuplicateSourceIndex,
    #[error("relation edge is duplicated")]
    DuplicateRelationEdge,
    #[error("relation references an unknown source index")]
    UnknownSourceIndex,
    #[error("different action semantics were merged")]
    DifferentActionSemanticsMerged,
    #[error("relation is not reflexive")]
    RelationNotReflexive,
    #[error("relation is not symmetric")]
    RelationNotSymmetric,
    #[error("relation is not transitive")]
    RelationNotTransitive,
    #[error("equal action semantics were split across classes")]
    EquivalentSemanticsSeparated,
    #[error("model exceeds representable artifact bounds")]
    ModelTooLarge,
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("quotient classes are not canonical")]
    NonCanonicalClasses,
    #[error("quotient artifact fields are inconsistent")]
    InvalidArtifact,
    #[error("{0} does not match its canonical payload")]
    DigestMismatch(&'static str),
    #[error("canonical artifact serialization failed")]
    Serialization,
}

pub fn derive_action_equivalence(
    states: &[QuotientState],
) -> Result<Vec<RelationEdge>, QuotientError> {
    validate_states(states)?;
    let mut edges = Vec::new();
    for left in states {
        for right in states {
            if left.action_semantics.semantics_sha256 == right.action_semantics.semantics_sha256 {
                edges.push(RelationEdge::new(left.source_index, right.source_index));
            }
        }
    }
    edges.sort();
    Ok(edges)
}

pub fn build_quotient_partition(
    problem_sha256: impl Into<String>,
    states: &[QuotientState],
    relation: &[RelationEdge],
) -> Result<QuotientPartition, QuotientError> {
    let problem_sha256 = problem_sha256.into();
    require_sha256("problem_sha256", &problem_sha256)?;
    validate_states(states)?;
    let by_index = states
        .iter()
        .map(|state| (state.source_index, state))
        .collect::<BTreeMap<_, _>>();
    let relation_set = relation.iter().copied().collect::<BTreeSet<_>>();
    if relation_set.len() != relation.len() {
        return Err(QuotientError::DuplicateRelationEdge);
    }
    for edge in &relation_set {
        let Some(left) = by_index.get(&edge.left_source_index) else {
            return Err(QuotientError::UnknownSourceIndex);
        };
        let Some(right) = by_index.get(&edge.right_source_index) else {
            return Err(QuotientError::UnknownSourceIndex);
        };
        if left.action_semantics.semantics_sha256 != right.action_semantics.semantics_sha256 {
            return Err(QuotientError::DifferentActionSemanticsMerged);
        }
    }
    for source_index in by_index.keys() {
        if !relation_set.contains(&RelationEdge::new(*source_index, *source_index)) {
            return Err(QuotientError::RelationNotReflexive);
        }
    }
    for edge in &relation_set {
        if !relation_set.contains(&RelationEdge::new(
            edge.right_source_index,
            edge.left_source_index,
        )) {
            return Err(QuotientError::RelationNotSymmetric);
        }
    }
    for left_middle in &relation_set {
        for middle_right in relation_set
            .iter()
            .filter(|edge| edge.left_source_index == left_middle.right_source_index)
        {
            if !relation_set.contains(&RelationEdge::new(
                left_middle.left_source_index,
                middle_right.right_source_index,
            )) {
                return Err(QuotientError::RelationNotTransitive);
            }
        }
    }
    for left in states {
        for right in states {
            if left.action_semantics.semantics_sha256 == right.action_semantics.semantics_sha256
                && !relation_set.contains(&RelationEdge::new(left.source_index, right.source_index))
            {
                return Err(QuotientError::EquivalentSemanticsSeparated);
            }
        }
    }

    let mut members_by_semantics = BTreeMap::<String, Vec<u32>>::new();
    for state in states {
        members_by_semantics
            .entry(state.action_semantics.semantics_sha256.clone())
            .or_default()
            .push(state.source_index);
    }
    let mut classes = Vec::new();
    let mut state_to_class = BTreeMap::new();
    for (class_index, (semantics_sha256, mut members)) in
        members_by_semantics.into_iter().enumerate()
    {
        let class_id = u32::try_from(class_index).map_err(|_| QuotientError::ModelTooLarge)?;
        members.sort_unstable();
        let member_count =
            u32::try_from(members.len()).map_err(|_| QuotientError::ModelTooLarge)?;
        for source_index in members {
            state_to_class.insert(source_index, class_id);
        }
        classes.push(CanonicalQuotientClass {
            class_id,
            action_semantics_sha256: semantics_sha256,
            member_count,
        });
    }
    let source_state_count =
        u32::try_from(states.len()).map_err(|_| QuotientError::ModelTooLarge)?;
    let relation_pair_count =
        u64::try_from(relation_set.len()).map_err(|_| QuotientError::ModelTooLarge)?;
    let mut artifact = CanonicalQuotientArtifact {
        schema_version: QUOTIENT_PARTITION_SCHEMA_V1.to_owned(),
        problem_sha256,
        source_state_count,
        relation_pair_count,
        classes,
        private_labels_included: false,
        artifact_sha256: String::new(),
    };
    artifact.artifact_sha256 = canonical_json_sha256(&artifact)?;
    artifact.validate()?;
    Ok(QuotientPartition {
        artifact,
        state_to_class,
    })
}

fn validate_states(states: &[QuotientState]) -> Result<(), QuotientError> {
    if states.is_empty() {
        return Err(QuotientError::EmptyStateSet);
    }
    let mut indices = BTreeSet::new();
    for state in states {
        state.action_semantics.validate()?;
        if !indices.insert(state.source_index) {
            return Err(QuotientError::DuplicateSourceIndex);
        }
    }
    Ok(())
}

fn require_sha256(field: &'static str, value: &str) -> Result<(), QuotientError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(QuotientError::InvalidSha256(field))
    }
}

fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String, QuotientError> {
    let bytes = serde_json::to_vec(value).map_err(|_| QuotientError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
