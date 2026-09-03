use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const QDIMACS_SCHEMA_V1: &str = "noticer.quotient_forge.qdimacs.v1";
pub const MAX_QDIMACS_VARIABLES: usize = 1_000_000;
pub const MAX_QDIMACS_CLAUSES: usize = 4_000_000;
pub const MAX_VARIABLE_COORDINATES: usize = 8;
pub const MAX_VARIABLE_COORDINATE: u32 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuantifierKind {
    Existential,
    Universal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VariableRole {
    MachineChoice,
    PrivateHistoryLeft,
    PrivateHistoryRight,
    EnvironmentTrace,
    FaultTrace,
    DependentWitness,
}

impl VariableRole {
    const fn quantifier(self) -> QuantifierKind {
        match self {
            Self::MachineChoice | Self::DependentWitness => QuantifierKind::Existential,
            Self::PrivateHistoryLeft
            | Self::PrivateHistoryRight
            | Self::EnvironmentTrace
            | Self::FaultTrace => QuantifierKind::Universal,
        }
    }

    const fn block_rank(self) -> u8 {
        match self {
            Self::MachineChoice => 0,
            Self::PrivateHistoryLeft
            | Self::PrivateHistoryRight
            | Self::EnvironmentTrace
            | Self::FaultTrace => 1,
            Self::DependentWitness => 2,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::MachineChoice => "MACHINE_CHOICE",
            Self::PrivateHistoryLeft => "PRIVATE_HISTORY_LEFT",
            Self::PrivateHistoryRight => "PRIVATE_HISTORY_RIGHT",
            Self::EnvironmentTrace => "ENVIRONMENT_TRACE",
            Self::FaultTrace => "FAULT_TRACE",
            Self::DependentWitness => "DEPENDENT_WITNESS",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VariableKey {
    pub role: VariableRole,
    pub coordinates: Vec<u32>,
}

impl VariableKey {
    pub fn new(role: VariableRole, coordinates: impl Into<Vec<u32>>) -> Self {
        Self {
            role,
            coordinates: coordinates.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolicLiteral {
    pub variable: VariableKey,
    pub positive: bool,
}

impl SymbolicLiteral {
    pub fn positive(variable: VariableKey) -> Self {
        Self {
            variable,
            positive: true,
        }
    }

    pub fn negative(variable: VariableKey) -> Self {
        Self {
            variable,
            positive: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolicClause {
    pub literals: Vec<SymbolicLiteral>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QdimacsBounds {
    pub plant_states: u32,
    pub machine_states: u32,
    pub horizon: u32,
    pub action_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QdimacsSpec {
    pub bounds: QdimacsBounds,
    pub seed: u64,
    pub variables: Vec<VariableKey>,
    pub clauses: Vec<SymbolicClause>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VariableRecord {
    pub id: u32,
    pub role: VariableRole,
    pub coordinates: Vec<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuantifierBlock {
    pub kind: QuantifierKind,
    pub variables: Vec<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QdimacsMetadata {
    pub schema_version: String,
    pub bounds: QdimacsBounds,
    pub seed: u64,
    pub variable_count: u32,
    pub clause_count: u32,
    pub quantifier_blocks: Vec<QuantifierBlock>,
    pub variables: Vec<VariableRecord>,
    pub qdimacs_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QdimacsArtifact {
    pub document: String,
    pub metadata: QdimacsMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QdimacsValidation {
    pub variable_count: u32,
    pub clause_count: u32,
    pub quantifier_block_count: u32,
}

#[derive(Debug, Error)]
pub enum QdimacsError {
    #[error("QDIMACS bound must be positive: {0}")]
    EmptyBound(&'static str),
    #[error("QDIMACS variable registry is empty")]
    EmptyVariableRegistry,
    #[error("QDIMACS variable limit exceeded")]
    VariableLimitExceeded,
    #[error("QDIMACS clause limit exceeded")]
    ClauseLimitExceeded,
    #[error("invalid variable key: {0:?}")]
    InvalidVariableKey(VariableKey),
    #[error("duplicate variable key: {0:?}")]
    DuplicateVariable(VariableKey),
    #[error("machine-choice existential block is missing")]
    MissingMachineBlock,
    #[error("universal trace block is missing")]
    MissingUniversalBlock,
    #[error("clause references an unregistered variable: {0:?}")]
    UnregisteredVariable(VariableKey),
    #[error("clause repeats literal for variable {0}")]
    DuplicateLiteral(u32),
    #[error("clause is tautological for variable {0}")]
    TautologicalClause(u32),
    #[error("duplicate clause after canonicalization")]
    DuplicateClause,
    #[error("malformed QDIMACS at line {line}: {reason}")]
    MalformedDocument { line: usize, reason: String },
    #[error("QDIMACS header count mismatch: {0}")]
    HeaderCountMismatch(&'static str),
    #[error("could not serialize QDIMACS metadata: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("could not write QDIMACS artifact: {0}")]
    Io(#[from] std::io::Error),
}

impl QdimacsArtifact {
    pub fn metadata_json_bytes(&self) -> Result<Vec<u8>, QdimacsError> {
        let mut bytes = serde_json::to_vec(&self.metadata)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn write_to_directory(&self, directory: &Path) -> Result<(), QdimacsError> {
        fs::create_dir_all(directory)?;
        fs::write(directory.join("problem.qdimacs"), self.document.as_bytes())?;
        fs::write(directory.join("metadata.json"), self.metadata_json_bytes()?)?;
        Ok(())
    }
}

pub fn encode_qdimacs(spec: &QdimacsSpec) -> Result<QdimacsArtifact, QdimacsError> {
    validate_bounds(spec.bounds)?;
    if spec.variables.is_empty() {
        return Err(QdimacsError::EmptyVariableRegistry);
    }
    if spec.variables.len() > MAX_QDIMACS_VARIABLES {
        return Err(QdimacsError::VariableLimitExceeded);
    }
    if spec.clauses.len() > MAX_QDIMACS_CLAUSES {
        return Err(QdimacsError::ClauseLimitExceeded);
    }

    let mut variables = spec.variables.clone();
    for variable in &variables {
        validate_variable_key(variable)?;
    }
    variables.sort_by_key(|variable| {
        (
            variable.role.block_rank(),
            variable.role,
            variable.coordinates.clone(),
        )
    });
    if let Some(duplicate) = variables.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(QdimacsError::DuplicateVariable(duplicate[0].clone()));
    }
    if !variables
        .iter()
        .any(|variable| variable.role == VariableRole::MachineChoice)
    {
        return Err(QdimacsError::MissingMachineBlock);
    }
    if !variables
        .iter()
        .any(|variable| variable.role.quantifier() == QuantifierKind::Universal)
    {
        return Err(QdimacsError::MissingUniversalBlock);
    }

    let registry = variables
        .iter()
        .enumerate()
        .map(|(index, variable)| (variable.clone(), u32::try_from(index + 1).unwrap()))
        .collect::<BTreeMap<_, _>>();
    let records = variables
        .iter()
        .map(|variable| VariableRecord {
            id: registry[variable],
            role: variable.role,
            coordinates: variable.coordinates.clone(),
        })
        .collect::<Vec<_>>();
    let quantifier_blocks = build_quantifier_blocks(&records);
    let clauses = canonicalize_clauses(&spec.clauses, &registry)?;
    let document = render_document(spec, &records, &quantifier_blocks, &clauses);
    validate_qdimacs(&document)?;

    let variable_count = u32::try_from(records.len()).unwrap();
    let clause_count = u32::try_from(clauses.len()).unwrap();
    let metadata = QdimacsMetadata {
        schema_version: QDIMACS_SCHEMA_V1.to_owned(),
        bounds: spec.bounds,
        seed: spec.seed,
        variable_count,
        clause_count,
        quantifier_blocks,
        variables: records,
        qdimacs_sha256: sha256(document.as_bytes()),
    };
    Ok(QdimacsArtifact { document, metadata })
}

pub fn validate_qdimacs(document: &str) -> Result<QdimacsValidation, QdimacsError> {
    let mut header = None;
    let mut quantified = BTreeSet::new();
    let mut block_kinds = Vec::new();
    let mut clauses = Vec::<Vec<i32>>::new();
    let mut clause_phase = false;

    for (line_index, line) in document.lines().enumerate() {
        let line_number = line_index + 1;
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.is_empty() || tokens[0] == "c" {
            continue;
        }
        match tokens[0] {
            "p" => {
                if header.is_some() || tokens.len() != 4 || tokens[1] != "cnf" {
                    return malformed(line_number, "invalid or duplicate problem header");
                }
                let variable_count = parse_u32(tokens[2], line_number, "variable count")?;
                let clause_count = parse_u32(tokens[3], line_number, "clause count")?;
                if variable_count == 0
                    || usize::try_from(variable_count).unwrap() > MAX_QDIMACS_VARIABLES
                    || usize::try_from(clause_count).unwrap() > MAX_QDIMACS_CLAUSES
                {
                    return malformed(line_number, "header count is outside the contract limit");
                }
                header = Some((variable_count, clause_count));
            }
            "e" | "a" => {
                let (variable_count, _) =
                    header.ok_or_else(|| malformed_value(line_number, "missing header"))?;
                if clause_phase || tokens.len() < 2 || tokens.last() != Some(&"0") {
                    return malformed(line_number, "invalid quantifier block");
                }
                let kind = if tokens[0] == "e" {
                    QuantifierKind::Existential
                } else {
                    QuantifierKind::Universal
                };
                if block_kinds.last() == Some(&kind) {
                    return malformed(line_number, "adjacent quantifier blocks must be merged");
                }
                let mut previous = 0;
                for token in &tokens[1..tokens.len() - 1] {
                    let variable = parse_u32(token, line_number, "quantified variable")?;
                    if variable == 0 || variable > variable_count || variable <= previous {
                        return malformed(
                            line_number,
                            "quantified variables must be unique ascending in-range IDs",
                        );
                    }
                    if !quantified.insert(variable) {
                        return malformed(line_number, "variable is quantified more than once");
                    }
                    previous = variable;
                }
                if previous == 0 {
                    return malformed(line_number, "empty quantifier block");
                }
                block_kinds.push(kind);
            }
            _ => {
                let (variable_count, _) =
                    header.ok_or_else(|| malformed_value(line_number, "missing header"))?;
                clause_phase = true;
                let clause = parse_clause(&tokens, variable_count, line_number)?;
                if let Some(previous) = clauses.last() {
                    if previous >= &clause {
                        if previous == &clause {
                            return Err(QdimacsError::DuplicateClause);
                        }
                        return malformed(line_number, "clauses are not in canonical order");
                    }
                }
                clauses.push(clause);
            }
        }
    }

    let (variable_count, declared_clause_count) =
        header.ok_or_else(|| malformed_value(0, "missing header"))?;
    let expected_blocks = [
        QuantifierKind::Existential,
        QuantifierKind::Universal,
        QuantifierKind::Existential,
    ];
    if block_kinds.len() < 2
        || block_kinds.len() > 3
        || block_kinds != expected_blocks[..block_kinds.len()]
    {
        return Err(QdimacsError::HeaderCountMismatch("quantifier blocks"));
    }
    if quantified.len() != usize::try_from(variable_count).unwrap()
        || !(1..=variable_count).all(|variable| quantified.contains(&variable))
    {
        return Err(QdimacsError::HeaderCountMismatch("quantified variables"));
    }
    if clauses.len() != usize::try_from(declared_clause_count).unwrap() {
        return Err(QdimacsError::HeaderCountMismatch("clauses"));
    }
    Ok(QdimacsValidation {
        variable_count,
        clause_count: declared_clause_count,
        quantifier_block_count: u32::try_from(block_kinds.len()).unwrap(),
    })
}

fn validate_bounds(bounds: QdimacsBounds) -> Result<(), QdimacsError> {
    for (name, value) in [
        ("plant_states", bounds.plant_states),
        ("machine_states", bounds.machine_states),
        ("horizon", bounds.horizon),
        ("action_count", bounds.action_count),
    ] {
        if value == 0 {
            return Err(QdimacsError::EmptyBound(name));
        }
    }
    Ok(())
}

fn validate_variable_key(variable: &VariableKey) -> Result<(), QdimacsError> {
    if variable.coordinates.is_empty()
        || variable.coordinates.len() > MAX_VARIABLE_COORDINATES
        || variable
            .coordinates
            .iter()
            .any(|coordinate| *coordinate > MAX_VARIABLE_COORDINATE)
    {
        return Err(QdimacsError::InvalidVariableKey(variable.clone()));
    }
    Ok(())
}

fn build_quantifier_blocks(records: &[VariableRecord]) -> Vec<QuantifierBlock> {
    let mut blocks = Vec::<QuantifierBlock>::new();
    for record in records {
        let kind = record.role.quantifier();
        if let Some(block) = blocks.last_mut().filter(|block| block.kind == kind) {
            block.variables.push(record.id);
        } else {
            blocks.push(QuantifierBlock {
                kind,
                variables: vec![record.id],
            });
        }
    }
    blocks
}

fn canonicalize_clauses(
    symbolic: &[SymbolicClause],
    registry: &BTreeMap<VariableKey, u32>,
) -> Result<Vec<Vec<i32>>, QdimacsError> {
    let mut clauses = Vec::with_capacity(symbolic.len());
    for clause in symbolic {
        let mut polarities = BTreeMap::<u32, bool>::new();
        for literal in &clause.literals {
            validate_variable_key(&literal.variable)?;
            let variable = registry
                .get(&literal.variable)
                .copied()
                .ok_or_else(|| QdimacsError::UnregisteredVariable(literal.variable.clone()))?;
            if let Some(previous) = polarities.insert(variable, literal.positive) {
                if previous == literal.positive {
                    return Err(QdimacsError::DuplicateLiteral(variable));
                }
                return Err(QdimacsError::TautologicalClause(variable));
            }
        }
        let mut literals = polarities
            .into_iter()
            .map(|(variable, positive)| {
                let signed = i32::try_from(variable).unwrap();
                if positive {
                    signed
                } else {
                    -signed
                }
            })
            .collect::<Vec<_>>();
        literals.sort_by_key(|literal| (literal.unsigned_abs(), *literal > 0));
        clauses.push(literals);
    }
    clauses.sort();
    if clauses.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(QdimacsError::DuplicateClause);
    }
    Ok(clauses)
}

fn render_document(
    spec: &QdimacsSpec,
    records: &[VariableRecord],
    blocks: &[QuantifierBlock],
    clauses: &[Vec<i32>],
) -> String {
    let mut document = String::new();
    writeln!(document, "c schema {QDIMACS_SCHEMA_V1}").unwrap();
    writeln!(
        document,
        "c bounds plant={} machine={} horizon={} actions={}",
        spec.bounds.plant_states,
        spec.bounds.machine_states,
        spec.bounds.horizon,
        spec.bounds.action_count
    )
    .unwrap();
    writeln!(document, "c seed {}", spec.seed).unwrap();
    for record in records {
        let coordinates = record
            .coordinates
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        writeln!(
            document,
            "c var {} {} {}",
            record.id,
            record.role.label(),
            coordinates
        )
        .unwrap();
    }
    writeln!(document, "p cnf {} {}", records.len(), clauses.len()).unwrap();
    for block in blocks {
        let prefix = match block.kind {
            QuantifierKind::Existential => 'e',
            QuantifierKind::Universal => 'a',
        };
        write!(document, "{prefix}").unwrap();
        for variable in &block.variables {
            write!(document, " {variable}").unwrap();
        }
        writeln!(document, " 0").unwrap();
    }
    for clause in clauses {
        for literal in clause {
            write!(document, "{literal} ").unwrap();
        }
        writeln!(document, "0").unwrap();
    }
    document
}

fn parse_clause(
    tokens: &[&str],
    variable_count: u32,
    line_number: usize,
) -> Result<Vec<i32>, QdimacsError> {
    if tokens.last() != Some(&"0") || tokens[..tokens.len() - 1].contains(&"0") {
        return malformed(
            line_number,
            "clause must end with exactly one zero terminator",
        );
    }
    let mut polarities = BTreeMap::<u32, bool>::new();
    let mut literals = Vec::with_capacity(tokens.len().saturating_sub(1));
    for token in &tokens[..tokens.len() - 1] {
        let literal = token
            .parse::<i64>()
            .map_err(|_| malformed_value(line_number, "literal is not an integer"))?;
        let absolute = literal
            .checked_abs()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| malformed_value(line_number, "literal is outside the integer range"))?;
        if absolute == 0 || absolute > variable_count {
            return malformed(line_number, "literal references an out-of-range variable");
        }
        let positive = literal > 0;
        if let Some(previous) = polarities.insert(absolute, positive) {
            if previous == positive {
                return Err(QdimacsError::DuplicateLiteral(absolute));
            }
            return Err(QdimacsError::TautologicalClause(absolute));
        }
        literals.push(i32::try_from(literal).map_err(|_| {
            malformed_value(line_number, "literal is outside the QDIMACS integer range")
        })?);
    }
    let mut canonical = literals.clone();
    canonical.sort_by_key(|literal| (literal.unsigned_abs(), *literal > 0));
    if canonical != literals {
        return malformed(line_number, "literals are not in canonical order");
    }
    Ok(literals)
}

fn parse_u32(token: &str, line: usize, field: &str) -> Result<u32, QdimacsError> {
    token
        .parse::<u32>()
        .map_err(|_| malformed_value(line, format!("{field} is not an unsigned integer")))
}

fn malformed<T>(line: usize, reason: impl Into<String>) -> Result<T, QdimacsError> {
    Err(malformed_value(line, reason))
}

fn malformed_value(line: usize, reason: impl Into<String>) -> QdimacsError {
    QdimacsError::MalformedDocument {
        line,
        reason: reason.into(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
