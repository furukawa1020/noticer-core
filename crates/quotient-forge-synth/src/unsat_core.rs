//! Non-trusting audit boundary for external solver unsat cores.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::session::SessionBlocker;

pub const NAMED_ASSERTION_REGISTRY_SCHEMA_V1: &str =
    "noticer.quotient_forge.named_assertion_registry.v1";
pub const UNSAT_CORE_AUDIT_SCHEMA_V1: &str = "noticer.quotient_forge.unsat_core_audit.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionNamespace {
    Security,
    Utility,
    Fault,
    Blocker,
}

impl AssertionNamespace {
    const fn label(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Utility => "utility",
            Self::Fault => "fault",
            Self::Blocker => "blocker",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Security => 0,
            Self::Utility => 1,
            Self::Fault => 2,
            Self::Blocker => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssertionSpec {
    namespace: AssertionNamespace,
    assertion_sha256: String,
    source_sha256: String,
}

impl AssertionSpec {
    pub fn hard_obligation(
        namespace: AssertionNamespace,
        assertion_sha256: impl Into<String>,
        source_sha256: impl Into<String>,
    ) -> Result<Self, UnsatCoreInputError> {
        if namespace == AssertionNamespace::Blocker {
            return Err(UnsatCoreInputError::WrongNamespace);
        }
        let spec = Self {
            namespace,
            assertion_sha256: assertion_sha256.into(),
            source_sha256: source_sha256.into(),
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn from_session_blocker(blocker: &SessionBlocker) -> Result<Self, UnsatCoreInputError> {
        blocker
            .validate()
            .map_err(|_| UnsatCoreInputError::InvalidBlocker)?;
        Ok(Self {
            namespace: AssertionNamespace::Blocker,
            assertion_sha256: blocker.assertion_sha256.clone(),
            source_sha256: blocker.blocker_sha256.clone(),
        })
    }

    fn validate(&self) -> Result<(), UnsatCoreInputError> {
        require_sha256("assertion_sha256", &self.assertion_sha256)?;
        require_sha256("source_sha256", &self.source_sha256)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamedAssertion {
    pub name: String,
    pub namespace: AssertionNamespace,
    pub ordinal: u32,
    pub assertion_sha256: String,
    pub source_sha256: String,
}

impl NamedAssertion {
    fn expected_name(&self) -> String {
        format!(
            "qf.v1.{}.{:08}.{}",
            self.namespace.label(),
            self.ordinal,
            self.assertion_sha256
        )
    }

    fn validate(&self) -> Result<(), UnsatCoreInputError> {
        require_sha256("assertion_sha256", &self.assertion_sha256)?;
        require_sha256("source_sha256", &self.source_sha256)?;
        if self.name != self.expected_name() {
            return Err(UnsatCoreInputError::NonCanonicalAssertion);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamedAssertionRegistry {
    pub schema_version: String,
    pub assertions: Vec<NamedAssertion>,
    pub registry_sha256: String,
}

impl NamedAssertionRegistry {
    pub fn new(mut specs: Vec<AssertionSpec>) -> Result<Self, UnsatCoreInputError> {
        for spec in &specs {
            spec.validate()?;
        }
        specs.sort_by(compare_specs);
        if specs.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(UnsatCoreInputError::DuplicateAssertion);
        }
        let mut ordinals = [0_u32; 4];
        let mut assertions = specs
            .into_iter()
            .map(|spec| {
                let ordinal = ordinals[spec.namespace.index()];
                ordinals[spec.namespace.index()] = ordinal
                    .checked_add(1)
                    .ok_or(UnsatCoreInputError::TooManyAssertions)?;
                let mut assertion = NamedAssertion {
                    name: String::new(),
                    namespace: spec.namespace,
                    ordinal,
                    assertion_sha256: spec.assertion_sha256,
                    source_sha256: spec.source_sha256,
                };
                assertion.name = assertion.expected_name();
                Ok(assertion)
            })
            .collect::<Result<Vec<_>, UnsatCoreInputError>>()?;
        assertions.sort_by(|left, right| left.name.cmp(&right.name));
        let mut registry = Self {
            schema_version: NAMED_ASSERTION_REGISTRY_SCHEMA_V1.to_owned(),
            assertions,
            registry_sha256: String::new(),
        };
        registry.registry_sha256 = registry.digest()?;
        registry.validate()?;
        Ok(registry)
    }

    pub fn resolve(&self, name: &str) -> Option<&NamedAssertion> {
        self.assertions
            .binary_search_by(|assertion| assertion.name.as_str().cmp(name))
            .ok()
            .map(|index| &self.assertions[index])
    }

    pub fn validate(&self) -> Result<(), UnsatCoreInputError> {
        if self.schema_version != NAMED_ASSERTION_REGISTRY_SCHEMA_V1 {
            return Err(UnsatCoreInputError::SchemaVersion);
        }
        require_sha256("registry_sha256", &self.registry_sha256)?;
        if self
            .assertions
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            return Err(UnsatCoreInputError::NonCanonicalAssertion);
        }
        let mut expected_ordinals = [0_u32; 4];
        for assertion in &self.assertions {
            assertion.validate()?;
            let expected = &mut expected_ordinals[assertion.namespace.index()];
            if assertion.ordinal != *expected {
                return Err(UnsatCoreInputError::NonCanonicalAssertion);
            }
            *expected = expected
                .checked_add(1)
                .ok_or(UnsatCoreInputError::TooManyAssertions)?;
        }
        if self.digest()? != self.registry_sha256 {
            return Err(UnsatCoreInputError::DigestMismatch("registry_sha256"));
        }
        Ok(())
    }

    fn digest(&self) -> Result<String, UnsatCoreInputError> {
        let mut payload = self.clone();
        payload.registry_sha256.clear();
        canonical_json_sha256(&payload)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UnsatCoreAuditContext {
    pub problem_sha256: String,
    pub epoch: u64,
}

impl UnsatCoreAuditContext {
    fn validate(&self) -> Result<(), UnsatCoreInputError> {
        require_sha256("problem_sha256", &self.problem_sha256)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundedDecisionRecord {
    Sat,
    Unsat,
    Inconclusive,
}

pub enum SolverCoreReport<'a> {
    Unsupported,
    Missing,
    Reported(&'a str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreRecheckDecision {
    Unsat,
    Sat,
    Inconclusive,
}

pub trait UnsatCoreRechecker {
    fn recheck(&mut self, assertions: &[NamedAssertion]) -> CoreRecheckDecision;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreDiagnosticStatus {
    NotApplicable,
    Unavailable,
    Rejected,
    Validated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreDiagnosticReason {
    Unsupported,
    Missing,
    Empty,
    Malformed,
    UnknownName,
    DuplicateName,
    RecheckSat,
    RecheckInconclusive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UnsatCoreAuditArtifact {
    pub schema_version: String,
    pub problem_sha256: String,
    pub epoch: u64,
    pub bounded_decision: BoundedDecisionRecord,
    pub assertion_registry_sha256: String,
    pub diagnostic_status: CoreDiagnosticStatus,
    pub diagnostic_reason: Option<CoreDiagnosticReason>,
    pub resolved_assertion_names: Vec<String>,
    pub recheck_performed: bool,
    pub diagnostic_accepted: bool,
    pub diagnostic_only: bool,
    pub artifact_sha256: String,
}

impl UnsatCoreAuditArtifact {
    pub fn validate(&self, registry: &NamedAssertionRegistry) -> Result<(), UnsatCoreInputError> {
        if self.schema_version != UNSAT_CORE_AUDIT_SCHEMA_V1 {
            return Err(UnsatCoreInputError::SchemaVersion);
        }
        require_sha256("problem_sha256", &self.problem_sha256)?;
        require_sha256("assertion_registry_sha256", &self.assertion_registry_sha256)?;
        require_sha256("artifact_sha256", &self.artifact_sha256)?;
        registry.validate()?;
        if self.assertion_registry_sha256 != registry.registry_sha256 {
            return Err(UnsatCoreInputError::RegistryMismatch);
        }
        if self
            .resolved_assertion_names
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || self
                .resolved_assertion_names
                .iter()
                .any(|name| registry.resolve(name).is_none())
        {
            return Err(UnsatCoreInputError::NonCanonicalCore);
        }
        let validated = self.diagnostic_status == CoreDiagnosticStatus::Validated;
        if self.diagnostic_accepted != validated
            || validated
                && (!self.recheck_performed
                    || self.resolved_assertion_names.is_empty()
                    || self.diagnostic_reason.is_some())
            || self.bounded_decision != BoundedDecisionRecord::Unsat
                && self.diagnostic_status != CoreDiagnosticStatus::NotApplicable
            || !self.diagnostic_only
        {
            return Err(UnsatCoreInputError::InconsistentAudit);
        }
        let mut payload = self.clone();
        payload.artifact_sha256.clear();
        if canonical_json_sha256(&payload)? != self.artifact_sha256 {
            return Err(UnsatCoreInputError::DigestMismatch("artifact_sha256"));
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum UnsatCoreInputError {
    #[error("{0} must be a lowercase SHA-256 digest")]
    InvalidSha256(&'static str),
    #[error("blocker artifact is invalid")]
    InvalidBlocker,
    #[error("blocker namespace is reserved for typed blockers")]
    WrongNamespace,
    #[error("duplicate assertion descriptor")]
    DuplicateAssertion,
    #[error("assertion ordinal overflow")]
    TooManyAssertions,
    #[error("unsupported schema version")]
    SchemaVersion,
    #[error("named assertions are not canonical")]
    NonCanonicalAssertion,
    #[error("resolved core is not canonical")]
    NonCanonicalCore,
    #[error("assertion registry does not match the audit artifact")]
    RegistryMismatch,
    #[error("audit status fields are inconsistent")]
    InconsistentAudit,
    #[error("{0} does not match its canonical payload")]
    DigestMismatch(&'static str),
    #[error("canonical artifact serialization failed")]
    Serialization,
}

pub fn audit_unsat_core<Rechecker: UnsatCoreRechecker>(
    context: &UnsatCoreAuditContext,
    bounded_decision: BoundedDecisionRecord,
    registry: &NamedAssertionRegistry,
    report: SolverCoreReport<'_>,
    rechecker: &mut Rechecker,
) -> Result<UnsatCoreAuditArtifact, UnsatCoreInputError> {
    context.validate()?;
    registry.validate()?;
    if bounded_decision != BoundedDecisionRecord::Unsat {
        return finalize_audit(
            context,
            bounded_decision,
            registry,
            CoreDiagnosticStatus::NotApplicable,
            None,
            Vec::new(),
            false,
        );
    }

    let raw = match report {
        SolverCoreReport::Unsupported => {
            return finalize_audit(
                context,
                bounded_decision,
                registry,
                CoreDiagnosticStatus::Unavailable,
                Some(CoreDiagnosticReason::Unsupported),
                Vec::new(),
                false,
            );
        }
        SolverCoreReport::Missing => {
            return finalize_audit(
                context,
                bounded_decision,
                registry,
                CoreDiagnosticStatus::Rejected,
                Some(CoreDiagnosticReason::Missing),
                Vec::new(),
                false,
            );
        }
        SolverCoreReport::Reported(raw) => raw,
    };

    let names = match parse_core(raw, registry) {
        Ok(names) => names,
        Err(reason) => {
            return finalize_audit(
                context,
                bounded_decision,
                registry,
                CoreDiagnosticStatus::Rejected,
                Some(reason),
                Vec::new(),
                false,
            );
        }
    };
    let assertions = names
        .iter()
        .map(|name| {
            registry
                .resolve(name)
                .expect("validated core names must resolve")
                .clone()
        })
        .collect::<Vec<_>>();
    let (status, reason) = match rechecker.recheck(&assertions) {
        CoreRecheckDecision::Unsat => (CoreDiagnosticStatus::Validated, None),
        CoreRecheckDecision::Sat => (
            CoreDiagnosticStatus::Rejected,
            Some(CoreDiagnosticReason::RecheckSat),
        ),
        CoreRecheckDecision::Inconclusive => (
            CoreDiagnosticStatus::Rejected,
            Some(CoreDiagnosticReason::RecheckInconclusive),
        ),
    };
    finalize_audit(
        context,
        bounded_decision,
        registry,
        status,
        reason,
        names,
        true,
    )
}

fn parse_core(
    raw: &str,
    registry: &NamedAssertionRegistry,
) -> Result<Vec<String>, CoreDiagnosticReason> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "()" {
        return Err(CoreDiagnosticReason::Empty);
    }
    if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
        return Err(CoreDiagnosticReason::Malformed);
    }
    let body = &trimmed[1..trimmed.len() - 1];
    if body.contains(['(', ')', '"', '|', ';']) {
        return Err(CoreDiagnosticReason::Malformed);
    }
    let mut names = body
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if names.is_empty() {
        return Err(CoreDiagnosticReason::Empty);
    }
    if names.iter().any(|name| !canonical_name_shape(name)) {
        return Err(CoreDiagnosticReason::Malformed);
    }
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CoreDiagnosticReason::DuplicateName);
    }
    if names.iter().any(|name| registry.resolve(name).is_none()) {
        return Err(CoreDiagnosticReason::UnknownName);
    }
    Ok(names)
}

fn canonical_name_shape(name: &str) -> bool {
    let parts = name.split('.').collect::<Vec<_>>();
    parts.len() == 5
        && parts[0] == "qf"
        && parts[1] == "v1"
        && matches!(parts[2], "security" | "utility" | "fault" | "blocker")
        && parts[3].len() == 8
        && parts[3].bytes().all(|byte| byte.is_ascii_digit())
        && require_sha256("assertion_name_digest", parts[4]).is_ok()
}

#[allow(clippy::too_many_arguments)]
fn finalize_audit(
    context: &UnsatCoreAuditContext,
    bounded_decision: BoundedDecisionRecord,
    registry: &NamedAssertionRegistry,
    diagnostic_status: CoreDiagnosticStatus,
    diagnostic_reason: Option<CoreDiagnosticReason>,
    resolved_assertion_names: Vec<String>,
    recheck_performed: bool,
) -> Result<UnsatCoreAuditArtifact, UnsatCoreInputError> {
    let mut artifact = UnsatCoreAuditArtifact {
        schema_version: UNSAT_CORE_AUDIT_SCHEMA_V1.to_owned(),
        problem_sha256: context.problem_sha256.clone(),
        epoch: context.epoch,
        bounded_decision,
        assertion_registry_sha256: registry.registry_sha256.clone(),
        diagnostic_status,
        diagnostic_reason,
        resolved_assertion_names,
        recheck_performed,
        diagnostic_accepted: diagnostic_status == CoreDiagnosticStatus::Validated,
        diagnostic_only: true,
        artifact_sha256: String::new(),
    };
    artifact.artifact_sha256 = canonical_json_sha256(&artifact)?;
    artifact.validate(registry)?;
    Ok(artifact)
}

fn compare_specs(left: &AssertionSpec, right: &AssertionSpec) -> Ordering {
    (left.namespace, &left.assertion_sha256, &left.source_sha256).cmp(&(
        right.namespace,
        &right.assertion_sha256,
        &right.source_sha256,
    ))
}

fn require_sha256(field: &'static str, value: &str) -> Result<(), UnsatCoreInputError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(UnsatCoreInputError::InvalidSha256(field))
    }
}

fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String, UnsatCoreInputError> {
    let bytes = serde_json::to_vec(value).map_err(|_| UnsatCoreInputError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
