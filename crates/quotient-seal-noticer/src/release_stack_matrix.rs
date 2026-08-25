//! Deterministic cross-module adversarial matrix for the public release stack.

use std::collections::BTreeSet;

use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    evaluate_release_stack_profile, execute_canonical_release_path, verify_canonical_release_path,
    AepaProfileAuthorization, DeploymentProfile, Digest, NoticerModuleId, NoticerQsmManifest,
    PolicyHash, ReleasePathKind, ReleaseStackCompositionContract, ReleaseStackCompositionError,
    ReleaseStackPathArtifact, ReleaseStackPathError, ReleaseStackProfileError,
    ReleaseStackProfileVerdict, ReleaseStackPublicInput, WireServiceAlias,
    RELEASE_STACK_HANDOFF_COUNT, RELEASE_STACK_HARDWARE_STATUS,
};

pub const RELEASE_STACK_MATRIX_VERSION: &str = "noticer-release-stack-adversarial-matrix/v1";
pub const RELEASE_STACK_MATRIX_SEED: u64 = 0x4b38_3133_4734_0001;
pub const RELEASE_STACK_ADVERSARIAL_CASES: usize = 42;
const SCENARIOS_PER_PROFILE: usize = 21;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseStackMatrixProfile {
    P0,
    P1,
}

impl ReleaseStackMatrixProfile {
    const ALL: [Self; 2] = [Self::P0, Self::P1];

    const fn deployment(self) -> DeploymentProfile {
        match self {
            Self::P0 => DeploymentProfile::P0PublicQuotientOnly,
            Self::P1 => DeploymentProfile::P1SealedAdmission,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::P0 => 0,
            Self::P1 => 1,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::P0 => "P0",
            Self::P1 => "P1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseStackScenario {
    CanonicalAction,
    CanonicalCover,
    ResetAtHandoff(u8),
    FaultAtHandoff(u8),
    DeadlineAtHandoff(u8),
    ReplayReceipt,
    DuplicateReceipt,
    WrongService,
    WrongPolicy,
    StageSkip,
    StageReorder,
    ReceiptSubstitution,
}

impl ReleaseStackScenario {
    const fn is_injected(self) -> bool {
        !matches!(self, Self::CanonicalAction | Self::CanonicalCover)
    }

    const fn path_kind(self) -> ReleasePathKind {
        match self {
            Self::CanonicalCover => ReleasePathKind::Cover,
            _ => ReleasePathKind::Action,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::CanonicalAction => 0,
            Self::CanonicalCover => 1,
            Self::ResetAtHandoff(index) => 10 + index,
            Self::FaultAtHandoff(index) => 20 + index,
            Self::DeadlineAtHandoff(index) => 30 + index,
            Self::ReplayReceipt => 40,
            Self::DuplicateReceipt => 41,
            Self::WrongService => 42,
            Self::WrongPolicy => 43,
            Self::StageSkip => 44,
            Self::StageReorder => 45,
            Self::ReceiptSubstitution => 46,
        }
    }

    fn label(self) -> String {
        match self {
            Self::CanonicalAction => "CANONICAL_ACTION".to_owned(),
            Self::CanonicalCover => "CANONICAL_COVER".to_owned(),
            Self::ResetAtHandoff(index) => format!("RESET_H{index}"),
            Self::FaultAtHandoff(index) => format!("FAULT_H{index}"),
            Self::DeadlineAtHandoff(index) => format!("DEADLINE_H{index}"),
            Self::ReplayReceipt => "REPLAY_RECEIPT".to_owned(),
            Self::DuplicateReceipt => "DUPLICATE_RECEIPT".to_owned(),
            Self::WrongService => "WRONG_SERVICE".to_owned(),
            Self::WrongPolicy => "WRONG_POLICY".to_owned(),
            Self::StageSkip => "STAGE_SKIP".to_owned(),
            Self::StageReorder => "STAGE_REORDER".to_owned(),
            Self::ReceiptSubstitution => "RECEIPT_SUBSTITUTION".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseStackEvidenceOrigin {
    SpecificationPath,
    InjectedTestFixture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseStackMatrixOutcome {
    Match,
    AttackRejected,
    ProfileUnresolved,
    InvariantViolation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseStackPathErrorKind {
    None,
    InvalidInput,
    CompositionBinding,
    ReceiptCount,
    ReceiptOrder,
    StageBinding,
    ReceiptChain,
    ReceiptDigest,
    Outcome,
    HardwareStatus,
    ArtifactDigest,
    NonCanonical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseStackMatrixLimits {
    pub max_cases: usize,
}

impl Default for ReleaseStackMatrixLimits {
    fn default() -> Self {
        Self {
            max_cases: RELEASE_STACK_ADVERSARIAL_CASES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseStackAdversarialCaseArtifact {
    pub case_id: String,
    pub seed: u64,
    pub profile: ReleaseStackMatrixProfile,
    pub scenario: ReleaseStackScenario,
    pub evidence_origin: ReleaseStackEvidenceOrigin,
    pub path_kind: ReleasePathKind,
    pub path_accepted: bool,
    pub path_error: ReleaseStackPathErrorKind,
    pub profile_verdict: ReleaseStackProfileVerdict,
    pub outcome: ReleaseStackMatrixOutcome,
    pub authorized_action_count: u8,
    pub unauthorized_action_count: u8,
    pub public_frame_count: u8,
    pub failure_count: u8,
    pub evaluated_path_digest: Digest,
    pub case_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseStackAdversarialMatrixArtifact {
    pub schema_version: String,
    pub seed: u64,
    pub public_step: u32,
    pub expected_case_count: usize,
    pub evaluated_case_count: usize,
    pub match_count: usize,
    pub attack_rejected_count: usize,
    pub profile_unresolved_count: usize,
    pub invariant_violation_count: usize,
    pub authorized_action_count: usize,
    pub unauthorized_action_count: usize,
    pub public_frame_count: usize,
    pub failure_count: usize,
    pub cases: Vec<ReleaseStackAdversarialCaseArtifact>,
    pub hardware_status: String,
    pub artifact_digest: Digest,
}

pub fn evaluate_release_stack_adversarial_matrix(
    p0_contract: &ReleaseStackCompositionContract,
    p1_contract: &ReleaseStackCompositionContract,
    p1_authorization: Option<&AepaProfileAuthorization>,
    public_step: u32,
    limits: ReleaseStackMatrixLimits,
) -> Result<ReleaseStackAdversarialMatrixArtifact, ReleaseStackMatrixError> {
    if limits.max_cases < RELEASE_STACK_ADVERSARIAL_CASES {
        return Err(ReleaseStackMatrixError::CaseLimit {
            actual: limits.max_cases,
            required: RELEASE_STACK_ADVERSARIAL_CASES,
        });
    }
    let scenarios = scenarios();
    debug_assert_eq!(scenarios.len(), SCENARIOS_PER_PROFILE);
    let mut cases = Vec::with_capacity(RELEASE_STACK_ADVERSARIAL_CASES);
    for profile in ReleaseStackMatrixProfile::ALL {
        let (contract, authorization) = match profile {
            ReleaseStackMatrixProfile::P0 => (p0_contract, None),
            ReleaseStackMatrixProfile::P1 => (p1_contract, p1_authorization),
        };
        let action = execute_canonical_release_path(
            contract,
            ReleaseStackPublicInput::new(ReleasePathKind::Action, u64::from(public_step), Some(7))?,
        )?;
        let cover = execute_canonical_release_path(
            contract,
            ReleaseStackPublicInput::new(ReleasePathKind::Cover, u64::from(public_step), None)?,
        )?;
        for scenario in &scenarios {
            cases.push(evaluate_case(
                contract,
                authorization,
                profile,
                *scenario,
                public_step,
                &action,
                &cover,
            )?);
        }
    }

    let mut artifact = ReleaseStackAdversarialMatrixArtifact {
        schema_version: RELEASE_STACK_MATRIX_VERSION.to_owned(),
        seed: RELEASE_STACK_MATRIX_SEED,
        public_step,
        expected_case_count: RELEASE_STACK_ADVERSARIAL_CASES,
        evaluated_case_count: cases.len(),
        match_count: count_outcome(&cases, ReleaseStackMatrixOutcome::Match),
        attack_rejected_count: count_outcome(&cases, ReleaseStackMatrixOutcome::AttackRejected),
        profile_unresolved_count: count_outcome(
            &cases,
            ReleaseStackMatrixOutcome::ProfileUnresolved,
        ),
        invariant_violation_count: count_outcome(
            &cases,
            ReleaseStackMatrixOutcome::InvariantViolation,
        ),
        authorized_action_count: cases
            .iter()
            .map(|case| usize::from(case.authorized_action_count))
            .sum(),
        unauthorized_action_count: cases
            .iter()
            .map(|case| usize::from(case.unauthorized_action_count))
            .sum(),
        public_frame_count: cases
            .iter()
            .map(|case| usize::from(case.public_frame_count))
            .sum(),
        failure_count: cases
            .iter()
            .map(|case| usize::from(case.failure_count))
            .sum(),
        cases,
        hardware_status: RELEASE_STACK_HARDWARE_STATUS.to_owned(),
        artifact_digest: Digest::zero(),
    };
    artifact.artifact_digest = Digest::new(matrix_digest(p0_contract, p1_contract, &artifact));
    Ok(artifact)
}

pub fn verify_release_stack_adversarial_matrix(
    p0_contract: &ReleaseStackCompositionContract,
    p1_contract: &ReleaseStackCompositionContract,
    p1_authorization: Option<&AepaProfileAuthorization>,
    artifact: &ReleaseStackAdversarialMatrixArtifact,
    limits: ReleaseStackMatrixLimits,
) -> Result<(), ReleaseStackMatrixError> {
    if artifact.schema_version != RELEASE_STACK_MATRIX_VERSION
        || artifact.seed != RELEASE_STACK_MATRIX_SEED
        || artifact.hardware_status != RELEASE_STACK_HARDWARE_STATUS
    {
        return Err(ReleaseStackMatrixError::Binding);
    }
    let unique_ids: BTreeSet<&str> = artifact
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect();
    if artifact.expected_case_count != RELEASE_STACK_ADVERSARIAL_CASES
        || artifact.evaluated_case_count != artifact.cases.len()
        || artifact.cases.len() != RELEASE_STACK_ADVERSARIAL_CASES
        || unique_ids.len() != RELEASE_STACK_ADVERSARIAL_CASES
    {
        return Err(ReleaseStackMatrixError::CaseAccounting);
    }
    let expected = evaluate_release_stack_adversarial_matrix(
        p0_contract,
        p1_contract,
        p1_authorization,
        artifact.public_step,
        limits,
    )?;
    if artifact.artifact_digest != expected.artifact_digest {
        return Err(ReleaseStackMatrixError::ArtifactDigest);
    }
    if artifact != &expected {
        return Err(ReleaseStackMatrixError::NonCanonical);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_case(
    contract: &ReleaseStackCompositionContract,
    authorization: Option<&AepaProfileAuthorization>,
    profile: ReleaseStackMatrixProfile,
    scenario: ReleaseStackScenario,
    public_step: u32,
    action: &ReleaseStackPathArtifact,
    cover: &ReleaseStackPathArtifact,
) -> Result<ReleaseStackAdversarialCaseArtifact, ReleaseStackMatrixError> {
    let base = if scenario.path_kind() == ReleasePathKind::Cover {
        cover
    } else {
        action
    };
    let profile_artifact = evaluate_release_stack_profile(
        contract,
        base,
        profile.deployment(),
        public_step,
        authorization,
    )?;
    let mut evaluated = base.clone();
    let mut alternate_contract = None;
    inject_scenario(
        contract,
        &mut evaluated,
        cover,
        scenario,
        &mut alternate_contract,
    )?;
    let verification_contract = alternate_contract.as_ref().unwrap_or(contract);
    let path_result = verify_canonical_release_path(verification_contract, &evaluated);
    let path_accepted = path_result.is_ok();
    let path_error = path_result
        .as_ref()
        .err()
        .map_or(ReleaseStackPathErrorKind::None, path_error_kind);
    let outcome = if profile_artifact.verdict == ReleaseStackProfileVerdict::ProfileUnresolved {
        ReleaseStackMatrixOutcome::ProfileUnresolved
    } else if scenario.is_injected() {
        if path_accepted {
            ReleaseStackMatrixOutcome::InvariantViolation
        } else {
            ReleaseStackMatrixOutcome::AttackRejected
        }
    } else if path_accepted {
        ReleaseStackMatrixOutcome::Match
    } else {
        ReleaseStackMatrixOutcome::InvariantViolation
    };
    let authorized_action_count = if outcome == ReleaseStackMatrixOutcome::Match
        && scenario.path_kind() == ReleasePathKind::Action
    {
        evaluated.authorized_action_count
    } else {
        0
    };
    let unauthorized_action_count = if scenario.is_injected() && path_accepted {
        evaluated.authorized_action_count
    } else {
        0
    };
    let public_frame_count = u8::from(
        evaluated
            .receipts
            .iter()
            .any(|receipt| receipt.module_id == NoticerModuleId::Atv2FramePlanner),
    );
    let failure_count = u8::from(outcome != ReleaseStackMatrixOutcome::Match);
    let case_id = format!("K8-13G4-{}-{}", profile.label(), scenario.label());
    let seed = case_seed(profile, scenario);
    let evaluated_path_digest = path_fingerprint(&evaluated);
    let case_digest = case_digest(
        &case_id,
        seed,
        profile,
        scenario,
        path_accepted,
        path_error,
        profile_artifact.artifact_digest,
        outcome,
        authorized_action_count,
        unauthorized_action_count,
        public_frame_count,
        failure_count,
        evaluated_path_digest,
        verification_contract,
    );
    Ok(ReleaseStackAdversarialCaseArtifact {
        case_id,
        seed,
        profile,
        scenario,
        evidence_origin: if scenario.is_injected() {
            ReleaseStackEvidenceOrigin::InjectedTestFixture
        } else {
            ReleaseStackEvidenceOrigin::SpecificationPath
        },
        path_kind: scenario.path_kind(),
        path_accepted,
        path_error,
        profile_verdict: profile_artifact.verdict,
        outcome,
        authorized_action_count,
        unauthorized_action_count,
        public_frame_count,
        failure_count,
        evaluated_path_digest,
        case_digest: Digest::new(case_digest),
    })
}

fn inject_scenario(
    contract: &ReleaseStackCompositionContract,
    evaluated: &mut ReleaseStackPathArtifact,
    cover: &ReleaseStackPathArtifact,
    scenario: ReleaseStackScenario,
    alternate_contract: &mut Option<ReleaseStackCompositionContract>,
) -> Result<(), ReleaseStackMatrixError> {
    match scenario {
        ReleaseStackScenario::CanonicalAction | ReleaseStackScenario::CanonicalCover => {}
        ReleaseStackScenario::ResetAtHandoff(index) => {
            evaluated.receipts[usize::from(index) + 1].predecessor_receipt_digest = Digest::zero();
        }
        ReleaseStackScenario::FaultAtHandoff(index) => {
            evaluated.receipts[usize::from(index)].output_commitment = Digest::zero();
        }
        ReleaseStackScenario::DeadlineAtHandoff(index) => {
            evaluated.receipts[usize::from(index) + 1].input_commitment = Digest::new([0xdd; 32]);
        }
        ReleaseStackScenario::ReplayReceipt => {
            evaluated.receipts[4] = evaluated.receipts[0].clone();
        }
        ReleaseStackScenario::DuplicateReceipt => {
            evaluated.receipts[2] = evaluated.receipts[1].clone();
        }
        ReleaseStackScenario::WrongService => {
            *alternate_contract = Some(mutated_contract(contract, true)?);
        }
        ReleaseStackScenario::WrongPolicy => {
            *alternate_contract = Some(mutated_contract(contract, false)?);
        }
        ReleaseStackScenario::StageSkip => {
            evaluated.receipts.remove(1);
        }
        ReleaseStackScenario::StageReorder => {
            evaluated.receipts.swap(2, 3);
        }
        ReleaseStackScenario::ReceiptSubstitution => {
            evaluated.receipts[2] = cover.receipts[2].clone();
        }
    }
    Ok(())
}

fn mutated_contract(
    contract: &ReleaseStackCompositionContract,
    service: bool,
) -> Result<ReleaseStackCompositionContract, ReleaseStackMatrixError> {
    let mut entries = contract.manifest().entries().to_vec();
    if service {
        let replacement = if entries[0].service_alias == WireServiceAlias([0xa5; 8]) {
            WireServiceAlias([0x5a; 8])
        } else {
            WireServiceAlias([0xa5; 8])
        };
        entries[0].service_alias = replacement;
    } else {
        let replacement = if entries[0].policy_hash == PolicyHash([0xa5; 32]) {
            PolicyHash([0x5a; 32])
        } else {
            PolicyHash([0xa5; 32])
        };
        entries[0].policy_hash = replacement;
    }
    let manifest = NoticerQsmManifest::new(entries).map_err(ReleaseStackMatrixError::Manifest)?;
    ReleaseStackCompositionContract::new(manifest).map_err(ReleaseStackMatrixError::Composition)
}

fn scenarios() -> Vec<ReleaseStackScenario> {
    let mut values = vec![
        ReleaseStackScenario::CanonicalAction,
        ReleaseStackScenario::CanonicalCover,
    ];
    for index in 0..RELEASE_STACK_HANDOFF_COUNT as u8 {
        values.push(ReleaseStackScenario::ResetAtHandoff(index));
        values.push(ReleaseStackScenario::FaultAtHandoff(index));
        values.push(ReleaseStackScenario::DeadlineAtHandoff(index));
    }
    values.extend([
        ReleaseStackScenario::ReplayReceipt,
        ReleaseStackScenario::DuplicateReceipt,
        ReleaseStackScenario::WrongService,
        ReleaseStackScenario::WrongPolicy,
        ReleaseStackScenario::StageSkip,
        ReleaseStackScenario::StageReorder,
        ReleaseStackScenario::ReceiptSubstitution,
    ]);
    values
}

fn path_error_kind(error: &ReleaseStackPathError) -> ReleaseStackPathErrorKind {
    match error {
        ReleaseStackPathError::InvalidInput => ReleaseStackPathErrorKind::InvalidInput,
        ReleaseStackPathError::CompositionBinding => ReleaseStackPathErrorKind::CompositionBinding,
        ReleaseStackPathError::ReceiptCount { .. } => ReleaseStackPathErrorKind::ReceiptCount,
        ReleaseStackPathError::ReceiptOrder { .. } => ReleaseStackPathErrorKind::ReceiptOrder,
        ReleaseStackPathError::StageBinding { .. } => ReleaseStackPathErrorKind::StageBinding,
        ReleaseStackPathError::ReceiptChain { .. } => ReleaseStackPathErrorKind::ReceiptChain,
        ReleaseStackPathError::ReceiptDigest { .. } => ReleaseStackPathErrorKind::ReceiptDigest,
        ReleaseStackPathError::Outcome => ReleaseStackPathErrorKind::Outcome,
        ReleaseStackPathError::HardwareStatus => ReleaseStackPathErrorKind::HardwareStatus,
        ReleaseStackPathError::ArtifactDigest => ReleaseStackPathErrorKind::ArtifactDigest,
        ReleaseStackPathError::NonCanonical => ReleaseStackPathErrorKind::NonCanonical,
    }
}

fn count_outcome(
    cases: &[ReleaseStackAdversarialCaseArtifact],
    outcome: ReleaseStackMatrixOutcome,
) -> usize {
    cases.iter().filter(|case| case.outcome == outcome).count()
}

fn case_seed(profile: ReleaseStackMatrixProfile, scenario: ReleaseStackScenario) -> u64 {
    RELEASE_STACK_MATRIX_SEED ^ (u64::from(profile.code()) << 32) ^ u64::from(scenario.code())
}

fn path_fingerprint(path: &ReleaseStackPathArtifact) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"noticer-release-stack-mutated-path/v1\0");
    hasher.update(path.schema_version.as_bytes());
    hasher.update(path.composition_digest.as_bytes());
    hasher.update(path.public_input.canonical_bytes());
    hasher.update((path.receipts.len() as u16).to_le_bytes());
    for receipt in &path.receipts {
        hasher.update([receipt.stage_index, receipt.module_id as u8]);
        hasher.update(receipt.input_commitment.as_bytes());
        hasher.update(receipt.output_commitment.as_bytes());
        hasher.update(receipt.predecessor_receipt_digest.as_bytes());
        hasher.update(receipt.source_digest.as_bytes());
        hasher.update(receipt.qsm_capsule_digest.as_bytes());
        hasher.update(receipt.observer_registry_digest.as_bytes());
        hasher.update(receipt.receipt_digest.as_bytes());
    }
    hasher.update([path.authorized_action_count, path.cover_count]);
    hasher.update(path.final_output_commitment.as_bytes());
    hasher.update(path.hardware_status.as_bytes());
    hasher.update(path.artifact_digest.as_bytes());
    Digest::new(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn case_digest(
    case_id: &str,
    seed: u64,
    profile: ReleaseStackMatrixProfile,
    scenario: ReleaseStackScenario,
    path_accepted: bool,
    path_error: ReleaseStackPathErrorKind,
    profile_digest: Digest,
    outcome: ReleaseStackMatrixOutcome,
    action_count: u8,
    unauthorized_count: u8,
    frame_count: u8,
    failure_count: u8,
    path_digest: Digest,
    verification_contract: &ReleaseStackCompositionContract,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"noticer-release-stack-matrix-case/v1\0");
    hasher.update((case_id.len() as u16).to_le_bytes());
    hasher.update(case_id.as_bytes());
    hasher.update(seed.to_le_bytes());
    hasher.update([profile.code(), scenario.code(), u8::from(path_accepted)]);
    hasher.update([path_error_code(path_error), outcome_code(outcome)]);
    hasher.update(profile_digest.as_bytes());
    hasher.update([action_count, unauthorized_count, frame_count, failure_count]);
    hasher.update(path_digest.as_bytes());
    hasher.update(verification_contract.canonical_bytes());
    hasher.finalize().into()
}

fn matrix_digest(
    p0_contract: &ReleaseStackCompositionContract,
    p1_contract: &ReleaseStackCompositionContract,
    artifact: &ReleaseStackAdversarialMatrixArtifact,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"noticer-release-stack-matrix/v1\0");
    hasher.update(p0_contract.canonical_bytes());
    hasher.update(p1_contract.canonical_bytes());
    hasher.update(artifact.seed.to_le_bytes());
    hasher.update(artifact.public_step.to_le_bytes());
    hasher.update((artifact.cases.len() as u16).to_le_bytes());
    for case in &artifact.cases {
        hasher.update(case.case_digest.as_bytes());
    }
    for count in [
        artifact.match_count,
        artifact.attack_rejected_count,
        artifact.profile_unresolved_count,
        artifact.invariant_violation_count,
        artifact.authorized_action_count,
        artifact.unauthorized_action_count,
        artifact.public_frame_count,
        artifact.failure_count,
    ] {
        hasher.update((count as u64).to_le_bytes());
    }
    hasher.update(RELEASE_STACK_HARDWARE_STATUS.as_bytes());
    hasher.finalize().into()
}

const fn path_error_code(error: ReleaseStackPathErrorKind) -> u8 {
    match error {
        ReleaseStackPathErrorKind::None => 0,
        ReleaseStackPathErrorKind::InvalidInput => 1,
        ReleaseStackPathErrorKind::CompositionBinding => 2,
        ReleaseStackPathErrorKind::ReceiptCount => 3,
        ReleaseStackPathErrorKind::ReceiptOrder => 4,
        ReleaseStackPathErrorKind::StageBinding => 5,
        ReleaseStackPathErrorKind::ReceiptChain => 6,
        ReleaseStackPathErrorKind::ReceiptDigest => 7,
        ReleaseStackPathErrorKind::Outcome => 8,
        ReleaseStackPathErrorKind::HardwareStatus => 9,
        ReleaseStackPathErrorKind::ArtifactDigest => 10,
        ReleaseStackPathErrorKind::NonCanonical => 11,
    }
}

const fn outcome_code(outcome: ReleaseStackMatrixOutcome) -> u8 {
    match outcome {
        ReleaseStackMatrixOutcome::Match => 1,
        ReleaseStackMatrixOutcome::AttackRejected => 2,
        ReleaseStackMatrixOutcome::ProfileUnresolved => 3,
        ReleaseStackMatrixOutcome::InvariantViolation => 4,
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReleaseStackMatrixError {
    #[error("release stack matrix case limit is {actual}, required {required}")]
    CaseLimit { actual: usize, required: usize },
    #[error("release stack path failed: {0}")]
    Path(#[from] ReleaseStackPathError),
    #[error("release stack profile failed: {0}")]
    Profile(#[from] ReleaseStackProfileError),
    #[error("mutated manifest is invalid: {0}")]
    Manifest(crate::ManifestError),
    #[error("mutated composition is invalid: {0}")]
    Composition(ReleaseStackCompositionError),
    #[error("release stack matrix binding is invalid")]
    Binding,
    #[error("release stack matrix case accounting is invalid")]
    CaseAccounting,
    #[error("release stack matrix artifact digest does not recompute")]
    ArtifactDigest,
    #[error("release stack matrix artifact is non-canonical")]
    NonCanonical,
}
