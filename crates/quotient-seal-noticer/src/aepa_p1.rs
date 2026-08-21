use quotient_forge_caqt::artifact_digest;
use quotient_seal_abi::DeploymentProfile;
use quotient_seal_context::{ProductVerdict, RelationBinding};
use quotient_seal_relation::RelationVerdict;
use quotient_seal_resource::{
    check_resource_strict, NormalizationOverhead, ResourceCase, ResourceLimits, ResourceReport,
    ResourceVerdict,
};
use thiserror::Error;

use crate::{
    aepa_transition_digest, bind_aepa_compiled_manifest, AepaCompiledQsm, AepaK7Binding,
    AepaP0Binding, AepaPublicSourceArtifact, Digest, NoticerModuleId, NoticerQsmManifest,
};

const WITNESS_MAGIC: &[u8; 8] = b"AEPAP1W1";
const WITNESS_DOMAIN: &[u8] = b"noticer-core/aepa/p1-resource-witness/v1";
const CASE_COMMITMENT_DOMAIN: &[u8] = b"noticer-core/aepa/p1-private-cases/v1";
const RELATION_BINDING_DOMAIN: &[u8] = b"noticer-core/aepa/p1-relation-binding/v1";
const AUTHORIZATION_DOMAIN: &[u8] = b"noticer-core/aepa/p1-authorization/v1";

/// Opaque, public-only evidence that a strict private resource comparison succeeded.
///
/// The canonical bytes contain digests, public bindings, counts, and a validity
/// window. They never contain resource events or their private values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AepaP1ResourceWitness {
    canonical_bytes: Box<[u8]>,
    digest: Digest,
    source_digest: Digest,
    transition_digest: Digest,
    certificate_digest: Digest,
    generated_runtime_digest: Digest,
    module_digest: Digest,
    target_ir_digest: Digest,
    abi_digest: Digest,
    capsule_digest: Digest,
    observer_registry_digest: Digest,
    relation_binding_digest: Digest,
    private_case_commitment: Digest,
    checked_cases: u64,
    checked_resource_events: u64,
    valid_from_public_step: u32,
    valid_until_public_step: u32,
}

impl AepaP1ResourceWitness {
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    #[must_use]
    pub const fn relation_binding_digest(&self) -> Digest {
        self.relation_binding_digest
    }

    #[must_use]
    pub const fn private_case_commitment(&self) -> Digest {
        self.private_case_commitment
    }

    #[must_use]
    pub const fn checked_cases(&self) -> u64 {
        self.checked_cases
    }

    #[must_use]
    pub const fn checked_resource_events(&self) -> u64 {
        self.checked_resource_events
    }

    #[must_use]
    pub const fn validity_window(&self) -> (u32, u32) {
        (self.valid_from_public_step, self.valid_until_public_step)
    }
}

/// Unforgeable outside this crate: construction always reruns the strict checker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AepaP1Revalidation {
    witness: AepaP1ResourceWitness,
    seal: AepaP1RevalidationSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AepaP1RevalidationSeal;

impl AepaP1Revalidation {
    #[must_use]
    pub const fn witness(&self) -> &AepaP1ResourceWitness {
        &self.witness
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AepaProfileAuthorization {
    profile: DeploymentProfile,
    authorization_digest: Digest,
    witness_digest: Option<Digest>,
    public_step: u32,
    seal: AepaProfileAuthorizationSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AepaProfileAuthorizationSeal;

impl AepaProfileAuthorization {
    #[must_use]
    pub const fn profile(&self) -> DeploymentProfile {
        self.profile
    }

    #[must_use]
    pub const fn authorization_digest(&self) -> Digest {
        self.authorization_digest
    }

    #[must_use]
    pub const fn witness_digest(&self) -> Option<Digest> {
        self.witness_digest
    }

    #[must_use]
    pub const fn public_step(&self) -> u32 {
        self.public_step
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AepaP1Error {
    #[error("K7 binding does not match the AEPA source")]
    K7SourceMismatch,
    #[error("compiled AEPA artifact does not match its source or K7 binding")]
    CompiledBindingMismatch,
    #[error("compiled AEPA transition table is not canonical")]
    TransitionBindingMismatch,
    #[error("compiled AEPA service does not match the source service")]
    ServiceBindingMismatch,
    #[error("P1 witness validity window is invalid")]
    InvalidValidityWindow,
    #[error("P1 witness validity window is outside the AEPA admission window")]
    ValidityOutsideAdmissionWindow,
    #[error("P1 strict resource evidence contains no cases or resource events")]
    EmptyStrictEvidence,
    #[error("resource report does not cover exactly the supplied private cases")]
    CaseCountMismatch,
    #[error("resource relation changed during strict checking")]
    RelationBindingChanged,
    #[error("resource relation is not bound to the compiled target IR")]
    RelationTargetMismatch,
    #[error("resource normalization is forbidden for AEPA P1")]
    NormalizationForbidden,
    #[error("strict resource equality failed; counterexample digest: {digest:?}")]
    ResourceCounterexample { digest: Digest },
    #[error("strict resource equality was inconclusive")]
    ResourceInconclusive,
    #[error("strict resource evidence count exceeds the canonical format")]
    EvidenceCountOverflow,
    #[error("fresh P1 resource revalidation did not reproduce the witness")]
    WitnessMismatch,
    #[error("manifest deployment profile does not match the requested AEPA profile")]
    ProfileMismatch,
    #[error("P0 authorization must not carry a P1 witness")]
    UnexpectedP1Witness,
    #[error("P1 authorization requires a fresh resource witness revalidation")]
    MissingP1Witness,
    #[error("P1 manifest has no resource evidence")]
    MissingManifestEvidence,
    #[error("P1 manifest resource evidence does not match the fresh witness")]
    ManifestEvidenceMismatch,
    #[error("AEPA manifest binding mismatch: {0}")]
    ManifestBinding(&'static str),
    #[error("P1 resource witness is stale at public step {public_step}")]
    StaleWitness { public_step: u32 },
    #[error("P0 manifest binding failed: {0}")]
    P0Binding(String),
}

#[allow(clippy::too_many_arguments)]
pub fn prove_aepa_p1_resource_equality(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    relation: &RelationVerdict,
    context: &ProductVerdict,
    cases: &[ResourceCase],
    limits: ResourceLimits,
    valid_from_public_step: u32,
    valid_until_public_step: u32,
) -> Result<AepaP1ResourceWitness, AepaP1Error> {
    let verdict = check_resource_strict(relation, context, cases, limits);
    issue_aepa_p1_resource_witness(
        source,
        k7,
        compiled,
        cases,
        verdict,
        valid_from_public_step,
        valid_until_public_step,
    )
}

/// Converts only a strict checker verdict into an opaque P1 witness.
///
/// This separate entry point makes normalized-verdict rejection directly
/// testable without introducing a normalization path into the gate itself.
#[allow(clippy::too_many_arguments)]
pub fn issue_aepa_p1_resource_witness(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    cases: &[ResourceCase],
    verdict: ResourceVerdict,
    valid_from_public_step: u32,
    valid_until_public_step: u32,
) -> Result<AepaP1ResourceWitness, AepaP1Error> {
    let compiled_binding = validate_compiled_binding(source, k7, compiled)?;
    validate_validity_window(source, valid_from_public_step, valid_until_public_step)?;

    let report = match verdict {
        ResourceVerdict::Strict(report) => report,
        ResourceVerdict::Normalized(_) => return Err(AepaP1Error::NormalizationForbidden),
        ResourceVerdict::Counterexample(counterexample) => {
            return Err(AepaP1Error::ResourceCounterexample {
                digest: counterexample.digest(),
            })
        }
        ResourceVerdict::Inconclusive(_) => return Err(AepaP1Error::ResourceInconclusive),
    };
    validate_strict_report(&report, cases, compiled_binding)?;

    let checked_cases =
        u64::try_from(report.checked_cases).map_err(|_| AepaP1Error::EvidenceCountOverflow)?;
    let checked_resource_events = u64::try_from(report.checked_resource_events)
        .map_err(|_| AepaP1Error::EvidenceCountOverflow)?;
    let relation_binding_digest = digest_relation_binding(report.pre_binding);
    let private_case_commitment = commit_private_cases(source, cases);
    let canonical_bytes = encode_witness(
        source,
        compiled_binding,
        relation_binding_digest,
        private_case_commitment,
        checked_cases,
        checked_resource_events,
        valid_from_public_step,
        valid_until_public_step,
    );
    let digest = artifact_digest(WITNESS_DOMAIN, &canonical_bytes);

    Ok(AepaP1ResourceWitness {
        canonical_bytes: canonical_bytes.into_boxed_slice(),
        digest,
        source_digest: compiled_binding.source_digest,
        transition_digest: compiled_binding.transition_digest,
        certificate_digest: compiled_binding.certificate_digest,
        generated_runtime_digest: compiled_binding.generated_runtime_digest,
        module_digest: compiled_binding.module_digest,
        target_ir_digest: compiled_binding.target_ir_digest,
        abi_digest: compiled_binding.abi_digest,
        capsule_digest: compiled_binding.capsule_digest,
        observer_registry_digest: compiled_binding.observer_registry_digest,
        relation_binding_digest,
        private_case_commitment,
        checked_cases,
        checked_resource_events,
        valid_from_public_step,
        valid_until_public_step,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn revalidate_aepa_p1_resource_witness(
    witness: &AepaP1ResourceWitness,
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    relation: &RelationVerdict,
    context: &ProductVerdict,
    cases: &[ResourceCase],
    limits: ResourceLimits,
) -> Result<AepaP1Revalidation, AepaP1Error> {
    let recomputed = prove_aepa_p1_resource_equality(
        source,
        k7,
        compiled,
        relation,
        context,
        cases,
        limits,
        witness.valid_from_public_step,
        witness.valid_until_public_step,
    )?;
    if &recomputed != witness {
        return Err(AepaP1Error::WitnessMismatch);
    }
    Ok(AepaP1Revalidation {
        witness: recomputed,
        seal: AepaP1RevalidationSeal,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn authorize_aepa_profile(
    requested_profile: DeploymentProfile,
    manifest: &NoticerQsmManifest,
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    revalidation: Option<&AepaP1Revalidation>,
    public_step: u32,
) -> Result<AepaProfileAuthorization, AepaP1Error> {
    let entry = manifest.binding(NoticerModuleId::Aepa);
    if entry.deployment_profile != requested_profile {
        return Err(AepaP1Error::ProfileMismatch);
    }

    match requested_profile {
        DeploymentProfile::P0PublicQuotientOnly => {
            if revalidation.is_some() {
                return Err(AepaP1Error::UnexpectedP1Witness);
            }
            let bound = bind_aepa_compiled_manifest(manifest, source, k7, compiled)
                .map_err(|error| AepaP1Error::P0Binding(error.to_string()))?;
            Ok(AepaProfileAuthorization {
                profile: requested_profile,
                authorization_digest: authorization_digest(
                    requested_profile,
                    manifest,
                    bound.capsule_digest,
                    None,
                    public_step,
                ),
                witness_digest: None,
                public_step,
                seal: AepaProfileAuthorizationSeal,
            })
        }
        DeploymentProfile::P1SealedAdmission => {
            let revalidation = revalidation.ok_or(AepaP1Error::MissingP1Witness)?;
            let witness = revalidation.witness();
            let compiled_binding = validate_compiled_binding(source, k7, compiled)?;
            validate_witness_artifacts(witness, compiled_binding)?;
            validate_p1_manifest(manifest, source, k7, compiled_binding, witness)?;
            if public_step < witness.valid_from_public_step
                || public_step >= witness.valid_until_public_step
            {
                return Err(AepaP1Error::StaleWitness { public_step });
            }
            Ok(AepaProfileAuthorization {
                profile: requested_profile,
                authorization_digest: authorization_digest(
                    requested_profile,
                    manifest,
                    compiled_binding.capsule_digest,
                    Some(witness.digest),
                    public_step,
                ),
                witness_digest: Some(witness.digest),
                public_step,
                seal: AepaProfileAuthorizationSeal,
            })
        }
    }
}

fn validate_compiled_binding(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
) -> Result<AepaP0Binding, AepaP1Error> {
    if k7.source_digest() != source.digest() {
        return Err(AepaP1Error::K7SourceMismatch);
    }
    let binding = compiled.binding();
    if binding.source_digest != source.digest()
        || binding.certificate_digest != k7.certificate_digest()
        || binding.generated_runtime_digest != k7.generated_runtime_digest()
        || !compiled.refines(source)
    {
        return Err(AepaP1Error::CompiledBindingMismatch);
    }
    if binding.transition_digest != aepa_transition_digest(compiled.transitions()) {
        return Err(AepaP1Error::TransitionBindingMismatch);
    }
    if compiled.service_code().service_alias != source.binding().wire_service_alias() {
        return Err(AepaP1Error::ServiceBindingMismatch);
    }
    Ok(binding)
}

fn validate_validity_window(
    source: &AepaPublicSourceArtifact,
    valid_from: u32,
    valid_until: u32,
) -> Result<(), AepaP1Error> {
    if valid_from >= valid_until {
        return Err(AepaP1Error::InvalidValidityWindow);
    }
    let (admission_start, admission_end) = source.binding().admission_window();
    if valid_from < admission_start || valid_until > admission_end {
        return Err(AepaP1Error::ValidityOutsideAdmissionWindow);
    }
    Ok(())
}

fn validate_strict_report(
    report: &ResourceReport,
    cases: &[ResourceCase],
    compiled: AepaP0Binding,
) -> Result<(), AepaP1Error> {
    if report.pre_binding != report.post_binding {
        return Err(AepaP1Error::RelationBindingChanged);
    }
    if report.pre_binding.target_ir_digest != compiled.target_ir_digest {
        return Err(AepaP1Error::RelationTargetMismatch);
    }
    if report.checked_cases != cases.len() {
        return Err(AepaP1Error::CaseCountMismatch);
    }
    if report.checked_cases == 0 || report.checked_resource_events == 0 {
        return Err(AepaP1Error::EmptyStrictEvidence);
    }
    if report.candidate_digest.is_some() || report.overhead != NormalizationOverhead::default() {
        return Err(AepaP1Error::NormalizationForbidden);
    }
    Ok(())
}

fn validate_witness_artifacts(
    witness: &AepaP1ResourceWitness,
    binding: AepaP0Binding,
) -> Result<(), AepaP1Error> {
    if witness.source_digest != binding.source_digest
        || witness.transition_digest != binding.transition_digest
        || witness.certificate_digest != binding.certificate_digest
        || witness.generated_runtime_digest != binding.generated_runtime_digest
        || witness.module_digest != binding.module_digest
        || witness.target_ir_digest != binding.target_ir_digest
        || witness.abi_digest != binding.abi_digest
        || witness.capsule_digest != binding.capsule_digest
        || witness.observer_registry_digest != binding.observer_registry_digest
    {
        return Err(AepaP1Error::WitnessMismatch);
    }
    Ok(())
}

fn validate_p1_manifest(
    manifest: &NoticerQsmManifest,
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: AepaP0Binding,
    witness: &AepaP1ResourceWitness,
) -> Result<(), AepaP1Error> {
    let entry = manifest.binding(NoticerModuleId::Aepa);
    let public = source.binding();
    if entry.service_alias != public.wire_service_alias() {
        return Err(AepaP1Error::ManifestBinding("service"));
    }
    if entry.epoch != public.epoch() {
        return Err(AepaP1Error::ManifestBinding("epoch"));
    }
    if entry.policy_hash != public.policy_hash() {
        return Err(AepaP1Error::ManifestBinding("policy"));
    }
    if entry.source_digest != source.digest() {
        return Err(AepaP1Error::ManifestBinding("source"));
    }
    if entry.source_certificate_digest != k7.certificate_digest() {
        return Err(AepaP1Error::ManifestBinding("certificate"));
    }
    if entry.generated_runtime_digest != k7.generated_runtime_digest() {
        return Err(AepaP1Error::ManifestBinding("runtime"));
    }
    if entry.qsm_capsule_digest != compiled.capsule_digest {
        return Err(AepaP1Error::ManifestBinding("capsule"));
    }
    if entry.observer_registry_digest != compiled.observer_registry_digest {
        return Err(AepaP1Error::ManifestBinding("observer_registry"));
    }
    let evidence = entry
        .p1_resource_evidence
        .ok_or(AepaP1Error::MissingManifestEvidence)?;
    if evidence.equivalence_certificate_digest != witness.digest
        || evidence.relation_binding_digest != witness.relation_binding_digest
        || evidence.checked_cases != witness.checked_cases
    {
        return Err(AepaP1Error::ManifestEvidenceMismatch);
    }
    Ok(())
}

fn digest_relation_binding(binding: RelationBinding) -> Digest {
    let mut bytes = Vec::with_capacity(96);
    push_digest(&mut bytes, binding.relation_digest);
    push_digest(&mut bytes, binding.inductive_digest);
    push_digest(&mut bytes, binding.target_ir_digest);
    artifact_digest(RELATION_BINDING_DOMAIN, &bytes)
}

fn commit_private_cases(source: &AepaPublicSourceArtifact, cases: &[ResourceCase]) -> Digest {
    let public = source.binding();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&public.pairwise_service_alias().0);
    bytes.extend_from_slice(&public.epoch().0.to_le_bytes());
    bytes.extend_from_slice(&(cases.len() as u64).to_le_bytes());
    for case in cases {
        let encoded = format!("{case:?}");
        bytes.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        bytes.extend_from_slice(encoded.as_bytes());
    }
    artifact_digest(CASE_COMMITMENT_DOMAIN, &bytes)
}

#[allow(clippy::too_many_arguments)]
fn encode_witness(
    source: &AepaPublicSourceArtifact,
    compiled: AepaP0Binding,
    relation_binding_digest: Digest,
    private_case_commitment: Digest,
    checked_cases: u64,
    checked_resource_events: u64,
    valid_from: u32,
    valid_until: u32,
) -> Vec<u8> {
    let public = source.binding();
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(WITNESS_MAGIC);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&public.wire_service_alias().0);
    bytes.extend_from_slice(&public.pairwise_service_alias().0);
    bytes.extend_from_slice(&public.epoch().0.to_le_bytes());
    bytes.extend_from_slice(&public.policy_hash().0);
    bytes.extend_from_slice(&public.lease_verifier_key_id().0);
    bytes.extend_from_slice(&public.pipeline_measurement_hash().0);
    bytes.extend_from_slice(&public.assurance_profile_digest().0);
    bytes.extend_from_slice(&public.atv2_issuer_key_id());
    let (admission_start, admission_end) = public.admission_window();
    bytes.extend_from_slice(&admission_start.to_le_bytes());
    bytes.extend_from_slice(&admission_end.to_le_bytes());
    for digest in [
        compiled.source_digest,
        compiled.transition_digest,
        compiled.certificate_digest,
        compiled.generated_runtime_digest,
        compiled.module_digest,
        compiled.target_ir_digest,
        compiled.abi_digest,
        compiled.compiler_manifest_digest,
        compiled.capsule_digest,
        compiled.observer_registry_digest,
        relation_binding_digest,
        private_case_commitment,
    ] {
        push_digest(&mut bytes, digest);
    }
    bytes.extend_from_slice(&checked_cases.to_le_bytes());
    bytes.extend_from_slice(&checked_resource_events.to_le_bytes());
    bytes.extend_from_slice(&valid_from.to_le_bytes());
    bytes.extend_from_slice(&valid_until.to_le_bytes());
    bytes
}

fn authorization_digest(
    profile: DeploymentProfile,
    manifest: &NoticerQsmManifest,
    capsule_digest: Digest,
    witness_digest: Option<Digest>,
    public_step: u32,
) -> Digest {
    let mut bytes = Vec::with_capacity(101);
    bytes.push(match profile {
        DeploymentProfile::P0PublicQuotientOnly => 0,
        DeploymentProfile::P1SealedAdmission => 1,
    });
    push_digest(&mut bytes, manifest.digest());
    push_digest(&mut bytes, capsule_digest);
    push_digest(&mut bytes, witness_digest.unwrap_or_else(Digest::zero));
    bytes.extend_from_slice(&public_step.to_le_bytes());
    artifact_digest(AUTHORIZATION_DOMAIN, &bytes)
}

fn push_digest(bytes: &mut Vec<u8>, digest: Digest) {
    bytes.extend_from_slice(digest.as_bytes());
}
