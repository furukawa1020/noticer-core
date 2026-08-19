use noticer_aetp::{PublicContext, ScheduleRandomTape};
use noticer_protocol::{FrameKind, WireServiceAlias, ENVELOPE_SIZE};
use noticer_release::TokenPlan;
use noticer_trace_shaper::{
    ActionEquivalentTraceShaper, FrameIssueError, FrameIssuer, PublicFrameIdentity,
};
use noticer_types::{Epoch, PolicyHash};
use quotient_forge_caqt::{
    artifact_digest, verify, Certificate, CertificateLimits, CertificateVerdict, Digest,
    ExpectedContract,
};
use quotient_seal_abi::DeploymentProfile;
use thiserror::Error;

use crate::{aets::codegen_metadata, codegen_manifest_digest, NoticerModuleId, NoticerQsmManifest};

pub const ATV2_PUBLIC_SOURCE_FORMAT_VERSION: &str = "noticer-atv2-public-source/v1";
pub const ATV2_K7_SPEC_FAMILY: &str = "noticer_atv2_action_window";
const SOURCE_MAGIC: &[u8; 8] = b"ATV2SRC1";
const SOURCE_DOMAIN: &[u8] = b"noticer-atv2-public-source-v1";
const FRAME_PLAN_DOMAIN: &[u8] = b"noticer-atv2-public-frame-plan-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Atv2PlannedFrame {
    identity: PublicFrameIdentity,
    kind: FrameKind,
}

impl Atv2PlannedFrame {
    #[must_use]
    pub const fn identity(&self) -> PublicFrameIdentity {
        self.identity
    }

    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Atv2PublicSourceArtifact {
    canonical_bytes: Box<[u8]>,
    digest: Digest,
    frame_plan_digest: Digest,
    service_alias: WireServiceAlias,
    epoch: Epoch,
    policy_hash: PolicyHash,
    token_plan: TokenPlan,
    public_context: PublicContext,
    schedule_tape: ScheduleRandomTape,
    frames: Box<[Atv2PlannedFrame]>,
}

impl Atv2PublicSourceArtifact {
    pub fn new(
        token_plan: &TokenPlan,
        public_context: &PublicContext,
        schedule_tape: ScheduleRandomTape,
        service_alias: WireServiceAlias,
        policy_hash: PolicyHash,
    ) -> Result<Self, Atv2BindingError> {
        public_context
            .validate()
            .map_err(|_| Atv2BindingError::InvalidPublicSource)?;
        let expected_frame_length =
            u16::try_from(ENVELOPE_SIZE).map_err(|_| Atv2BindingError::FrameShape)?;
        if public_context.schedule.fixed_ciphertext_size != expected_frame_length {
            return Err(Atv2BindingError::FrameShape);
        }
        if public_context.network.services.as_slice() != token_plan.services() {
            return Err(Atv2BindingError::ServiceSetMismatch);
        }
        if token_plan
            .actions()
            .iter()
            .any(|planned| planned.obligation().policy_hash != policy_hash)
        {
            return Err(Atv2BindingError::PolicyMismatch);
        }

        let issuer = ShapeOnlyIssuer {
            frame_length: ENVELOPE_SIZE,
        };
        let trace =
            ActionEquivalentTraceShaper::shape(token_plan, public_context, &schedule_tape, &issuer)
                .map_err(|_| Atv2BindingError::InvalidPublicSource)?;
        let expected_count = public_context
            .schedule
            .frame_count(public_context.network.services.len())
            .map_err(|_| Atv2BindingError::InvalidPublicSource)?;
        if trace.frames.len() != expected_count {
            return Err(Atv2BindingError::FrameShape);
        }
        let mut frames = Vec::with_capacity(trace.frames.len());
        for frame in trace.frames {
            let kind = match frame.bytes.first().copied() {
                Some(0) => FrameKind::Cover,
                Some(1) => FrameKind::Action,
                _ => return Err(Atv2BindingError::FrameShape),
            };
            frames.push(Atv2PlannedFrame {
                identity: frame.identity,
                kind,
            });
        }

        let service_count = u16::try_from(token_plan.services().len())
            .map_err(|_| Atv2BindingError::PublicSourceTooLarge)?;
        let action_count = u32::try_from(token_plan.actions().len())
            .map_err(|_| Atv2BindingError::PublicSourceTooLarge)?;
        let frame_count =
            u32::try_from(frames.len()).map_err(|_| Atv2BindingError::PublicSourceTooLarge)?;
        let frame_plan_bytes = encode_frame_plan(&frames);
        let frame_plan_digest = artifact_digest(FRAME_PLAN_DOMAIN, &frame_plan_bytes);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(SOURCE_MAGIC);
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&(ATV2_K7_SPEC_FAMILY.len() as u16).to_le_bytes());
        bytes.extend_from_slice(ATV2_K7_SPEC_FAMILY.as_bytes());
        bytes.extend_from_slice(&service_alias.0);
        bytes.extend_from_slice(&u64::from(public_context.network.public_epoch).to_le_bytes());
        bytes.extend_from_slice(&policy_hash.0);
        bytes.extend_from_slice(&public_context.schedule.buckets.to_le_bytes());
        bytes.extend_from_slice(&public_context.schedule.slots_per_bucket.to_le_bytes());
        bytes.extend_from_slice(&public_context.schedule.frame_interval_ms.to_le_bytes());
        bytes.extend_from_slice(&public_context.schedule.fixed_plaintext_size.to_le_bytes());
        bytes.extend_from_slice(&public_context.schedule.fixed_ciphertext_size.to_le_bytes());
        bytes.extend_from_slice(&public_context.network.start_slot.0.to_le_bytes());
        bytes.extend_from_slice(&schedule_tape.0);
        bytes.extend_from_slice(&service_count.to_le_bytes());
        bytes.extend_from_slice(&action_count.to_le_bytes());
        bytes.extend_from_slice(&frame_count.to_le_bytes());
        for service in token_plan.services() {
            bytes.extend_from_slice(&service.0);
        }
        for planned in token_plan.actions() {
            let obligation = planned.obligation();
            let bound = planned.claim_bound();
            bytes.extend_from_slice(&obligation.service.0);
            bytes.extend_from_slice(&(obligation.action as u16).to_le_bytes());
            bytes.extend_from_slice(&obligation.public_bucket.0.to_le_bytes());
            bytes.extend_from_slice(&obligation.admission_cutoff.0.to_le_bytes());
            bytes.extend_from_slice(&obligation.release_window_start.0.to_le_bytes());
            bytes.extend_from_slice(&obligation.release_deadline.0.to_le_bytes());
            bytes.extend_from_slice(&obligation.max_uses.to_le_bytes());
            bytes.extend_from_slice(&obligation.policy_hash.0);
            bytes.extend_from_slice(&[
                bound.semantic as u8,
                bound.audience as u8,
                bound.impact as u8,
            ]);
        }
        bytes.extend_from_slice(frame_plan_digest.as_bytes());
        bytes.extend_from_slice(&frame_plan_bytes);
        let digest = artifact_digest(SOURCE_DOMAIN, &bytes);

        Ok(Self {
            canonical_bytes: bytes.into_boxed_slice(),
            digest,
            frame_plan_digest,
            service_alias,
            epoch: Epoch(u64::from(public_context.network.public_epoch)),
            policy_hash,
            token_plan: token_plan.clone(),
            public_context: public_context.clone(),
            schedule_tape,
            frames: frames.into_boxed_slice(),
        })
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    #[must_use]
    pub const fn frame_plan_digest(&self) -> Digest {
        self.frame_plan_digest
    }

    #[must_use]
    pub const fn service_alias(&self) -> WireServiceAlias {
        self.service_alias
    }

    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    #[must_use]
    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    #[must_use]
    pub fn token_plan(&self) -> &TokenPlan {
        &self.token_plan
    }

    #[must_use]
    pub fn public_context(&self) -> &PublicContext {
        &self.public_context
    }

    #[must_use]
    pub const fn schedule_tape(&self) -> ScheduleRandomTape {
        self.schedule_tape
    }

    #[must_use]
    pub fn frames(&self) -> &[Atv2PlannedFrame] {
        &self.frames
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Atv2K7Binding {
    source_digest: Digest,
    certificate_digest: Digest,
    generated_runtime_digest: Digest,
    certificate: Certificate,
    source_certificate: Box<[u8]>,
    quotient_inputs: u16,
    public_inputs: u16,
    fault_inputs: u16,
}

impl Atv2K7Binding {
    #[must_use]
    pub const fn source_digest(&self) -> Digest {
        self.source_digest
    }

    #[must_use]
    pub const fn certificate_digest(&self) -> Digest {
        self.certificate_digest
    }

    #[must_use]
    pub const fn generated_runtime_digest(&self) -> Digest {
        self.generated_runtime_digest
    }

    #[must_use]
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    #[must_use]
    pub fn source_certificate(&self) -> &[u8] {
        &self.source_certificate
    }

    #[must_use]
    pub const fn input_axes(&self) -> (u16, u16, u16) {
        (self.quotient_inputs, self.public_inputs, self.fault_inputs)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Atv2K7ManifestBinding {
    pub source_digest: Digest,
    pub certificate_digest: Digest,
    pub generated_runtime_digest: Digest,
    seal: Atv2ManifestSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Atv2ManifestSeal;

pub fn verify_atv2_k7(
    source: &Atv2PublicSourceArtifact,
    certificate_bytes: &[u8],
    expected_contract: ExpectedContract,
    certificate_limits: CertificateLimits,
    generated_runtime_manifest: &[u8],
) -> Result<Atv2K7Binding, Atv2BindingError> {
    let certificate_digest = match verify(certificate_bytes, expected_contract, certificate_limits)
    {
        CertificateVerdict::Valid(report) => report.certificate_digest,
        verdict => {
            return Err(Atv2BindingError::CertificateRejected(format!(
                "{verdict:?}"
            )))
        }
    };
    let certificate = Certificate::decode(certificate_bytes, certificate_limits)
        .map_err(|error| Atv2BindingError::CertificateParse(error.to_string()))?;
    let metadata = codegen_metadata(generated_runtime_manifest)
        .map_err(|_| Atv2BindingError::InvalidCodegenManifest)?;
    if metadata.certificate_digest != certificate_digest {
        return Err(Atv2BindingError::CodegenCertificateMismatch);
    }
    let input_product = u32::from(metadata.quotient_inputs)
        .checked_mul(u32::from(metadata.public_inputs))
        .and_then(|value| value.checked_mul(u32::from(metadata.fault_inputs)))
        .ok_or(Atv2BindingError::CodegenInputAxes)?;
    if input_product != certificate.input_count {
        return Err(Atv2BindingError::CodegenInputAxes);
    }
    Ok(Atv2K7Binding {
        source_digest: source.digest(),
        certificate_digest,
        generated_runtime_digest: codegen_manifest_digest(generated_runtime_manifest),
        certificate,
        source_certificate: certificate_bytes.to_vec().into_boxed_slice(),
        quotient_inputs: metadata.quotient_inputs,
        public_inputs: metadata.public_inputs,
        fault_inputs: metadata.fault_inputs,
    })
}

pub fn bind_atv2_k7_manifest(
    manifest: &NoticerQsmManifest,
    source: &Atv2PublicSourceArtifact,
    k7: &Atv2K7Binding,
) -> Result<Atv2K7ManifestBinding, Atv2BindingError> {
    let entry = manifest.binding(NoticerModuleId::Atv2FramePlanner);
    if entry.deployment_profile != DeploymentProfile::P0PublicQuotientOnly {
        return Err(Atv2BindingError::ProfileNotP0);
    }
    if entry.p1_resource_evidence.is_some() {
        return Err(Atv2BindingError::UnexpectedP1Evidence);
    }
    if entry.service_alias != source.service_alias() {
        return Err(Atv2BindingError::ServiceAliasMismatch);
    }
    if entry.epoch != source.epoch() {
        return Err(Atv2BindingError::EpochMismatch);
    }
    if entry.policy_hash != source.policy_hash() {
        return Err(Atv2BindingError::PolicyMismatch);
    }
    ensure_digest("k7_source", source.digest(), k7.source_digest())?;
    ensure_digest("source", entry.source_digest, source.digest())?;
    ensure_digest(
        "certificate",
        entry.source_certificate_digest,
        k7.certificate_digest(),
    )?;
    ensure_digest(
        "generated_runtime",
        entry.generated_runtime_digest,
        k7.generated_runtime_digest(),
    )?;
    Ok(Atv2K7ManifestBinding {
        source_digest: source.digest(),
        certificate_digest: k7.certificate_digest(),
        generated_runtime_digest: k7.generated_runtime_digest(),
        seal: Atv2ManifestSeal,
    })
}

fn encode_frame_plan(frames: &[Atv2PlannedFrame]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(frames.len().saturating_mul(39));
    for frame in frames {
        let identity = frame.identity;
        bytes.extend_from_slice(&identity.service.0);
        bytes.extend_from_slice(&identity.public_epoch.to_le_bytes());
        bytes.extend_from_slice(&identity.public_bucket.to_le_bytes());
        bytes.extend_from_slice(&identity.slot_in_bucket.to_le_bytes());
        bytes.extend_from_slice(&identity.sequence.to_le_bytes());
        bytes.extend_from_slice(&identity.absolute_slot.0.to_le_bytes());
        bytes.push(frame.kind as u8);
    }
    bytes
}

fn ensure_digest(
    field: &'static str,
    expected: Digest,
    actual: Digest,
) -> Result<(), Atv2BindingError> {
    if expected != actual {
        return Err(Atv2BindingError::DigestMismatch { field });
    }
    Ok(())
}

struct ShapeOnlyIssuer {
    frame_length: usize,
}

impl ShapeOnlyIssuer {
    fn marker(&self, kind: FrameKind) -> Vec<u8> {
        let mut bytes = vec![0_u8; self.frame_length];
        bytes[0] = kind as u8;
        bytes
    }
}

impl FrameIssuer for ShapeOnlyIssuer {
    fn frame_length(&self) -> usize {
        self.frame_length
    }

    fn issue_cover(&self, _identity: PublicFrameIdentity) -> Result<Vec<u8>, FrameIssueError> {
        Ok(self.marker(FrameKind::Cover))
    }

    fn issue_action(
        &self,
        _identity: PublicFrameIdentity,
        _obligation: &noticer_aetp::ActionObligation,
        _claim_bound: noticer_aetp::ClaimBound,
    ) -> Result<Vec<u8>, FrameIssueError> {
        Ok(self.marker(FrameKind::Action))
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Atv2BindingError {
    #[error("ATv2 public source is invalid")]
    InvalidPublicSource,
    #[error("ATv2 public context and token plan services differ")]
    ServiceSetMismatch,
    #[error("ATv2 source policy binding differs")]
    PolicyMismatch,
    #[error("ATv2 source must project fixed 236-byte frames")]
    FrameShape,
    #[error("ATv2 public source exceeds its canonical integer fields")]
    PublicSourceTooLarge,
    #[error("K7 certificate was rejected: {0}")]
    CertificateRejected(String),
    #[error("K7 certificate parse failed: {0}")]
    CertificateParse(String),
    #[error("generated runtime manifest is invalid")]
    InvalidCodegenManifest,
    #[error("generated runtime names a different K7 certificate")]
    CodegenCertificateMismatch,
    #[error("generated runtime input axes differ from the K7 certificate")]
    CodegenInputAxes,
    #[error("ATv2 manifest deployment profile is not P0")]
    ProfileNotP0,
    #[error("ATv2 P0 manifest unexpectedly contains P1 resource evidence")]
    UnexpectedP1Evidence,
    #[error("ATv2 service alias differs from the registry")]
    ServiceAliasMismatch,
    #[error("ATv2 public epoch differs from the registry")]
    EpochMismatch,
    #[error("ATv2 digest mismatch for {field}")]
    DigestMismatch { field: &'static str },
}
