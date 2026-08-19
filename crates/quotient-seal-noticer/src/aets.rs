use std::collections::BTreeSet;

use noticer_aetp::{ActionSemantics, AetpError, PublicContext, ScheduleRandomTape};
use noticer_protocol::WireServiceAlias;
use noticer_types::{Epoch, PolicyHash};
use quotient_forge_caqt::{
    artifact_digest, verify, Certificate, CertificateLimits, CertificateVerdict, Digest,
    ExpectedContract,
};
use quotient_seal_abi::DeploymentProfile;
use thiserror::Error;

use crate::{NoticerModuleId, NoticerQsmManifest};

pub const AETS_PUBLIC_SOURCE_FORMAT_VERSION: &str = "noticer-aets-public-source/v1";
const AETS_SOURCE_MAGIC: &[u8; 8] = b"AETSSRC1";
const AETS_SOURCE_DOMAIN: &[u8] = b"noticer-aets-public-source-v1";
const CODEGEN_MANIFEST_DOMAIN: &[u8] = b"quotient-forge-codegen-manifest-v2";
const QSM_CAPSULE_DOMAIN: &[u8] = b"noticer-aets-qsm-capsule-v1";
const OBSERVER_REGISTRY_DOMAIN: &[u8] = b"noticer-aets-observer-registry-v1";
const CODEGEN_FORMAT_LINE: &str = "format = \"quotient-forge-codegen-v2\"";
const CERTIFICATE_DIGEST_PREFIX: &str = "certificate_digest = \"";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AetsPublicSourceArtifact {
    canonical_bytes: Box<[u8]>,
    digest: Digest,
    service_alias: WireServiceAlias,
    epoch: Epoch,
    policy_hash: PolicyHash,
    action_semantics: ActionSemantics,
    public_context: PublicContext,
    schedule_tape: ScheduleRandomTape,
}

impl AetsPublicSourceArtifact {
    pub fn new(
        action_semantics: &ActionSemantics,
        public_context: &PublicContext,
        schedule_tape: ScheduleRandomTape,
        service_alias: WireServiceAlias,
        policy_hash: PolicyHash,
    ) -> Result<Self, AetsBindingError> {
        public_context
            .validate()
            .map_err(AetsBindingError::PublicSource)?;
        let semantics = ActionSemantics::new(action_semantics.obligations.clone())
            .map_err(AetsBindingError::PublicSource)?;
        let mut services = public_context.network.services.clone();
        services.sort_unstable();
        let service_set: BTreeSet<_> = services.iter().copied().collect();
        for obligation in &semantics.obligations {
            if !service_set.contains(&obligation.service) {
                return Err(AetsBindingError::ObligationServiceOutsideContext);
            }
            if obligation.policy_hash != policy_hash {
                return Err(AetsBindingError::PolicyMismatch);
            }
        }
        let service_count =
            u16::try_from(services.len()).map_err(|_| AetsBindingError::PublicSourceTooLarge)?;
        let obligation_count = u32::try_from(semantics.obligations.len())
            .map_err(|_| AetsBindingError::PublicSourceTooLarge)?;

        let mut canonical_context = public_context.clone();
        canonical_context.network.services = services.clone();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(AETS_SOURCE_MAGIC);
        bytes.extend_from_slice(&1_u16.to_le_bytes());
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
        bytes.extend_from_slice(&obligation_count.to_le_bytes());
        for service in services {
            bytes.extend_from_slice(&service.0);
        }
        for obligation in &semantics.obligations {
            bytes.extend_from_slice(&obligation.service.0);
            bytes.extend_from_slice(&(obligation.action as u16).to_le_bytes());
            bytes.extend_from_slice(&obligation.public_bucket.0.to_le_bytes());
            bytes.extend_from_slice(&obligation.admission_cutoff.0.to_le_bytes());
            bytes.extend_from_slice(&obligation.release_window_start.0.to_le_bytes());
            bytes.extend_from_slice(&obligation.release_deadline.0.to_le_bytes());
            bytes.extend_from_slice(&obligation.max_uses.to_le_bytes());
            bytes.extend_from_slice(&obligation.policy_hash.0);
        }
        let digest = artifact_digest(AETS_SOURCE_DOMAIN, &bytes);
        Ok(Self {
            canonical_bytes: bytes.into_boxed_slice(),
            digest,
            service_alias,
            epoch: Epoch(u64::from(public_context.network.public_epoch)),
            policy_hash,
            action_semantics: semantics,
            public_context: canonical_context,
            schedule_tape,
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
    pub fn action_semantics(&self) -> &ActionSemantics {
        &self.action_semantics
    }

    #[must_use]
    pub fn public_context(&self) -> &PublicContext {
        &self.public_context
    }

    #[must_use]
    pub const fn schedule_tape(&self) -> ScheduleRandomTape {
        self.schedule_tape
    }
}

pub struct AetsArtifactSet<'a> {
    pub certificate: &'a [u8],
    pub expected_contract: ExpectedContract,
    pub certificate_limits: CertificateLimits,
    pub generated_runtime_manifest: &'a [u8],
    pub qsm_capsule: &'a [u8],
    pub observer_registry: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AetsK7Binding {
    source_digest: Digest,
    certificate_digest: Digest,
    generated_runtime_digest: Digest,
    certificate: Certificate,
    source_certificate: Box<[u8]>,
    quotient_inputs: u16,
    public_inputs: u16,
    fault_inputs: u16,
}

impl AetsK7Binding {
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
    pub fn source_certificate(&self) -> &[u8] {
        &self.source_certificate
    }

    #[must_use]
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    #[must_use]
    pub const fn input_axes(&self) -> (u16, u16, u16) {
        (self.quotient_inputs, self.public_inputs, self.fault_inputs)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AetsP0Binding {
    pub source_digest: Digest,
    pub certificate_digest: Digest,
    pub generated_runtime_digest: Digest,
    pub qsm_capsule_digest: Digest,
    pub observer_registry_digest: Digest,
    seal: AetsBindingSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AetsBindingSeal;

pub fn verify_aets_k7(
    source: &AetsPublicSourceArtifact,
    certificate_bytes: &[u8],
    expected_contract: ExpectedContract,
    certificate_limits: CertificateLimits,
    generated_runtime_manifest: &[u8],
) -> Result<AetsK7Binding, AetsBindingError> {
    let certificate_digest = match verify(certificate_bytes, expected_contract, certificate_limits)
    {
        CertificateVerdict::Valid(report) => report.certificate_digest,
        verdict => {
            return Err(AetsBindingError::CertificateRejected(format!(
                "{verdict:?}"
            )))
        }
    };
    let certificate = Certificate::decode(certificate_bytes, certificate_limits)
        .map_err(|error| AetsBindingError::CertificateParse(error.to_string()))?;
    let metadata = codegen_metadata(generated_runtime_manifest)?;
    if metadata.certificate_digest != certificate_digest {
        return Err(AetsBindingError::CodegenCertificateMismatch);
    }
    let input_product = u32::from(metadata.quotient_inputs)
        .checked_mul(u32::from(metadata.public_inputs))
        .and_then(|value| value.checked_mul(u32::from(metadata.fault_inputs)))
        .ok_or(AetsBindingError::CodegenInputAxes)?;
    if input_product != certificate.input_count {
        return Err(AetsBindingError::CodegenInputAxes);
    }
    Ok(AetsK7Binding {
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

pub fn bind_aets_p0(
    manifest: &NoticerQsmManifest,
    source: &AetsPublicSourceArtifact,
    artifacts: AetsArtifactSet<'_>,
) -> Result<AetsP0Binding, AetsBindingError> {
    let entry = manifest.binding(NoticerModuleId::Aets);
    if entry.deployment_profile != DeploymentProfile::P0PublicQuotientOnly {
        return Err(AetsBindingError::ProfileNotP0);
    }
    if entry.p1_resource_evidence.is_some() {
        return Err(AetsBindingError::UnexpectedP1Evidence);
    }
    if entry.service_alias != source.service_alias() {
        return Err(AetsBindingError::ServiceAliasMismatch);
    }
    if entry.epoch != source.epoch() {
        return Err(AetsBindingError::EpochMismatch);
    }
    if entry.policy_hash != source.policy_hash() {
        return Err(AetsBindingError::PolicyMismatch);
    }
    ensure_digest("source", entry.source_digest, source.digest())?;

    let k7 = verify_aets_k7(
        source,
        artifacts.certificate,
        artifacts.expected_contract,
        artifacts.certificate_limits,
        artifacts.generated_runtime_manifest,
    )?;
    let certificate_digest = k7.certificate_digest();
    ensure_digest(
        "certificate",
        entry.source_certificate_digest,
        certificate_digest,
    )?;
    let generated_runtime_digest = k7.generated_runtime_digest();
    let qsm_capsule_digest = aets_qsm_capsule_digest(artifacts.qsm_capsule);
    let observer_registry_digest = aets_observer_registry_digest(artifacts.observer_registry);
    ensure_digest(
        "generated_runtime",
        entry.generated_runtime_digest,
        generated_runtime_digest,
    )?;
    ensure_digest("qsm_capsule", entry.qsm_capsule_digest, qsm_capsule_digest)?;
    ensure_digest(
        "observer_registry",
        entry.observer_registry_digest,
        observer_registry_digest,
    )?;

    Ok(AetsP0Binding {
        source_digest: source.digest(),
        certificate_digest,
        generated_runtime_digest,
        qsm_capsule_digest,
        observer_registry_digest,
        seal: AetsBindingSeal,
    })
}

#[must_use]
pub fn codegen_manifest_digest(bytes: &[u8]) -> Digest {
    artifact_digest(CODEGEN_MANIFEST_DOMAIN, bytes)
}

#[must_use]
pub fn aets_qsm_capsule_digest(bytes: &[u8]) -> Digest {
    artifact_digest(QSM_CAPSULE_DOMAIN, bytes)
}

#[must_use]
pub fn aets_observer_registry_digest(bytes: &[u8]) -> Digest {
    artifact_digest(OBSERVER_REGISTRY_DOMAIN, bytes)
}

pub(crate) struct CodegenMetadata {
    pub(crate) certificate_digest: Digest,
    pub(crate) quotient_inputs: u16,
    pub(crate) public_inputs: u16,
    pub(crate) fault_inputs: u16,
}

pub(crate) fn codegen_metadata(bytes: &[u8]) -> Result<CodegenMetadata, AetsBindingError> {
    let text = std::str::from_utf8(bytes).map_err(|_| AetsBindingError::InvalidCodegenManifest)?;
    let mut format_seen = false;
    let mut certificate_digest = None;
    for line in text.lines() {
        if line == CODEGEN_FORMAT_LINE {
            if format_seen {
                return Err(AetsBindingError::InvalidCodegenManifest);
            }
            format_seen = true;
        }
        if let Some(value) = line.strip_prefix(CERTIFICATE_DIGEST_PREFIX) {
            let Some(value) = value.strip_suffix('"') else {
                return Err(AetsBindingError::InvalidCodegenManifest);
            };
            if certificate_digest.is_some() {
                return Err(AetsBindingError::InvalidCodegenManifest);
            }
            certificate_digest = Some(parse_digest(value)?);
        }
    }
    if !format_seen {
        return Err(AetsBindingError::InvalidCodegenManifest);
    }
    let certificate_digest = certificate_digest.ok_or(AetsBindingError::InvalidCodegenManifest)?;
    Ok(CodegenMetadata {
        certificate_digest,
        quotient_inputs: manifest_u16(text, "quotient_inputs = ")?,
        public_inputs: manifest_u16(text, "public_inputs = ")?,
        fault_inputs: manifest_u16(text, "fault_inputs = ")?,
    })
}

fn manifest_u16(text: &str, prefix: &str) -> Result<u16, AetsBindingError> {
    let mut value = None;
    for line in text.lines() {
        if let Some(candidate) = line.strip_prefix(prefix) {
            if value.is_some()
                || candidate.is_empty()
                || !candidate.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(AetsBindingError::InvalidCodegenManifest);
            }
            value = Some(
                candidate
                    .parse::<u16>()
                    .map_err(|_| AetsBindingError::InvalidCodegenManifest)?,
            );
        }
    }
    value
        .filter(|value| *value > 0)
        .ok_or(AetsBindingError::InvalidCodegenManifest)
}

fn parse_digest(value: &str) -> Result<Digest, AetsBindingError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AetsBindingError::InvalidCodegenManifest);
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(AetsBindingError::InvalidCodegenManifest)?;
        let low = hex_nibble(pair[1]).ok_or(AetsBindingError::InvalidCodegenManifest)?;
        bytes[index] = (high << 4) | low;
    }
    Ok(Digest::new(bytes))
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn ensure_digest(
    artifact: &'static str,
    expected: Digest,
    actual: Digest,
) -> Result<(), AetsBindingError> {
    if expected == actual {
        Ok(())
    } else {
        Err(AetsBindingError::ArtifactDigestMismatch { artifact })
    }
}

#[derive(Debug, Error)]
pub enum AetsBindingError {
    #[error("invalid AETS public source: {0}")]
    PublicSource(AetpError),
    #[error("AETS public source exceeds the canonical count limits")]
    PublicSourceTooLarge,
    #[error("an AETS action obligation references a service outside PublicContext")]
    ObligationServiceOutsideContext,
    #[error("AETS integration currently accepts only P0 Public Quotient Only")]
    ProfileNotP0,
    #[error("P1 resource evidence is forbidden in an AETS P0 binding")]
    UnexpectedP1Evidence,
    #[error("AETS service alias does not match the Noticer QSM manifest")]
    ServiceAliasMismatch,
    #[error("AETS epoch does not match the Noticer QSM manifest")]
    EpochMismatch,
    #[error("AETS policy hash does not match the public source or manifest")]
    PolicyMismatch,
    #[error("CAQT certificate was rejected: {0}")]
    CertificateRejected(String),
    #[error("CAQT certificate could not be decoded after verification: {0}")]
    CertificateParse(String),
    #[error("generated runtime manifest is not canonical codegen v2 metadata")]
    InvalidCodegenManifest,
    #[error("generated runtime manifest is bound to a different CAQT certificate")]
    CodegenCertificateMismatch,
    #[error("generated runtime input axes do not match the CAQT certificate")]
    CodegenInputAxes,
    #[error("{artifact} digest does not match the Noticer QSM manifest")]
    ArtifactDigestMismatch { artifact: &'static str },
}
