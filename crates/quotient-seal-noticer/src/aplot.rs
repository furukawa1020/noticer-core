use crate::aets::{codegen_manifest_digest, codegen_metadata};
use crate::{
    DeploymentProfile, Digest, Epoch, NoticerModuleId, NoticerQsmManifest, PolicyHash,
    WireServiceAlias,
};
use noticer_transport_core::{
    DATA_FRAGMENT_COUNT, FRAGMENT_HEADER_SIZE, FRAGMENT_PAYLOAD_SIZE, FRAGMENT_SIZE,
    PARITY_FRAGMENT_COUNT, TOTAL_FRAGMENT_COUNT, TRANSPORT_PAYLOAD_SIZE,
};
use noticer_transport_sim::PublicLossTape;
use quotient_forge_caqt::{
    artifact_digest, verify, Certificate, CertificateLimits, CertificateVerdict, ExpectedContract,
};
use thiserror::Error;

pub const APLOT_PUBLIC_SOURCE_FORMAT_VERSION: u16 = 1;
pub const APLOT_APPLICATION_RETRY_COUNT: u8 = 0;
pub const APLOT_MAX_FRAMES: usize = 1_024;
pub const APLOT_MAX_RECONNECT_TICKS: usize = 64;

const SOURCE_MAGIC: &[u8; 8] = b"APLOTSR1";
const SOURCE_DIGEST_DOMAIN: &[u8] = b"noticer-core/aplot/public-source/v1";
const SCHEDULE_DIGEST_DOMAIN: &[u8] = b"noticer-core/aplot/public-schedule/v1";
const ENVELOPE_BYTES: u16 = 236;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AplotFrameInput {
    pub public_bucket: u32,
    pub sequence: u32,
    pub start_tick: u64,
    pub fragment_cadence_ticks: u64,
    pub deadline_tick: u64,
    pub loss_tape: PublicLossTape,
    pub reconnect_ticks: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AplotPublicFramePlan {
    public_bucket: u32,
    sequence: u32,
    start_tick: u64,
    fragment_cadence_ticks: u64,
    deadline_tick: u64,
    loss_mask: u32,
    reconnect_ticks: Box<[u64]>,
}

impl AplotPublicFramePlan {
    #[must_use]
    pub const fn public_bucket(&self) -> u32 {
        self.public_bucket
    }

    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    #[must_use]
    pub const fn start_tick(&self) -> u64 {
        self.start_tick
    }

    #[must_use]
    pub const fn fragment_cadence_ticks(&self) -> u64 {
        self.fragment_cadence_ticks
    }

    #[must_use]
    pub const fn deadline_tick(&self) -> u64 {
        self.deadline_tick
    }

    #[must_use]
    pub const fn loss_mask(&self) -> u32 {
        self.loss_mask
    }

    #[must_use]
    pub fn reconnect_ticks(&self) -> &[u64] {
        &self.reconnect_ticks
    }

    #[must_use]
    pub const fn application_retry_count(&self) -> u8 {
        APLOT_APPLICATION_RETRY_COUNT
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AplotFragmentSlot {
    pub frame_ordinal: u32,
    pub public_bucket: u32,
    pub sequence: u32,
    pub ordinal: u8,
    pub fragment_index: u8,
    pub scheduled_tick: u64,
    pub delivered: bool,
    pub fragment_bytes: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AplotPublicSourceArtifact {
    service_alias: WireServiceAlias,
    epoch: Epoch,
    policy_hash: PolicyHash,
    active_frame_capacity: u16,
    ttl_ticks: u64,
    frames: Box<[AplotPublicFramePlan]>,
    fragment_slots: Box<[AplotFragmentSlot]>,
    canonical_bytes: Box<[u8]>,
    digest: Digest,
    schedule_digest: Digest,
}

impl AplotPublicSourceArtifact {
    pub fn new(
        service_alias: WireServiceAlias,
        epoch: Epoch,
        policy_hash: PolicyHash,
        active_frame_capacity: u16,
        ttl_ticks: u64,
        frames: Vec<AplotFrameInput>,
    ) -> Result<Self, AplotBindingError> {
        if service_alias.0 == [0; 8]
            || epoch.0 > u64::from(u32::MAX)
            || active_frame_capacity == 0
            || ttl_ticks == 0
            || frames.is_empty()
            || frames.len() > APLOT_MAX_FRAMES
        {
            return Err(AplotBindingError::InvalidPublicSource);
        }

        let mut plans = frames
            .into_iter()
            .map(canonical_frame)
            .collect::<Result<Vec<_>, _>>()?;
        plans.sort_by_key(|frame| (frame.public_bucket, frame.sequence));
        if plans.windows(2).any(|pair| {
            pair[0].public_bucket == pair[1].public_bucket && pair[0].sequence == pair[1].sequence
        }) {
            return Err(AplotBindingError::DuplicateFrameIdentity);
        }

        let fragment_slots = fragment_slots(&plans)?;
        let canonical_bytes = encode_source(
            service_alias,
            epoch,
            policy_hash,
            active_frame_capacity,
            ttl_ticks,
            &plans,
        )?;
        let schedule_bytes = encode_schedule(&fragment_slots, &plans)?;
        let digest = artifact_digest(SOURCE_DIGEST_DOMAIN, &canonical_bytes);
        let schedule_digest = artifact_digest(SCHEDULE_DIGEST_DOMAIN, &schedule_bytes);
        Ok(Self {
            service_alias,
            epoch,
            policy_hash,
            active_frame_capacity,
            ttl_ticks,
            frames: plans.into_boxed_slice(),
            fragment_slots: fragment_slots.into_boxed_slice(),
            canonical_bytes: canonical_bytes.into_boxed_slice(),
            digest,
            schedule_digest,
        })
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
    pub const fn active_frame_capacity(&self) -> u16 {
        self.active_frame_capacity
    }

    #[must_use]
    pub const fn ttl_ticks(&self) -> u64 {
        self.ttl_ticks
    }

    #[must_use]
    pub fn frames(&self) -> &[AplotPublicFramePlan] {
        &self.frames
    }

    #[must_use]
    pub fn fragment_slots(&self) -> &[AplotFragmentSlot] {
        &self.fragment_slots
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
    pub const fn schedule_digest(&self) -> Digest {
        self.schedule_digest
    }

    #[must_use]
    pub const fn application_retry_count(&self) -> u8 {
        APLOT_APPLICATION_RETRY_COUNT
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AplotK7Binding {
    source_digest: Digest,
    schedule_digest: Digest,
    certificate_digest: Digest,
    generated_runtime_digest: Digest,
    certificate: Certificate,
    source_certificate: Box<[u8]>,
    quotient_inputs: u16,
    public_inputs: u16,
    fault_inputs: u16,
}

impl AplotK7Binding {
    #[must_use]
    pub const fn source_digest(&self) -> Digest {
        self.source_digest
    }

    #[must_use]
    pub const fn schedule_digest(&self) -> Digest {
        self.schedule_digest
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
pub struct AplotK7ManifestBinding {
    pub source_digest: Digest,
    pub schedule_digest: Digest,
    pub certificate_digest: Digest,
    pub generated_runtime_digest: Digest,
    seal: AplotManifestSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AplotManifestSeal;

pub fn verify_aplot_k7(
    source: &AplotPublicSourceArtifact,
    certificate_bytes: &[u8],
    expected_contract: ExpectedContract,
    certificate_limits: CertificateLimits,
    generated_runtime_manifest: &[u8],
) -> Result<AplotK7Binding, AplotBindingError> {
    let certificate_digest = match verify(certificate_bytes, expected_contract, certificate_limits)
    {
        CertificateVerdict::Valid(report) => report.certificate_digest,
        verdict => {
            return Err(AplotBindingError::CertificateRejected(format!(
                "{verdict:?}"
            )))
        }
    };
    let certificate = Certificate::decode(certificate_bytes, certificate_limits)
        .map_err(|error| AplotBindingError::CertificateParse(error.to_string()))?;
    let metadata = codegen_metadata(generated_runtime_manifest)
        .map_err(|_| AplotBindingError::InvalidCodegenManifest)?;
    if metadata.certificate_digest != certificate_digest {
        return Err(AplotBindingError::CodegenCertificateMismatch);
    }
    let input_product = u32::from(metadata.quotient_inputs)
        .checked_mul(u32::from(metadata.public_inputs))
        .and_then(|value| value.checked_mul(u32::from(metadata.fault_inputs)))
        .ok_or(AplotBindingError::CodegenInputAxes)?;
    if input_product != certificate.input_count {
        return Err(AplotBindingError::CodegenInputAxes);
    }
    Ok(AplotK7Binding {
        source_digest: source.digest(),
        schedule_digest: source.schedule_digest(),
        certificate_digest,
        generated_runtime_digest: codegen_manifest_digest(generated_runtime_manifest),
        certificate,
        source_certificate: certificate_bytes.to_vec().into_boxed_slice(),
        quotient_inputs: metadata.quotient_inputs,
        public_inputs: metadata.public_inputs,
        fault_inputs: metadata.fault_inputs,
    })
}

pub fn bind_aplot_k7_manifest(
    manifest: &NoticerQsmManifest,
    source: &AplotPublicSourceArtifact,
    k7: &AplotK7Binding,
) -> Result<AplotK7ManifestBinding, AplotBindingError> {
    let entry = manifest.binding(NoticerModuleId::Aplot);
    if entry.deployment_profile != DeploymentProfile::P0PublicQuotientOnly {
        return Err(AplotBindingError::ProfileNotP0);
    }
    if entry.p1_resource_evidence.is_some() {
        return Err(AplotBindingError::UnexpectedP1Evidence);
    }
    if entry.service_alias != source.service_alias() {
        return Err(AplotBindingError::ServiceAliasMismatch);
    }
    if entry.epoch != source.epoch() {
        return Err(AplotBindingError::EpochMismatch);
    }
    if entry.policy_hash != source.policy_hash() {
        return Err(AplotBindingError::PolicyMismatch);
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
    Ok(AplotK7ManifestBinding {
        source_digest: source.digest(),
        schedule_digest: source.schedule_digest(),
        certificate_digest: k7.certificate_digest(),
        generated_runtime_digest: k7.generated_runtime_digest(),
        seal: AplotManifestSeal,
    })
}

fn canonical_frame(input: AplotFrameInput) -> Result<AplotPublicFramePlan, AplotBindingError> {
    if input.fragment_cadence_ticks == 0 || input.reconnect_ticks.len() > APLOT_MAX_RECONNECT_TICKS
    {
        return Err(AplotBindingError::InvalidFrameSchedule);
    }
    let final_fragment_tick = input
        .fragment_cadence_ticks
        .checked_mul((TOTAL_FRAGMENT_COUNT - 1) as u64)
        .and_then(|offset| input.start_tick.checked_add(offset))
        .ok_or(AplotBindingError::ScheduleArithmetic)?;
    if input.deadline_tick < final_fragment_tick {
        return Err(AplotBindingError::InvalidFrameSchedule);
    }
    let mut reconnect_ticks = input.reconnect_ticks;
    reconnect_ticks.sort_unstable();
    let before_dedup = reconnect_ticks.len();
    reconnect_ticks.dedup();
    if reconnect_ticks.len() != before_dedup
        || reconnect_ticks
            .iter()
            .any(|tick| *tick < input.start_tick || *tick > input.deadline_tick)
    {
        return Err(AplotBindingError::InvalidReconnectSchedule);
    }
    let mut loss_mask = 0_u32;
    for ordinal in 0..TOTAL_FRAGMENT_COUNT {
        if input.loss_tape.is_dropped(ordinal) {
            loss_mask |= 1_u32 << ordinal;
        }
    }
    Ok(AplotPublicFramePlan {
        public_bucket: input.public_bucket,
        sequence: input.sequence,
        start_tick: input.start_tick,
        fragment_cadence_ticks: input.fragment_cadence_ticks,
        deadline_tick: input.deadline_tick,
        loss_mask,
        reconnect_ticks: reconnect_ticks.into_boxed_slice(),
    })
}

fn fragment_slots(
    frames: &[AplotPublicFramePlan],
) -> Result<Vec<AplotFragmentSlot>, AplotBindingError> {
    let count = frames
        .len()
        .checked_mul(TOTAL_FRAGMENT_COUNT)
        .ok_or(AplotBindingError::ScheduleArithmetic)?;
    let mut slots = Vec::with_capacity(count);
    for (frame_ordinal, frame) in frames.iter().enumerate() {
        let frame_ordinal =
            u32::try_from(frame_ordinal).map_err(|_| AplotBindingError::ScheduleArithmetic)?;
        for ordinal in 0..TOTAL_FRAGMENT_COUNT {
            let scheduled_tick = frame
                .fragment_cadence_ticks
                .checked_mul(ordinal as u64)
                .and_then(|offset| frame.start_tick.checked_add(offset))
                .ok_or(AplotBindingError::ScheduleArithmetic)?;
            slots.push(AplotFragmentSlot {
                frame_ordinal,
                public_bucket: frame.public_bucket,
                sequence: frame.sequence,
                ordinal: ordinal as u8,
                fragment_index: ordinal as u8,
                scheduled_tick,
                delivered: frame.loss_mask & (1_u32 << ordinal) == 0,
                fragment_bytes: FRAGMENT_SIZE as u16,
            });
        }
    }
    Ok(slots)
}

fn encode_source(
    service_alias: WireServiceAlias,
    epoch: Epoch,
    policy_hash: PolicyHash,
    active_frame_capacity: u16,
    ttl_ticks: u64,
    frames: &[AplotPublicFramePlan],
) -> Result<Vec<u8>, AplotBindingError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SOURCE_MAGIC);
    bytes.extend_from_slice(&APLOT_PUBLIC_SOURCE_FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&ENVELOPE_BYTES.to_le_bytes());
    bytes.extend_from_slice(&(TRANSPORT_PAYLOAD_SIZE as u16).to_le_bytes());
    bytes.extend_from_slice(&(FRAGMENT_SIZE as u16).to_le_bytes());
    bytes.extend_from_slice(&(FRAGMENT_HEADER_SIZE as u16).to_le_bytes());
    bytes.extend_from_slice(&(FRAGMENT_PAYLOAD_SIZE as u16).to_le_bytes());
    bytes.extend_from_slice(&(DATA_FRAGMENT_COUNT as u16).to_le_bytes());
    bytes.extend_from_slice(&(PARITY_FRAGMENT_COUNT as u16).to_le_bytes());
    bytes.extend_from_slice(&(TOTAL_FRAGMENT_COUNT as u16).to_le_bytes());
    bytes.push(APLOT_APPLICATION_RETRY_COUNT);
    bytes.push(0);
    bytes.extend_from_slice(&service_alias.0);
    bytes.extend_from_slice(&epoch.0.to_le_bytes());
    bytes.extend_from_slice(&policy_hash.0);
    bytes.extend_from_slice(&active_frame_capacity.to_le_bytes());
    bytes.extend_from_slice(&ttl_ticks.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(frames.len())
            .map_err(|_| AplotBindingError::ScheduleArithmetic)?
            .to_le_bytes(),
    );
    for frame in frames {
        bytes.extend_from_slice(&frame.public_bucket.to_le_bytes());
        bytes.extend_from_slice(&frame.sequence.to_le_bytes());
        bytes.extend_from_slice(&frame.start_tick.to_le_bytes());
        bytes.extend_from_slice(&frame.fragment_cadence_ticks.to_le_bytes());
        bytes.extend_from_slice(&frame.deadline_tick.to_le_bytes());
        bytes.extend_from_slice(&frame.loss_mask.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(frame.reconnect_ticks.len())
                .map_err(|_| AplotBindingError::ScheduleArithmetic)?
                .to_le_bytes(),
        );
        for tick in frame.reconnect_ticks() {
            bytes.extend_from_slice(&tick.to_le_bytes());
        }
    }
    Ok(bytes)
}

fn encode_schedule(
    slots: &[AplotFragmentSlot],
    frames: &[AplotPublicFramePlan],
) -> Result<Vec<u8>, AplotBindingError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"APLOTSCH");
    bytes.extend_from_slice(&APLOT_PUBLIC_SOURCE_FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(slots.len())
            .map_err(|_| AplotBindingError::ScheduleArithmetic)?
            .to_le_bytes(),
    );
    for slot in slots {
        bytes.extend_from_slice(&slot.frame_ordinal.to_le_bytes());
        bytes.extend_from_slice(&slot.public_bucket.to_le_bytes());
        bytes.extend_from_slice(&slot.sequence.to_le_bytes());
        bytes.push(slot.ordinal);
        bytes.push(slot.fragment_index);
        bytes.extend_from_slice(&slot.scheduled_tick.to_le_bytes());
        bytes.push(u8::from(slot.delivered));
        bytes.extend_from_slice(&slot.fragment_bytes.to_le_bytes());
    }
    for frame in frames {
        for tick in frame.reconnect_ticks() {
            bytes.extend_from_slice(&frame.public_bucket.to_le_bytes());
            bytes.extend_from_slice(&frame.sequence.to_le_bytes());
            bytes.extend_from_slice(&tick.to_le_bytes());
        }
    }
    Ok(bytes)
}

fn ensure_digest(
    field: &'static str,
    expected: Digest,
    actual: Digest,
) -> Result<(), AplotBindingError> {
    if expected == actual {
        Ok(())
    } else {
        Err(AplotBindingError::DigestMismatch { field })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AplotBindingError {
    #[error("APLOT public source is invalid")]
    InvalidPublicSource,
    #[error("APLOT frame schedule is invalid")]
    InvalidFrameSchedule,
    #[error("APLOT reconnect schedule is invalid")]
    InvalidReconnectSchedule,
    #[error("APLOT public source contains a duplicate frame identity")]
    DuplicateFrameIdentity,
    #[error("APLOT public schedule arithmetic overflow")]
    ScheduleArithmetic,
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
    #[error("APLOT manifest deployment profile is not P0")]
    ProfileNotP0,
    #[error("APLOT P0 manifest unexpectedly contains P1 resource evidence")]
    UnexpectedP1Evidence,
    #[error("APLOT service alias differs from the registry")]
    ServiceAliasMismatch,
    #[error("APLOT public epoch differs from the registry")]
    EpochMismatch,
    #[error("APLOT policy binding differs")]
    PolicyMismatch,
    #[error("APLOT digest mismatch for {field}")]
    DigestMismatch { field: &'static str },
}
