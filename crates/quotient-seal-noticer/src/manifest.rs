use noticer_protocol::WireServiceAlias;
use noticer_types::{Epoch, PolicyHash};
use quotient_forge_caqt::{artifact_digest, Digest};
use quotient_seal_abi::DeploymentProfile;

pub const NOTICER_QSM_MANIFEST_MAGIC: [u8; 8] = *b"NQSMREG1";
pub const NOTICER_QSM_MANIFEST_VERSION: u16 = 1;
const MODULE_COUNT: usize = 5;
const HEADER_BYTES: usize = 12;
const ENTRY_BYTES: usize = 284;
pub const NOTICER_QSM_MANIFEST_BYTES: usize = HEADER_BYTES + MODULE_COUNT * ENTRY_BYTES;
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"noticer-core/qseal/noticer-qsm-manifest/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NoticerModuleId {
    Aets = 1,
    Atv2FramePlanner = 2,
    Aplot = 3,
    Aepa = 4,
    MenfuguExecutionPlanner = 5,
}

impl NoticerModuleId {
    pub const ALL: [Self; MODULE_COUNT] = [
        Self::Aets,
        Self::Atv2FramePlanner,
        Self::Aplot,
        Self::Aepa,
        Self::MenfuguExecutionPlanner,
    ];

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Aets),
            2 => Some(Self::Atv2FramePlanner),
            3 => Some(Self::Aplot),
            4 => Some(Self::Aepa),
            5 => Some(Self::MenfuguExecutionPlanner),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P1ResourceEvidence {
    pub equivalence_certificate_digest: Digest,
    pub relation_binding_digest: Digest,
    pub checked_cases: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoticerModuleBinding {
    pub module_id: NoticerModuleId,
    pub deployment_profile: DeploymentProfile,
    pub service_alias: WireServiceAlias,
    pub epoch: Epoch,
    pub policy_hash: PolicyHash,
    pub source_digest: Digest,
    pub source_certificate_digest: Digest,
    pub generated_runtime_digest: Digest,
    pub qsm_capsule_digest: Digest,
    pub observer_registry_digest: Digest,
    pub p1_resource_evidence: Option<P1ResourceEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoticerQsmManifest {
    entries: Vec<NoticerModuleBinding>,
}

impl NoticerQsmManifest {
    pub fn new(mut entries: Vec<NoticerModuleBinding>) -> Result<Self, ManifestError> {
        entries.sort_by_key(|entry| entry.module_id);
        let manifest = Self { entries };
        manifest.validate()?;
        Ok(manifest)
    }

    #[must_use]
    pub fn entries(&self) -> &[NoticerModuleBinding] {
        &self.entries
    }

    #[must_use]
    pub fn binding(&self, module_id: NoticerModuleId) -> &NoticerModuleBinding {
        let index = module_id as usize - 1;
        &self.entries[index]
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.entries.len() != MODULE_COUNT {
            return Err(ManifestError::ModuleSet);
        }
        for (expected, entry) in NoticerModuleId::ALL.iter().zip(&self.entries) {
            if entry.module_id != *expected {
                return Err(ManifestError::ModuleSet);
            }
            validate_entry(entry)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.validate().is_ok());
        let mut bytes = Vec::with_capacity(NOTICER_QSM_MANIFEST_BYTES);
        bytes.extend_from_slice(&NOTICER_QSM_MANIFEST_MAGIC);
        bytes.extend_from_slice(&NOTICER_QSM_MANIFEST_VERSION.to_le_bytes());
        bytes.push(MODULE_COUNT as u8);
        bytes.push(0);
        for entry in &self.entries {
            encode_entry(entry, &mut bytes);
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestDecodeError> {
        if bytes.len() != NOTICER_QSM_MANIFEST_BYTES {
            return Err(ManifestDecodeError::Length {
                actual: bytes.len(),
                expected: NOTICER_QSM_MANIFEST_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<8>()? != NOTICER_QSM_MANIFEST_MAGIC {
            return Err(ManifestDecodeError::Magic);
        }
        let version = reader.u16()?;
        if version != NOTICER_QSM_MANIFEST_VERSION {
            return Err(ManifestDecodeError::Version(version));
        }
        if reader.u8()? != MODULE_COUNT as u8 {
            return Err(ManifestDecodeError::ModuleCount);
        }
        if reader.u8()? != 0 {
            return Err(ManifestDecodeError::Reserved);
        }
        let mut entries = Vec::with_capacity(MODULE_COUNT);
        for _ in 0..MODULE_COUNT {
            entries.push(decode_entry(&mut reader)?);
        }
        let manifest = Self::new(entries).map_err(ManifestDecodeError::Manifest)?;
        if manifest.encode() != bytes {
            return Err(ManifestDecodeError::NonCanonical);
        }
        Ok(manifest)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        artifact_digest(MANIFEST_DIGEST_DOMAIN, &self.encode())
    }
}

fn validate_entry(entry: &NoticerModuleBinding) -> Result<(), ManifestError> {
    if entry.service_alias.0 == [0; 8] || entry.epoch.0 == 0 || entry.policy_hash.0 == [0; 32] {
        return Err(ManifestError::PublicBinding(entry.module_id));
    }
    for digest in [
        entry.source_digest,
        entry.source_certificate_digest,
        entry.generated_runtime_digest,
        entry.qsm_capsule_digest,
        entry.observer_registry_digest,
    ] {
        if digest == Digest::zero() {
            return Err(ManifestError::ArtifactDigest(entry.module_id));
        }
    }
    match (entry.deployment_profile, entry.p1_resource_evidence) {
        (DeploymentProfile::P0PublicQuotientOnly, None) => Ok(()),
        (DeploymentProfile::P0PublicQuotientOnly, Some(_)) => {
            Err(ManifestError::UnexpectedP1Evidence(entry.module_id))
        }
        (DeploymentProfile::P1SealedAdmission, None) => {
            Err(ManifestError::MissingP1Evidence(entry.module_id))
        }
        (DeploymentProfile::P1SealedAdmission, Some(evidence)) => {
            if evidence.equivalence_certificate_digest == Digest::zero()
                || evidence.relation_binding_digest == Digest::zero()
                || evidence.checked_cases == 0
            {
                Err(ManifestError::InvalidP1Evidence(entry.module_id))
            } else {
                Ok(())
            }
        }
    }
}

fn encode_entry(entry: &NoticerModuleBinding, bytes: &mut Vec<u8>) {
    bytes.push(entry.module_id as u8);
    bytes.push(profile_code(entry.deployment_profile));
    bytes.extend_from_slice(&u16::from(entry.p1_resource_evidence.is_some()).to_le_bytes());
    bytes.extend_from_slice(&entry.service_alias.0);
    bytes.extend_from_slice(&entry.epoch.0.to_le_bytes());
    bytes.extend_from_slice(&entry.policy_hash.0);
    for digest in [
        entry.source_digest,
        entry.source_certificate_digest,
        entry.generated_runtime_digest,
        entry.qsm_capsule_digest,
        entry.observer_registry_digest,
    ] {
        bytes.extend_from_slice(digest.as_bytes());
    }
    match entry.p1_resource_evidence {
        Some(evidence) => {
            bytes.extend_from_slice(evidence.equivalence_certificate_digest.as_bytes());
            bytes.extend_from_slice(evidence.relation_binding_digest.as_bytes());
            bytes.extend_from_slice(&evidence.checked_cases.to_le_bytes());
        }
        None => bytes.extend_from_slice(&[0; 72]),
    }
}

fn decode_entry(reader: &mut Reader<'_>) -> Result<NoticerModuleBinding, ManifestDecodeError> {
    let module_code = reader.u8()?;
    let module_id =
        NoticerModuleId::from_code(module_code).ok_or(ManifestDecodeError::Module(module_code))?;
    let profile = reader.u8()?;
    let deployment_profile = match profile {
        0 => DeploymentProfile::P0PublicQuotientOnly,
        1 => DeploymentProfile::P1SealedAdmission,
        _ => return Err(ManifestDecodeError::Profile(profile)),
    };
    let flags = reader.u16()?;
    if flags & !1 != 0 {
        return Err(ManifestDecodeError::Flags(flags));
    }
    let service_alias = WireServiceAlias(reader.array()?);
    let epoch = Epoch(reader.u64()?);
    let policy_hash = PolicyHash(reader.array()?);
    let source_digest = Digest::new(reader.array()?);
    let source_certificate_digest = Digest::new(reader.array()?);
    let generated_runtime_digest = Digest::new(reader.array()?);
    let qsm_capsule_digest = Digest::new(reader.array()?);
    let observer_registry_digest = Digest::new(reader.array()?);
    let equivalence_certificate_digest = Digest::new(reader.array()?);
    let relation_binding_digest = Digest::new(reader.array()?);
    let checked_cases = reader.u64()?;
    let p1_resource_evidence = if flags == 1 {
        Some(P1ResourceEvidence {
            equivalence_certificate_digest,
            relation_binding_digest,
            checked_cases,
        })
    } else {
        if equivalence_certificate_digest != Digest::zero()
            || relation_binding_digest != Digest::zero()
            || checked_cases != 0
        {
            return Err(ManifestDecodeError::NonCanonical);
        }
        None
    };
    Ok(NoticerModuleBinding {
        module_id,
        deployment_profile,
        service_alias,
        epoch,
        policy_hash,
        source_digest,
        source_certificate_digest,
        generated_runtime_digest,
        qsm_capsule_digest,
        observer_registry_digest,
        p1_resource_evidence,
    })
}

const fn profile_code(profile: DeploymentProfile) -> u8 {
    match profile {
        DeploymentProfile::P0PublicQuotientOnly => 0,
        DeploymentProfile::P1SealedAdmission => 1,
    }
}

#[must_use]
pub fn existing_binding_type_names() -> [&'static str; 4] {
    [
        core::any::type_name::<WireServiceAlias>(),
        core::any::type_name::<Epoch>(),
        core::any::type_name::<PolicyHash>(),
        core::any::type_name::<DeploymentProfile>(),
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    ModuleSet,
    PublicBinding(NoticerModuleId),
    ArtifactDigest(NoticerModuleId),
    UnexpectedP1Evidence(NoticerModuleId),
    MissingP1Evidence(NoticerModuleId),
    InvalidP1Evidence(NoticerModuleId),
}

impl core::fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "Noticer QSM manifest error: {self:?}")
    }
}

impl std::error::Error for ManifestError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestDecodeError {
    Length { actual: usize, expected: usize },
    Magic,
    Version(u16),
    ModuleCount,
    Reserved,
    Module(u8),
    Profile(u8),
    Flags(u16),
    Truncated,
    NonCanonical,
    Manifest(ManifestError),
}

impl core::fmt::Display for ManifestDecodeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "Noticer QSM manifest decode error: {self:?}")
    }
}

impl std::error::Error for ManifestDecodeError {}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ManifestDecodeError> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or(ManifestDecodeError::Truncated)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ManifestDecodeError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManifestDecodeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ManifestDecodeError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, ManifestDecodeError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ManifestDecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ManifestDecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}
