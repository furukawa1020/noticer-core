//! Canonical public composition contract for the five-stage Noticer release stack.
//!
//! This module binds public artifacts only. It deliberately has no dependency on
//! acquisition, baseline, raw-feature, private-token, or replay-state crates.

use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::NOTICER_QSM_MANIFEST_BYTES;
use crate::{Digest, ManifestDecodeError, ManifestError, NoticerModuleId, NoticerQsmManifest};

pub const RELEASE_STACK_COMPOSITION_MAGIC: [u8; 8] = *b"NQSMCMP1";
pub const RELEASE_STACK_COMPOSITION_VERSION: u16 = 1;
pub const RELEASE_STACK_HARDWARE_STATUS: &str = "NOT_VERIFIED";
pub const RELEASE_STACK_STAGE_COUNT: usize = 5;
pub const RELEASE_STACK_HANDOFF_COUNT: usize = 4;
pub const RELEASE_STACK_COMPOSITION_BYTES: usize = NOTICER_QSM_MANIFEST_BYTES + 64;

pub const RELEASE_STACK_FORBIDDEN_FIELDS: [&str; 5] = [
    "raw_ppg",
    "private_baseline",
    "k1_raw_feature",
    "private_token_material",
    "replay_state",
];

pub const RELEASE_STACK_HANDOFFS: [(NoticerModuleId, NoticerModuleId); 4] = [
    (NoticerModuleId::Aets, NoticerModuleId::Atv2FramePlanner),
    (NoticerModuleId::Atv2FramePlanner, NoticerModuleId::Aplot),
    (NoticerModuleId::Aplot, NoticerModuleId::Aepa),
    (
        NoticerModuleId::Aepa,
        NoticerModuleId::MenfuguExecutionPlanner,
    ),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseStackCompositionContract {
    manifest: NoticerQsmManifest,
    canonical_bytes: Box<[u8]>,
    digest: Digest,
    privacy_registry_digest: Digest,
}

impl ReleaseStackCompositionContract {
    pub fn new(manifest: NoticerQsmManifest) -> Result<Self, ReleaseStackCompositionError> {
        validate_manifest(&manifest)?;
        let privacy_registry_sha256 = privacy_registry_sha256();
        let canonical_bytes = encode_contract(&manifest, privacy_registry_sha256);
        let digest = Digest::new(sha256(&canonical_bytes));
        Ok(Self {
            manifest,
            canonical_bytes: canonical_bytes.into_boxed_slice(),
            digest,
            privacy_registry_digest: Digest::new(privacy_registry_sha256),
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ReleaseStackCompositionError> {
        if bytes.len() != RELEASE_STACK_COMPOSITION_BYTES {
            return Err(ReleaseStackCompositionError::Length {
                actual: bytes.len(),
                expected: RELEASE_STACK_COMPOSITION_BYTES,
            });
        }
        if bytes[..8] != RELEASE_STACK_COMPOSITION_MAGIC {
            return Err(ReleaseStackCompositionError::Magic);
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed slice"));
        if version != RELEASE_STACK_COMPOSITION_VERSION {
            return Err(ReleaseStackCompositionError::Version(version));
        }
        if bytes[10..12] != [0, 0] {
            return Err(ReleaseStackCompositionError::Reserved);
        }
        let manifest_length =
            u32::from_le_bytes(bytes[12..16].try_into().expect("fixed slice")) as usize;
        if manifest_length != NOTICER_QSM_MANIFEST_BYTES {
            return Err(ReleaseStackCompositionError::ManifestLength(
                manifest_length,
            ));
        }

        let manifest_end = 16 + manifest_length;
        let manifest = NoticerQsmManifest::decode(&bytes[16..manifest_end])
            .map_err(ReleaseStackCompositionError::ManifestDecode)?;
        let mut cursor = manifest_end;

        if bytes[cursor] as usize != RELEASE_STACK_STAGE_COUNT {
            return Err(ReleaseStackCompositionError::StageCount(bytes[cursor]));
        }
        cursor += 1;
        for expected in NoticerModuleId::ALL {
            if bytes[cursor] != expected as u8 {
                return Err(ReleaseStackCompositionError::StageOrder);
            }
            cursor += 1;
        }

        if bytes[cursor] as usize != RELEASE_STACK_HANDOFF_COUNT {
            return Err(ReleaseStackCompositionError::HandoffCount(bytes[cursor]));
        }
        cursor += 1;
        for (from, to) in RELEASE_STACK_HANDOFFS {
            if bytes[cursor] != from as u8 || bytes[cursor + 1] != to as u8 {
                return Err(ReleaseStackCompositionError::Handoff);
            }
            cursor += 2;
        }

        let expected_privacy = privacy_registry_sha256();
        if bytes[cursor..cursor + 32] != expected_privacy {
            return Err(ReleaseStackCompositionError::PrivacyBoundary);
        }
        cursor += 32;
        if bytes[cursor] != 0 {
            return Err(ReleaseStackCompositionError::HardwareStatus(bytes[cursor]));
        }

        let contract = Self::new(manifest)?;
        if contract.canonical_bytes() != bytes {
            return Err(ReleaseStackCompositionError::NonCanonical);
        }
        Ok(contract)
    }

    pub fn manifest(&self) -> &NoticerQsmManifest {
        &self.manifest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub const fn privacy_registry_digest(&self) -> Digest {
        self.privacy_registry_digest
    }

    pub const fn hardware_status(&self) -> &'static str {
        RELEASE_STACK_HARDWARE_STATUS
    }

    pub const fn stages(&self) -> [NoticerModuleId; RELEASE_STACK_STAGE_COUNT] {
        NoticerModuleId::ALL
    }

    pub const fn handoffs(
        &self,
    ) -> [(NoticerModuleId, NoticerModuleId); RELEASE_STACK_HANDOFF_COUNT] {
        RELEASE_STACK_HANDOFFS
    }
}

fn validate_manifest(manifest: &NoticerQsmManifest) -> Result<(), ReleaseStackCompositionError> {
    manifest
        .validate()
        .map_err(ReleaseStackCompositionError::Manifest)?;
    if manifest.entries().len() != RELEASE_STACK_STAGE_COUNT
        || manifest
            .entries()
            .iter()
            .zip(NoticerModuleId::ALL)
            .any(|(binding, expected)| binding.module_id != expected)
    {
        return Err(ReleaseStackCompositionError::StageOrder);
    }
    Ok(())
}

fn encode_contract(manifest: &NoticerQsmManifest, privacy_digest: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RELEASE_STACK_COMPOSITION_BYTES);
    bytes.extend_from_slice(&RELEASE_STACK_COMPOSITION_MAGIC);
    bytes.extend_from_slice(&RELEASE_STACK_COMPOSITION_VERSION.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&(NOTICER_QSM_MANIFEST_BYTES as u32).to_le_bytes());
    bytes.extend_from_slice(&manifest.encode());
    bytes.push(RELEASE_STACK_STAGE_COUNT as u8);
    bytes.extend(NoticerModuleId::ALL.map(|module| module as u8));
    bytes.push(RELEASE_STACK_HANDOFF_COUNT as u8);
    for (from, to) in RELEASE_STACK_HANDOFFS {
        bytes.push(from as u8);
        bytes.push(to as u8);
    }
    bytes.extend_from_slice(&privacy_digest);
    bytes.push(0);
    debug_assert_eq!(bytes.len(), RELEASE_STACK_COMPOSITION_BYTES);
    bytes
}

fn privacy_registry_sha256() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"noticer-release-stack-private-field-registry/v1\0");
    for name in RELEASE_STACK_FORBIDDEN_FIELDS {
        hasher.update((name.len() as u16).to_le_bytes());
        hasher.update(name.as_bytes());
    }
    hasher.finalize().into()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReleaseStackCompositionError {
    #[error("release stack composition length is {actual}, expected {expected}")]
    Length { actual: usize, expected: usize },
    #[error("release stack composition magic is invalid")]
    Magic,
    #[error("unsupported release stack composition version {0}")]
    Version(u16),
    #[error("release stack composition reserved bits are nonzero")]
    Reserved,
    #[error("release stack manifest length is non-canonical: {0}")]
    ManifestLength(usize),
    #[error("release stack manifest is invalid: {0}")]
    Manifest(ManifestError),
    #[error("release stack manifest decoding failed: {0}")]
    ManifestDecode(ManifestDecodeError),
    #[error("release stack stage count is invalid: {0}")]
    StageCount(u8),
    #[error("release stack stages are missing, duplicated, or reordered")]
    StageOrder,
    #[error("release stack handoff count is invalid: {0}")]
    HandoffCount(u8),
    #[error("release stack handoff graph is non-canonical")]
    Handoff,
    #[error("release stack private-field registry binding is invalid")]
    PrivacyBoundary,
    #[error("release stack hardware status code is unsupported: {0}")]
    HardwareStatus(u8),
    #[error("release stack composition bytes are non-canonical")]
    NonCanonical,
}
