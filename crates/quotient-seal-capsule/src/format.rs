use quotient_forge_caqt::{artifact_digest, Digest};
use quotient_seal_abi::AbiManifest;

use crate::manifest::{encode_abi_manifest, CompilerManifest, OBSERVER_REGISTRY_V1};

pub const QSM_MAGIC: [u8; 8] = *b"QSEALCAP";
pub const QSM_FORMAT_VERSION: u16 = 1;
pub const QSM_SECTION_COUNT: u16 = 9;
const HEADER_BYTES: usize = 24;
const SECTION_HEADER_BYTES: usize = 44;
const BOUNDS_MAGIC: [u8; 4] = *b"QSBL";
const BOUNDS_BYTES: usize = 120;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum QsmSectionTag {
    ResourceBounds = 1,
    SourceCertificate = 2,
    WasmModule = 3,
    AbiManifest = 4,
    ObserverRegistry = 5,
    RelationCertificate = 6,
    RobustCertificate = 7,
    ResourceCertificate = 8,
    CompilerManifest = 9,
}

impl QsmSectionTag {
    pub const ALL: [Self; 9] = [
        Self::ResourceBounds,
        Self::SourceCertificate,
        Self::WasmModule,
        Self::AbiManifest,
        Self::ObserverRegistry,
        Self::RelationCertificate,
        Self::RobustCertificate,
        Self::ResourceCertificate,
        Self::CompilerManifest,
    ];

    const fn hash_domain(self) -> &'static [u8] {
        match self {
            Self::ResourceBounds => b"noticer-core/qseal/section/resource-bounds/v1",
            Self::SourceCertificate => b"noticer-core/qseal/section/source-certificate/v1",
            Self::WasmModule => b"noticer-core/qseal/section/wasm-module/v1",
            Self::AbiManifest => b"noticer-core/qseal/section/abi-manifest/v1",
            Self::ObserverRegistry => b"noticer-core/qseal/section/observer-registry/v1",
            Self::RelationCertificate => b"noticer-core/qseal/section/relation-certificate/v1",
            Self::RobustCertificate => b"noticer-core/qseal/section/robust-certificate/v1",
            Self::ResourceCertificate => b"noticer-core/qseal/section/resource-certificate/v1",
            Self::CompilerManifest => b"noticer-core/qseal/section/compiler-manifest/v1",
        }
    }
}

impl TryFrom<u16> for QsmSectionTag {
    type Error = QsmDecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ResourceBounds),
            2 => Ok(Self::SourceCertificate),
            3 => Ok(Self::WasmModule),
            4 => Ok(Self::AbiManifest),
            5 => Ok(Self::ObserverRegistry),
            6 => Ok(Self::RelationCertificate),
            7 => Ok(Self::RobustCertificate),
            8 => Ok(Self::ResourceCertificate),
            9 => Ok(Self::CompilerManifest),
            actual => Err(QsmDecodeError::UnknownSection { actual }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QsmResourceBounds {
    pub max_wasm_bytes: u64,
    pub max_source_certificate_bytes: u64,
    pub max_relation_certificate_bytes: u64,
    pub max_robust_certificate_bytes: u64,
    pub max_resource_certificate_bytes: u64,
    pub max_parser_sections: u64,
    pub max_relation_cases: u64,
    pub max_context_product_states: u64,
    pub max_context_prefix: u64,
    pub max_resource_events: u64,
    pub max_pad_operations: u64,
    pub max_added_instructions: u64,
    pub max_added_fuel: u64,
    pub max_scratch_bytes: u64,
}

impl QsmResourceBounds {
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BOUNDS_BYTES);
        bytes.extend_from_slice(&BOUNDS_MAGIC);
        bytes.extend_from_slice(&QSM_FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        for value in self.values() {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QsmBoundsError> {
        if bytes.len() != BOUNDS_BYTES {
            return Err(QsmBoundsError::Length {
                actual: bytes.len(),
                expected: BOUNDS_BYTES,
            });
        }
        if bytes[..4] != BOUNDS_MAGIC {
            return Err(QsmBoundsError::BadMagic);
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != QSM_FORMAT_VERSION {
            return Err(QsmBoundsError::UnsupportedVersion { actual: version });
        }
        if bytes[6..8] != [0, 0] {
            return Err(QsmBoundsError::Reserved);
        }
        let mut values = [0_u64; 14];
        for (index, value) in values.iter_mut().enumerate() {
            let start = 8 + index * 8;
            let mut encoded = [0_u8; 8];
            encoded.copy_from_slice(&bytes[start..start + 8]);
            *value = u64::from_le_bytes(encoded);
        }
        Ok(Self {
            max_wasm_bytes: values[0],
            max_source_certificate_bytes: values[1],
            max_relation_certificate_bytes: values[2],
            max_robust_certificate_bytes: values[3],
            max_resource_certificate_bytes: values[4],
            max_parser_sections: values[5],
            max_relation_cases: values[6],
            max_context_product_states: values[7],
            max_context_prefix: values[8],
            max_resource_events: values[9],
            max_pad_operations: values[10],
            max_added_instructions: values[11],
            max_added_fuel: values[12],
            max_scratch_bytes: values[13],
        })
    }

    pub fn validate(self, hard: QsmHardBounds) -> Result<(), QsmBoundsError> {
        for (index, (actual, limit)) in self.values().into_iter().zip(hard.0.values()).enumerate() {
            if actual == 0 || actual > limit {
                return Err(QsmBoundsError::OutsideHardLimit {
                    index,
                    actual,
                    limit,
                });
            }
        }
        Ok(())
    }

    const fn values(self) -> [u64; 14] {
        [
            self.max_wasm_bytes,
            self.max_source_certificate_bytes,
            self.max_relation_certificate_bytes,
            self.max_robust_certificate_bytes,
            self.max_resource_certificate_bytes,
            self.max_parser_sections,
            self.max_relation_cases,
            self.max_context_product_states,
            self.max_context_prefix,
            self.max_resource_events,
            self.max_pad_operations,
            self.max_added_instructions,
            self.max_added_fuel,
            self.max_scratch_bytes,
        ]
    }
}

impl Default for QsmResourceBounds {
    fn default() -> Self {
        QsmHardBounds::default().0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QsmHardBounds(pub QsmResourceBounds);

impl Default for QsmHardBounds {
    fn default() -> Self {
        Self(QsmResourceBounds {
            max_wasm_bytes: 1_048_576,
            max_source_certificate_bytes: 16 * 1024 * 1024,
            max_relation_certificate_bytes: 8 * 1024 * 1024,
            max_robust_certificate_bytes: 8 * 1024 * 1024,
            max_resource_certificate_bytes: 8 * 1024 * 1024,
            max_parser_sections: 32,
            max_relation_cases: 4_000_000,
            max_context_product_states: 65_536,
            max_context_prefix: 256,
            max_resource_events: 1_000_000,
            max_pad_operations: 65_536,
            max_added_instructions: 1_000_000,
            max_added_fuel: 1_000_000,
            max_scratch_bytes: 1_048_576,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QsmContainerLimits {
    pub max_capsule_bytes: usize,
    pub max_compiler_manifest_bytes: usize,
    pub hard_bounds: QsmHardBounds,
}

impl Default for QsmContainerLimits {
    fn default() -> Self {
        Self {
            max_capsule_bytes: 48 * 1024 * 1024,
            max_compiler_manifest_bytes: 64 * 1024,
            hard_bounds: QsmHardBounds::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsmBuildInput {
    pub resource_bounds: QsmResourceBounds,
    pub source_certificate: Vec<u8>,
    pub wasm_module: Vec<u8>,
    pub abi_manifest: AbiManifest,
    pub relation_certificate: Vec<u8>,
    pub robust_certificate: Vec<u8>,
    pub resource_certificate: Vec<u8>,
    pub compiler_manifest: CompilerManifest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsmSection {
    pub tag: QsmSectionTag,
    pub digest: Digest,
    payload: Vec<u8>,
}

impl QsmSection {
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QsmCapsule {
    sections: Vec<QsmSection>,
    digest: Digest,
}

impl QsmCapsule {
    pub fn decode(bytes: &[u8], limits: QsmContainerLimits) -> Result<Self, QsmDecodeError> {
        if bytes.len() > limits.max_capsule_bytes {
            return Err(QsmDecodeError::CapsuleSize {
                actual: bytes.len(),
                limit: limits.max_capsule_bytes,
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<8>()? != QSM_MAGIC {
            return Err(QsmDecodeError::BadMagic);
        }
        let version = reader.u16()?;
        if version != QSM_FORMAT_VERSION {
            return Err(QsmDecodeError::UnsupportedVersion { actual: version });
        }
        let section_count = reader.u16()?;
        if section_count != QSM_SECTION_COUNT {
            return Err(QsmDecodeError::SectionCount {
                actual: section_count,
            });
        }
        if reader.u32()? != 0 {
            return Err(QsmDecodeError::Reserved);
        }
        let declared_length =
            usize::try_from(reader.u64()?).map_err(|_| QsmDecodeError::IntegerOverflow)?;
        if declared_length != bytes.len() {
            return Err(if declared_length < bytes.len() {
                QsmDecodeError::TrailingBytes {
                    remaining: bytes.len() - declared_length,
                }
            } else {
                QsmDecodeError::DeclaredLength {
                    declared: declared_length,
                    actual: bytes.len(),
                }
            });
        }

        let mut sections = Vec::with_capacity(usize::from(QSM_SECTION_COUNT));
        for expected in QsmSectionTag::ALL {
            let tag = QsmSectionTag::try_from(reader.u16()?)?;
            if tag != expected {
                return Err(QsmDecodeError::SectionOrder {
                    expected,
                    actual: tag,
                });
            }
            if reader.u16()? != 0 {
                return Err(QsmDecodeError::SectionFlags { tag });
            }
            let length =
                usize::try_from(reader.u64()?).map_err(|_| QsmDecodeError::IntegerOverflow)?;
            let limit = section_limit(tag, limits);
            if length == 0 || length > limit {
                return Err(QsmDecodeError::SectionSize {
                    tag,
                    actual: length,
                    limit,
                });
            }
            let digest = Digest::new(reader.array::<32>()?);
            let payload = reader.bytes(length)?.to_vec();
            let actual_digest = artifact_digest(tag.hash_domain(), &payload);
            if digest != actual_digest {
                return Err(QsmDecodeError::SectionDigest { tag });
            }
            sections.push(QsmSection {
                tag,
                digest,
                payload,
            });
        }
        if !reader.is_empty() {
            return Err(QsmDecodeError::TrailingBytes {
                remaining: reader.remaining(),
            });
        }
        Ok(Self {
            sections,
            digest: artifact_digest(b"noticer-core/qseal/capsule/v1", bytes),
        })
    }

    #[must_use]
    pub fn section(&self, tag: QsmSectionTag) -> &QsmSection {
        &self.sections[usize::from(tag as u16 - 1)]
    }

    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }
}

pub fn build_qsm(
    input: QsmBuildInput,
    limits: QsmContainerLimits,
) -> Result<Vec<u8>, QsmBuildError> {
    input
        .resource_bounds
        .validate(limits.hard_bounds)
        .map_err(QsmBuildError::Bounds)?;
    let payloads = [
        input.resource_bounds.encode(),
        input.source_certificate,
        input.wasm_module,
        encode_abi_manifest(input.abi_manifest),
        OBSERVER_REGISTRY_V1.to_vec(),
        input.relation_certificate,
        input.robust_certificate,
        input.resource_certificate,
        input.compiler_manifest.encode(),
    ];
    let mut total = HEADER_BYTES;
    for (tag, payload) in QsmSectionTag::ALL.into_iter().zip(&payloads) {
        let limit = section_limit(tag, limits);
        if payload.is_empty() || payload.len() > limit {
            return Err(QsmBuildError::SectionSize {
                tag,
                actual: payload.len(),
                limit,
            });
        }
        total = total
            .checked_add(SECTION_HEADER_BYTES)
            .and_then(|value| value.checked_add(payload.len()))
            .ok_or(QsmBuildError::IntegerOverflow)?;
    }
    if total > limits.max_capsule_bytes {
        return Err(QsmBuildError::CapsuleSize {
            actual: total,
            limit: limits.max_capsule_bytes,
        });
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&QSM_MAGIC);
    bytes.extend_from_slice(&QSM_FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&QSM_SECTION_COUNT.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(
        &u64::try_from(total)
            .map_err(|_| QsmBuildError::IntegerOverflow)?
            .to_le_bytes(),
    );
    for (tag, payload) in QsmSectionTag::ALL.into_iter().zip(payloads) {
        bytes.extend_from_slice(&(tag as u16).to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(
            &u64::try_from(payload.len())
                .map_err(|_| QsmBuildError::IntegerOverflow)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(artifact_digest(tag.hash_domain(), &payload).as_bytes());
        bytes.extend_from_slice(&payload);
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QsmBuildError {
    Bounds(QsmBoundsError),
    SectionSize {
        tag: QsmSectionTag,
        actual: usize,
        limit: usize,
    },
    CapsuleSize {
        actual: usize,
        limit: usize,
    },
    IntegerOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QsmDecodeError {
    CapsuleSize {
        actual: usize,
        limit: usize,
    },
    BadMagic,
    UnsupportedVersion {
        actual: u16,
    },
    SectionCount {
        actual: u16,
    },
    Reserved,
    DeclaredLength {
        declared: usize,
        actual: usize,
    },
    UnknownSection {
        actual: u16,
    },
    SectionOrder {
        expected: QsmSectionTag,
        actual: QsmSectionTag,
    },
    SectionFlags {
        tag: QsmSectionTag,
    },
    SectionSize {
        tag: QsmSectionTag,
        actual: usize,
        limit: usize,
    },
    SectionDigest {
        tag: QsmSectionTag,
    },
    UnexpectedEof {
        offset: usize,
    },
    TrailingBytes {
        remaining: usize,
    },
    IntegerOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QsmBoundsError {
    Length {
        actual: usize,
        expected: usize,
    },
    BadMagic,
    UnsupportedVersion {
        actual: u16,
    },
    Reserved,
    OutsideHardLimit {
        index: usize,
        actual: u64,
        limit: u64,
    },
}

const fn section_limit(tag: QsmSectionTag, limits: QsmContainerLimits) -> usize {
    match tag {
        QsmSectionTag::ResourceBounds => BOUNDS_BYTES,
        QsmSectionTag::SourceCertificate => {
            saturating_usize(limits.hard_bounds.0.max_source_certificate_bytes)
        }
        QsmSectionTag::WasmModule => saturating_usize(limits.hard_bounds.0.max_wasm_bytes),
        QsmSectionTag::AbiManifest => 64,
        QsmSectionTag::ObserverRegistry => 32,
        QsmSectionTag::RelationCertificate => {
            saturating_usize(limits.hard_bounds.0.max_relation_certificate_bytes)
        }
        QsmSectionTag::RobustCertificate => {
            saturating_usize(limits.hard_bounds.0.max_robust_certificate_bytes)
        }
        QsmSectionTag::ResourceCertificate => {
            saturating_usize(limits.hard_bounds.0.max_resource_certificate_bytes)
        }
        QsmSectionTag::CompilerManifest => limits.max_compiler_manifest_bytes,
    }
}

const fn saturating_usize(value: u64) -> usize {
    if value > usize::MAX as u64 {
        usize::MAX
    } else {
        value as usize
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], QsmDecodeError> {
        let bytes = self.bytes(N)?;
        let mut result = [0_u8; N];
        result.copy_from_slice(bytes);
        Ok(result)
    }

    fn u16(&mut self) -> Result<u16, QsmDecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, QsmDecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, QsmDecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], QsmDecodeError> {
        let start = self.offset;
        let end = start
            .checked_add(length)
            .ok_or(QsmDecodeError::IntegerOverflow)?;
        let bytes = self
            .bytes
            .get(start..end)
            .ok_or(QsmDecodeError::UnexpectedEof { offset: start })?;
        self.offset = end;
        Ok(bytes)
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}
