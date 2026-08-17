use quotient_forge_caqt::Digest;
use quotient_seal_abi::{AbiManifest, DeploymentProfile};

const ABI_MAGIC: [u8; 4] = *b"QSAM";
const COMPILER_MAGIC: [u8; 4] = *b"QSCM";
const MANIFEST_VERSION: u16 = 1;
const MAX_ENTRIES: usize = 64;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 4_096;
const FORBIDDEN_KEYS: &[&str] = &[
    "acc",
    "baseline",
    "biosignal",
    "device_id",
    "key_material",
    "lease",
    "participant",
    "permit",
    "ppg",
    "private",
    "secret",
    "token_bytes",
];

pub const OBSERVER_REGISTRY_V1: &[u8] = b"QSOR\x01\x00\x07\x00\x00\x01\x02\x03\x04\x05\x06";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CompilerManifestEntry {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilerManifest {
    entries: Vec<CompilerManifestEntry>,
}

impl CompilerManifest {
    pub fn new(entries: Vec<CompilerManifestEntry>) -> Result<Self, CompilerManifestError> {
        if entries.is_empty() {
            return Err(CompilerManifestError::Empty);
        }
        if entries.len() > MAX_ENTRIES {
            return Err(CompilerManifestError::EntryLimit {
                actual: entries.len(),
                limit: MAX_ENTRIES,
            });
        }
        let mut previous: Option<&str> = None;
        for (index, entry) in entries.iter().enumerate() {
            if entry.key.is_empty()
                || entry.key.len() > MAX_KEY_BYTES
                || !entry.key.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
                })
            {
                return Err(CompilerManifestError::InvalidKey { index });
            }
            if entry.value.is_empty() || entry.value.len() > MAX_VALUE_BYTES {
                return Err(CompilerManifestError::InvalidValue { index });
            }
            if FORBIDDEN_KEYS.iter().any(|forbidden| {
                entry.key == *forbidden
                    || entry.key.starts_with(&format!("{forbidden}."))
                    || entry.key.ends_with(&format!(".{forbidden}"))
            }) {
                return Err(CompilerManifestError::ForbiddenKey { index });
            }
            if previous.is_some_and(|key| key >= entry.key.as_str()) {
                return Err(CompilerManifestError::EntryOrder { index });
            }
            previous = Some(&entry.key);
        }
        Ok(Self { entries })
    }

    #[must_use]
    pub fn entries(&self) -> &[CompilerManifestEntry] {
        &self.entries
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&COMPILER_MAGIC);
        bytes.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(self.entries.len())
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        for entry in &self.entries {
            bytes.extend_from_slice(
                &u16::try_from(entry.key.len())
                    .unwrap_or(u16::MAX)
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(entry.key.as_bytes());
            bytes.extend_from_slice(
                &u32::try_from(entry.value.len())
                    .unwrap_or(u32::MAX)
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(entry.value.as_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CompilerManifestError> {
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != COMPILER_MAGIC {
            return Err(CompilerManifestError::BadMagic);
        }
        let version = reader.u16()?;
        if version != MANIFEST_VERSION {
            return Err(CompilerManifestError::UnsupportedVersion { actual: version });
        }
        let count = usize::from(reader.u16()?);
        if count > MAX_ENTRIES {
            return Err(CompilerManifestError::EntryLimit {
                actual: count,
                limit: MAX_ENTRIES,
            });
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let key_len = usize::from(reader.u16()?);
            let key = reader.string(key_len)?;
            let value_len = usize::try_from(reader.u32()?)
                .map_err(|_| CompilerManifestError::IntegerOverflow)?;
            let value = reader.string(value_len)?;
            entries.push(CompilerManifestEntry { key, value });
        }
        if !reader.is_empty() {
            return Err(CompilerManifestError::TrailingBytes {
                remaining: reader.remaining(),
            });
        }
        Self::new(entries)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompilerManifestError {
    Empty,
    BadMagic,
    UnsupportedVersion { actual: u16 },
    UnexpectedEof { offset: usize },
    InvalidUtf8 { offset: usize },
    IntegerOverflow,
    EntryLimit { actual: usize, limit: usize },
    InvalidKey { index: usize },
    InvalidValue { index: usize },
    ForbiddenKey { index: usize },
    EntryOrder { index: usize },
    TrailingBytes { remaining: usize },
}

pub(crate) fn encode_abi_manifest(manifest: AbiManifest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(&ABI_MAGIC);
    bytes.extend_from_slice(&manifest.version.to_le_bytes());
    bytes.push(match manifest.profile {
        DeploymentProfile::P0PublicQuotientOnly => 0,
        DeploymentProfile::P1SealedAdmission => 1,
    });
    bytes.push(0);
    bytes.extend_from_slice(manifest.abi_hash.as_bytes());
    bytes
}

pub(crate) fn decode_abi_manifest(bytes: &[u8]) -> Result<AbiManifest, AbiManifestError> {
    if bytes.len() != 40 {
        return Err(AbiManifestError::Length {
            actual: bytes.len(),
        });
    }
    if bytes[..4] != ABI_MAGIC {
        return Err(AbiManifestError::BadMagic);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    let profile = match bytes[6] {
        0 => DeploymentProfile::P0PublicQuotientOnly,
        1 => DeploymentProfile::P1SealedAdmission,
        actual => return Err(AbiManifestError::Profile { actual }),
    };
    if bytes[7] != 0 {
        return Err(AbiManifestError::Reserved);
    }
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&bytes[8..40]);
    Ok(AbiManifest {
        version,
        profile,
        abi_hash: Digest::new(digest),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AbiManifestError {
    Length { actual: usize },
    BadMagic,
    Profile { actual: u8 },
    Reserved,
}

pub(crate) fn validate_observer_registry(bytes: &[u8]) -> bool {
    bytes == OBSERVER_REGISTRY_V1
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CompilerManifestError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(CompilerManifestError::IntegerOverflow)?;
        let source =
            self.bytes
                .get(self.offset..end)
                .ok_or(CompilerManifestError::UnexpectedEof {
                    offset: self.offset,
                })?;
        let mut result = [0_u8; N];
        result.copy_from_slice(source);
        self.offset = end;
        Ok(result)
    }

    fn u16(&mut self) -> Result<u16, CompilerManifestError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CompilerManifestError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn string(&mut self, length: usize) -> Result<String, CompilerManifestError> {
        let start = self.offset;
        let end = start
            .checked_add(length)
            .ok_or(CompilerManifestError::IntegerOverflow)?;
        let bytes = self
            .bytes
            .get(start..end)
            .ok_or(CompilerManifestError::UnexpectedEof { offset: start })?;
        let value = core::str::from_utf8(bytes)
            .map_err(|_| CompilerManifestError::InvalidUtf8 { offset: start })?
            .to_owned();
        self.offset = end;
        Ok(value)
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}
