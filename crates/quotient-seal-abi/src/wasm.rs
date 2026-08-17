use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use quotient_forge_caqt::Digest;

use crate::{quotient_seal_abi_v1_hash, DeploymentProfile, ABI_VERSION};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueType {
    I32,
    I64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuncType {
    pub params: Vec<ValueType>,
    pub results: Vec<ValueType>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalKind {
    Function,
    Table,
    Memory,
    Global,
    Tag,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
    pub kind: ExternalKind,
    pub signature: Option<FuncType>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmExport {
    pub name: String,
    pub kind: ExternalKind,
    pub signature: Option<FuncType>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmAbiSurface {
    pub imports: Vec<WasmImport>,
    pub exports: Vec<WasmExport>,
    pub defined_functions: usize,
}

impl WasmAbiSurface {
    pub fn parse(bytes: &[u8], limits: WasmSurfaceLimits) -> Result<Self, WasmSurfaceError> {
        Parser::new(bytes, limits)?.parse()
    }

    #[must_use]
    pub fn export(&self, name: &str) -> Option<&WasmExport> {
        self.exports.iter().find(|export| export.name == name)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WasmSurfaceLimits {
    pub max_bytes: usize,
    pub max_sections: usize,
    pub max_entries: usize,
    pub max_types: usize,
    pub max_name_bytes: usize,
    pub max_params: usize,
    pub max_results: usize,
}

impl Default for WasmSurfaceLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_sections: 64,
            max_entries: 1024,
            max_types: 256,
            max_name_bytes: 128,
            max_params: 16,
            max_results: 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WasmSurfaceError {
    SizeLimit { actual: usize, limit: usize },
    SectionLimit { actual: usize, limit: usize },
    EntryLimit { actual: usize, limit: usize },
    TypeLimit { actual: usize, limit: usize },
    NameLimit { actual: usize, limit: usize },
    ParameterLimit { actual: usize, limit: usize },
    ResultLimit { actual: usize, limit: usize },
    UnexpectedEof { offset: usize },
    BadMagic,
    BadVersion,
    LebOverflow { offset: usize },
    NonCanonicalLeb { offset: usize },
    InvalidUtf8 { offset: usize },
    DuplicateSection(u8),
    SectionOrder { previous: u8, current: u8 },
    UnsupportedSection(u8),
    InvalidFunctionType(u8),
    UnsupportedValueType(u8),
    UnsupportedExternalKind(u8),
    UnknownType(u32),
    UnknownFunction(u32),
    MissingSection(u8),
    FunctionCodeMismatch { functions: usize, bodies: usize },
    MalformedCodeBody,
    TrailingSectionBytes { section: u8, remaining: usize },
}

impl WasmSurfaceError {
    const fn is_resource_bound(&self) -> bool {
        matches!(
            self,
            Self::SizeLimit { .. }
                | Self::SectionLimit { .. }
                | Self::EntryLimit { .. }
                | Self::TypeLimit { .. }
                | Self::NameLimit { .. }
                | Self::ParameterLimit { .. }
                | Self::ResultLimit { .. }
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiManifest {
    pub version: u16,
    pub profile: DeploymentProfile,
    pub abi_hash: Digest,
}

impl AbiManifest {
    #[must_use]
    pub fn canonical(profile: DeploymentProfile) -> Self {
        Self {
            version: ABI_VERSION,
            profile,
            abi_hash: quotient_seal_abi_v1_hash(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbiViolation {
    AbiHashMismatch,
    MalformedModule(WasmSurfaceError),
    ImportCount { expected: usize, actual: usize },
    ExportCount { expected: usize, actual: usize },
    ImportMismatch { index: usize },
    ExportMismatch { index: usize },
    PrivateCapabilityExport(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbiIncompatible {
    ManifestVersion { expected: u16, actual: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbiResourceBound {
    pub error: WasmSurfaceError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbiReport {
    pub profile: DeploymentProfile,
    pub abi_hash: Digest,
    pub imports_checked: usize,
    pub exports_checked: usize,
    pub defined_functions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbiVerdict {
    Valid(AbiReport),
    Invalid(AbiViolation),
    Incompatible(AbiIncompatible),
    ResourceBound(AbiResourceBound),
}

pub fn validate_wasm_abi(
    wasm: &[u8],
    manifest: AbiManifest,
    limits: WasmSurfaceLimits,
) -> AbiVerdict {
    if manifest.version != ABI_VERSION {
        return AbiVerdict::Incompatible(AbiIncompatible::ManifestVersion {
            expected: ABI_VERSION,
            actual: manifest.version,
        });
    }
    if manifest.abi_hash != quotient_seal_abi_v1_hash() {
        return AbiVerdict::Invalid(AbiViolation::AbiHashMismatch);
    }
    let surface = match WasmAbiSurface::parse(wasm, limits) {
        Ok(surface) => surface,
        Err(error) if error.is_resource_bound() => {
            return AbiVerdict::ResourceBound(AbiResourceBound { error });
        }
        Err(error) => return AbiVerdict::Invalid(AbiViolation::MalformedModule(error)),
    };
    if let Some(export) = surface
        .exports
        .iter()
        .find(|export| export.name.contains("private") || export.name.contains("ingest"))
    {
        return AbiVerdict::Invalid(AbiViolation::PrivateCapabilityExport(export.name.clone()));
    }
    let expected_imports = canonical_imports();
    if surface.imports.len() != expected_imports.len() {
        return AbiVerdict::Invalid(AbiViolation::ImportCount {
            expected: expected_imports.len(),
            actual: surface.imports.len(),
        });
    }
    for (index, (actual, expected)) in surface.imports.iter().zip(&expected_imports).enumerate() {
        if actual != expected {
            return AbiVerdict::Invalid(AbiViolation::ImportMismatch { index });
        }
    }
    let expected_exports = canonical_exports();
    if surface.exports.len() != expected_exports.len() {
        return AbiVerdict::Invalid(AbiViolation::ExportCount {
            expected: expected_exports.len(),
            actual: surface.exports.len(),
        });
    }
    for (index, (actual, expected)) in surface.exports.iter().zip(&expected_exports).enumerate() {
        if actual != expected {
            return AbiVerdict::Invalid(AbiViolation::ExportMismatch { index });
        }
    }
    AbiVerdict::Valid(AbiReport {
        profile: manifest.profile,
        abi_hash: manifest.abi_hash,
        imports_checked: surface.imports.len(),
        exports_checked: surface.exports.len(),
        defined_functions: surface.defined_functions,
    })
}

fn canonical_imports() -> Vec<WasmImport> {
    vec![
        WasmImport {
            module: "qseal".to_string(),
            name: "emit_frame".to_string(),
            kind: ExternalKind::Function,
            signature: Some(function(
                &[ValueType::I32, ValueType::I64],
                &[ValueType::I32],
            )),
        },
        WasmImport {
            module: "qseal".to_string(),
            name: "emit_action".to_string(),
            kind: ExternalKind::Function,
            signature: Some(function(
                &[ValueType::I32, ValueType::I32],
                &[ValueType::I32],
            )),
        },
        WasmImport {
            module: "qseal".to_string(),
            name: "public_failure".to_string(),
            kind: ExternalKind::Function,
            signature: Some(function(&[ValueType::I32], &[ValueType::I32])),
        },
    ]
}

fn canonical_exports() -> Vec<WasmExport> {
    vec![
        WasmExport {
            name: "qseal.public.tick".to_string(),
            kind: ExternalKind::Function,
            signature: Some(function(
                &[ValueType::I32, ValueType::I64, ValueType::I32],
                &[ValueType::I32],
            )),
        },
        WasmExport {
            name: "qseal.public.reset".to_string(),
            kind: ExternalKind::Function,
            signature: Some(function(&[], &[ValueType::I32])),
        },
        WasmExport {
            name: "qseal.public.handoff".to_string(),
            kind: ExternalKind::Function,
            signature: Some(function(&[], &[ValueType::I64])),
        },
        WasmExport {
            name: "qseal.public.status".to_string(),
            kind: ExternalKind::Function,
            signature: Some(function(&[], &[ValueType::I32])),
        },
    ]
}

fn function(params: &[ValueType], results: &[ValueType]) -> FuncType {
    FuncType {
        params: params.to_vec(),
        results: results.to_vec(),
    }
}

struct Parser<'a> {
    reader: Reader<'a>,
    limits: WasmSurfaceLimits,
    section_count: usize,
    previous_section: u8,
    seen: [bool; 13],
    types: Vec<FuncType>,
    import_type_indices: Vec<u32>,
    imports: Vec<PendingImport>,
    functions: Vec<u32>,
    exports: Vec<PendingExport>,
    code_bodies: Option<usize>,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8], limits: WasmSurfaceLimits) -> Result<Self, WasmSurfaceError> {
        if bytes.len() > limits.max_bytes {
            return Err(WasmSurfaceError::SizeLimit {
                actual: bytes.len(),
                limit: limits.max_bytes,
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != b"\0asm" {
            return Err(WasmSurfaceError::BadMagic);
        }
        if reader.take(4)? != [1, 0, 0, 0] {
            return Err(WasmSurfaceError::BadVersion);
        }
        Ok(Self {
            reader,
            limits,
            section_count: 0,
            previous_section: 0,
            seen: [false; 13],
            types: Vec::new(),
            import_type_indices: Vec::new(),
            imports: Vec::new(),
            functions: Vec::new(),
            exports: Vec::new(),
            code_bodies: None,
        })
    }

    fn parse(mut self) -> Result<WasmAbiSurface, WasmSurfaceError> {
        while !self.reader.is_empty() {
            self.section_count = self.section_count.saturating_add(1);
            if self.section_count > self.limits.max_sections {
                return Err(WasmSurfaceError::SectionLimit {
                    actual: self.section_count,
                    limit: self.limits.max_sections,
                });
            }
            let id = self.reader.byte()?;
            if id > 12 {
                return Err(WasmSurfaceError::UnsupportedSection(id));
            }
            if id != 0 {
                if self.seen[usize::from(id)] {
                    return Err(WasmSurfaceError::DuplicateSection(id));
                }
                if id < self.previous_section {
                    return Err(WasmSurfaceError::SectionOrder {
                        previous: self.previous_section,
                        current: id,
                    });
                }
                self.seen[usize::from(id)] = true;
                self.previous_section = id;
            }
            let size = usize::try_from(self.reader.var_u32()?).unwrap_or(usize::MAX);
            let payload = self.reader.take(size)?;
            let mut section = Reader::new(payload);
            match id {
                0 => {}
                1 => self.parse_types(&mut section)?,
                2 => self.parse_imports(&mut section)?,
                3 => self.parse_functions(&mut section)?,
                7 => self.parse_exports(&mut section)?,
                10 => self.parse_code(&mut section)?,
                4 | 5 | 6 | 8 | 9 | 11 | 12 => {}
                _ => return Err(WasmSurfaceError::UnsupportedSection(id)),
            }
            if matches!(id, 1 | 2 | 3 | 7 | 10) && !section.is_empty() {
                return Err(WasmSurfaceError::TrailingSectionBytes {
                    section: id,
                    remaining: section.remaining(),
                });
            }
        }
        for required in [1_u8, 2, 3, 7, 10] {
            if !self.seen[usize::from(required)] {
                return Err(WasmSurfaceError::MissingSection(required));
            }
        }
        let code_bodies = self
            .code_bodies
            .ok_or(WasmSurfaceError::MissingSection(10))?;
        if self.functions.len() != code_bodies {
            return Err(WasmSurfaceError::FunctionCodeMismatch {
                functions: self.functions.len(),
                bodies: code_bodies,
            });
        }
        let mut resolved_imports = Vec::with_capacity(self.imports.len());
        for pending in &self.imports {
            let signature = pending
                .type_index
                .map(|index| self.resolve_type(index))
                .transpose()?;
            resolved_imports.push(WasmImport {
                module: pending.module.clone(),
                name: pending.name.clone(),
                kind: pending.kind,
                signature,
            });
        }
        let mut function_types = self.import_type_indices.clone();
        function_types.extend_from_slice(&self.functions);
        let mut resolved_exports = Vec::with_capacity(self.exports.len());
        for pending in &self.exports {
            let signature = if pending.kind == ExternalKind::Function {
                let type_index = *function_types
                    .get(usize::try_from(pending.index).unwrap_or(usize::MAX))
                    .ok_or(WasmSurfaceError::UnknownFunction(pending.index))?;
                Some(self.resolve_type(type_index)?)
            } else {
                None
            };
            resolved_exports.push(WasmExport {
                name: pending.name.clone(),
                kind: pending.kind,
                signature,
            });
        }
        Ok(WasmAbiSurface {
            imports: resolved_imports,
            exports: resolved_exports,
            defined_functions: self.functions.len(),
        })
    }

    fn parse_types(&mut self, reader: &mut Reader<'_>) -> Result<(), WasmSurfaceError> {
        let count = self.count(reader)?;
        if count > self.limits.max_types {
            return Err(WasmSurfaceError::TypeLimit {
                actual: count,
                limit: self.limits.max_types,
            });
        }
        for _ in 0..count {
            let prefix = reader.byte()?;
            if prefix != 0x60 {
                return Err(WasmSurfaceError::InvalidFunctionType(prefix));
            }
            let params = self.value_types(reader, self.limits.max_params, true)?;
            let results = self.value_types(reader, self.limits.max_results, false)?;
            self.types.push(FuncType { params, results });
        }
        Ok(())
    }

    fn parse_imports(&mut self, reader: &mut Reader<'_>) -> Result<(), WasmSurfaceError> {
        let count = self.count(reader)?;
        for _ in 0..count {
            let module = self.name(reader)?;
            let name = self.name(reader)?;
            let kind_byte = reader.byte()?;
            let kind = external_kind(kind_byte)?;
            let type_index = match kind {
                ExternalKind::Function => {
                    let index = reader.var_u32()?;
                    self.import_type_indices.push(index);
                    Some(index)
                }
                ExternalKind::Table => {
                    reader.byte()?;
                    read_limits(reader)?;
                    None
                }
                ExternalKind::Memory => {
                    read_limits(reader)?;
                    None
                }
                ExternalKind::Global => {
                    value_type(reader.byte()?)?;
                    reader.byte()?;
                    None
                }
                ExternalKind::Tag => {
                    reader.byte()?;
                    reader.var_u32()?;
                    None
                }
            };
            self.imports.push(PendingImport {
                module,
                name,
                kind,
                type_index,
            });
        }
        Ok(())
    }

    fn parse_functions(&mut self, reader: &mut Reader<'_>) -> Result<(), WasmSurfaceError> {
        let count = self.count(reader)?;
        for _ in 0..count {
            self.functions.push(reader.var_u32()?);
        }
        Ok(())
    }

    fn parse_exports(&mut self, reader: &mut Reader<'_>) -> Result<(), WasmSurfaceError> {
        let count = self.count(reader)?;
        for _ in 0..count {
            self.exports.push(PendingExport {
                name: self.name(reader)?,
                kind: external_kind(reader.byte()?)?,
                index: reader.var_u32()?,
            });
        }
        Ok(())
    }

    fn parse_code(&mut self, reader: &mut Reader<'_>) -> Result<(), WasmSurfaceError> {
        let count = self.count(reader)?;
        for _ in 0..count {
            let size = usize::try_from(reader.var_u32()?).unwrap_or(usize::MAX);
            let body = reader.take(size)?;
            if body.last().copied() != Some(0x0b) {
                return Err(WasmSurfaceError::MalformedCodeBody);
            }
        }
        self.code_bodies = Some(count);
        Ok(())
    }

    fn value_types(
        &self,
        reader: &mut Reader<'_>,
        limit: usize,
        parameters: bool,
    ) -> Result<Vec<ValueType>, WasmSurfaceError> {
        let count = usize::try_from(reader.var_u32()?).unwrap_or(usize::MAX);
        if count > limit {
            return Err(if parameters {
                WasmSurfaceError::ParameterLimit {
                    actual: count,
                    limit,
                }
            } else {
                WasmSurfaceError::ResultLimit {
                    actual: count,
                    limit,
                }
            });
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(value_type(reader.byte()?)?);
        }
        Ok(values)
    }

    fn count(&self, reader: &mut Reader<'_>) -> Result<usize, WasmSurfaceError> {
        let count = usize::try_from(reader.var_u32()?).unwrap_or(usize::MAX);
        if count > self.limits.max_entries {
            Err(WasmSurfaceError::EntryLimit {
                actual: count,
                limit: self.limits.max_entries,
            })
        } else {
            Ok(count)
        }
    }

    fn name(&self, reader: &mut Reader<'_>) -> Result<String, WasmSurfaceError> {
        let offset = reader.position();
        let length = usize::try_from(reader.var_u32()?).unwrap_or(usize::MAX);
        if length > self.limits.max_name_bytes {
            return Err(WasmSurfaceError::NameLimit {
                actual: length,
                limit: self.limits.max_name_bytes,
            });
        }
        let bytes = reader.take(length)?;
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| WasmSurfaceError::InvalidUtf8 { offset })
    }

    fn resolve_type(&self, index: u32) -> Result<FuncType, WasmSurfaceError> {
        self.types
            .get(usize::try_from(index).unwrap_or(usize::MAX))
            .cloned()
            .ok_or(WasmSurfaceError::UnknownType(index))
    }
}

#[derive(Clone, Debug)]
struct PendingImport {
    module: String,
    name: String,
    kind: ExternalKind,
    type_index: Option<u32>,
}

#[derive(Clone, Debug)]
struct PendingExport {
    name: String,
    kind: ExternalKind,
    index: u32,
}

fn external_kind(value: u8) -> Result<ExternalKind, WasmSurfaceError> {
    match value {
        0 => Ok(ExternalKind::Function),
        1 => Ok(ExternalKind::Table),
        2 => Ok(ExternalKind::Memory),
        3 => Ok(ExternalKind::Global),
        4 => Ok(ExternalKind::Tag),
        _ => Err(WasmSurfaceError::UnsupportedExternalKind(value)),
    }
}

fn value_type(value: u8) -> Result<ValueType, WasmSurfaceError> {
    match value {
        0x7f => Ok(ValueType::I32),
        0x7e => Ok(ValueType::I64),
        _ => Err(WasmSurfaceError::UnsupportedValueType(value)),
    }
}

fn read_limits(reader: &mut Reader<'_>) -> Result<(), WasmSurfaceError> {
    match reader.byte()? {
        0 => {
            reader.var_u32()?;
            Ok(())
        }
        1 => {
            reader.var_u32()?;
            reader.var_u32()?;
            Ok(())
        }
        value => Err(WasmSurfaceError::UnsupportedExternalKind(value)),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn byte(&mut self) -> Result<u8, WasmSurfaceError> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or(WasmSurfaceError::UnexpectedEof {
                offset: self.position,
            })?;
        self.position += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WasmSurfaceError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(WasmSurfaceError::UnexpectedEof {
                offset: self.position,
            })?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(WasmSurfaceError::UnexpectedEof {
                offset: self.position,
            })?;
        self.position = end;
        Ok(value)
    }

    fn var_u32(&mut self) -> Result<u32, WasmSurfaceError> {
        let offset = self.position;
        let mut result = 0_u32;
        for index in 0..5 {
            let byte = self.byte()?;
            if index == 4 && byte & 0xf0 != 0 {
                return Err(WasmSurfaceError::LebOverflow { offset });
            }
            result |= u32::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                let consumed = index + 1;
                let canonical = if result < (1 << 7) {
                    1
                } else if result < (1 << 14) {
                    2
                } else if result < (1 << 21) {
                    3
                } else if result < (1 << 28) {
                    4
                } else {
                    5
                };
                if consumed != canonical {
                    return Err(WasmSurfaceError::NonCanonicalLeb { offset });
                }
                return Ok(result);
            }
        }
        Err(WasmSurfaceError::LebOverflow { offset })
    }
}
