#![forbid(unsafe_code)]

//! Generates a heap-free `no_std` runtime from a valid CAQT certificate.

use std::fmt::{self, Write as _};
use std::fs;
use std::path::{Path, PathBuf};

use quotient_forge_caqt::{
    verify, Certificate, CertificateLimits, CertificateVerdict, Digest, ExpectedContract,
    OutputRecord,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodegenConfig {
    pub package_name: String,
    pub quotient_inputs: u16,
    pub public_inputs: u16,
    pub fault_inputs: u16,
    pub max_payload_bytes: usize,
    pub max_actions: usize,
}

impl Default for CodegenConfig {
    fn default() -> Self {
        Self {
            package_name: "quotient-forge-generated".to_owned(),
            quotient_inputs: 1,
            public_inputs: 1,
            fault_inputs: 1,
            max_payload_bytes: 4_096,
            max_actions: 1_024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedPackage {
    pub root: PathBuf,
    pub files: Vec<PathBuf>,
    pub certificate_digest: Digest,
    pub transition_vectors: usize,
}

#[derive(Debug)]
pub enum CodegenError {
    InvalidPackageName,
    EmptyInputAxis(&'static str),
    InputProductOverflow,
    InputCountMismatch { axes: u32, certificate: u32 },
    CertificateRejected(String),
    CertificateParse(String),
    StateCountOverflow(u32),
    TransitionValueOverflow,
    PayloadLimit { actual: usize, limit: usize },
    ActionLimit { actual: usize, limit: usize },
    TargetExists(PathBuf),
    Io(std::io::Error),
}

impl fmt::Display for CodegenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "code generation error: {self:?}")
    }
}

impl std::error::Error for CodegenError {}

impl From<std::io::Error> for CodegenError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn generate_package(
    certificate_bytes: &[u8],
    expected: ExpectedContract,
    certificate_limits: CertificateLimits,
    config: &CodegenConfig,
    target: &Path,
) -> Result<GeneratedPackage, CodegenError> {
    validate_config(config)?;
    if target.exists() {
        return Err(CodegenError::TargetExists(target.to_path_buf()));
    }
    let report = match verify(certificate_bytes, expected, certificate_limits) {
        CertificateVerdict::Valid(report) => report,
        verdict => return Err(CodegenError::CertificateRejected(format!("{verdict:?}"))),
    };
    let certificate = Certificate::decode(certificate_bytes, certificate_limits)
        .map_err(|error| CodegenError::CertificateParse(error.to_string()))?;
    validate_certificate(&certificate, config)?;

    let cargo_toml = generate_cargo_toml(config);
    let runtime = generate_runtime(&certificate, config, report.certificate_digest)?;
    let vectors = generate_vectors(&certificate, config)?;
    let manifest = generate_manifest(&certificate, config, report.certificate_digest);
    let vector_table = generate_vector_table(&certificate, config)?;

    let source = target.join("src");
    fs::create_dir_all(&source)?;
    let files = vec![
        target.join("Cargo.toml"),
        source.join("lib.rs"),
        source.join("vectors.rs"),
        target.join("certificate.caqt"),
        target.join("codegen-manifest.toml"),
        target.join("test-vectors.tsv"),
    ];
    fs::write(&files[0], cargo_toml)?;
    fs::write(&files[1], runtime)?;
    fs::write(&files[2], vectors)?;
    fs::write(&files[3], certificate_bytes)?;
    fs::write(&files[4], manifest)?;
    fs::write(&files[5], vector_table)?;

    Ok(GeneratedPackage {
        root: target.to_path_buf(),
        files,
        certificate_digest: report.certificate_digest,
        transition_vectors: certificate.transitions.len(),
    })
}

fn validate_config(config: &CodegenConfig) -> Result<(), CodegenError> {
    let valid_name = !config.package_name.is_empty()
        && config.package_name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
        && !config.package_name.starts_with(['-', '_'])
        && !config.package_name.ends_with(['-', '_']);
    if !valid_name {
        return Err(CodegenError::InvalidPackageName);
    }
    if config.quotient_inputs == 0 {
        return Err(CodegenError::EmptyInputAxis("quotient"));
    }
    if config.public_inputs == 0 {
        return Err(CodegenError::EmptyInputAxis("public"));
    }
    if config.fault_inputs == 0 {
        return Err(CodegenError::EmptyInputAxis("fault"));
    }
    Ok(())
}

fn validate_certificate(
    certificate: &Certificate,
    config: &CodegenConfig,
) -> Result<(), CodegenError> {
    let axes = u32::from(config.quotient_inputs)
        .checked_mul(u32::from(config.public_inputs))
        .and_then(|value| value.checked_mul(u32::from(config.fault_inputs)))
        .ok_or(CodegenError::InputProductOverflow)?;
    if axes != certificate.input_count {
        return Err(CodegenError::InputCountMismatch {
            axes,
            certificate: certificate.input_count,
        });
    }
    if certificate.state_count > u32::from(u16::MAX) {
        return Err(CodegenError::StateCountOverflow(certificate.state_count));
    }
    for transition in &certificate.transitions {
        if transition.to > u32::from(u16::MAX) || transition.output > u32::from(u16::MAX) {
            return Err(CodegenError::TransitionValueOverflow);
        }
    }
    for output in &certificate.outputs {
        if output.payload.len() > config.max_payload_bytes {
            return Err(CodegenError::PayloadLimit {
                actual: output.payload.len(),
                limit: config.max_payload_bytes,
            });
        }
        if output.actions.len() > config.max_actions {
            return Err(CodegenError::ActionLimit {
                actual: output.actions.len(),
                limit: config.max_actions,
            });
        }
    }
    Ok(())
}

fn generate_cargo_toml(config: &CodegenConfig) -> String {
    format!(
        "[package]\nname = \"{}\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n[lib]\npath = \"src/lib.rs\"\n",
        config.package_name
    )
}

fn generate_runtime(
    certificate: &Certificate,
    config: &CodegenConfig,
    certificate_digest: Digest,
) -> Result<String, CodegenError> {
    let max_payload = certificate
        .outputs
        .iter()
        .map(|output| output.payload.len())
        .max()
        .unwrap_or(0);
    let max_actions = certificate
        .outputs
        .iter()
        .map(|output| output.actions.len())
        .max()
        .unwrap_or(0);
    let encoded_bytes = 1_usize
        .checked_add(2)
        .and_then(|value| value.checked_add(max_payload))
        .and_then(|value| value.checked_add(2))
        .and_then(|value| value.checked_add(max_actions.saturating_mul(4)))
        .ok_or(CodegenError::PayloadLimit {
            actual: usize::MAX,
            limit: config.max_payload_bytes,
        })?;
    let crate_name = config.package_name.replace('-', "_");
    let mut source = String::new();
    writeln!(source, "#![no_std]").unwrap();
    writeln!(source, "#![forbid(unsafe_code)]").unwrap();
    writeln!(source, "//! Generated from a VALID CAQT certificate.").unwrap();
    writeln!(source, "//! ```compile_fail").unwrap();
    writeln!(source, "//! use {crate_name}::PrivateInput;").unwrap();
    writeln!(source, "//! ```").unwrap();
    writeln!(source, "//! ```compile_fail").unwrap();
    writeln!(
        source,
        "//! {crate_name}::TRANSITIONS[0] = {crate_name}::TRANSITIONS[0];"
    )
    .unwrap();
    writeln!(source, "//! ```").unwrap();
    writeln!(source, "//! ```compile_fail").unwrap();
    writeln!(source, "//! struct Rogue;").unwrap();
    writeln!(
        source,
        "//! impl {crate_name}::CertifiedAdapter for Rogue {{}}"
    )
    .unwrap();
    writeln!(source, "//! ```").unwrap();
    writeln!(source).unwrap();
    writeln!(
        source,
        "pub const CERTIFICATE_DIGEST: [u8; 32] = {};",
        byte_array(certificate_digest.as_bytes(), 32)
    )
    .unwrap();
    writeln!(
        source,
        "pub const QUOTIENT_INPUTS: usize = {};",
        config.quotient_inputs
    )
    .unwrap();
    writeln!(
        source,
        "pub const PUBLIC_INPUTS: usize = {};",
        config.public_inputs
    )
    .unwrap();
    writeln!(
        source,
        "pub const FAULT_INPUTS: usize = {};",
        config.fault_inputs
    )
    .unwrap();
    writeln!(
        source,
        "pub const INPUT_COUNT: usize = {};",
        certificate.input_count
    )
    .unwrap();
    writeln!(
        source,
        "pub const STATE_COUNT: usize = {};",
        certificate.state_count
    )
    .unwrap();
    writeln!(source, "pub const MAX_PAYLOAD: usize = {max_payload};").unwrap();
    writeln!(source, "pub const MAX_ACTIONS: usize = {max_actions};").unwrap();
    writeln!(
        source,
        "pub const ENCODED_OUTPUT_BYTES: usize = {encoded_bytes};"
    )
    .unwrap();
    writeln!(source).unwrap();
    writeln!(
        source,
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct QuotientInput(pub u16);"
    )
    .unwrap();
    writeln!(
        source,
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct PublicInput(pub u16);"
    )
    .unwrap();
    writeln!(
        source,
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct FaultInput(pub u16);"
    )
    .unwrap();
    writeln!(source, "#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub enum StepError {{ InputOutOfRange, ArithmeticOverflow, InvalidState, InvalidOutput }}").unwrap();
    writeln!(source).unwrap();
    writeln!(source, "#[derive(Clone, Copy, Debug, Eq, PartialEq)]").unwrap();
    writeln!(source, "pub struct EncodedOutput {{ pub emitted: bool, pub payload_len: u16, pub payload: [u8; MAX_PAYLOAD], pub action_len: u16, pub actions: [u32; MAX_ACTIONS] }}").unwrap();
    writeln!(source, "impl EncodedOutput {{").unwrap();
    writeln!(
        source,
        "    #[must_use] pub fn encode(&self) -> [u8; ENCODED_OUTPUT_BYTES] {{"
    )
    .unwrap();
    writeln!(
        source,
        "        let mut bytes = [0_u8; ENCODED_OUTPUT_BYTES];"
    )
    .unwrap();
    writeln!(source, "        bytes[0] = u8::from(self.emitted);").unwrap();
    writeln!(source, "        let payload_len = self.payload_len.to_le_bytes(); bytes[1] = payload_len[0]; bytes[2] = payload_len[1];").unwrap();
    writeln!(source, "        let mut index = 0; while index < MAX_PAYLOAD {{ bytes[3 + index] = self.payload[index]; index += 1; }}").unwrap();
    writeln!(source, "        let action_offset = 3 + MAX_PAYLOAD; let action_len = self.action_len.to_le_bytes(); bytes[action_offset] = action_len[0]; bytes[action_offset + 1] = action_len[1];").unwrap();
    writeln!(source, "        index = 0; while index < MAX_ACTIONS {{ let encoded = self.actions[index].to_le_bytes(); let offset = action_offset + 2 + index * 4; bytes[offset] = encoded[0]; bytes[offset + 1] = encoded[1]; bytes[offset + 2] = encoded[2]; bytes[offset + 3] = encoded[3]; index += 1; }}").unwrap();
    writeln!(source, "        bytes").unwrap();
    writeln!(source, "    }}").unwrap();
    writeln!(source, "}}").unwrap();
    writeln!(source).unwrap();
    writeln!(
        source,
        "#[derive(Clone, Copy)] struct Transition {{ next: u16, output: u16 }}"
    )
    .unwrap();
    writeln!(
        source,
        "const TRANSITIONS: [Transition; {}] = [",
        certificate.transitions.len()
    )
    .unwrap();
    for transition in &certificate.transitions {
        writeln!(
            source,
            "    Transition {{ next: {}, output: {} }},",
            transition.to, transition.output
        )
        .unwrap();
    }
    writeln!(source, "];\n").unwrap();
    writeln!(
        source,
        "const OUTPUTS: [EncodedOutput; {}] = [",
        certificate.outputs.len()
    )
    .unwrap();
    for output in &certificate.outputs {
        writeln!(
            source,
            "    {},",
            output_literal(output, max_payload, max_actions)
        )
        .unwrap();
    }
    writeln!(source, "];\n").unwrap();
    writeln!(source, "mod sealed {{ pub trait Sealed {{}} }}").unwrap();
    writeln!(source, "pub trait CertifiedAdapter: sealed::Sealed {{}}").unwrap();
    writeln!(
        source,
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct Runtime {{ state: u16 }}"
    )
    .unwrap();
    writeln!(
        source,
        "impl sealed::Sealed for Runtime {{}} impl CertifiedAdapter for Runtime {{}}"
    )
    .unwrap();
    writeln!(
        source,
        "impl Default for Runtime {{ fn default() -> Self {{ Self::new() }} }}"
    )
    .unwrap();
    writeln!(source, "impl Runtime {{").unwrap();
    writeln!(
        source,
        "    #[must_use] pub const fn new() -> Self {{ Self {{ state: 0 }} }}"
    )
    .unwrap();
    writeln!(
        source,
        "    #[must_use] pub const fn state(&self) -> u16 {{ self.state }}"
    )
    .unwrap();
    writeln!(source, "    pub fn step(&mut self, quotient: QuotientInput, public: PublicInput, fault: FaultInput) -> Result<EncodedOutput, StepError> {{").unwrap();
    writeln!(source, "        let quotient = usize::from(quotient.0); let public = usize::from(public.0); let fault = usize::from(fault.0);").unwrap();
    writeln!(source, "        if quotient >= QUOTIENT_INPUTS || public >= PUBLIC_INPUTS || fault >= FAULT_INPUTS {{ return Err(StepError::InputOutOfRange); }}").unwrap();
    writeln!(source, "        let input = quotient.checked_mul(PUBLIC_INPUTS).and_then(|value| value.checked_add(public)).and_then(|value| value.checked_mul(FAULT_INPUTS)).and_then(|value| value.checked_add(fault)).ok_or(StepError::ArithmeticOverflow)?;").unwrap();
    writeln!(source, "        let table = usize::from(self.state).checked_mul(INPUT_COUNT).and_then(|value| value.checked_add(input)).ok_or(StepError::ArithmeticOverflow)?;").unwrap();
    writeln!(
        source,
        "        let transition = *TRANSITIONS.get(table).ok_or(StepError::InvalidState)?;"
    )
    .unwrap();
    writeln!(source, "        let output = *OUTPUTS.get(usize::from(transition.output)).ok_or(StepError::InvalidOutput)?;").unwrap();
    writeln!(source, "        if usize::from(transition.next) >= STATE_COUNT {{ return Err(StepError::InvalidState); }} self.state = transition.next; Ok(output)").unwrap();
    writeln!(source, "    }}").unwrap();
    writeln!(source, "}}").unwrap();
    writeln!(source, "#[cfg(test)] mod vectors;").unwrap();
    Ok(source)
}

fn generate_vectors(
    certificate: &Certificate,
    config: &CodegenConfig,
) -> Result<String, CodegenError> {
    let mut source = String::new();
    writeln!(source, "use super::*;").unwrap();
    writeln!(source, "#[derive(Clone, Copy)] struct Vector {{ from: u16, quotient: u16, public: u16, fault: u16, to: u16, output: u16 }}").unwrap();
    writeln!(
        source,
        "const VECTORS: [Vector; {}] = [",
        certificate.transitions.len()
    )
    .unwrap();
    for transition in &certificate.transitions {
        let (quotient, public, fault) = decompose_input(transition.input, config)?;
        writeln!(source, "    Vector {{ from: {}, quotient: {quotient}, public: {public}, fault: {fault}, to: {}, output: {} }},", transition.from, transition.to, transition.output).unwrap();
    }
    writeln!(source, "];\n").unwrap();
    writeln!(
        source,
        "#[test] fn every_certificate_transition_matches_runtime() {{"
    )
    .unwrap();
    writeln!(source, "    for vector in VECTORS {{ let mut runtime = Runtime {{ state: vector.from }}; let output = runtime.step(QuotientInput(vector.quotient), PublicInput(vector.public), FaultInput(vector.fault)).expect(\"certificate vector must execute\"); assert_eq!(runtime.state(), vector.to); assert_eq!(output, OUTPUTS[usize::from(vector.output)]); let first = output.encode(); let second = output.encode(); assert_eq!(first, second); }}").unwrap();
    writeln!(source, "}}").unwrap();
    Ok(source)
}

fn generate_vector_table(
    certificate: &Certificate,
    config: &CodegenConfig,
) -> Result<String, CodegenError> {
    let mut table = "from\tquotient\tpublic\tfault\tto\toutput\n".to_owned();
    for transition in &certificate.transitions {
        let (quotient, public, fault) = decompose_input(transition.input, config)?;
        writeln!(
            table,
            "{}\t{quotient}\t{public}\t{fault}\t{}\t{}",
            transition.from, transition.to, transition.output
        )
        .unwrap();
    }
    Ok(table)
}

fn decompose_input(input: u32, config: &CodegenConfig) -> Result<(u16, u16, u16), CodegenError> {
    let public_fault = u32::from(config.public_inputs)
        .checked_mul(u32::from(config.fault_inputs))
        .ok_or(CodegenError::InputProductOverflow)?;
    let quotient = input / public_fault;
    let remainder = input % public_fault;
    let public = remainder / u32::from(config.fault_inputs);
    let fault = remainder % u32::from(config.fault_inputs);
    Ok((
        u16::try_from(quotient).map_err(|_| CodegenError::InputProductOverflow)?,
        u16::try_from(public).map_err(|_| CodegenError::InputProductOverflow)?,
        u16::try_from(fault).map_err(|_| CodegenError::InputProductOverflow)?,
    ))
}

fn generate_manifest(
    certificate: &Certificate,
    config: &CodegenConfig,
    certificate_digest: Digest,
) -> String {
    let hashes = certificate.hashes;
    format!(
        "format = \"quotient-forge-codegen-v1\"\npackage = \"{}\"\ncertificate_version = {}\ncertificate_digest = \"{}\"\nspec_hash = \"{}\"\nplant_hash = \"{}\"\nquotient_hash = \"{}\"\nobserver_hash = \"{}\"\nutility_hash = \"{}\"\nfault_hash = \"{}\"\ntransducer_hash = \"{}\"\nchecker_contract_hash = \"{}\"\nstates = {}\ninputs = {}\noutputs = {}\nquotient_inputs = {}\npublic_inputs = {}\nfault_inputs = {}\noutput_encoding = \"qf-fixed-le-v1\"\n",
        config.package_name,
        certificate.version,
        hex(certificate_digest),
        hex(hashes.spec),
        hex(hashes.plant),
        hex(hashes.quotient),
        hex(hashes.observer),
        hex(hashes.utility),
        hex(hashes.fault),
        hex(hashes.transducer),
        hex(hashes.checker_contract),
        certificate.state_count,
        certificate.input_count,
        certificate.outputs.len(),
        config.quotient_inputs,
        config.public_inputs,
        config.fault_inputs,
    )
}

fn output_literal(output: &OutputRecord, max_payload: usize, max_actions: usize) -> String {
    format!(
        "EncodedOutput {{ emitted: {}, payload_len: {}, payload: {}, action_len: {}, actions: {} }}",
        output.emitted,
        output.payload.len(),
        byte_array(&output.payload, max_payload),
        output.actions.len(),
        u32_array(&output.actions, max_actions),
    )
}

fn byte_array(values: &[u8], length: usize) -> String {
    let mut padded = values.to_vec();
    padded.resize(length, 0);
    format!(
        "[{}]",
        padded
            .iter()
            .map(|value| format!("0x{value:02x}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn u32_array(values: &[u32], length: usize) -> String {
    let mut padded = values.to_vec();
    padded.resize(length, 0);
    format!(
        "[{}]",
        padded
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn hex(digest: Digest) -> String {
    digest
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
