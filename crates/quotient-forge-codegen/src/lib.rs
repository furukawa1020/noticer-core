#![forbid(unsafe_code)]

//! Generates a heap-free `no_std` runtime from a valid CAQT certificate.

use std::fmt::{self, Write as _};
use std::fs;
use std::path::{Path, PathBuf};

use quotient_forge_caqt::{
    artifact_digest, verify, Certificate, CertificateLimits, CertificateVerdict, Digest,
    ExpectedContract, OutputRecord,
};

mod translation;

pub use translation::{
    reference_transcript, validate_translation, BuildContext, BuildEvidence, ExecutionStatus,
    IncompatibleReason as TranslationIncompatibleReason, InvalidProbeKind, InvalidProbeObservation,
    LifecycleObservation, ReferenceError, StepObservation, TargetKind, TranslationLimits,
    TranslationMismatch, TranslationReport, TranslationResourceBound, TranslationTranscript,
    TranslationVerdict,
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
    pub manifest_digest: Digest,
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

    let manifest = generate_manifest(&certificate, config, report.certificate_digest);
    let manifest_digest =
        artifact_digest(b"quotient-forge-codegen-manifest-v2", manifest.as_bytes());
    let cargo_toml = generate_cargo_toml(config);
    let runtime = generate_runtime(
        &certificate,
        config,
        report.certificate_digest,
        manifest_digest,
    )?;
    let vectors = generate_vectors(&certificate, config)?;
    let vector_table = generate_vector_table(&certificate, config)?;
    let wasm_validation = generate_wasm_validation(
        &certificate,
        config,
        report.certificate_digest,
        manifest_digest,
    )?;

    let source = target.join("src");
    fs::create_dir_all(&source)?;
    let files = vec![
        target.join("Cargo.toml"),
        source.join("lib.rs"),
        source.join("vectors.rs"),
        target.join("certificate.caqt"),
        target.join("codegen-manifest.toml"),
        target.join("test-vectors.tsv"),
        target.join("wasm-validation.mjs"),
    ];
    fs::write(&files[0], cargo_toml)?;
    fs::write(&files[1], runtime)?;
    fs::write(&files[2], vectors)?;
    fs::write(&files[3], certificate_bytes)?;
    fs::write(&files[4], manifest)?;
    fs::write(&files[5], vector_table)?;
    fs::write(&files[6], wasm_validation)?;

    Ok(GeneratedPackage {
        root: target.to_path_buf(),
        files,
        certificate_digest: report.certificate_digest,
        manifest_digest,
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
        "[package]\nname = \"{}\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n[lib]\npath = \"src/lib.rs\"\ncrate-type = [\"rlib\"]\n",
        config.package_name
    )
}

fn generate_runtime(
    certificate: &Certificate,
    config: &CodegenConfig,
    certificate_digest: Digest,
    manifest_digest: Digest,
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
    writeln!(
        source,
        "#![cfg_attr(not(target_arch = \"wasm32\"), forbid(unsafe_code))]"
    )
    .unwrap();
    writeln!(
        source,
        "#![cfg_attr(target_arch = \"wasm32\", deny(unsafe_code))]"
    )
    .unwrap();
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
        "pub const MANIFEST_DIGEST: [u8; 32] = {};",
        byte_array(manifest_digest.as_bytes(), 32)
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
    writeln!(source, "#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub enum StepError {{ InputOutOfRange, ArithmeticOverflow, InvalidState, InvalidOutput, CertificateMismatch }}").unwrap();
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
    writeln!(source, "#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct Handoff {{ state: u16, certificate_digest: [u8; 32], manifest_digest: [u8; 32] }}").unwrap();
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
    writeln!(source, "fn table_offset(state: usize, input: usize) -> Result<usize, StepError> {{ state.checked_mul(INPUT_COUNT).and_then(|value| value.checked_add(input)).ok_or(StepError::ArithmeticOverflow) }}").unwrap();
    writeln!(source, "fn transition_for(state: usize, quotient: usize, public: usize, fault: usize) -> Result<(Transition, EncodedOutput), StepError> {{").unwrap();
    writeln!(source, "    if quotient >= QUOTIENT_INPUTS || public >= PUBLIC_INPUTS || fault >= FAULT_INPUTS {{ return Err(StepError::InputOutOfRange); }}").unwrap();
    writeln!(
        source,
        "    if state >= STATE_COUNT {{ return Err(StepError::InvalidState); }}"
    )
    .unwrap();
    writeln!(source, "    let input = quotient.checked_mul(PUBLIC_INPUTS).and_then(|value| value.checked_add(public)).and_then(|value| value.checked_mul(FAULT_INPUTS)).and_then(|value| value.checked_add(fault)).ok_or(StepError::ArithmeticOverflow)?;").unwrap();
    writeln!(source, "    let transition = *TRANSITIONS.get(table_offset(state, input)?).ok_or(StepError::InvalidState)?;").unwrap();
    writeln!(source, "    if usize::from(transition.next) >= STATE_COUNT {{ return Err(StepError::InvalidState); }}").unwrap();
    writeln!(source, "    let output = *OUTPUTS.get(usize::from(transition.output)).ok_or(StepError::InvalidOutput)?; Ok((transition, output))").unwrap();
    writeln!(source, "}}").unwrap();
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
    writeln!(source, "    pub fn reset(&mut self) {{ self.state = 0; }}").unwrap();
    writeln!(source, "    #[must_use] pub const fn handoff(&self) -> Handoff {{ Handoff {{ state: self.state, certificate_digest: CERTIFICATE_DIGEST, manifest_digest: MANIFEST_DIGEST }} }}").unwrap();
    writeln!(source, "    pub fn restore(handoff: Handoff) -> Result<Self, StepError> {{ if handoff.certificate_digest != CERTIFICATE_DIGEST || handoff.manifest_digest != MANIFEST_DIGEST {{ return Err(StepError::CertificateMismatch); }} if usize::from(handoff.state) >= STATE_COUNT {{ return Err(StepError::InvalidState); }} Ok(Self {{ state: handoff.state }}) }}").unwrap();
    writeln!(source, "    pub fn step(&mut self, quotient: QuotientInput, public: PublicInput, fault: FaultInput) -> Result<EncodedOutput, StepError> {{ let (transition, output) = transition_for(usize::from(self.state), usize::from(quotient.0), usize::from(public.0), usize::from(fault.0))?; self.state = transition.next; Ok(output) }}").unwrap();
    writeln!(source, "}}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] fn wasm_step(state: u32, quotient: u32, public: u32, fault: u32) -> Result<(Transition, EncodedOutput), StepError> {{ let state = usize::try_from(state).map_err(|_| StepError::ArithmeticOverflow)?; let quotient = usize::try_from(quotient).map_err(|_| StepError::ArithmeticOverflow)?; let public = usize::try_from(public).map_err(|_| StepError::ArithmeticOverflow)?; let fault = usize::try_from(fault).map_err(|_| StepError::ArithmeticOverflow)?; transition_for(state, quotient, public, fault) }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] const fn error_code(error: StepError) -> u32 {{ match error {{ StepError::InputOutOfRange => 1, StepError::ArithmeticOverflow => 2, StepError::InvalidState => 3, StepError::InvalidOutput => 4, StepError::CertificateMismatch => 5 }} }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_state_count() -> u32 {{ STATE_COUNT as u32 }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_quotient_inputs() -> u32 {{ QUOTIENT_INPUTS as u32 }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_public_inputs() -> u32 {{ PUBLIC_INPUTS as u32 }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_fault_inputs() -> u32 {{ FAULT_INPUTS as u32 }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_encoded_output_bytes() -> u32 {{ ENCODED_OUTPUT_BYTES as u32 }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_step_status(state: u32, quotient: u32, public: u32, fault: u32) -> u32 {{ match wasm_step(state, quotient, public, fault) {{ Ok(_) => 0, Err(error) => error_code(error) }} }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_step_next(state: u32, quotient: u32, public: u32, fault: u32) -> u32 {{ match wasm_step(state, quotient, public, fault) {{ Ok((transition, _)) => u32::from(transition.next), Err(_) => u32::MAX }} }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_step_output(state: u32, quotient: u32, public: u32, fault: u32) -> u32 {{ match wasm_step(state, quotient, public, fault) {{ Ok((transition, _)) => u32::from(transition.output), Err(_) => u32::MAX }} }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_output_encoded_byte(output: u32, index: u32) -> u32 {{ let output = usize::try_from(output).ok().and_then(|value| OUTPUTS.get(value)); let index = usize::try_from(index).ok(); match (output, index) {{ (Some(output), Some(index)) => output.encode().get(index).copied().map_or(u32::MAX, u32::from), _ => u32::MAX }} }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_certificate_digest_byte(index: u32) -> u32 {{ usize::try_from(index).ok().and_then(|value| CERTIFICATE_DIGEST.get(value)).copied().map_or(u32::MAX, u32::from) }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_manifest_digest_byte(index: u32) -> u32 {{ usize::try_from(index).ok().and_then(|value| MANIFEST_DIGEST.get(value)).copied().map_or(u32::MAX, u32::from) }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_reset() -> u32 {{ 0 }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_handoff(state: u32) -> u32 {{ if usize::try_from(state).is_ok_and(|value| value < STATE_COUNT) {{ state }} else {{ u32::MAX }} }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_restore(state: u32) -> u32 {{ qf_handoff(state) }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[allow(unsafe_code)] #[unsafe(no_mangle)] pub extern \"C\" fn qf_probe_offset_status(state: u32, input: u32) -> u32 {{ let state = usize::try_from(state).unwrap_or(usize::MAX); let input = usize::try_from(input).unwrap_or(usize::MAX); match table_offset(state, input) {{ Ok(_) => 0, Err(error) => error_code(error) }} }}").unwrap();
    writeln!(source, "#[cfg(target_arch = \"wasm32\")] #[panic_handler] fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {{ loop {{ core::hint::spin_loop(); }} }}").unwrap();
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
    writeln!(source, "#[test] fn reset_handoff_and_restore_are_bound_to_the_build() {{ for state in 0..STATE_COUNT {{ let mut runtime = Runtime {{ state: state as u16 }}; let handoff = runtime.handoff(); runtime.reset(); assert_eq!(runtime.state(), 0); let restored = Runtime::restore(handoff).expect(\"bound handoff must restore\"); assert_eq!(usize::from(restored.state()), state); let mut changed = handoff; changed.manifest_digest[0] ^= 1; assert_eq!(Runtime::restore(changed), Err(StepError::CertificateMismatch)); }} }}").unwrap();
    writeln!(source, "#[test] fn invalid_axes_and_offset_overflow_fail_closed() {{ let mut runtime = Runtime::new(); assert_eq!(runtime.step(QuotientInput(QUOTIENT_INPUTS as u16), PublicInput(0), FaultInput(0)), Err(StepError::InputOutOfRange)); assert_eq!(runtime.step(QuotientInput(0), PublicInput(PUBLIC_INPUTS as u16), FaultInput(0)), Err(StepError::InputOutOfRange)); assert_eq!(runtime.step(QuotientInput(0), PublicInput(0), FaultInput(FAULT_INPUTS as u16)), Err(StepError::InputOutOfRange)); assert_eq!(table_offset(usize::MAX, usize::MAX), Err(StepError::ArithmeticOverflow)); }}").unwrap();
    writeln!(source, "#[test] fn bounded_sequence_matches_the_certificate_table() {{ let mut runtime = Runtime::new(); for step in 0..64 {{ let input = step % INPUT_COUNT; let index = usize::from(runtime.state()) * INPUT_COUNT + input; let vector = VECTORS[index]; assert_eq!(runtime.state(), vector.from); let output = runtime.step(QuotientInput(vector.quotient), PublicInput(vector.public), FaultInput(vector.fault)).expect(\"bounded sequence must execute\"); assert_eq!(runtime.state(), vector.to); assert_eq!(output, OUTPUTS[usize::from(vector.output)]); }} }}").unwrap();
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
        "format = \"quotient-forge-codegen-v2\"\npackage = \"{}\"\ncertificate_version = {}\ncertificate_digest = \"{}\"\nspec_hash = \"{}\"\nplant_hash = \"{}\"\nquotient_hash = \"{}\"\nobserver_hash = \"{}\"\nutility_hash = \"{}\"\nfault_hash = \"{}\"\ntransducer_hash = \"{}\"\nchecker_contract_hash = \"{}\"\nstates = {}\ninputs = {}\noutputs = {}\nquotient_inputs = {}\npublic_inputs = {}\nfault_inputs = {}\noutput_encoding = \"qf-fixed-le-v1\"\ntranslation_semantics = \"all-state-input-step-reset-handoff-v1\"\ntargets = [\"native-no-std\", \"wasm32-unknown-unknown\"]\n",
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

fn generate_wasm_validation(
    certificate: &Certificate,
    config: &CodegenConfig,
    certificate_digest: Digest,
    manifest_digest: Digest,
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
    let sequence = bounded_sequence(certificate, 64)?;
    let mut script = String::new();
    writeln!(script, "import {{ readFile }} from \"node:fs/promises\";").unwrap();
    writeln!(script, "import process from \"node:process\";").unwrap();
    writeln!(script, "const vectors = [").unwrap();
    for transition in &certificate.transitions {
        let (quotient, public, fault) = decompose_input(transition.input, config)?;
        writeln!(script, "  {{ from: {}, quotient: {quotient}, public: {public}, fault: {fault}, to: {}, output: {} }},", transition.from, transition.to, transition.output).unwrap();
    }
    writeln!(script, "];").unwrap();
    writeln!(script, "const outputs = [").unwrap();
    for output in &certificate.outputs {
        writeln!(
            script,
            "  {},",
            js_array(&encoded_output(output, max_payload, max_actions))
        )
        .unwrap();
    }
    writeln!(script, "];").unwrap();
    writeln!(script, "const sequence = [").unwrap();
    for (from, input, to, output) in sequence {
        let (quotient, public, fault) = decompose_input(input, config)?;
        writeln!(script, "  {{ from: {from}, quotient: {quotient}, public: {public}, fault: {fault}, to: {to}, output: {output} }},").unwrap();
    }
    writeln!(script, "];").unwrap();
    writeln!(
        script,
        "const certificateDigest = {};",
        js_array(certificate_digest.as_bytes())
    )
    .unwrap();
    writeln!(
        script,
        "const manifestDigest = {};",
        js_array(manifest_digest.as_bytes())
    )
    .unwrap();
    writeln!(script, "const assertEqual = (actual, expected, label) => {{ if (actual !== expected) throw new Error(label + \": expected \" + expected + \", got \" + actual); }};").unwrap();
    writeln!(script, "if (process.argv.length !== 3) throw new Error(\"usage: node wasm-validation.mjs runtime.wasm\");").unwrap();
    writeln!(
        script,
        "const module = await WebAssembly.compile(await readFile(process.argv[2]));"
    )
    .unwrap();
    writeln!(
        script,
        "const imports = WebAssembly.Module.imports(module);"
    )
    .unwrap();
    writeln!(script, "if (imports.length !== 0) throw new Error(\"WASM runtime unexpectedly imports host capabilities\");").unwrap();
    writeln!(
        script,
        "const exportedNames = WebAssembly.Module.exports(module).map((entry) => entry.name);"
    )
    .unwrap();
    writeln!(script, "if (exportedNames.some((name) => /(private|biosignal|ingest)/i.test(name))) throw new Error(\"private-input surface exported\");").unwrap();
    writeln!(
        script,
        "const instance = await WebAssembly.instantiate(module, {{}});"
    )
    .unwrap();
    writeln!(script, "const e = instance.exports;").unwrap();
    writeln!(script, "for (let index = 0; index < 32; index += 1) {{ assertEqual(e.qf_certificate_digest_byte(index), certificateDigest[index], \"certificate digest byte \" + index); assertEqual(e.qf_manifest_digest_byte(index), manifestDigest[index], \"manifest digest byte \" + index); }}").unwrap();
    writeln!(script, "for (const vector of vectors) {{ const args = [vector.from, vector.quotient, vector.public, vector.fault]; assertEqual(e.qf_step_status(...args), 0, \"step status\"); assertEqual(e.qf_step_next(...args), vector.to, \"next-state mismatch\"); assertEqual(e.qf_step_output(...args), vector.output, \"output-id mismatch\"); const expected = outputs[vector.output]; assertEqual(e.qf_encoded_output_bytes(), expected.length, \"encoded output length\"); for (let index = 0; index < expected.length; index += 1) assertEqual(e.qf_output_encoded_byte(vector.output, index), expected[index], \"output byte mismatch at \" + index); }}").unwrap();
    writeln!(script, "assertEqual(e.qf_step_status(0, e.qf_quotient_inputs(), 0, 0), 1, \"quotient range status\");").unwrap();
    writeln!(
        script,
        "assertEqual(e.qf_step_status(0, 0, e.qf_public_inputs(), 0), 1, \"public range status\");"
    )
    .unwrap();
    writeln!(
        script,
        "assertEqual(e.qf_step_status(0, 0, 0, e.qf_fault_inputs()), 1, \"fault range status\");"
    )
    .unwrap();
    writeln!(
        script,
        "assertEqual(e.qf_step_status(e.qf_state_count(), 0, 0, 0), 3, \"invalid state status\");"
    )
    .unwrap();
    writeln!(script, "assertEqual(e.qf_probe_offset_status(0xffffffff, 0xffffffff), 2, \"offset overflow status\");").unwrap();
    writeln!(script, "for (let state = 0; state < e.qf_state_count(); state += 1) {{ assertEqual(e.qf_reset(), 0, \"reset mismatch\"); assertEqual(e.qf_handoff(state), state, \"handoff mismatch\"); assertEqual(e.qf_restore(e.qf_handoff(state)), state, \"restore mismatch\"); }}").unwrap();
    writeln!(script, "let sequenceState = 0; for (const vector of sequence) {{ assertEqual(sequenceState, vector.from, \"sequence source mismatch\"); const args = [sequenceState, vector.quotient, vector.public, vector.fault]; assertEqual(e.qf_step_status(...args), 0, \"sequence status\"); assertEqual(e.qf_step_output(...args), vector.output, \"sequence output\"); sequenceState = e.qf_step_next(...args); assertEqual(sequenceState, vector.to, \"sequence next state\"); }}").unwrap();
    writeln!(script, "process.stdout.write(JSON.stringify({{ verdict: \"VALID\", target: \"wasm32-unknown-unknown\", transitions: vectors.length, sequenceSteps: sequence.length }}) + \"\\n\");").unwrap();
    Ok(script)
}

fn bounded_sequence(
    certificate: &Certificate,
    steps: usize,
) -> Result<Vec<(u32, u32, u32, u32)>, CodegenError> {
    let mut state = 0_u32;
    let mut sequence = Vec::with_capacity(steps);
    for step in 0..steps {
        let input = u32::try_from(step % certificate.input_count as usize)
            .map_err(|_| CodegenError::InputProductOverflow)?;
        let transition = certificate
            .transitions
            .iter()
            .find(|transition| transition.from == state && transition.input == input)
            .ok_or_else(|| {
                CodegenError::CertificateRejected(format!(
                    "missing transition for state {state}, input {input}"
                ))
            })?;
        sequence.push((state, input, transition.to, transition.output));
        state = transition.to;
    }
    Ok(sequence)
}

fn encoded_output(output: &OutputRecord, max_payload: usize, max_actions: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(5 + max_payload + max_actions.saturating_mul(4));
    bytes.push(u8::from(output.emitted));
    bytes.extend_from_slice(
        &u16::try_from(output.payload.len())
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&output.payload);
    bytes.resize(3 + max_payload, 0);
    bytes.extend_from_slice(
        &u16::try_from(output.actions.len())
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    for action in &output.actions {
        bytes.extend_from_slice(&action.to_le_bytes());
    }
    bytes.resize(5 + max_payload + max_actions.saturating_mul(4), 0);
    bytes
}

fn js_array(values: &[u8]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ")
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
