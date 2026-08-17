use quotient_forge_caqt::{
    verify, Certificate, CertificateLimits, CertificateVerdict, Digest, ExpectedContract,
    OutputRecord,
};

use crate::CodegenConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetKind {
    NativeNoStd,
    Wasm32UnknownUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionStatus {
    Ok,
    InputOutOfRange,
    ArithmeticOverflow,
    InvalidState,
    InvalidOutput,
    CertificateMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildContext {
    pub target: TargetKind,
    pub manifest_digest: Digest,
    pub compiler: String,
    pub compiler_version: String,
    pub command: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildEvidence {
    pub target: TargetKind,
    pub certificate_digest: Digest,
    pub manifest_digest: Digest,
    pub compiler: String,
    pub compiler_version: String,
    pub command: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepObservation {
    pub from: u32,
    pub quotient: u16,
    pub public: u16,
    pub fault: u16,
    pub status: ExecutionStatus,
    pub next_state: Option<u32>,
    pub output_id: Option<u32>,
    pub output_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleObservation {
    pub state: u32,
    pub reset_state: u32,
    pub handoff_state: Option<u32>,
    pub restored_state: Option<u32>,
    pub status: ExecutionStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidProbeKind {
    QuotientAxis,
    PublicAxis,
    FaultAxis,
    State,
    OffsetOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidProbeObservation {
    pub kind: InvalidProbeKind,
    pub status: ExecutionStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslationTranscript {
    pub build: BuildEvidence,
    pub steps: Vec<StepObservation>,
    pub lifecycle: Vec<LifecycleObservation>,
    pub invalid_probes: Vec<InvalidProbeObservation>,
    pub bounded_sequence: Vec<StepObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranslationLimits {
    pub max_observations: usize,
    pub max_output_bytes: usize,
    pub bounded_sequence_steps: usize,
}

impl Default for TranslationLimits {
    fn default() -> Self {
        Self {
            max_observations: 1_000_000,
            max_output_bytes: 64 * 1024,
            bounded_sequence_steps: 64,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceError {
    CertificateRejected(String),
    CertificateParse(String),
    InputProductOverflow,
    InputCountMismatch { axes: u32, certificate: u32 },
    AxisValueOverflow,
    MissingTransition { state: u32, input: u32 },
    MissingOutput(u32),
    OutputLengthOverflow,
    ResourceBound(TranslationResourceBound),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IncompatibleReason {
    TargetMismatch {
        expected: TargetKind,
        actual: TargetKind,
    },
    MissingBuildMetadata(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranslationMismatch {
    Binding(&'static str),
    Count {
        section: &'static str,
        expected: usize,
        actual: usize,
    },
    Observation {
        section: &'static str,
        index: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranslationResourceBound {
    ObservationCount { actual: usize, limit: usize },
    OutputBytes { actual: usize, limit: usize },
    ArithmeticOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranslationReport {
    pub target: TargetKind,
    pub certificate_digest: Digest,
    pub manifest_digest: Digest,
    pub checked_steps: usize,
    pub checked_lifecycle_states: usize,
    pub checked_invalid_probes: usize,
    pub checked_sequence_steps: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranslationVerdict {
    Valid(TranslationReport),
    Mismatch(Vec<TranslationMismatch>),
    Incompatible(IncompatibleReason),
    ResourceBound(TranslationResourceBound),
}

pub fn reference_transcript(
    certificate_bytes: &[u8],
    expected: ExpectedContract,
    certificate_limits: CertificateLimits,
    config: &CodegenConfig,
    build: BuildContext,
    limits: TranslationLimits,
) -> Result<TranslationTranscript, ReferenceError> {
    let report = match verify(certificate_bytes, expected, certificate_limits) {
        CertificateVerdict::Valid(report) => report,
        verdict => return Err(ReferenceError::CertificateRejected(format!("{verdict:?}"))),
    };
    let certificate = Certificate::decode(certificate_bytes, certificate_limits)
        .map_err(|error| ReferenceError::CertificateParse(error.to_string()))?;
    let axes = u32::from(config.quotient_inputs)
        .checked_mul(u32::from(config.public_inputs))
        .and_then(|value| value.checked_mul(u32::from(config.fault_inputs)))
        .ok_or(ReferenceError::InputProductOverflow)?;
    if axes != certificate.input_count {
        return Err(ReferenceError::InputCountMismatch {
            axes,
            certificate: certificate.input_count,
        });
    }
    let base_observations = usize::try_from(certificate.state_count)
        .ok()
        .and_then(|states| {
            usize::try_from(certificate.input_count)
                .ok()
                .and_then(|inputs| states.checked_mul(inputs))
                .and_then(|steps| steps.checked_add(states))
        })
        .and_then(|count| count.checked_add(5))
        .and_then(|count| count.checked_add(limits.bounded_sequence_steps))
        .ok_or(ReferenceError::ResourceBound(
            TranslationResourceBound::ArithmeticOverflow,
        ))?;
    if base_observations > limits.max_observations {
        return Err(ReferenceError::ResourceBound(
            TranslationResourceBound::ObservationCount {
                actual: base_observations,
                limit: limits.max_observations,
            },
        ));
    }
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
    let encoded_length = 5_usize
        .checked_add(max_payload)
        .and_then(|value| value.checked_add(max_actions.checked_mul(4)?))
        .ok_or(ReferenceError::OutputLengthOverflow)?;
    if encoded_length > limits.max_output_bytes {
        return Err(ReferenceError::ResourceBound(
            TranslationResourceBound::OutputBytes {
                actual: encoded_length,
                limit: limits.max_output_bytes,
            },
        ));
    }

    let mut steps = Vec::new();
    for state in 0..certificate.state_count {
        for input in 0..certificate.input_count {
            steps.push(reference_step(
                &certificate,
                config,
                state,
                input,
                max_payload,
                max_actions,
            )?);
        }
    }
    let lifecycle = (0..certificate.state_count)
        .map(|state| LifecycleObservation {
            state,
            reset_state: 0,
            handoff_state: Some(state),
            restored_state: Some(state),
            status: ExecutionStatus::Ok,
        })
        .collect();
    let invalid_probes = vec![
        InvalidProbeObservation {
            kind: InvalidProbeKind::QuotientAxis,
            status: ExecutionStatus::InputOutOfRange,
        },
        InvalidProbeObservation {
            kind: InvalidProbeKind::PublicAxis,
            status: ExecutionStatus::InputOutOfRange,
        },
        InvalidProbeObservation {
            kind: InvalidProbeKind::FaultAxis,
            status: ExecutionStatus::InputOutOfRange,
        },
        InvalidProbeObservation {
            kind: InvalidProbeKind::State,
            status: ExecutionStatus::InvalidState,
        },
        InvalidProbeObservation {
            kind: InvalidProbeKind::OffsetOverflow,
            status: ExecutionStatus::ArithmeticOverflow,
        },
    ];
    let mut bounded_sequence = Vec::with_capacity(limits.bounded_sequence_steps);
    let mut state = 0_u32;
    for index in 0..limits.bounded_sequence_steps {
        let input = u32::try_from(index % certificate.input_count as usize)
            .map_err(|_| ReferenceError::InputProductOverflow)?;
        let step = reference_step(&certificate, config, state, input, max_payload, max_actions)?;
        state = step
            .next_state
            .ok_or(ReferenceError::MissingTransition { state, input })?;
        bounded_sequence.push(step);
    }
    Ok(TranslationTranscript {
        build: BuildEvidence {
            target: build.target,
            certificate_digest: report.certificate_digest,
            manifest_digest: build.manifest_digest,
            compiler: build.compiler,
            compiler_version: build.compiler_version,
            command: build.command,
        },
        steps,
        lifecycle,
        invalid_probes,
        bounded_sequence,
    })
}

pub fn validate_translation(
    reference: &TranslationTranscript,
    observed: &TranslationTranscript,
    limits: TranslationLimits,
) -> TranslationVerdict {
    if observed.build.target != reference.build.target {
        return TranslationVerdict::Incompatible(IncompatibleReason::TargetMismatch {
            expected: reference.build.target,
            actual: observed.build.target,
        });
    }
    for (field, value) in [
        ("compiler", observed.build.compiler.as_str()),
        ("compiler_version", observed.build.compiler_version.as_str()),
        ("command", observed.build.command.as_str()),
    ] {
        if value.trim().is_empty() {
            return TranslationVerdict::Incompatible(IncompatibleReason::MissingBuildMetadata(
                field,
            ));
        }
    }
    let count = observed
        .steps
        .len()
        .checked_add(observed.lifecycle.len())
        .and_then(|value| value.checked_add(observed.invalid_probes.len()))
        .and_then(|value| value.checked_add(observed.bounded_sequence.len()));
    let Some(count) = count else {
        return TranslationVerdict::ResourceBound(TranslationResourceBound::ArithmeticOverflow);
    };
    if count > limits.max_observations {
        return TranslationVerdict::ResourceBound(TranslationResourceBound::ObservationCount {
            actual: count,
            limit: limits.max_observations,
        });
    }
    for observation in observed
        .steps
        .iter()
        .chain(observed.bounded_sequence.iter())
    {
        if observation.output_bytes.len() > limits.max_output_bytes {
            return TranslationVerdict::ResourceBound(TranslationResourceBound::OutputBytes {
                actual: observation.output_bytes.len(),
                limit: limits.max_output_bytes,
            });
        }
    }

    let mut mismatches = Vec::new();
    if observed.build.certificate_digest != reference.build.certificate_digest {
        mismatches.push(TranslationMismatch::Binding("certificate_digest"));
    }
    if observed.build.manifest_digest != reference.build.manifest_digest {
        mismatches.push(TranslationMismatch::Binding("manifest_digest"));
    }
    compare_section("step", &reference.steps, &observed.steps, &mut mismatches);
    compare_section(
        "lifecycle",
        &reference.lifecycle,
        &observed.lifecycle,
        &mut mismatches,
    );
    compare_section(
        "invalid_probe",
        &reference.invalid_probes,
        &observed.invalid_probes,
        &mut mismatches,
    );
    compare_section(
        "bounded_sequence",
        &reference.bounded_sequence,
        &observed.bounded_sequence,
        &mut mismatches,
    );
    if mismatches.is_empty() {
        TranslationVerdict::Valid(TranslationReport {
            target: observed.build.target,
            certificate_digest: observed.build.certificate_digest,
            manifest_digest: observed.build.manifest_digest,
            checked_steps: observed.steps.len(),
            checked_lifecycle_states: observed.lifecycle.len(),
            checked_invalid_probes: observed.invalid_probes.len(),
            checked_sequence_steps: observed.bounded_sequence.len(),
        })
    } else {
        TranslationVerdict::Mismatch(mismatches)
    }
}

fn compare_section<T: Eq>(
    section: &'static str,
    expected: &[T],
    actual: &[T],
    mismatches: &mut Vec<TranslationMismatch>,
) {
    if expected.len() != actual.len() {
        mismatches.push(TranslationMismatch::Count {
            section,
            expected: expected.len(),
            actual: actual.len(),
        });
    }
    for (index, (expected, actual)) in expected.iter().zip(actual).enumerate() {
        if expected != actual {
            mismatches.push(TranslationMismatch::Observation { section, index });
        }
    }
}

fn reference_step(
    certificate: &Certificate,
    config: &CodegenConfig,
    state: u32,
    input: u32,
    max_payload: usize,
    max_actions: usize,
) -> Result<StepObservation, ReferenceError> {
    let transition = certificate
        .transitions
        .iter()
        .find(|transition| transition.from == state && transition.input == input)
        .ok_or(ReferenceError::MissingTransition { state, input })?;
    let output = certificate
        .outputs
        .iter()
        .find(|output| output.id == transition.output)
        .ok_or(ReferenceError::MissingOutput(transition.output))?;
    let public_fault = u32::from(config.public_inputs)
        .checked_mul(u32::from(config.fault_inputs))
        .ok_or(ReferenceError::InputProductOverflow)?;
    let quotient = input / public_fault;
    let remainder = input % public_fault;
    let public = remainder / u32::from(config.fault_inputs);
    let fault = remainder % u32::from(config.fault_inputs);
    Ok(StepObservation {
        from: state,
        quotient: u16::try_from(quotient).map_err(|_| ReferenceError::AxisValueOverflow)?,
        public: u16::try_from(public).map_err(|_| ReferenceError::AxisValueOverflow)?,
        fault: u16::try_from(fault).map_err(|_| ReferenceError::AxisValueOverflow)?,
        status: ExecutionStatus::Ok,
        next_state: Some(transition.to),
        output_id: Some(transition.output),
        output_bytes: encode_output(output, max_payload, max_actions)?,
    })
}

fn encode_output(
    output: &OutputRecord,
    max_payload: usize,
    max_actions: usize,
) -> Result<Vec<u8>, ReferenceError> {
    let payload_length =
        u16::try_from(output.payload.len()).map_err(|_| ReferenceError::OutputLengthOverflow)?;
    let action_length =
        u16::try_from(output.actions.len()).map_err(|_| ReferenceError::OutputLengthOverflow)?;
    let capacity = 5_usize
        .checked_add(max_payload)
        .and_then(|value| value.checked_add(max_actions.checked_mul(4)?))
        .ok_or(ReferenceError::OutputLengthOverflow)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(u8::from(output.emitted));
    bytes.extend_from_slice(&payload_length.to_le_bytes());
    bytes.extend_from_slice(&output.payload);
    bytes.resize(3 + max_payload, 0);
    bytes.extend_from_slice(&action_length.to_le_bytes());
    for action in &output.actions {
        bytes.extend_from_slice(&action.to_le_bytes());
    }
    bytes.resize(capacity, 0);
    Ok(bytes)
}
