use std::collections::BTreeSet;

use noticer_protocol::{KeyId, WireServiceAlias};
use noticer_types::{ActionCode, Epoch, PolicyHash};
use quotient_seal_abi::DeploymentProfile;
use quotient_seal_noticer::{
    bind_menfugu_compiled_manifest, compile_menfugu_p0, menfugu_generated_runtime_digest,
    menfugu_observer_registry_digest, menfugu_source_certificate_digest, Digest,
    MenfuguCompileError, MenfuguCompileLimits, MenfuguCompiledQsm, MenfuguK7Artifacts,
    MenfuguK7Binding, MenfuguLoweredTransition, MenfuguPublicInput, MenfuguPublicOutput,
    MenfuguPublicPolicyBinding, MenfuguPublicSourceArtifact, MenfuguPublicState,
    MenfuguServiceCode, NoticerModuleBinding, NoticerModuleId,
};

const WIRE_ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const QSM_ALIAS: u32 = 23;
const CERTIFICATE: &[u8] = b"MENFUGU_K7_PUBLIC_CERTIFICATE_V1";
const RUNTIME: &[u8] = b"MENFUGU_K7_GENERATED_RUNTIME_V1";

fn digest(value: u8) -> Digest {
    Digest::new([value; 32])
}

fn policy() -> MenfuguPublicPolicyBinding {
    MenfuguPublicPolicyBinding {
        service_alias: WIRE_ALIAS,
        epoch: Epoch(11),
        policy_hash: PolicyHash([0x41; 32]),
        verifier_key_id: KeyId([0x51; 8]),
        allowed_action: ActionCode::MenfuguInflateSoft,
        pump_ticks: 20,
        maximum_pump_ticks: 25,
        cooldown_slots: 3,
        execution_period_slots: 4,
        execution_offset_slots: 1,
        public_deadline_slots: 2,
    }
}

fn artifacts() -> MenfuguK7Artifacts {
    MenfuguK7Artifacts::new(CERTIFICATE.to_vec(), RUNTIME.to_vec())
}

fn k7(source: &MenfuguPublicSourceArtifact) -> MenfuguK7Binding {
    MenfuguK7Binding {
        public_policy_digest: policy().digest().expect("public policy"),
        source_digest: source.digest,
        source_certificate_digest: menfugu_source_certificate_digest(CERTIFICATE),
        generated_runtime_digest: menfugu_generated_runtime_digest(RUNTIME),
        qsm_capsule_digest: digest(0),
        observer_registry_digest: menfugu_observer_registry_digest(),
    }
}

fn service_code() -> MenfuguServiceCode {
    MenfuguServiceCode {
        service_alias: WIRE_ALIAS,
        qsm_alias: QSM_ALIAS,
    }
}

fn compile_fixture(
    source: &MenfuguPublicSourceArtifact,
    k7: &MenfuguK7Binding,
) -> MenfuguCompiledQsm {
    compile_menfugu_p0(
        source,
        policy(),
        k7,
        &artifacts(),
        &[service_code()],
        MenfuguCompileLimits::default(),
    )
    .expect("Menfugu P0 compile")
}

fn finalized_k7(
    source: &MenfuguPublicSourceArtifact,
    compiled: &MenfuguCompiledQsm,
) -> MenfuguK7Binding {
    MenfuguK7Binding {
        qsm_capsule_digest: compiled.binding().capsule_digest,
        observer_registry_digest: compiled.binding().observer_registry_digest,
        ..k7(source)
    }
}

fn module(k7: MenfuguK7Binding) -> NoticerModuleBinding {
    let policy = policy();
    NoticerModuleBinding {
        module_id: NoticerModuleId::MenfuguExecutionPlanner,
        deployment_profile: DeploymentProfile::P0PublicQuotientOnly,
        service_alias: policy.service_alias,
        epoch: policy.epoch,
        policy_hash: policy.policy_hash,
        source_digest: k7.source_digest,
        source_certificate_digest: k7.source_certificate_digest,
        generated_runtime_digest: k7.generated_runtime_digest,
        qsm_capsule_digest: k7.qsm_capsule_digest,
        observer_registry_digest: k7.observer_registry_digest,
        p1_resource_evidence: None,
    }
}

fn transition(
    compiled: &MenfuguCompiledQsm,
    state: MenfuguPublicState,
    input: MenfuguPublicInput,
) -> MenfuguLoweredTransition {
    compiled
        .transitions()
        .iter()
        .copied()
        .find(|transition| transition.source_state == state && transition.public_input == input)
        .expect("lowered transition")
}

#[test]
fn compile_is_byte_identical_and_refines_all_transitions() {
    let source = MenfuguPublicSourceArtifact::canonical();
    let k7 = k7(&source);
    let first = compile_fixture(&source, &k7);
    let second = compile_fixture(&source, &k7);

    assert_eq!(first, second);
    assert_eq!(first.wasm(), second.wasm());
    assert_eq!(first.capsule(), second.capsule());
    assert_eq!(first.compiler_manifest(), second.compiler_manifest());
    assert_eq!(first.transitions().len(), 56);
    assert!(first.refines(&source));
    assert_eq!(first.action_code(), ActionCode::MenfuguInflateSoft as u32);
    assert_eq!(first.service_code(), service_code());

    let source_steps = source
        .transitions
        .iter()
        .map(|step| (step.state, step.input, step.next_state, step.output))
        .collect::<BTreeSet<_>>();
    let target_steps = first
        .transitions()
        .iter()
        .map(|step| {
            (
                step.source_state,
                step.public_input,
                step.target_state,
                step.public_output,
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(source_steps, target_steps);
    assert!(quotient_seal_capsule::QsmCapsule::decode(
        first.capsule(),
        quotient_seal_capsule::QsmContainerLimits::default(),
    )
    .is_ok());

    let manifest = String::from_utf8_lossy(first.compiler_manifest());
    for required in [
        "menfugu.action_code",
        "menfugu.public_policy_digest",
        "menfugu.transition_digest",
        "CHECKED_ALL_56_SOURCE_TRANSITIONS",
        "privacy.private_ingress",
        "NOT_VERIFIED",
    ] {
        assert!(manifest.contains(required));
    }
}

#[test]
fn exactly_once_and_lifecycle_transitions_are_lowered_without_gaps() {
    let source = MenfuguPublicSourceArtifact::canonical();
    let compiled = compile_fixture(&source, &k7(&source));

    let first = transition(
        &compiled,
        MenfuguPublicState::Ready,
        MenfuguPublicInput::AuthorizedAction,
    );
    assert_eq!(first.target_state, MenfuguPublicState::Executing);
    assert_eq!(first.public_output, MenfuguPublicOutput::ExecuteOnce);

    let duplicate = transition(
        &compiled,
        MenfuguPublicState::Executing,
        MenfuguPublicInput::AuthorizedAction,
    );
    assert_eq!(duplicate.public_output, MenfuguPublicOutput::Reject);

    for rejection in [
        MenfuguPublicInput::ReplayRejected,
        MenfuguPublicInput::ExpiredRejected,
        MenfuguPublicInput::WrongServiceRejected,
        MenfuguPublicInput::WrongPolicyRejected,
        MenfuguPublicInput::WrongKeyRejected,
        MenfuguPublicInput::DuplicateTransport,
    ] {
        assert_eq!(
            transition(&compiled, MenfuguPublicState::Ready, rejection).public_output,
            MenfuguPublicOutput::Reject
        );
    }

    assert_eq!(
        transition(
            &compiled,
            MenfuguPublicState::Executing,
            MenfuguPublicInput::Deadline,
        )
        .public_output,
        MenfuguPublicOutput::Stop
    );
    assert_eq!(
        transition(
            &compiled,
            MenfuguPublicState::Executing,
            MenfuguPublicInput::Handoff,
        )
        .public_output,
        MenfuguPublicOutput::StopAndHandoff
    );
    assert_eq!(
        transition(
            &compiled,
            MenfuguPublicState::Ready,
            MenfuguPublicInput::Fault,
        )
        .target_state,
        MenfuguPublicState::FailClosed
    );
}

#[test]
fn registry_and_all_compiled_artifacts_are_rebound() {
    let source = MenfuguPublicSourceArtifact::canonical();
    let initial_k7 = k7(&source);
    let compiled = compile_fixture(&source, &initial_k7);
    let k7 = finalized_k7(&source, &compiled);
    let module = module(k7);
    let bound =
        bind_menfugu_compiled_manifest(module, &source, policy(), k7, &artifacts(), &compiled)
            .expect("compiled manifest binding");
    assert_eq!(bound.source_digest, source.digest);
    assert_eq!(bound.capsule_digest, compiled.binding().capsule_digest);
    assert_eq!(bound.module_digest, compiled.binding().module_digest);
    assert_eq!(bound.abi_digest, compiled.binding().abi_digest);

    let tampered = NoticerModuleBinding {
        qsm_capsule_digest: digest(0x99),
        ..module
    };
    assert!(bind_menfugu_compiled_manifest(
        tampered,
        &source,
        policy(),
        k7,
        &artifacts(),
        &compiled,
    )
    .is_err());
}

#[test]
fn artifact_tamper_and_resource_limits_fail_closed() {
    let source = MenfuguPublicSourceArtifact::canonical();
    let k7 = k7(&source);
    let compile = |artifacts: &MenfuguK7Artifacts, codes: &[MenfuguServiceCode], limits| {
        compile_menfugu_p0(&source, policy(), &k7, artifacts, codes, limits)
    };

    let wrong_certificate = MenfuguK7Artifacts::new(b"tampered".to_vec(), RUNTIME.to_vec());
    assert_eq!(
        compile(
            &wrong_certificate,
            &[service_code()],
            MenfuguCompileLimits::default()
        ),
        Err(MenfuguCompileError::CertificateDigestMismatch)
    );
    let wrong_runtime = MenfuguK7Artifacts::new(CERTIFICATE.to_vec(), b"tampered".to_vec());
    assert_eq!(
        compile(
            &wrong_runtime,
            &[service_code()],
            MenfuguCompileLimits::default()
        ),
        Err(MenfuguCompileError::GeneratedRuntimeDigestMismatch)
    );
    assert!(compile(&artifacts(), &[], MenfuguCompileLimits::default()).is_err());
    assert!(compile(
        &artifacts(),
        &[MenfuguServiceCode {
            service_alias: WIRE_ALIAS,
            qsm_alias: 0,
        }],
        MenfuguCompileLimits::default(),
    )
    .is_err());

    for limits in [
        MenfuguCompileLimits {
            max_states: 3,
            ..MenfuguCompileLimits::default()
        },
        MenfuguCompileLimits {
            max_public_inputs: 13,
            ..MenfuguCompileLimits::default()
        },
        MenfuguCompileLimits {
            max_transitions: 55,
            ..MenfuguCompileLimits::default()
        },
        MenfuguCompileLimits {
            max_certificate_bytes: 8,
            ..MenfuguCompileLimits::default()
        },
        MenfuguCompileLimits {
            max_generated_runtime_bytes: 8,
            ..MenfuguCompileLimits::default()
        },
        MenfuguCompileLimits {
            max_wasm_bytes: 8,
            ..MenfuguCompileLimits::default()
        },
        MenfuguCompileLimits {
            max_capsule_bytes: 64,
            ..MenfuguCompileLimits::default()
        },
    ] {
        assert!(compile(&artifacts(), &[service_code()], limits).is_err());
    }
}

#[test]
fn fixed_abi_and_frozen_contract_exclude_private_ingress() {
    let source = MenfuguPublicSourceArtifact::canonical();
    let compiled = compile_fixture(&source, &k7(&source));
    let wasm_text = String::from_utf8_lossy(compiled.wasm());
    for required in ["qseal", "emit_frame", "emit_action", "public_failure"] {
        assert!(wasm_text.contains(required));
    }
    for forbidden in [
        "private",
        "token_id",
        "replay_set",
        "biosignal",
        "baseline",
        "evidence",
        "nonce",
        "attestation",
    ] {
        assert!(!wasm_text.contains(forbidden));
    }

    let config = include_str!("../../../configs/quotient_seal/menfugu_p0_compiler_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_menfugu_p0_compiler_v1.md");
    assert!(config.contains("source_target_refinement: CHECKED_ALL_56_TRANSITIONS"));
    assert!(config.contains("private_import: FORBIDDEN"));
    assert!(config.contains("three_engine_equivalence: NOT_VERIFIED"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("Issue #198"));
    assert!(docs.contains("world-first"));
    assert!(docs.contains("NOT_VERIFIED"));
}
