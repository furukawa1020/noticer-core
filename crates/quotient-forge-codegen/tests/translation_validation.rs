mod common;

use quotient_forge_caqt::{artifact_digest, CertificateLimits, Digest};
use quotient_forge_codegen::{
    reference_transcript, validate_translation, BuildContext, ExecutionStatus, TargetKind,
    TranslationLimits, TranslationVerdict,
};

use common::{certificate, config};

fn make_transcript(target: TargetKind) -> quotient_forge_codegen::TranslationTranscript {
    let (bytes, expected) = certificate();
    reference_transcript(
        &bytes,
        expected,
        CertificateLimits::default(),
        &config(),
        BuildContext {
            target,
            manifest_digest: artifact_digest(b"test-manifest", b"manifest-v1"),
            compiler: "rustc".to_owned(),
            compiler_version: "test-version".to_owned(),
            command: "cargo build --offline".to_owned(),
        },
        TranslationLimits::default(),
    )
    .unwrap()
}

#[test]
fn native_and_wasm_reference_transcripts_are_valid() {
    for target in [TargetKind::NativeNoStd, TargetKind::Wasm32UnknownUnknown] {
        let observed = make_transcript(target);
        assert!(matches!(
            validate_translation(&observed, &observed, TranslationLimits::default()),
            TranslationVerdict::Valid(_)
        ));
    }
}

#[test]
fn mutated_transition_is_rejected() {
    let reference = make_transcript(TargetKind::NativeNoStd);
    let mut observed = reference.clone();
    observed.steps[0].next_state = Some(0);
    assert!(matches!(
        validate_translation(&reference, &observed, TranslationLimits::default()),
        TranslationVerdict::Mismatch(_)
    ));
}

#[test]
fn missing_step_and_extra_output_byte_are_rejected() {
    let reference = make_transcript(TargetKind::NativeNoStd);
    let mut missing = reference.clone();
    missing.steps.pop();
    assert!(matches!(
        validate_translation(&reference, &missing, TranslationLimits::default()),
        TranslationVerdict::Mismatch(_)
    ));

    let mut extra = reference.clone();
    extra.steps[0].output_bytes.push(0);
    assert!(matches!(
        validate_translation(&reference, &extra, TranslationLimits::default()),
        TranslationVerdict::Mismatch(_)
    ));
}

#[test]
fn output_endianness_change_is_rejected() {
    let reference = make_transcript(TargetKind::NativeNoStd);
    let mut observed = reference.clone();
    let length = observed.steps[0].output_bytes.len();
    observed.steps[0].output_bytes[length - 4..].reverse();
    assert!(matches!(
        validate_translation(&reference, &observed, TranslationLimits::default()),
        TranslationVerdict::Mismatch(_)
    ));
}

#[test]
fn overflow_status_and_reset_mismatch_are_rejected() {
    let reference = make_transcript(TargetKind::Wasm32UnknownUnknown);
    let mut overflow = reference.clone();
    overflow.invalid_probes[4].status = ExecutionStatus::Ok;
    assert!(matches!(
        validate_translation(&reference, &overflow, TranslationLimits::default()),
        TranslationVerdict::Mismatch(_)
    ));

    let mut reset = reference.clone();
    reset.lifecycle[1].reset_state = 1;
    assert!(matches!(
        validate_translation(&reference, &reset, TranslationLimits::default()),
        TranslationVerdict::Mismatch(_)
    ));
}

#[test]
fn manifest_binding_mismatch_is_rejected() {
    let reference = make_transcript(TargetKind::NativeNoStd);
    let mut observed = reference.clone();
    observed.build.manifest_digest = Digest::zero();
    assert!(matches!(
        validate_translation(&reference, &observed, TranslationLimits::default()),
        TranslationVerdict::Mismatch(_)
    ));
}

#[test]
fn observation_limit_never_degrades_to_valid() {
    let reference = make_transcript(TargetKind::NativeNoStd);
    let limits = TranslationLimits {
        max_observations: 1,
        ..TranslationLimits::default()
    };
    assert!(matches!(
        validate_translation(&reference, &reference, limits),
        TranslationVerdict::ResourceBound(_)
    ));
}
