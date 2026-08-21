use noticer_protocol::{KeyId, WireServiceAlias};
use noticer_types::{ActionCode, Epoch, PolicyHash};
use quotient_seal_abi::DeploymentProfile;
use quotient_seal_noticer::{
    bind_menfugu_k7_manifest, Digest, MenfuguBindingError, MenfuguK7Binding, MenfuguPublicInput,
    MenfuguPublicOutput, MenfuguPublicPolicyBinding, MenfuguPublicSourceArtifact,
    MenfuguPublicState, NoticerModuleBinding, NoticerModuleId,
};

fn digest(value: u8) -> Digest {
    Digest::new([value; 32])
}

fn policy() -> MenfuguPublicPolicyBinding {
    MenfuguPublicPolicyBinding {
        service_alias: WireServiceAlias([0x11; 8]),
        epoch: Epoch(7),
        policy_hash: PolicyHash([0x22; 32]),
        verifier_key_id: KeyId([0x33; 8]),
        allowed_action: ActionCode::MenfuguInflateSoft,
        pump_ticks: 20,
        maximum_pump_ticks: 25,
        cooldown_slots: 3,
        execution_period_slots: 4,
        execution_offset_slots: 1,
        public_deadline_slots: 2,
    }
}

fn k7(source: &MenfuguPublicSourceArtifact) -> MenfuguK7Binding {
    MenfuguK7Binding {
        public_policy_digest: policy().digest().expect("valid policy"),
        source_digest: source.digest,
        source_certificate_digest: digest(0x44),
        generated_runtime_digest: digest(0x55),
        qsm_capsule_digest: digest(0x66),
        observer_registry_digest: digest(0x77),
    }
}

fn module(binding: MenfuguK7Binding) -> NoticerModuleBinding {
    let policy = policy();
    NoticerModuleBinding {
        module_id: NoticerModuleId::MenfuguExecutionPlanner,
        deployment_profile: DeploymentProfile::P0PublicQuotientOnly,
        service_alias: policy.service_alias,
        epoch: policy.epoch,
        policy_hash: policy.policy_hash,
        source_digest: binding.source_digest,
        source_certificate_digest: binding.source_certificate_digest,
        generated_runtime_digest: binding.generated_runtime_digest,
        qsm_capsule_digest: binding.qsm_capsule_digest,
        observer_registry_digest: binding.observer_registry_digest,
        p1_resource_evidence: None,
    }
}

#[test]
fn canonical_source_is_total_and_stable() {
    let source = MenfuguPublicSourceArtifact::canonical();
    source.verify().expect("canonical source");
    assert_eq!(
        source.transitions.len(),
        MenfuguPublicState::ALL.len() * MenfuguPublicInput::ALL.len()
    );
    assert_eq!(source, MenfuguPublicSourceArtifact::canonical());

    let mut missing = source.clone();
    missing.transitions.pop();
    assert_eq!(missing.verify(), Err(MenfuguBindingError::TransitionCount));

    let mut reordered = source.clone();
    reordered.transitions.swap(0, 1);
    assert!(matches!(
        reordered.verify(),
        Err(MenfuguBindingError::NonCanonicalTransition { .. })
    ));
}

#[test]
fn only_first_ready_authorization_executes_an_action() {
    let source = MenfuguPublicSourceArtifact::canonical();
    let first = source
        .step(
            MenfuguPublicState::Ready,
            MenfuguPublicInput::AuthorizedAction,
        )
        .expect("first action");
    assert_eq!(first.next_state, MenfuguPublicState::Executing);
    assert_eq!(first.output, MenfuguPublicOutput::ExecuteOnce);
    assert!(first.output.executes_action());

    let duplicate = source
        .step(first.next_state, MenfuguPublicInput::AuthorizedAction)
        .expect("duplicate action");
    assert_eq!(duplicate.output, MenfuguPublicOutput::Reject);
    assert!(!duplicate.output.executes_action());

    for rejection in [
        MenfuguPublicInput::ReplayRejected,
        MenfuguPublicInput::ExpiredRejected,
        MenfuguPublicInput::WrongServiceRejected,
        MenfuguPublicInput::WrongPolicyRejected,
        MenfuguPublicInput::WrongKeyRejected,
        MenfuguPublicInput::DuplicateTransport,
    ] {
        let transition = source
            .step(MenfuguPublicState::Ready, rejection)
            .expect("rejection");
        assert_eq!(transition.output, MenfuguPublicOutput::Reject);
        assert!(!transition.output.executes_action());
    }
}

#[test]
fn reset_handoff_deadline_and_fault_are_fail_closed() {
    let source = MenfuguPublicSourceArtifact::canonical();
    let deadline = source
        .step(MenfuguPublicState::Executing, MenfuguPublicInput::Deadline)
        .expect("deadline");
    assert_eq!(deadline.next_state, MenfuguPublicState::Cooldown);
    assert_eq!(deadline.output, MenfuguPublicOutput::Stop);

    let fault = source
        .step(MenfuguPublicState::Ready, MenfuguPublicInput::Fault)
        .expect("fault");
    assert_eq!(fault.next_state, MenfuguPublicState::FailClosed);
    assert_eq!(fault.output, MenfuguPublicOutput::FailClosed);

    let blocked = source
        .step(fault.next_state, MenfuguPublicInput::AuthorizedAction)
        .expect("blocked action");
    assert!(!blocked.output.executes_action());

    let reset = source
        .step(fault.next_state, MenfuguPublicInput::Reset)
        .expect("trusted reset");
    assert_eq!(reset.next_state, MenfuguPublicState::Ready);
    assert_eq!(reset.output, MenfuguPublicOutput::StopAndReset);

    let handoff = source
        .step(MenfuguPublicState::Executing, MenfuguPublicInput::Handoff)
        .expect("handoff");
    assert_eq!(handoff.next_state, MenfuguPublicState::Ready);
    assert_eq!(handoff.output, MenfuguPublicOutput::StopAndHandoff);
}

#[test]
fn public_policy_maps_to_existing_executor_policy() {
    let binding = policy();
    let execution = binding.execution_policy().expect("execution policy");
    assert_eq!(execution.pump_ticks, binding.pump_ticks);
    assert_eq!(execution.maximum_pump_ticks, binding.maximum_pump_ticks);
    assert_eq!(execution.cooldown_slots, binding.cooldown_slots);
    assert_eq!(
        execution.execution_period_slots,
        binding.execution_period_slots
    );
    assert_eq!(
        execution.execution_offset_slots,
        binding.execution_offset_slots
    );

    let mut wrong_action = binding;
    wrong_action.allowed_action = ActionCode::RenderAmbientPulse;
    assert_eq!(
        wrong_action.validate(),
        Err(MenfuguBindingError::InvalidPolicy)
    );
}

#[test]
fn k7_and_manifest_tampering_fail_closed() {
    let source = MenfuguPublicSourceArtifact::canonical();
    let k7 = k7(&source);
    let module = module(k7);
    bind_menfugu_k7_manifest(&source, policy(), k7, module).expect("valid binding");

    let mut tampered_source = source.clone();
    tampered_source.digest = digest(0x99);
    assert_eq!(
        bind_menfugu_k7_manifest(&tampered_source, policy(), k7, module),
        Err(MenfuguBindingError::SourceDigest)
    );

    let mut wrong_policy = policy();
    wrong_policy.verifier_key_id = KeyId([0x88; 8]);
    assert_eq!(
        bind_menfugu_k7_manifest(&source, wrong_policy, k7, module),
        Err(MenfuguBindingError::K7Mismatch("public_policy_digest"))
    );

    let mut wrong_k7 = k7;
    wrong_k7.source_certificate_digest = digest(0x98);
    assert_eq!(
        bind_menfugu_k7_manifest(&source, policy(), wrong_k7, module),
        Err(MenfuguBindingError::ManifestMismatch(
            "source_certificate_digest"
        ))
    );
    wrong_k7 = k7;
    wrong_k7.generated_runtime_digest = digest(0x97);
    assert_eq!(
        bind_menfugu_k7_manifest(&source, policy(), wrong_k7, module),
        Err(MenfuguBindingError::ManifestMismatch(
            "generated_runtime_digest"
        ))
    );

    for (field, tampered) in [
        (
            "source_digest",
            NoticerModuleBinding {
                source_digest: digest(1),
                ..module
            },
        ),
        (
            "source_certificate_digest",
            NoticerModuleBinding {
                source_certificate_digest: digest(2),
                ..module
            },
        ),
        (
            "generated_runtime_digest",
            NoticerModuleBinding {
                generated_runtime_digest: digest(3),
                ..module
            },
        ),
        (
            "qsm_capsule_digest",
            NoticerModuleBinding {
                qsm_capsule_digest: digest(4),
                ..module
            },
        ),
        (
            "observer_registry_digest",
            NoticerModuleBinding {
                observer_registry_digest: digest(5),
                ..module
            },
        ),
    ] {
        assert_eq!(
            bind_menfugu_k7_manifest(&source, policy(), k7, tampered),
            Err(MenfuguBindingError::ManifestMismatch(field))
        );
    }

    let wrong_profile = NoticerModuleBinding {
        deployment_profile: DeploymentProfile::P1SealedAdmission,
        ..module
    };
    assert_eq!(
        bind_menfugu_k7_manifest(&source, policy(), k7, wrong_profile),
        Err(MenfuguBindingError::ManifestMismatch("deployment_profile"))
    );

    let wrong_service = NoticerModuleBinding {
        service_alias: WireServiceAlias([0x99; 8]),
        ..module
    };
    assert_eq!(
        bind_menfugu_k7_manifest(&source, policy(), k7, wrong_service),
        Err(MenfuguBindingError::ManifestMismatch("service_alias"))
    );
}
