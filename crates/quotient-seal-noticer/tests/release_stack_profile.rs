use quotient_seal_noticer::{
    evaluate_release_stack_profile, execute_canonical_release_path, verify_release_stack_profile,
    DeploymentProfile, Digest, Epoch, NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest,
    P1ResourceEvidence, PolicyHash, ReleasePathKind, ReleaseStackCompositionContract,
    ReleaseStackProfileError, ReleaseStackProfileUnresolvedReason, ReleaseStackProfileVerdict,
    ReleaseStackPublicInput, WireServiceAlias, RELEASE_STACK_HARDWARE_STATUS,
};

fn digest(value: u8) -> Digest {
    Digest::new([value; 32])
}

fn contract(
    profile: DeploymentProfile,
    p1_module: NoticerModuleId,
) -> ReleaseStackCompositionContract {
    let entries = NoticerModuleId::ALL
        .iter()
        .enumerate()
        .map(|(index, module_id)| {
            let value = index as u8 + 1;
            let is_p1 = profile == DeploymentProfile::P1SealedAdmission && *module_id == p1_module;
            NoticerModuleBinding {
                module_id: *module_id,
                deployment_profile: if is_p1 {
                    DeploymentProfile::P1SealedAdmission
                } else {
                    DeploymentProfile::P0PublicQuotientOnly
                },
                service_alias: WireServiceAlias([value; 8]),
                epoch: Epoch(u64::from(value)),
                policy_hash: PolicyHash([value; 32]),
                source_digest: digest(value),
                source_certificate_digest: digest(value + 10),
                generated_runtime_digest: digest(value + 20),
                qsm_capsule_digest: digest(value + 30),
                observer_registry_digest: digest(value + 40),
                p1_resource_evidence: is_p1.then_some(P1ResourceEvidence {
                    equivalence_certificate_digest: digest(91),
                    relation_binding_digest: digest(92),
                    checked_cases: 8,
                }),
            }
        })
        .collect();
    ReleaseStackCompositionContract::new(NoticerQsmManifest::new(entries).expect("manifest"))
        .expect("contract")
}

fn path(
    contract: &ReleaseStackCompositionContract,
) -> quotient_seal_noticer::ReleaseStackPathArtifact {
    let input = ReleaseStackPublicInput::new(ReleasePathKind::Action, 9, Some(3)).expect("input");
    execute_canonical_release_path(contract, input).expect("path")
}

#[test]
fn p0_authorizes_without_p1_evidence() {
    let contract = contract(
        DeploymentProfile::P0PublicQuotientOnly,
        NoticerModuleId::Aepa,
    );
    let path = path(&contract);
    let artifact = evaluate_release_stack_profile(
        &contract,
        &path,
        DeploymentProfile::P0PublicQuotientOnly,
        9,
        None,
    )
    .expect("P0 evaluation");
    assert_eq!(artifact.verdict, ReleaseStackProfileVerdict::Authorized);
    assert_eq!(
        artifact.effective_profile,
        Some(DeploymentProfile::P0PublicQuotientOnly)
    );
    assert_eq!(artifact.unresolved_reason, None);
    assert_eq!(artifact.manifest_evidence_digest, None);
    assert_eq!(artifact.hardware_status, RELEASE_STACK_HARDWARE_STATUS);
    verify_release_stack_profile(&contract, &path, &artifact, None).expect("verify P0");
}

#[test]
fn requested_p1_never_downgrades_to_p0() {
    let contract = contract(
        DeploymentProfile::P0PublicQuotientOnly,
        NoticerModuleId::Aepa,
    );
    let path = path(&contract);
    let artifact = evaluate_release_stack_profile(
        &contract,
        &path,
        DeploymentProfile::P1SealedAdmission,
        9,
        None,
    )
    .expect("P1 evaluation");
    assert_eq!(
        artifact.verdict,
        ReleaseStackProfileVerdict::ProfileUnresolved
    );
    assert_eq!(artifact.effective_profile, None);
    assert_eq!(
        artifact.unresolved_reason,
        Some(ReleaseStackProfileUnresolvedReason::ProfileTopology)
    );
}

#[test]
fn p1_without_fresh_aepa_authorization_is_unresolved() {
    let contract = contract(DeploymentProfile::P1SealedAdmission, NoticerModuleId::Aepa);
    let path = path(&contract);
    let artifact = evaluate_release_stack_profile(
        &contract,
        &path,
        DeploymentProfile::P1SealedAdmission,
        9,
        None,
    )
    .expect("P1 evaluation");
    assert_eq!(
        artifact.verdict,
        ReleaseStackProfileVerdict::ProfileUnresolved
    );
    assert_eq!(artifact.effective_profile, None);
    assert_eq!(
        artifact.unresolved_reason,
        Some(ReleaseStackProfileUnresolvedReason::MissingAepaAuthorization)
    );
    assert_eq!(artifact.manifest_evidence_digest, Some(digest(91)));
    verify_release_stack_profile(&contract, &path, &artifact, None).expect("verify unresolved");
}

#[test]
fn p1_on_a_non_aepa_stage_is_unresolved() {
    let contract = contract(DeploymentProfile::P1SealedAdmission, NoticerModuleId::Aplot);
    let path = path(&contract);
    let artifact = evaluate_release_stack_profile(
        &contract,
        &path,
        DeploymentProfile::P1SealedAdmission,
        9,
        None,
    )
    .expect("P1 evaluation");
    assert_eq!(
        artifact.unresolved_reason,
        Some(ReleaseStackProfileUnresolvedReason::ProfileTopology)
    );
    assert_eq!(artifact.effective_profile, None);
}

#[test]
fn artifact_tampering_and_private_material_fail_closed() {
    let contract = contract(
        DeploymentProfile::P0PublicQuotientOnly,
        NoticerModuleId::Aepa,
    );
    let path = path(&contract);
    let artifact = evaluate_release_stack_profile(
        &contract,
        &path,
        DeploymentProfile::P0PublicQuotientOnly,
        9,
        None,
    )
    .expect("P0 evaluation");

    let mut digest_tamper = artifact.clone();
    digest_tamper.artifact_digest = Digest::zero();
    assert_eq!(
        verify_release_stack_profile(&contract, &path, &digest_tamper, None),
        Err(ReleaseStackProfileError::ArtifactDigest)
    );

    let mut verdict_tamper = artifact.clone();
    verdict_tamper.verdict = ReleaseStackProfileVerdict::ProfileUnresolved;
    assert_eq!(
        verify_release_stack_profile(&contract, &path, &verdict_tamper, None),
        Err(ReleaseStackProfileError::NonCanonical)
    );

    let public_debug = format!("{artifact:?}");
    for forbidden in [
        "raw_ppg",
        "private_baseline",
        "k1_raw_feature",
        "private_token_material",
        "replay_state",
    ] {
        assert!(!public_debug.contains(forbidden));
    }
}
