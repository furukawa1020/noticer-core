use std::fs;

use quotient_seal_noticer::{
    existing_binding_type_names, DeploymentProfile, Digest, Epoch, ManifestDecodeError,
    ManifestError, NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest, P1ResourceEvidence,
    PolicyHash, WireServiceAlias, NOTICER_QSM_MANIFEST_BYTES,
};

fn digest(value: u8) -> Digest {
    Digest::new([value; 32])
}

fn binding(module_id: NoticerModuleId, value: u8) -> NoticerModuleBinding {
    NoticerModuleBinding {
        module_id,
        deployment_profile: DeploymentProfile::P0PublicQuotientOnly,
        service_alias: WireServiceAlias([value; 8]),
        epoch: Epoch(u64::from(value)),
        policy_hash: PolicyHash([value; 32]),
        source_digest: digest(value),
        source_certificate_digest: digest(value.wrapping_add(10)),
        generated_runtime_digest: digest(value.wrapping_add(20)),
        qsm_capsule_digest: digest(value.wrapping_add(30)),
        observer_registry_digest: digest(value.wrapping_add(40)),
        p1_resource_evidence: None,
    }
}

fn bindings() -> Vec<NoticerModuleBinding> {
    NoticerModuleId::ALL
        .iter()
        .enumerate()
        .map(|(index, module_id)| binding(*module_id, index as u8 + 1))
        .collect()
}

#[test]
fn exactly_five_modules_are_canonical_and_order_independent() {
    let first = NoticerQsmManifest::new(bindings()).expect("manifest");
    let mut reversed = bindings();
    reversed.reverse();
    let second = NoticerQsmManifest::new(reversed).expect("manifest");

    assert_eq!(first, second);
    assert_eq!(first.entries().len(), 5);
    assert_eq!(first.encode().len(), NOTICER_QSM_MANIFEST_BYTES);
    assert_eq!(first.digest(), second.digest());
    assert_eq!(
        first.binding(NoticerModuleId::Aplot).module_id,
        NoticerModuleId::Aplot
    );
}

#[test]
fn missing_and_duplicate_module_sets_fail_closed() {
    let mut missing = bindings();
    missing.pop();
    assert_eq!(
        NoticerQsmManifest::new(missing),
        Err(ManifestError::ModuleSet)
    );

    let mut duplicate = bindings();
    duplicate[4].module_id = NoticerModuleId::Aets;
    assert_eq!(
        NoticerQsmManifest::new(duplicate),
        Err(ManifestError::ModuleSet)
    );
}

#[test]
fn zero_public_bindings_and_artifact_digests_are_rejected() {
    let mut zero_service = bindings();
    zero_service[0].service_alias = WireServiceAlias([0; 8]);
    assert!(matches!(
        NoticerQsmManifest::new(zero_service),
        Err(ManifestError::PublicBinding(NoticerModuleId::Aets))
    ));

    let mut zero_qsm = bindings();
    zero_qsm[1].qsm_capsule_digest = Digest::zero();
    assert!(matches!(
        NoticerQsmManifest::new(zero_qsm),
        Err(ManifestError::ArtifactDigest(
            NoticerModuleId::Atv2FramePlanner
        ))
    ));
}

#[test]
fn p1_requires_public_resource_equivalence_evidence() {
    let mut missing = bindings();
    missing[3].deployment_profile = DeploymentProfile::P1SealedAdmission;
    assert!(matches!(
        NoticerQsmManifest::new(missing),
        Err(ManifestError::MissingP1Evidence(NoticerModuleId::Aepa))
    ));

    let mut valid = bindings();
    valid[3].deployment_profile = DeploymentProfile::P1SealedAdmission;
    valid[3].p1_resource_evidence = Some(P1ResourceEvidence {
        equivalence_certificate_digest: digest(91),
        relation_binding_digest: digest(92),
        checked_cases: 8,
    });
    let manifest = NoticerQsmManifest::new(valid).expect("P1 manifest");
    assert_eq!(
        manifest.binding(NoticerModuleId::Aepa).deployment_profile,
        DeploymentProfile::P1SealedAdmission
    );

    let mut unexpected = bindings();
    unexpected[0].p1_resource_evidence = Some(P1ResourceEvidence {
        equivalence_certificate_digest: digest(91),
        relation_binding_digest: digest(92),
        checked_cases: 8,
    });
    assert!(matches!(
        NoticerQsmManifest::new(unexpected),
        Err(ManifestError::UnexpectedP1Evidence(NoticerModuleId::Aets))
    ));
}

#[test]
fn strict_binary_decoder_rejects_trailing_private_payload_and_unknown_codes() {
    let manifest = NoticerQsmManifest::new(bindings()).expect("manifest");
    let encoded = manifest.encode();
    assert_eq!(
        NoticerQsmManifest::decode(&encoded).expect("decode"),
        manifest
    );

    let mut trailing = encoded.clone();
    trailing.extend_from_slice(b"raw-ppg-or-private-baseline");
    assert!(matches!(
        NoticerQsmManifest::decode(&trailing),
        Err(ManifestDecodeError::Length { .. })
    ));

    let mut unknown_module = encoded.clone();
    unknown_module[12] = 99;
    assert_eq!(
        NoticerQsmManifest::decode(&unknown_module),
        Err(ManifestDecodeError::Module(99))
    );

    let mut unknown_profile = encoded;
    unknown_profile[13] = 99;
    assert_eq!(
        NoticerQsmManifest::decode(&unknown_profile),
        Err(ManifestDecodeError::Profile(99))
    );
}

#[test]
fn every_public_or_artifact_binding_changes_manifest_digest() {
    let baseline = NoticerQsmManifest::new(bindings()).expect("manifest");
    let baseline_digest = baseline.digest();
    let mut mutations = Vec::new();

    let mut service = bindings();
    service[0].service_alias = WireServiceAlias([9; 8]);
    mutations.push(service);
    let mut epoch = bindings();
    epoch[0].epoch = Epoch(99);
    mutations.push(epoch);
    let mut policy = bindings();
    policy[0].policy_hash = PolicyHash([9; 32]);
    mutations.push(policy);
    let mut source = bindings();
    source[0].source_digest = digest(99);
    mutations.push(source);
    let mut certificate = bindings();
    certificate[0].source_certificate_digest = digest(99);
    mutations.push(certificate);
    let mut runtime = bindings();
    runtime[0].generated_runtime_digest = digest(99);
    mutations.push(runtime);
    let mut qsm = bindings();
    qsm[0].qsm_capsule_digest = digest(99);
    mutations.push(qsm);
    let mut observer = bindings();
    observer[0].observer_registry_digest = digest(99);
    mutations.push(observer);

    for mutation in mutations {
        assert_ne!(
            NoticerQsmManifest::new(mutation)
                .expect("mutated manifest")
                .digest(),
            baseline_digest
        );
    }
}

#[test]
fn existing_public_types_are_reused_and_private_crates_are_absent() {
    let names = existing_binding_type_names();
    assert!(names[0].starts_with("noticer_protocol::"));
    assert!(names[1].starts_with("noticer_types::"));
    assert!(names[2].starts_with("noticer_types::"));
    assert!(names[3].starts_with("quotient_seal_abi::"));

    let manifest =
        fs::read_to_string(format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"))).expect("Cargo");
    for forbidden in [
        "noticer-acquisition-core",
        "noticer-evidence",
        "noticer-evidence-bridge",
        "noticer-ppg-features",
        "noticer-baseline",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "forbidden dependency: {forbidden}"
        );
    }
}
