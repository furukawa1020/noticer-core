use quotient_seal_noticer::{
    DeploymentProfile, Digest, Epoch, NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest,
    P1ResourceEvidence, PolicyHash, ReleaseStackCompositionContract, ReleaseStackCompositionError,
    WireServiceAlias, NOTICER_QSM_MANIFEST_BYTES, RELEASE_STACK_COMPOSITION_BYTES,
    RELEASE_STACK_COMPOSITION_MAGIC, RELEASE_STACK_COMPOSITION_VERSION,
    RELEASE_STACK_FORBIDDEN_FIELDS, RELEASE_STACK_HANDOFFS, RELEASE_STACK_HARDWARE_STATUS,
};

fn digest(value: u8) -> Digest {
    Digest::new([value; 32])
}

fn bindings() -> Vec<NoticerModuleBinding> {
    NoticerModuleId::ALL
        .iter()
        .enumerate()
        .map(|(index, module_id)| {
            let value = index as u8 + 1;
            NoticerModuleBinding {
                module_id: *module_id,
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
        })
        .collect()
}

fn contract() -> ReleaseStackCompositionContract {
    ReleaseStackCompositionContract::new(NoticerQsmManifest::new(bindings()).expect("manifest"))
        .expect("composition contract")
}

#[test]
fn canonical_contract_has_fixed_golden_layout_and_round_trips() {
    let contract = contract();
    let bytes = contract.canonical_bytes();
    assert_eq!(bytes.len(), RELEASE_STACK_COMPOSITION_BYTES);
    assert_eq!(&bytes[..8], &RELEASE_STACK_COMPOSITION_MAGIC);
    assert_eq!(
        u16::from_le_bytes(bytes[8..10].try_into().expect("version")),
        RELEASE_STACK_COMPOSITION_VERSION
    );
    assert_eq!(&bytes[10..12], &[0, 0]);
    assert_eq!(
        u32::from_le_bytes(bytes[12..16].try_into().expect("length")) as usize,
        NOTICER_QSM_MANIFEST_BYTES
    );

    let suffix = 16 + NOTICER_QSM_MANIFEST_BYTES;
    assert_eq!(&bytes[suffix..suffix + 6], &[5, 1, 2, 3, 4, 5]);
    assert_eq!(
        &bytes[suffix + 6..suffix + 15],
        &[4, 1, 2, 2, 3, 3, 4, 4, 5]
    );
    assert_eq!(bytes[bytes.len() - 1], 0);

    let decoded = ReleaseStackCompositionContract::decode(bytes).expect("decode");
    assert_eq!(decoded.canonical_bytes(), bytes);
    assert_eq!(decoded.digest(), contract.digest());
    assert_eq!(decoded.stages(), NoticerModuleId::ALL);
    assert_eq!(decoded.handoffs(), RELEASE_STACK_HANDOFFS);
    assert_eq!(decoded.hardware_status(), RELEASE_STACK_HARDWARE_STATUS);
}

#[test]
fn stage_and_handoff_tampering_fail_closed() {
    let baseline = contract();
    let suffix = 16 + NOTICER_QSM_MANIFEST_BYTES;

    let mut reordered = baseline.canonical_bytes().to_vec();
    reordered.swap(suffix + 1, suffix + 2);
    assert_eq!(
        ReleaseStackCompositionContract::decode(&reordered),
        Err(ReleaseStackCompositionError::StageOrder)
    );

    let mut wrong_handoff = baseline.canonical_bytes().to_vec();
    wrong_handoff[suffix + 8] = NoticerModuleId::MenfuguExecutionPlanner as u8;
    assert_eq!(
        ReleaseStackCompositionContract::decode(&wrong_handoff),
        Err(ReleaseStackCompositionError::Handoff)
    );

    let mut missing = baseline.canonical_bytes().to_vec();
    missing[suffix] = 4;
    assert_eq!(
        ReleaseStackCompositionContract::decode(&missing),
        Err(ReleaseStackCompositionError::StageCount(4))
    );
}

#[test]
fn privacy_hardware_and_trailing_payload_tampering_fail_closed() {
    let baseline = contract();
    let suffix = 16 + NOTICER_QSM_MANIFEST_BYTES;
    let privacy_offset = suffix + 15;

    let mut privacy = baseline.canonical_bytes().to_vec();
    privacy[privacy_offset] ^= 0x01;
    assert_eq!(
        ReleaseStackCompositionContract::decode(&privacy),
        Err(ReleaseStackCompositionError::PrivacyBoundary)
    );

    let mut hardware = baseline.canonical_bytes().to_vec();
    let final_index = hardware.len() - 1;
    hardware[final_index] = 1;
    assert_eq!(
        ReleaseStackCompositionContract::decode(&hardware),
        Err(ReleaseStackCompositionError::HardwareStatus(1))
    );

    let mut trailing = baseline.canonical_bytes().to_vec();
    trailing.extend_from_slice(b"private-payload");
    assert!(matches!(
        ReleaseStackCompositionContract::decode(&trailing),
        Err(ReleaseStackCompositionError::Length { .. })
    ));
}

#[test]
fn public_contract_contains_no_private_field_or_value() {
    let contract = contract();
    let text = String::from_utf8_lossy(contract.canonical_bytes());
    for forbidden in RELEASE_STACK_FORBIDDEN_FIELDS {
        assert!(!text.contains(forbidden));
    }
    for private_value in ["subject-17", "raw-ppg", "baseline-vector", "replay-secret"] {
        assert!(!text.contains(private_value));
    }
    assert_ne!(contract.privacy_registry_digest(), Digest::zero());
}

#[test]
fn profile_and_every_public_binding_are_covered_by_composition_digest() {
    let baseline = contract().digest();

    let mut changed = bindings();
    changed[0].policy_hash = PolicyHash([99; 32]);
    let changed = ReleaseStackCompositionContract::new(
        NoticerQsmManifest::new(changed).expect("changed manifest"),
    )
    .expect("changed contract");
    assert_ne!(changed.digest(), baseline);

    let mut p1 = bindings();
    p1[3].deployment_profile = DeploymentProfile::P1SealedAdmission;
    p1[3].p1_resource_evidence = Some(P1ResourceEvidence {
        equivalence_certificate_digest: digest(91),
        relation_binding_digest: digest(92),
        checked_cases: 8,
    });
    let p1 =
        ReleaseStackCompositionContract::new(NoticerQsmManifest::new(p1).expect("P1 manifest"))
            .expect("P1 contract");
    assert_ne!(p1.digest(), baseline);
}
