use quotient_seal_noticer::{
    execute_canonical_release_path, verify_canonical_release_path, DeploymentProfile, Digest,
    Epoch, NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest, PolicyHash, ReleasePathKind,
    ReleaseStackCompositionContract, ReleaseStackPathError, ReleaseStackPublicInput,
    WireServiceAlias, RELEASE_STACK_CANONICAL_SEED, RELEASE_STACK_HARDWARE_STATUS,
};

fn digest(value: u8) -> Digest {
    Digest::new([value; 32])
}

fn contract() -> ReleaseStackCompositionContract {
    let entries = NoticerModuleId::ALL
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
                source_certificate_digest: digest(value + 10),
                generated_runtime_digest: digest(value + 20),
                qsm_capsule_digest: digest(value + 30),
                observer_registry_digest: digest(value + 40),
                p1_resource_evidence: None,
            }
        })
        .collect();
    ReleaseStackCompositionContract::new(NoticerQsmManifest::new(entries).expect("manifest"))
        .expect("contract")
}

#[test]
fn action_and_cover_paths_chain_exactly_five_receipts() {
    let contract = contract();
    let action_input =
        ReleaseStackPublicInput::new(ReleasePathKind::Action, 42, Some(7)).expect("action input");
    let action = execute_canonical_release_path(&contract, action_input).expect("action path");
    assert_eq!(action.receipts.len(), 5);
    assert_eq!(action.authorized_action_count, 1);
    assert_eq!(action.cover_count, 0);
    assert_eq!(action.hardware_status, RELEASE_STACK_HARDWARE_STATUS);
    verify_canonical_release_path(&contract, &action).expect("verify action");

    for pair in action.receipts.windows(2) {
        assert_eq!(pair[1].input_commitment, pair[0].output_commitment);
        assert_eq!(pair[1].predecessor_receipt_digest, pair[0].receipt_digest);
    }

    let cover_input =
        ReleaseStackPublicInput::new(ReleasePathKind::Cover, 42, None).expect("cover input");
    let cover = execute_canonical_release_path(&contract, cover_input).expect("cover path");
    assert_eq!(cover.authorized_action_count, 0);
    assert_eq!(cover.cover_count, 1);
    verify_canonical_release_path(&contract, &cover).expect("verify cover");
    assert_ne!(action.artifact_digest, cover.artifact_digest);
}

#[test]
fn canonical_seed_and_artifact_are_byte_for_byte_deterministic() {
    let contract = contract();
    let input = ReleaseStackPublicInput::new(ReleasePathKind::Action, 9, Some(3)).expect("input");
    assert_eq!(input.deterministic_seed(), RELEASE_STACK_CANONICAL_SEED);
    let first = execute_canonical_release_path(&contract, input.clone()).expect("first");
    let second = execute_canonical_release_path(&contract, input).expect("second");
    assert_eq!(first, second);
}

#[test]
fn missing_reordered_and_reused_receipts_fail_closed() {
    let contract = contract();
    let input = ReleaseStackPublicInput::new(ReleasePathKind::Action, 1, Some(1)).expect("input");
    let artifact = execute_canonical_release_path(&contract, input).expect("artifact");

    let mut missing = artifact.clone();
    missing.receipts.pop();
    assert_eq!(
        verify_canonical_release_path(&contract, &missing),
        Err(ReleaseStackPathError::ReceiptCount { actual: 4 })
    );

    let mut reordered = artifact.clone();
    reordered.receipts.swap(1, 2);
    assert_eq!(
        verify_canonical_release_path(&contract, &reordered),
        Err(ReleaseStackPathError::ReceiptOrder { index: 1 })
    );

    let mut reused = artifact;
    reused.receipts[2] = reused.receipts[1].clone();
    assert_eq!(
        verify_canonical_release_path(&contract, &reused),
        Err(ReleaseStackPathError::ReceiptOrder { index: 2 })
    );
}

#[test]
fn chain_binding_and_digest_tampering_fail_closed() {
    let contract = contract();
    let input = ReleaseStackPublicInput::new(ReleasePathKind::Cover, 5, None).expect("input");
    let artifact = execute_canonical_release_path(&contract, input).expect("artifact");

    let mut chain = artifact.clone();
    chain.receipts[2].input_commitment = Digest::zero();
    assert_eq!(
        verify_canonical_release_path(&contract, &chain),
        Err(ReleaseStackPathError::ReceiptChain { index: 2 })
    );

    let mut binding = artifact.clone();
    binding.receipts[3].qsm_capsule_digest = Digest::zero();
    assert_eq!(
        verify_canonical_release_path(&contract, &binding),
        Err(ReleaseStackPathError::StageBinding { index: 3 })
    );

    let mut digest_tamper = artifact.clone();
    digest_tamper.receipts[4].receipt_digest = Digest::zero();
    assert_eq!(
        verify_canonical_release_path(&contract, &digest_tamper),
        Err(ReleaseStackPathError::ReceiptDigest { index: 4 })
    );

    let mut artifact_tamper = artifact;
    artifact_tamper.artifact_digest = Digest::zero();
    assert_eq!(
        verify_canonical_release_path(&contract, &artifact_tamper),
        Err(ReleaseStackPathError::ArtifactDigest)
    );
}

#[test]
fn public_input_rejects_action_cover_ambiguity_and_contains_no_private_payload() {
    assert_eq!(
        ReleaseStackPublicInput::new(ReleasePathKind::Action, 0, None),
        Err(ReleaseStackPathError::InvalidInput)
    );
    assert_eq!(
        ReleaseStackPublicInput::new(ReleasePathKind::Cover, 0, Some(1)),
        Err(ReleaseStackPathError::InvalidInput)
    );

    let contract = contract();
    let input = ReleaseStackPublicInput::new(ReleasePathKind::Cover, 0, None).expect("input");
    let artifact = execute_canonical_release_path(&contract, input).expect("artifact");
    let public_debug = format!("{artifact:?}");
    for forbidden in [
        "raw_ppg",
        "private_baseline",
        "k1_raw_feature",
        "private_token_material",
        "replay_state",
        "subject-17",
    ] {
        assert!(!public_debug.contains(forbidden));
    }
}
