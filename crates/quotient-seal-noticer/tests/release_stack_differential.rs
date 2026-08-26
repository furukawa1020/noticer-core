use quotient_seal_noticer::{
    DifferentialDifference, DifferentialDifferenceKind, DifferentialEvidenceOrigin,
    DifferentialUnresolvedReason, EngineArtifactDigests, ModuleDifferentialEvidence,
    NoticerModuleId, ReleaseStackDifferentialArtifact, ReleaseStackDifferentialBindings,
    ReleaseStackDifferentialError, ReleaseStackDifferentialVerdict,
    RELEASE_STACK_DIFFERENTIAL_SCHEMA,
};

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn bindings() -> ReleaseStackDifferentialBindings {
    ReleaseStackDifferentialBindings {
        manifest_sha256: digest(1),
        composition_contract_sha256: digest(2),
        path_contract_sha256: digest(3),
        profile_contract_sha256: digest(4),
    }
}

fn evidence(index: usize) -> ModuleDifferentialEvidence {
    let base = 10 + (index as u8 * 4);
    ModuleDifferentialEvidence::from_existing_artifact(
        NoticerModuleId::ALL[index],
        digest(base),
        EngineArtifactDigests {
            reference_sha256: digest(base + 1),
            wasmi_sha256: digest(base + 2),
            wasmtime_sha256: digest(base + 3),
        },
        ReleaseStackDifferentialVerdict::Match,
        None,
        None,
        DifferentialEvidenceOrigin::ExecutedSoftware,
    )
}

fn all_match() -> [ModuleDifferentialEvidence; 5] {
    std::array::from_fn(evidence)
}

#[test]
fn five_stage_three_engine_match_is_deterministic() {
    let first = ReleaseStackDifferentialArtifact::evaluate(bindings(), all_match()).unwrap();
    let second = ReleaseStackDifferentialArtifact::evaluate(bindings(), all_match()).unwrap();

    assert_eq!(first.schema, RELEASE_STACK_DIFFERENTIAL_SCHEMA);
    assert_eq!(first.verdict, ReleaseStackDifferentialVerdict::Match);
    assert_eq!(first.first_counterexample_module, None);
    assert_eq!(first.first_unresolved_module, None);
    assert_eq!(
        first.evidence_origin,
        DifferentialEvidenceOrigin::ExecutedSoftware
    );
    assert_eq!(first, second);
    first.verify_complete_recomputation().unwrap();
}

#[test]
fn counterexample_dominates_unresolved_without_rounding_to_match() {
    let mut modules = all_match();
    modules[1].verdict = ReleaseStackDifferentialVerdict::Unresolved;
    modules[1].unresolved_reason = Some(DifferentialUnresolvedReason::EngineTimeout);
    modules[3].verdict = ReleaseStackDifferentialVerdict::Counterexample;
    modules[3].first_difference = Some(DifferentialDifference {
        kind: DifferentialDifferenceKind::HostCall,
        step_index: 7,
    });
    modules[3].evidence_origin = DifferentialEvidenceOrigin::InjectedTestFixture;

    let artifact = ReleaseStackDifferentialArtifact::evaluate(bindings(), modules).unwrap();

    assert_eq!(
        artifact.verdict,
        ReleaseStackDifferentialVerdict::Counterexample
    );
    assert_eq!(
        artifact.first_counterexample_module,
        Some(NoticerModuleId::Aepa)
    );
    assert_eq!(
        artifact.first_unresolved_module,
        Some(NoticerModuleId::Atv2FramePlanner)
    );
    assert_eq!(
        artifact.evidence_origin,
        DifferentialEvidenceOrigin::InjectedTestFixture
    );
    artifact.verify_complete_recomputation().unwrap();
}

#[test]
fn unresolved_is_preserved_when_no_counterexample_exists() {
    let mut modules = all_match();
    modules[2].verdict = ReleaseStackDifferentialVerdict::Unresolved;
    modules[2].unresolved_reason = Some(DifferentialUnresolvedReason::MissingWasmtimeRun);

    let artifact = ReleaseStackDifferentialArtifact::evaluate(bindings(), modules).unwrap();

    assert_eq!(
        artifact.verdict,
        ReleaseStackDifferentialVerdict::Unresolved
    );
    assert_eq!(
        artifact.first_unresolved_module,
        Some(NoticerModuleId::Aplot)
    );
    assert_eq!(artifact.first_counterexample_module, None);
}

#[test]
fn canonical_order_and_verdict_evidence_are_rejected_when_invalid() {
    let mut wrong_order = all_match();
    wrong_order.swap(0, 1);
    assert!(matches!(
        ReleaseStackDifferentialArtifact::evaluate(bindings(), wrong_order),
        Err(ReleaseStackDifferentialError::UnexpectedModule { index: 0, .. })
    ));

    let mut inconsistent = all_match();
    inconsistent[0].verdict = ReleaseStackDifferentialVerdict::Counterexample;
    assert!(matches!(
        ReleaseStackDifferentialArtifact::evaluate(bindings(), inconsistent),
        Err(ReleaseStackDifferentialError::InvalidVerdictEvidence(
            NoticerModuleId::Aets
        ))
    ));
}

#[test]
fn every_binding_and_engine_digest_is_required() {
    let mut zero_binding = bindings();
    zero_binding.path_contract_sha256 = [0; 32];
    assert_eq!(
        ReleaseStackDifferentialArtifact::evaluate(zero_binding, all_match()),
        Err(ReleaseStackDifferentialError::ZeroBinding("path_contract"))
    );

    let mut zero_engine = all_match();
    zero_engine[4].engines.wasmi_sha256 = [0; 32];
    assert!(matches!(
        ReleaseStackDifferentialArtifact::evaluate(bindings(), zero_engine),
        Err(ReleaseStackDifferentialError::ZeroEngineDigest {
            module: NoticerModuleId::MenfuguExecutionPlanner,
            engine: "wasmi"
        })
    ));
}

#[test]
fn complete_recomputation_detects_any_bound_digest_change() {
    let mut artifact = ReleaseStackDifferentialArtifact::evaluate(bindings(), all_match()).unwrap();
    artifact.modules[2].engines.wasmtime_sha256[0] ^= 0xff;

    assert_eq!(
        artifact.verify_complete_recomputation(),
        Err(ReleaseStackDifferentialError::ArtifactMismatch)
    );
}
