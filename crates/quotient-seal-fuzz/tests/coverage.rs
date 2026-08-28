use quotient_seal_fuzz::{
    apply_public_feedback, AdaptiveContextBounds, AdaptiveContextState, AdaptiveHostAction,
    AdaptivePublicObservation, CorpusBounds, CorpusEntry, CorpusInsertDisposition, CoverageError,
    CoverageFeedback, CoverageKind, DeterministicCorpus, PublicCoverageSnapshot,
    PublicObserverDivergence, PublicUtilityViolation,
};
use std::collections::BTreeSet;

fn transition(marker: u8) -> quotient_seal_fuzz::AdaptiveStateTransition {
    let bounds = AdaptiveContextBounds {
        max_steps: 16,
        max_service_alias: 4,
        max_repeat: 4,
        max_faults: 4,
        max_public_events: 64,
    };
    let state = AdaptiveContextState::initial(bounds).expect("valid bounds");
    apply_public_feedback(
        state,
        AdaptiveHostAction::Tick { public_slot: 1 },
        AdaptivePublicObservation {
            event_count: 2,
            action_count: 1,
            trap_count: 0,
            host_call_count: 1,
            resource_units: 3,
            public_trace_sha256: [marker; 32],
        },
    )
    .expect("public transition")
}

fn feedback(marker: u8, target_block: u32) -> CoverageFeedback {
    CoverageFeedback::from_public_transition(
        &transition(marker),
        PublicCoverageSnapshot {
            target_block,
            product_source_state: 2,
            product_target_state: u32::from(marker),
            observer_divergence: Some(PublicObserverDivergence {
                observer_profile: 1,
                divergence_code: 7,
                public_trace_sha256: [marker; 32],
            }),
            utility_violation: Some(PublicUtilityViolation {
                obligation_id: 4,
                violation_code: 2,
                public_slot: u64::from(marker),
            }),
        },
    )
    .expect("coverage feedback")
}

fn corpus_bounds(max_entries: u32) -> CorpusBounds {
    CorpusBounds {
        max_entries,
        max_coverage_points: 64,
        max_actions_per_entry: 16,
    }
}

#[test]
fn five_public_feedback_categories_have_stable_sorted_ids() {
    let first = feedback(3, 11);
    let second = feedback(3, 11);
    assert_eq!(first.canonical_json().unwrap(), second.canonical_json().unwrap());
    assert_eq!(first.records.len(), 5);
    assert!(first
        .records
        .windows(2)
        .all(|pair| pair[0].coverage_id < pair[1].coverage_id));
    let kinds: BTreeSet<_> = first
        .records
        .iter()
        .map(|record| record.point.kind())
        .collect();
    assert_eq!(
        kinds,
        BTreeSet::from([
            CoverageKind::TargetBlock,
            CoverageKind::ProductState,
            CoverageKind::ObserverDivergence,
            CoverageKind::ContextState,
            CoverageKind::UtilityViolation,
        ])
    );
    assert_ne!(first.feedback_sha256, [0; 32]);
}

#[test]
fn same_seed_and_insert_sequence_produce_byte_identical_corpus() {
    let first = CorpusEntry::build(41, [1; 32], 3, feedback(3, 11)).unwrap();
    let second = CorpusEntry::build(42, [2; 32], 4, feedback(4, 12)).unwrap();
    let mut left = DeterministicCorpus::new(99, corpus_bounds(8)).unwrap();
    let mut right = DeterministicCorpus::new(99, corpus_bounds(8)).unwrap();
    for corpus in [&mut left, &mut right] {
        assert_eq!(
            corpus.insert(first.clone()).unwrap().disposition,
            CorpusInsertDisposition::Inserted
        );
        assert_eq!(
            corpus.insert(second.clone()).unwrap().disposition,
            CorpusInsertDisposition::Inserted
        );
    }
    assert_eq!(left.canonical_json().unwrap(), right.canonical_json().unwrap());
    assert_eq!(left.artifact_sha256, right.artifact_sha256);
    assert!(left
        .global_coverage
        .windows(2)
        .all(|pair| pair[0].coverage_id < pair[1].coverage_id));
}

#[test]
fn duplicate_and_non_increasing_entries_do_not_mutate_corpus() {
    let entry = CorpusEntry::build(41, [1; 32], 3, feedback(3, 11)).unwrap();
    let alias = CorpusEntry::build(42, [2; 32], 3, entry.feedback.clone()).unwrap();
    let mut corpus = DeterministicCorpus::new(99, corpus_bounds(8)).unwrap();
    corpus.insert(entry.clone()).unwrap();
    let before = corpus.canonical_json().unwrap();
    assert_eq!(
        corpus.insert(entry).unwrap().disposition,
        CorpusInsertDisposition::Duplicate
    );
    assert_eq!(
        corpus.insert(alias).unwrap().disposition,
        CorpusInsertDisposition::NoNewCoverage
    );
    assert_eq!(before, corpus.canonical_json().unwrap());
}

#[test]
fn collision_tamper_and_bounds_fail_closed() {
    let original = feedback(3, 11);
    let mut forged = original.records[1].clone();
    forged.coverage_id = original.records[0].coverage_id;
    assert_eq!(
        CoverageFeedback::build(vec![original.records[0].clone(), forged]).unwrap_err(),
        CoverageError::CoverageCollision
    );

    let mut tampered = original.clone();
    tampered.feedback_sha256[0] ^= 0xff;
    assert_eq!(tampered.validate().unwrap_err(), CoverageError::ArtifactMismatch);

    let mut corpus = DeterministicCorpus::new(99, corpus_bounds(1)).unwrap();
    corpus
        .insert(CorpusEntry::build(41, [1; 32], 3, original).unwrap())
        .unwrap();
    let error = corpus
        .insert(CorpusEntry::build(42, [2; 32], 3, feedback(4, 12)).unwrap())
        .unwrap_err();
    assert_eq!(error, CoverageError::CorpusEntryBound);
}

#[test]
fn canonical_artifact_contains_only_public_feedback() {
    let private_marker = "PRIVATE_BIOSIGNAL_DO_NOT_SERIALIZE";
    let entry = CorpusEntry::build(41, [1; 32], 3, feedback(3, 11)).unwrap();
    let mut corpus = DeterministicCorpus::new(99, corpus_bounds(8)).unwrap();
    corpus.insert(entry).unwrap();
    let artifact = String::from_utf8(corpus.canonical_json().unwrap()).unwrap();
    assert!(!artifact.contains(private_marker));
    assert!(artifact.contains("INJECTED_TEST_FIXTURE"));
    assert!(artifact.contains("NOT_VERIFIED"));
}
