use std::collections::BTreeMap;

use quotient_forge_check::{
    ActionEmission, ActionId, CanonicalCounterexampleKind, CatalogInsert, CausalField,
    Counterexample, CounterexampleCatalog, CounterexampleKind, CounterexampleSignature,
    EnvironmentInput, FieldId, InputId, ObligationId, ObligationRef, Observation, ObserverId,
    Release, RepairCandidate, StateId, TraceStep,
};

fn action(name: &str, obligation: &str) -> ActionEmission {
    ActionEmission {
        obligation: ObligationRef::Authorized(ObligationId::from(obligation)),
        action: ActionId::from(name),
    }
}

fn release(secret: &str, reverse_actions: bool) -> Release {
    let mut actions = vec![action("notify", "permit"), action("audit", "audit")];
    if reverse_actions {
        actions.reverse();
    }
    Release {
        emitted: true,
        fields: BTreeMap::from([(FieldId::from("bucket"), secret.to_owned())]),
        actions,
    }
}

fn fixture(secret: &str, trace_len: u32, reverse_order: bool) -> Counterexample {
    let left_release = release(secret, reverse_order);
    let right_release = release("other-private-value", !reverse_order);
    let mut repairs = vec![
        RepairCandidate::NormalizeField(FieldId::from("bucket")),
        RepairCandidate::HideField {
            observer: ObserverId::from("network"),
            field: FieldId::from("bucket"),
        },
    ];
    if reverse_order {
        repairs.reverse();
    }
    Counterexample {
        kind: CounterexampleKind::SecurityDivergence,
        slot: trace_len.saturating_sub(1),
        observer: Some(ObserverId::from("network")),
        left_observation: Some(Observation {
            emitted: true,
            fields: BTreeMap::from([(FieldId::from("bucket"), secret.to_owned())]),
            actions: left_release.actions.clone(),
        }),
        right_observation: Some(Observation {
            emitted: true,
            fields: BTreeMap::from([(FieldId::from("bucket"), "other-private-value".to_owned())]),
            actions: right_release.actions.clone(),
        }),
        causal_field: Some(CausalField::Field(FieldId::from("bucket"))),
        trace: (0..trace_len)
            .map(|slot| TraceStep {
                slot,
                input: EnvironmentInput {
                    id: InputId::from("tick"),
                    public_symbol: "public-tick".to_owned(),
                    fault: None,
                },
                left_state: StateId::from(format!("private-left-{secret}:m0")),
                right_state: StateId::from("private-right:m0"),
                left_release: left_release.clone(),
                right_release: right_release.clone(),
            })
            .collect(),
        repair_candidates: repairs,
    }
}

#[test]
fn private_values_and_unordered_sets_do_not_change_the_signature() {
    let first =
        CounterexampleSignature::from_counterexample(&fixture("secret-alpha", 1, false)).unwrap();
    let second =
        CounterexampleSignature::from_counterexample(&fixture("secret-beta", 1, true)).unwrap();
    assert!(first.is_exact_duplicate(&second));
    assert_eq!(first.digest_sha256, second.digest_sha256);
    assert!(first.validate_digest().unwrap());

    let public = String::from_utf8(first.canonical_bytes().unwrap()).unwrap();
    assert!(!public.contains("secret-alpha"));
    assert!(!public.contains("private-left"));
    assert!(!public.contains("other-private-value"));
    assert!(public.contains("public-tick"));
}

#[test]
fn strict_prefix_subsumption_and_catalog_replacement_are_deterministic() {
    let short = CounterexampleSignature::from_counterexample(&fixture("a", 1, false)).unwrap();
    let long = CounterexampleSignature::from_counterexample(&fixture("b", 3, true)).unwrap();
    assert!(short.is_strict_prefix_of(&long));
    assert!(short.subsumes(&long));
    assert!(!long.subsumes(&short));

    let mut catalog = CounterexampleCatalog::default();
    assert_eq!(
        catalog.insert(long.clone()),
        CatalogInsert::Inserted {
            removed_subsumed: 0
        }
    );
    assert_eq!(catalog.insert(long), CatalogInsert::ExactDuplicate);
    assert_eq!(
        catalog.insert(short.clone()),
        CatalogInsert::Inserted {
            removed_subsumed: 1
        }
    );
    assert_eq!(catalog.entries(), &[short]);
    assert_eq!(
        catalog
            .insert(CounterexampleSignature::from_counterexample(&fixture("c", 4, false)).unwrap()),
        CatalogInsert::SubsumedByExisting
    );
}

#[test]
fn distinct_public_contexts_are_never_collapsed() {
    let baseline = CounterexampleSignature::from_counterexample(&fixture("a", 1, false)).unwrap();
    for index in 0..32_u32 {
        let mut changed = fixture("different-private-value", 1, index % 2 == 0);
        if index % 2 == 0 {
            changed.trace[0].input.public_symbol = format!("public-{index}");
        } else {
            changed.kind = CounterexampleKind::UnauthorizedAction {
                side: quotient_forge_check::Side::Left,
                action: ActionId::from(format!("action-{index}")),
                obligation: ObligationRef::Authorized(ObligationId::from("permit")),
            };
        }
        let signature = CounterexampleSignature::from_counterexample(&changed).unwrap();
        assert!(!baseline.is_exact_duplicate(&signature));
        assert!(!baseline.subsumes(&signature));
        assert!(
            !matches!(
                signature.counterexample.kind,
                CanonicalCounterexampleKind::SecurityDivergence
            ) || index % 2 == 0
        );
    }
}

#[test]
fn serialized_signature_round_trips_without_changing_bytes() {
    let signature =
        CounterexampleSignature::from_counterexample(&fixture("private", 2, true)).unwrap();
    let bytes = signature.canonical_bytes().unwrap();
    let decoded: CounterexampleSignature = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, signature);
    assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
}
