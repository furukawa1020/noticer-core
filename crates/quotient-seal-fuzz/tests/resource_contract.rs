use quotient_seal_fuzz::{
    build_report, load_contract, validate_report, ArtifactTarget, FuzzContractError, InputShape,
    RunStatus,
};
use std::path::PathBuf;

fn contract_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../configs/quotient_forge/fuzz_resource_contract_v1.json")
}

#[test]
fn frozen_contract_is_canonical_and_covers_every_target() {
    let contract = load_contract(&contract_path()).unwrap();
    assert_eq!(contract.target_limits.len(), ArtifactTarget::ALL.len());
    assert_eq!(contract.sha256().unwrap().len(), 64);
    for target in ArtifactTarget::ALL {
        contract
            .preflight(
                target,
                &InputShape {
                    input_bytes: 128,
                    depth: 4,
                    integer_bits: 64,
                    collection_items: 16,
                    state_factors: &[4, 8, 16],
                },
            )
            .unwrap();
    }
}

#[test]
fn each_resource_dimension_fails_with_a_stable_category() {
    let contract = load_contract(&contract_path()).unwrap();
    let target = ArtifactTarget::Dsl;
    let limits = contract.target_limits[&target];
    let cases = [
        (
            InputShape {
                input_bytes: limits.max_input_bytes + 1,
                depth: 1,
                integer_bits: 1,
                collection_items: 1,
                state_factors: &[1],
            },
            FuzzContractError::InputBytesExceeded,
        ),
        (
            InputShape {
                input_bytes: 1,
                depth: limits.max_depth + 1,
                integer_bits: 1,
                collection_items: 1,
                state_factors: &[1],
            },
            FuzzContractError::DepthExceeded,
        ),
        (
            InputShape {
                input_bytes: 1,
                depth: 1,
                integer_bits: limits.max_integer_bits + 1,
                collection_items: 1,
                state_factors: &[1],
            },
            FuzzContractError::IntegerBitsExceeded,
        ),
        (
            InputShape {
                input_bytes: 1,
                depth: 1,
                integer_bits: 1,
                collection_items: limits.max_collection_items + 1,
                state_factors: &[1],
            },
            FuzzContractError::CollectionItemsExceeded,
        ),
        (
            InputShape {
                input_bytes: 1,
                depth: 1,
                integer_bits: 1,
                collection_items: 1,
                state_factors: &[u64::MAX, 2],
            },
            FuzzContractError::StateProductExceeded,
        ),
    ];
    for (shape, expected) in cases {
        assert_eq!(contract.preflight(target, &shape), Err(expected));
    }
}

#[test]
fn timeout_failure_and_disagreement_cannot_be_reported_as_success() {
    let contract = load_contract(&contract_path()).unwrap();
    let timeout = build_report(
        &contract,
        ArtifactTarget::Caqt,
        7,
        contract.budget.max_runtime_ms + 1,
        10,
        3,
        RunStatus::Timeout,
    )
    .unwrap();
    validate_report(&contract, &timeout).unwrap();
    assert_eq!(timeout.status, RunStatus::Timeout);
    assert_eq!(
        build_report(
            &contract,
            ArtifactTarget::Caqt,
            7,
            contract.budget.max_runtime_ms + 1,
            10,
            3,
            RunStatus::Completed,
        ),
        Err(FuzzContractError::TimeoutReportedAsSuccess)
    );
    for status in [RunStatus::Failure, RunStatus::Disagreement] {
        let report = build_report(&contract, ArtifactTarget::Caqt, 7, 10, 10, 3, status).unwrap();
        assert_eq!(report.status, status);
    }
}
