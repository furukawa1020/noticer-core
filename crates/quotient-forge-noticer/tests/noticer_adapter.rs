use std::fs;

use quotient_forge_caqt::{
    Certificate, CertificateLimits, CostVector, DomainHashes, ExpectedContract, ObserverRecord,
    OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_noticer::{
    connect_generated_plan, run_handwritten_benchmark, shared_contract_type_names, AdapterVerdict,
    CertifiedGeneratedPlan, HandwrittenPlan,
};

fn certificate() -> (Vec<u8>, ExpectedContract) {
    let mut certificate = Certificate {
        version: FORMAT_VERSION,
        hashes: DomainHashes::zero(),
        state_count: 2,
        input_count: 1,
        observer_count: 1,
        state_bound: 2,
        claimed_cost: CostVector::default(),
        observers: vec![ObserverRecord {
            id: 0,
            sees_presence: true,
            sees_payload: true,
            sees_actions: true,
        }],
        outputs: vec![
            OutputRecord {
                id: 0,
                emitted: true,
                payload: b"same".to_vec(),
                actions: Vec::new(),
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: b"same".to_vec(),
                actions: Vec::new(),
            },
        ],
        transitions: vec![
            TransitionRecord {
                from: 0,
                input: 0,
                to: 1,
                output: 0,
                authorized_actions: Vec::new(),
                required_action: None,
                recoverable_fault_action: None,
            },
            TransitionRecord {
                from: 1,
                input: 0,
                to: 1,
                output: 1,
                authorized_actions: Vec::new(),
                required_action: None,
                recoverable_fault_action: None,
            },
        ],
        relation: vec![RelationPair { left: 0, right: 1 }],
    };
    certificate.seal();
    let expected = ExpectedContract {
        version: FORMAT_VERSION,
        hashes: certificate.hashes,
        state_bound: certificate.state_bound,
        max_cost: certificate.claimed_cost,
    };
    (certificate.encode(), expected)
}

#[test]
fn four_known_bad_plans_return_counterexamples() {
    for plan in [
        HandwrittenPlan::ImmediateRelease,
        HandwrittenPlan::FixedSizeOnly,
        HandwrittenPlan::CoarseBucket,
        HandwrittenPlan::EvidenceDependentSlot,
    ] {
        let evaluation = run_handwritten_benchmark(plan).unwrap();
        assert!(
            matches!(evaluation.verdict, AdapterVerdict::Counterexample(_)),
            "{} unexpectedly passed",
            plan.name()
        );
    }
}

#[test]
fn handwritten_aets_and_bounded_loss_aplot_are_valid() {
    for plan in [HandwrittenPlan::Aets, HandwrittenPlan::AplotBoundedLoss] {
        let evaluation = run_handwritten_benchmark(plan).unwrap();
        assert!(
            matches!(evaluation.verdict, AdapterVerdict::Valid(_)),
            "{} unexpectedly failed",
            plan.name()
        );
    }
}

#[test]
fn shared_aetp_contracts_are_existing_noticer_types() {
    let names = shared_contract_type_names();
    assert!(names[..3]
        .iter()
        .all(|name| name.starts_with("noticer_aetp::")));
    assert!(names[3].starts_with("noticer_transport_sim::"));
}

#[test]
fn certified_plan_borrows_atv2_menfugu_and_aepa_values() {
    let (bytes, expected) = certificate();
    let certified =
        CertifiedGeneratedPlan::from_certificate(&bytes, expected, CertificateLimits::default())
            .unwrap();
    struct ExistingAtv2FramePlan;
    struct ExistingMenfuguActionWindow;
    struct ExistingAepaRequirement;
    let frame = ExistingAtv2FramePlan;
    let window = ExistingMenfuguActionWindow;
    let requirement = ExistingAepaRequirement;
    let connected = connect_generated_plan(certified, &frame, &window, &requirement);
    assert!(std::ptr::eq(connected.atv2_frame_plan, &frame));
    assert!(std::ptr::eq(connected.menfugu_action_window, &window));
    assert!(std::ptr::eq(connected.aepa_requirement, &requirement));
    assert_eq!(connected.certified, certified);
}

#[test]
fn modified_certificate_cannot_be_connected() {
    let (mut bytes, expected) = certificate();
    bytes.push(0);
    assert!(CertifiedGeneratedPlan::from_certificate(
        &bytes,
        expected,
        CertificateLimits::default()
    )
    .is_err());
}

#[test]
fn adapter_manifest_has_no_private_or_raw_acquisition_dependency() {
    let manifest =
        fs::read_to_string(format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"))).unwrap();
    for forbidden in [
        "noticer-acquisition-core",
        "noticer-evidence",
        "noticer-evidence-bridge",
        "noticer-ppg-features",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "forbidden dependency: {forbidden}"
        );
    }
}
