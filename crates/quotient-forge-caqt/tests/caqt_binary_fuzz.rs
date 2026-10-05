use quotient_forge_caqt::{run_binary_fuzz, BinaryFuzzError, BinaryFuzzLimits, CertificateLimits};

fn limits() -> BinaryFuzzLimits {
    BinaryFuzzLimits {
        max_cases: 64,
        max_input_bytes: 4_096,
        certificate: CertificateLimits {
            max_bytes: 4_096,
            ..CertificateLimits::default()
        },
    }
}

#[test]
fn arbitrary_binary_mutations_are_bounded_and_reproducible() {
    let corpus = vec![
        Vec::new(),
        b"CAQT".to_vec(),
        (0_u8..=255).collect(),
        vec![0xff; 4_097],
    ];
    let first = run_binary_fuzz(0x0ca0_715d, &corpus, limits()).unwrap();
    let second = run_binary_fuzz(0x0ca0_715d, &corpus, limits()).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.executed_mutations + first.resource_rejections, 24);
    assert!(first.parser_rejections > 0);
    assert!(first.resource_rejections > 0);
    assert_eq!(first.unstable_round_trips, 0);
}

#[test]
fn invalid_limits_and_case_count_fail_before_parsing() {
    let invalid = BinaryFuzzLimits {
        max_cases: 0,
        ..limits()
    };
    assert_eq!(
        run_binary_fuzz(1, &[], invalid),
        Err(BinaryFuzzError::InvalidLimits)
    );
    let corpus = vec![Vec::new(); limits().max_cases + 1];
    assert_eq!(
        run_binary_fuzz(1, &corpus, limits()),
        Err(BinaryFuzzError::TooManyCases)
    );
}
