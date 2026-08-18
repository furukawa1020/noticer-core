use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

use quotient_seal_mutation::{
    mutate_wasm, validate_wasm_container, MutationFamily, MutationOperator, ALL_MUTATION_OPERATORS,
    MUTATION_TAXONOMY_VERSION,
};

#[test]
fn taxonomy_has_37_unique_operators_and_all_seven_families() {
    assert_eq!(ALL_MUTATION_OPERATORS.len(), 37);
    let ids: HashSet<_> = ALL_MUTATION_OPERATORS
        .iter()
        .map(|operator| operator.id())
        .collect();
    assert_eq!(ids.len(), 37);
    let families: HashSet<_> = ALL_MUTATION_OPERATORS
        .iter()
        .map(|operator| operator.family())
        .collect();
    assert_eq!(families.len(), 7);
    assert!(families.contains(&MutationFamily::Binding));
}

#[test]
fn every_operator_is_byte_deterministic_unique_and_container_valid() {
    let seed = fixture_wasm();
    validate_wasm_container(&seed).expect("fixture container");
    let mut hashes = HashSet::new();
    let mut primary_sections = BTreeSet::new();
    for operator in ALL_MUTATION_OPERATORS {
        let first = mutate_wasm(&seed, operator)
            .unwrap_or_else(|error| panic!("{}: {error}", operator.id()));
        let second = mutate_wasm(&seed, operator)
            .unwrap_or_else(|error| panic!("{}: {error}", operator.id()));
        assert_eq!(first, second, "{} must be deterministic", operator.id());
        assert_ne!(first.bytes, seed, "{} must change bytes", operator.id());
        assert_eq!(&first.bytes[..8], b"\0asm\x01\0\0\0");
        validate_wasm_container(&first.bytes).expect("mutant container must reconstruct");
        assert_eq!(first.edits.len(), 2, "primary edit plus witness");
        assert_ne!(first.edits[0].locus, "mutation witness");
        assert_eq!(first.edits[1].locus, "mutation witness");
        assert!(hashes.insert(first.mutant_sha256));
        primary_sections.insert(first.edits[0].section_id);
    }
    assert!(primary_sections.len() >= 6);
}

#[test]
fn mutating_never_changes_the_seed_buffer() {
    let seed = fixture_wasm();
    let original = seed.clone();
    let _ = mutate_wasm(&seed, MutationOperator::PolicyBypass).expect("mutation");
    assert_eq!(seed, original);
}

#[test]
fn missing_required_locus_is_not_applicable_not_success() {
    let empty = b"\0asm\x01\0\0\0";
    let error = mutate_wasm(empty, MutationOperator::DuplicateActionCall)
        .expect_err("code-free module cannot duplicate a call");
    assert!(error.to_string().contains("not applicable"));
}

#[test]
fn malformed_and_noncanonical_containers_are_rejected() {
    assert!(validate_wasm_container(b"bad").is_err());
    let noncanonical = [b'\0', b'a', b's', b'm', 1, 0, 0, 0, 0, 0x80, 0x00];
    assert!(validate_wasm_container(&noncanonical).is_err());
}

#[test]
fn checked_in_taxonomy_matches_public_operator_ids() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../configs/quotient_seal/wasm_mutation_taxonomy_v1.yaml");
    let value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(path).expect("checked-in taxonomy should be readable"),
    )
    .expect("taxonomy is strict JSON-compatible YAML");
    assert_eq!(value["schema_version"], MUTATION_TAXONOMY_VERSION);
    let configured: BTreeSet<_> = value["operators"]
        .as_array()
        .expect("operators array")
        .iter()
        .map(|operator| operator["id"].as_str().expect("operator id"))
        .collect();
    let implemented: BTreeSet<_> = ALL_MUTATION_OPERATORS
        .iter()
        .map(|operator| operator.id())
        .collect();
    assert_eq!(configured, implemented);
}

fn fixture_wasm() -> Vec<u8> {
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    push_section(&mut module, 1, &[0x01, 0x60, 0x00, 0x00]);

    let mut import = vec![0x01];
    import.extend(name("env"));
    import.extend(name("emit_action"));
    import.extend([0x00, 0x00]);
    push_section(&mut module, 2, &import);

    push_section(&mut module, 3, &[0x01, 0x00]);
    push_section(&mut module, 5, &[0x01, 0x01, 0x01, 0x01]);
    push_section(&mut module, 6, &[0x01, 0x7f, 0x00, 0x41, 0x00, 0x0b]);

    let mut export = vec![0x01];
    export.extend(name("tick"));
    export.extend([0x00, 0x01]);
    push_section(&mut module, 7, &export);

    let body = [
        0x00, 0x41, 0x00, 0x28, 0x02, 0x00, 0x1a, 0x10, 0x00, 0x10, 0x01, 0x0b,
    ];
    let mut code = vec![0x01];
    code.extend(leb(u32::try_from(body.len()).expect("body length")));
    code.extend(body);
    push_section(&mut module, 10, &code);
    push_section(&mut module, 11, &[0x01, 0x00, 0x41, 0x00, 0x0b, 0x01, 0x00]);
    module
}

fn push_section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(u32::try_from(payload.len()).expect("payload length")));
    module.extend_from_slice(payload);
}

fn name(value: &str) -> Vec<u8> {
    let mut encoded = leb(u32::try_from(value.len()).expect("name length"));
    encoded.extend_from_slice(value.as_bytes());
    encoded
}

fn leb(mut value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            return bytes;
        }
    }
}
