use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quotient_seal_mutation::{
    run_campaign, CampaignRequest, DatasetSplit, Evaluation, InconclusiveEvaluator,
    MutantEvaluator, MutationArtifact, MutationVerdict, SplitContract, ALL_MUTATION_OPERATORS,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quotient-seal-campaign-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("test directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TriEvaluator;

impl MutantEvaluator for TriEvaluator {
    fn evaluator_id(&self) -> &str {
        "test-triage/v1"
    }

    fn evaluate(&self, _artifact_path: &Path, artifact: &MutationArtifact) -> Evaluation {
        match artifact.operator.ordinal() % 3 {
            0 => Evaluation::killed("test_kill", "deterministic test rejection"),
            1 => Evaluation::escaped("test_escape", "deterministic test acceptance"),
            _ => Evaluation::inconclusive("test_unknown", "deterministic test uncertainty"),
        }
    }
}

#[test]
fn checked_in_split_is_disjoint_and_classifies_both_axes() {
    let contract = load_split();
    contract.validate().expect("split should validate");
    assert_eq!(
        contract
            .classify("noticer_reference", "stable-o0-off-default-none")
            .expect("development pair"),
        DatasetSplit::Development
    );
    assert_eq!(
        contract
            .classify("noticer_atv2_held_out", "nightly-o0-off-1-o2")
            .expect("held-out pair"),
        DatasetSplit::HeldOut
    );
    assert!(contract
        .classify("noticer_reference", "nightly-o0-off-1-o2")
        .is_err());
}

#[test]
fn campaign_writes_all_records_and_preserves_all_three_verdicts() {
    let temp = TestDirectory::new();
    let request = request(&temp.0);
    let manifest = run_campaign(&load_split(), &request, &TriEvaluator).expect("campaign");
    assert_eq!(manifest.mutants.len(), ALL_MUTATION_OPERATORS.len());
    let verdicts: BTreeSet<_> = manifest
        .mutants
        .iter()
        .map(|record| record.evaluation.verdict)
        .collect();
    assert_eq!(verdicts.len(), 3);
    assert!(verdicts.contains(&MutationVerdict::Escaped));
    for escaped in manifest
        .mutants
        .iter()
        .filter(|record| record.evaluation.verdict == MutationVerdict::Escaped)
    {
        let relative = escaped
            .artifact_path
            .as_ref()
            .expect("escaped mutant must retain artifact");
        assert!(temp
            .0
            .join("artifacts")
            .join(&manifest.campaign_id)
            .join(relative.replace('/', std::path::MAIN_SEPARATOR_STR))
            .is_file());
    }
}

#[test]
fn rerun_has_same_campaign_id_manifest_and_artifact_tree() {
    let temp = TestDirectory::new();
    let request = request(&temp.0);
    let first = run_campaign(&load_split(), &request, &TriEvaluator).expect("first campaign");
    let first_json = serde_json::to_vec(&first).expect("first manifest");
    let second = run_campaign(&load_split(), &request, &TriEvaluator).expect("second campaign");
    assert_eq!(first, second);
    assert_eq!(
        first_json,
        serde_json::to_vec(&second).expect("second manifest")
    );
}

#[test]
fn existing_different_artifact_is_a_collision_not_an_overwrite() {
    let temp = TestDirectory::new();
    let request = request(&temp.0);
    let first = run_campaign(&load_split(), &request, &TriEvaluator).expect("first campaign");
    let artifact = first.mutants[0]
        .artifact_path
        .as_ref()
        .expect("first mutant artifact");
    let path = temp
        .0
        .join("artifacts")
        .join(first.campaign_id)
        .join(artifact.replace('/', std::path::MAIN_SEPARATOR_STR));
    fs::write(&path, b"collision").expect("corrupt artifact");
    assert!(run_campaign(&load_split(), &request, &TriEvaluator).is_err());
    assert_eq!(fs::read(path).expect("collision remains"), b"collision");
}

#[test]
fn default_evaluator_never_claims_a_kill_or_escape() {
    let temp = TestDirectory::new();
    let manifest = run_campaign(&load_split(), &request(&temp.0), &InconclusiveEvaluator)
        .expect("deferred campaign");
    assert!(manifest.mutants.iter().all(|record| {
        record.evaluation.verdict == MutationVerdict::Inconclusive
            && record.evaluation.reason_code == "checker_not_configured"
    }));
    assert_eq!(manifest.hardware_status, "NOT_VERIFIED");
}

fn load_split() -> SplitContract {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../configs/quotient_seal/mutation_split_v1.yaml");
    SplitContract::from_path(&path).expect("checked-in split should parse")
}

fn request(root: &Path) -> CampaignRequest {
    let seed_path = root.join("seed.wasm");
    fs::write(&seed_path, fixture_wasm()).expect("seed");
    CampaignRequest {
        seed_path,
        module_family: "noticer_reference".to_owned(),
        compiler_configuration: "stable-o0-off-default-none".to_owned(),
        output_root: root.join("artifacts"),
    }
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
