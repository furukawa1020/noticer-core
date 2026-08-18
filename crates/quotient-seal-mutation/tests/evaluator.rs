use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quotient_seal_matrix::{CommandExecutor, CommandOutput, CommandSpec};
use quotient_seal_mutation::{
    run_campaign, CampaignRequest, CommandTemplate, IndependentPipelineEvaluator,
    MutationArtifact, MutationVerdict, SplitContract,
};
use quotient_seal_target_ir::{local_parser_decision, LocalParserDecision, ParserLimits};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quotient-seal-evaluator-{}-{sequence}",
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

#[derive(Clone, Copy)]
enum ParserMode {
    Mirror,
    Resource,
}

struct FakePipelineExecutor {
    parser_mode: ParserMode,
}

impl CommandExecutor for FakePipelineExecutor {
    fn run(&self, command: &CommandSpec) -> io::Result<CommandOutput> {
        let artifact = PathBuf::from(command.args.first().expect("artifact argument"));
        let bytes = fs::read(artifact)?;
        if command.program.starts_with("parser-") {
            if command.program == "parser-b" && contains(&bytes, b"wrong_observer_binding") {
                return Ok(output(9));
            }
            let code = match self.parser_mode {
                ParserMode::Resource => 2,
                ParserMode::Mirror => match local_parser_decision(&bytes, ParserLimits::default()) {
                    LocalParserDecision::Accepted(_) => 0,
                    LocalParserDecision::Rejected => 1,
                    LocalParserDecision::ResourceBound => 2,
                },
            };
            return Ok(output(code));
        }
        if contains(&bytes, b"action_to_cover") {
            return Ok(output(0));
        }
        if contains(&bytes, b"stale_state_restore") {
            return Err(io::Error::new(io::ErrorKind::NotFound, "checker missing"));
        }
        Ok(output(1))
    }

    fn resolve(&self, program: &str) -> io::Result<PathBuf> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("not needed in test: {program}"),
        ))
    }
}

#[test]
fn full_37_mutant_pipeline_preserves_kill_escape_and_inconclusive() {
    let temp = TestDirectory::new();
    let evaluator = evaluator(&temp.0, ParserMode::Mirror, ParserLimits::default());
    let manifest = run_campaign(&load_split(), &request(&temp.0), &evaluator)
        .expect("37-mutant campaign");
    assert_eq!(manifest.mutants.len(), 37);
    let verdicts: BTreeSet<_> = manifest
        .mutants
        .iter()
        .map(|record| record.evaluation.verdict)
        .collect();
    assert_eq!(verdicts.len(), 3);
    assert!(verdicts.contains(&MutationVerdict::Escaped));
    assert!(manifest.mutants.iter().all(|record| {
        record.artifact_path.is_none() || record.evaluation.evidence.len() >= 2
    }));
    let escaped = manifest
        .mutants
        .iter()
        .find(|record| record.evaluation.verdict == MutationVerdict::Escaped)
        .expect("at least one escaped mutant");
    assert!(escaped.artifact_path.is_some());
}

#[test]
fn parser_disagreement_and_checker_failure_are_inconclusive() {
    let temp = TestDirectory::new();
    let evaluator = evaluator(&temp.0, ParserMode::Mirror, ParserLimits::default());
    let manifest = run_campaign(&load_split(), &request(&temp.0), &evaluator)
        .expect("campaign");
    let disagreement = record(&manifest, "wrong_observer_binding");
    assert_eq!(disagreement.evaluation.verdict, MutationVerdict::Inconclusive);
    assert_eq!(disagreement.evaluation.reason_code, "parser_disagreement");
    let unavailable = record(&manifest, "stale_state_restore");
    assert_eq!(unavailable.evaluation.verdict, MutationVerdict::Inconclusive);
    assert_eq!(unavailable.evaluation.reason_code, "checker_unavailable");
}

#[test]
fn unanimous_resource_bound_is_never_counted_as_killed() {
    let temp = TestDirectory::new();
    let mut limits = ParserLimits::default();
    limits.max_module_bytes = 1;
    let evaluator = evaluator(&temp.0, ParserMode::Resource, limits);
    let manifest = run_campaign(&load_split(), &request(&temp.0), &evaluator)
        .expect("resource-bound campaign");
    assert!(manifest.mutants.iter().all(|record| {
        record.evaluation.verdict == MutationVerdict::Inconclusive
            && record.evaluation.reason_code == "parser_resource_bound"
    }));
}

#[test]
fn command_evidence_contains_instantiated_paths_not_placeholders() {
    let temp = TestDirectory::new();
    let evaluator = evaluator(&temp.0, ParserMode::Mirror, ParserLimits::default());
    let manifest = run_campaign(&load_split(), &request(&temp.0), &evaluator)
        .expect("campaign");
    for evidence in manifest
        .mutants
        .iter()
        .flat_map(|record| &record.evaluation.evidence)
    {
        assert!(evidence
            .command
            .args
            .iter()
            .all(|argument| !argument.contains("{artifact}")));
        assert!(evidence.exit_code.is_some() || !evidence.stderr.is_empty());
    }
}

fn evaluator(
    root: &Path,
    parser_mode: ParserMode,
    limits: ParserLimits,
) -> IndependentPipelineEvaluator<FakePipelineExecutor> {
    IndependentPipelineEvaluator::with_parser_limits(
        FakePipelineExecutor { parser_mode },
        template("parser_a", "parser-a", root),
        template("parser_b", "parser-b", root),
        template("checker", "checker", root),
        limits,
    )
    .expect("pipeline evaluator")
}

fn template(stage: &str, program: &str, root: &Path) -> CommandTemplate {
    CommandTemplate::new(
        stage,
        program,
        vec!["{artifact}".to_owned()],
        root.to_path_buf(),
    )
    .expect("command template")
}

fn record<'a>(
    manifest: &'a quotient_seal_mutation::CampaignManifest,
    id: &str,
) -> &'a quotient_seal_mutation::MutantRecord {
    manifest
        .mutants
        .iter()
        .find(|record| record.operator.id() == id)
        .expect("operator record")
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

fn output(exit_code: i32) -> CommandOutput {
    CommandOutput {
        exit_code: Some(exit_code),
        stdout: format!("exit={exit_code}"),
        stderr: String::new(),
    }
}

fn load_split() -> SplitContract {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../configs/quotient_seal/mutation_split_v1.yaml");
    SplitContract::from_path(&path).expect("split")
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

