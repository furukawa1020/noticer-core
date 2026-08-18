use std::io;
use std::path::{Path, PathBuf};

use quotient_seal_matrix::{CommandExecutor, CommandOutput, CommandSpec};
use quotient_seal_target_ir::{
    local_parser_decision, parse_and_lower, reconcile_parser_decisions, ConsensusVerdict,
    ExternalParserDecision, ParserLimits,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{Evaluation, EvaluationEvidence, MutantEvaluator, MutationArtifact};

pub const PARSER_ACCEPT_EXIT: i32 = 0;
pub const PARSER_REJECT_EXIT: i32 = 1;
pub const PARSER_RESOURCE_EXIT: i32 = 2;
pub const CHECKER_ACCEPT_EXIT: i32 = 0;
pub const CHECKER_REJECT_EXIT: i32 = 1;
const PIPELINE_VERSION: &str = "quotient-seal-independent-pipeline/v1";
const MAX_CAPTURE_CHARS: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandTemplate {
    pub stage: String,
    pub program: String,
    pub args: Vec<String>,
    pub current_dir: PathBuf,
}

impl CommandTemplate {
    pub fn new(
        stage: impl Into<String>,
        program: impl Into<String>,
        args: Vec<String>,
        current_dir: PathBuf,
    ) -> Result<Self, PipelineError> {
        let template = Self {
            stage: stage.into(),
            program: program.into(),
            args,
            current_dir,
        };
        if template.stage.is_empty() || template.program.is_empty() {
            return Err(PipelineError::EmptyCommandIdentity);
        }
        if !template
            .args
            .iter()
            .any(|argument| argument.contains("{artifact}"))
        {
            return Err(PipelineError::MissingArtifactPlaceholder(
                template.stage.clone(),
            ));
        }
        Ok(template)
    }

    #[must_use]
    pub fn instantiate(&self, artifact_path: &Path) -> CommandSpec {
        let artifact = artifact_path.to_string_lossy();
        CommandSpec {
            program: self.program.clone(),
            args: self
                .args
                .iter()
                .map(|argument| argument.replace("{artifact}", &artifact))
                .collect(),
            current_dir: self.current_dir.clone(),
        }
    }
}

pub struct IndependentPipelineEvaluator<E> {
    executor: E,
    parser_a: CommandTemplate,
    parser_b: CommandTemplate,
    checker: CommandTemplate,
    parser_limits: ParserLimits,
    evaluator_id: String,
}

impl<E> IndependentPipelineEvaluator<E> {
    pub fn new(
        executor: E,
        parser_a: CommandTemplate,
        parser_b: CommandTemplate,
        checker: CommandTemplate,
    ) -> Result<Self, PipelineError> {
        Self::with_parser_limits(
            executor,
            parser_a,
            parser_b,
            checker,
            ParserLimits::default(),
        )
    }

    pub fn with_parser_limits(
        executor: E,
        parser_a: CommandTemplate,
        parser_b: CommandTemplate,
        checker: CommandTemplate,
        parser_limits: ParserLimits,
    ) -> Result<Self, PipelineError> {
        let mut stages = [
            parser_a.stage.as_str(),
            parser_b.stage.as_str(),
            checker.stage.as_str(),
        ];
        stages.sort_unstable();
        if stages.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PipelineError::DuplicateStage);
        }
        let evaluator_id = pipeline_id(&parser_a, &parser_b, &checker, parser_limits)?;
        Ok(Self {
            executor,
            parser_a,
            parser_b,
            checker,
            parser_limits,
            evaluator_id,
        })
    }
}

impl<E: CommandExecutor> MutantEvaluator for IndependentPipelineEvaluator<E> {
    fn evaluator_id(&self) -> &str {
        &self.evaluator_id
    }

    fn evaluate(&self, artifact_path: &Path, artifact: &MutationArtifact) -> Evaluation {
        let local_result = parse_and_lower(&artifact.bytes, self.parser_limits);
        let local = local_parser_decision(&local_result);
        let (parser_a, evidence_a) = run_parser(&self.executor, &self.parser_a, artifact_path);
        let (parser_b, evidence_b) = run_parser(&self.executor, &self.parser_b, artifact_path);
        let mut evidence = vec![evidence_a, evidence_b];
        match reconcile_parser_decisions(local, parser_a, parser_b) {
            ConsensusVerdict::Valid(_) => {
                let (output, checker_evidence) =
                    run_command(&self.executor, &self.checker, artifact_path);
                evidence.push(checker_evidence);
                let mut evaluation = match output {
                    Ok(output) if output.exit_code == Some(CHECKER_ACCEPT_EXIT) => {
                        Evaluation::escaped(
                            "independent_checker_accept",
                            "all parsers accepted and the independent checker accepted the mutant",
                        )
                    }
                    Ok(output) if output.exit_code == Some(CHECKER_REJECT_EXIT) => {
                        Evaluation::killed(
                            "independent_checker_reject",
                            "all parsers accepted and the independent checker rejected the mutant",
                        )
                    }
                    Ok(output) => Evaluation::inconclusive(
                        "checker_non_verdict",
                        format!("checker returned exit code {:?}", output.exit_code),
                    ),
                    Err(error) => Evaluation::inconclusive(
                        "checker_unavailable",
                        format!("checker execution failed: {error}"),
                    ),
                };
                evaluation.evidence = evidence;
                evaluation
            }
            ConsensusVerdict::Invalid => with_evidence(
                Evaluation::killed(
                    "parser_consensus_reject",
                    "local parser and both independent parsers rejected the mutant",
                ),
                evidence,
            ),
            ConsensusVerdict::ResourceBound => with_evidence(
                Evaluation::inconclusive(
                    "parser_resource_bound",
                    "all parsers reached their declared resource bound",
                ),
                evidence,
            ),
            ConsensusVerdict::Unresolved => with_evidence(
                Evaluation::inconclusive(
                    "parser_disagreement",
                    format!(
                        "parser decisions disagree: local={local:?}, parser_a={parser_a:?}, parser_b={parser_b:?}"
                    ),
                ),
                evidence,
            ),
        }
    }
}

fn run_parser<E: CommandExecutor>(
    executor: &E,
    template: &CommandTemplate,
    artifact_path: &Path,
) -> (ExternalParserDecision, EvaluationEvidence) {
    let (output, evidence) = run_command(executor, template, artifact_path);
    let decision = match output {
        Ok(output) => match output.exit_code {
            Some(PARSER_ACCEPT_EXIT) => ExternalParserDecision::Accepted,
            Some(PARSER_REJECT_EXIT) => ExternalParserDecision::Rejected,
            Some(PARSER_RESOURCE_EXIT) => ExternalParserDecision::ResourceBound,
            _ => ExternalParserDecision::NotRun,
        },
        Err(_) => ExternalParserDecision::NotRun,
    };
    (decision, evidence)
}

fn run_command<E: CommandExecutor>(
    executor: &E,
    template: &CommandTemplate,
    artifact_path: &Path,
) -> (io::Result<CommandOutput>, EvaluationEvidence) {
    let command = template.instantiate(artifact_path);
    match executor.run(&command) {
        Ok(output) => {
            let evidence = EvaluationEvidence {
                stage: template.stage.clone(),
                command,
                exit_code: output.exit_code,
                stdout: bounded(&output.stdout),
                stderr: bounded(&output.stderr),
            };
            (Ok(output), evidence)
        }
        Err(error) => {
            let kind = error.kind();
            let message = error.to_string();
            let evidence = EvaluationEvidence {
                stage: template.stage.clone(),
                command,
                exit_code: None,
                stdout: String::new(),
                stderr: bounded(&message),
            };
            (Err(io::Error::new(kind, message)), evidence)
        }
    }
}

fn with_evidence(mut evaluation: Evaluation, evidence: Vec<EvaluationEvidence>) -> Evaluation {
    evaluation.evidence = evidence;
    evaluation
}

fn bounded(value: &str) -> String {
    value.chars().take(MAX_CAPTURE_CHARS).collect()
}

fn pipeline_id(
    parser_a: &CommandTemplate,
    parser_b: &CommandTemplate,
    checker: &CommandTemplate,
    parser_limits: ParserLimits,
) -> Result<String, PipelineError> {
    let mut hasher = Sha256::new();
    hasher.update(PIPELINE_VERSION.as_bytes());
    for template in [parser_a, parser_b, checker] {
        hasher.update([0]);
        hasher.update(serde_json::to_vec(template).map_err(PipelineError::Serialize)?);
    }
    hasher.update([0]);
    hasher.update(format!("{parser_limits:?}").as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    Ok(format!("independent-pipeline/{}", &digest[..20]))
}

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("command stage and program must not be empty")]
    EmptyCommandIdentity,
    #[error("command template for {0} must contain {{artifact}}")]
    MissingArtifactPlaceholder(String),
    #[error("parser and checker stage names must be distinct")]
    DuplicateStage,
    #[error("failed to serialize pipeline identity: {0}")]
    Serialize(serde_json::Error),
}
