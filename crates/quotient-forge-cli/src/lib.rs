//! 日本語診断とpublic-only artifactを提供するQuotientForge統合CLI。

mod artifact;
mod fixtures;
mod workflow;

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use artifact::{create_output_root, finalize_manifest, resolve_solver, ManifestContext};

pub const HELP: &str = "\
QuotientForge bounded security compiler\n\
\n\
使用法:\n\
  quotient-forge <check|synthesize|repair|verify|frontier|generate> [options]\n\
\n\
共通option:\n\
  --output <path>       artifact出力先（既存directoryは拒否）\n\
  --seed <u64>          再現seed（既定: 0）\n\
  --solver <mode>       off | auto | required（既定: off）\n\
  --certificate <path>  verify/generate用CAQT certificate\n\
  --case <name>         check対象plan（既定: immediate-release）\n\
  --help                この日本語診断を表示\n\
  --version             tool versionを表示\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandName {
    Check,
    Synthesize,
    Repair,
    Verify,
    Frontier,
    Generate,
}

impl CommandName {
    pub const ALL: [Self; 6] = [
        Self::Check,
        Self::Synthesize,
        Self::Repair,
        Self::Verify,
        Self::Frontier,
        Self::Generate,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Synthesize => "synthesize",
            Self::Repair => "repair",
            Self::Verify => "verify",
            Self::Frontier => "frontier",
            Self::Generate => "generate",
        }
    }

    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "check" => Ok(Self::Check),
            "synthesize" => Ok(Self::Synthesize),
            "repair" => Ok(Self::Repair),
            "verify" => Ok(Self::Verify),
            "frontier" => Ok(Self::Frontier),
            "generate" => Ok(Self::Generate),
            _ => Err(CliError::new(format!("未知のsubcommandです: {value}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckCase {
    ImmediateRelease,
    FixedSizeOnly,
    CoarseBucket,
    EvidenceDependentSlot,
    Aets,
    AplotBoundedLoss,
}

impl CheckCase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImmediateRelease => "immediate-release",
            Self::FixedSizeOnly => "fixed-size-only",
            Self::CoarseBucket => "coarse-bucket",
            Self::EvidenceDependentSlot => "evidence-dependent-slot",
            Self::Aets => "aets",
            Self::AplotBoundedLoss => "aplot-bounded-loss",
        }
    }

    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "immediate-release" => Ok(Self::ImmediateRelease),
            "fixed-size-only" => Ok(Self::FixedSizeOnly),
            "coarse-bucket" => Ok(Self::CoarseBucket),
            "evidence-dependent-slot" => Ok(Self::EvidenceDependentSlot),
            "aets" => Ok(Self::Aets),
            "aplot-bounded-loss" => Ok(Self::AplotBoundedLoss),
            _ => Err(CliError::new(format!("未知のcheck caseです: {value}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolverMode {
    Off,
    Auto,
    Required,
}

impl SolverMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Auto => "auto",
            Self::Required => "required",
        }
    }

    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "off" => Ok(Self::Off),
            "auto" => Ok(Self::Auto),
            "required" => Ok(Self::Required),
            _ => Err(CliError::new(format!("未知のsolver modeです: {value}"))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    pub command: CommandName,
    pub output: PathBuf,
    pub seed: u64,
    pub solver: SolverMode,
    pub certificate: Option<PathBuf>,
    pub check_case: CheckCase,
}

impl Options {
    pub fn parse<I>(arguments: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut arguments = arguments.into_iter();
        let command = arguments
            .next()
            .ok_or_else(|| CliError::new("subcommandが必要です"))?;
        let command = command
            .to_str()
            .ok_or_else(|| CliError::new("subcommandはUTF-8で指定してください"))?;
        let command = CommandName::parse(command)?;
        let mut output = None;
        let mut seed = 0_u64;
        let mut solver = std::env::var("QUOTIENT_FORGE_SOLVER")
            .ok()
            .map(|value| SolverMode::parse(&value))
            .transpose()?
            .unwrap_or(SolverMode::Off);
        let mut certificate = None;
        let mut check_case = CheckCase::ImmediateRelease;

        while let Some(flag) = arguments.next() {
            let flag = flag
                .to_str()
                .ok_or_else(|| CliError::new("option名はUTF-8で指定してください"))?;
            match flag {
                "--output" => output = Some(PathBuf::from(required_value(&mut arguments, flag)?)),
                "--seed" => {
                    let value = required_utf8(&mut arguments, flag)?;
                    seed = value
                        .parse()
                        .map_err(|_| CliError::new(format!("seedがu64ではありません: {value}")))?;
                }
                "--solver" => {
                    solver = SolverMode::parse(&required_utf8(&mut arguments, flag)?)?;
                }
                "--certificate" => {
                    certificate = Some(PathBuf::from(required_value(&mut arguments, flag)?));
                }
                "--case" => {
                    check_case = CheckCase::parse(&required_utf8(&mut arguments, flag)?)?;
                }
                _ => return Err(CliError::new(format!("未知のoptionです: {flag}"))),
            }
        }

        let output = output.unwrap_or_else(|| {
            PathBuf::from("artifacts")
                .join("quotient_forge")
                .join(command.as_str())
        });
        Ok(Self {
            command,
            output,
            seed,
            solver,
            certificate,
            check_case,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunSummary {
    pub command: CommandName,
    pub status: String,
    pub output: PathBuf,
    pub message_ja: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliError(String);

impl CliError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

pub fn execute(options: &Options) -> Result<RunSummary, CliError> {
    let solver =
        resolve_solver(options.solver).map_err(|error| CliError::new(error.to_string()))?;
    create_output_root(&options.output).map_err(|error| CliError::new(error.to_string()))?;
    let result = workflow::run(options).map_err(CliError::new)?;
    finalize_manifest(
        &options.output,
        ManifestContext {
            command: options.command.as_str(),
            engine: result.engine,
            seed: options.seed,
            solver: &solver,
            status: &result.status,
        },
        &result.files,
    )
    .map_err(|error| CliError::new(error.to_string()))?;
    Ok(RunSummary {
        command: options.command,
        status: result.status,
        output: options.output.clone(),
        message_ja: result.message_ja,
    })
}

pub fn run_from<I>(arguments: I) -> Result<Option<RunSummary>, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.len() == 1 && arguments[0] == "--help" {
        print!("{HELP}");
        return Ok(None);
    }
    if arguments.len() == 1 && arguments[0] == "--version" {
        println!("quotient-forge {}", env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }
    execute(&Options::parse(arguments)?).map(Some)
}

fn required_value(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<OsString, CliError> {
    arguments
        .next()
        .ok_or_else(|| CliError::new(format!("{flag}に値が必要です")))
}

fn required_utf8(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<String, CliError> {
    required_value(arguments, flag)?
        .into_string()
        .map_err(|_| CliError::new(format!("{flag}の値はUTF-8で指定してください")))
}
