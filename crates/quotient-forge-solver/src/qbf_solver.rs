use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    run_bounded_process, validate_qdimacs, BoundedProcessOutput, OutputStream, ProcessLimits,
    QdimacsBounds,
};

pub const QBF_SOLVER_MANIFEST_SCHEMA_V1: &str = "noticer.quotient_forge.qbf_solver_manifest.v1";
pub const QBF_INSTALL_SCHEMA_V1: &str = "noticer.quotient_forge.qbf_solver_install.v1";
pub const QBF_SOLVER_RESULT_SCHEMA_V1: &str = "noticer.quotient_forge.qbf_solver_result.v1";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
static QUERY_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum QbfPlatform {
    #[serde(rename = "linux-x86_64")]
    LinuxX86_64,
    #[serde(rename = "windows-x86_64")]
    WindowsX86_64,
}

impl QbfPlatform {
    pub fn parse(value: &str) -> Result<Self, QbfSolverError> {
        match value {
            "linux-x86_64" => Ok(Self::LinuxX86_64),
            "windows-x86_64" => Ok(Self::WindowsX86_64),
            _ => Err(QbfSolverError::InvalidManifest("unsupported platform")),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "linux-x86_64",
            Self::WindowsX86_64 => "windows-x86_64",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QbfCommands {
    pub version: Vec<String>,
    pub solve: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QbfPlatformAsset {
    pub platform: QbfPlatform,
    pub executable_path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QbfSolverManifest {
    pub schema_version: String,
    pub solver: String,
    pub version: String,
    pub source_revision: String,
    pub source_tag: String,
    pub source_archive_name: String,
    pub source_url: String,
    pub source_sha256: String,
    pub commands: QbfCommands,
    pub platforms: Vec<QbfPlatformAsset>,
    pub network_policy: String,
    pub security_interpretation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QbfInstallReceipt {
    pub schema_version: String,
    pub solver: String,
    pub version: String,
    pub platform: QbfPlatform,
    pub source_revision: String,
    pub source_sha256: String,
    pub manifest_sha256: String,
    pub binary_sha256: String,
    pub executable_path: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QbfSolverStatus {
    Sat,
    UnsatAtBound,
    Unknown,
    Timeout,
    Malformed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QbfCandidateStatus {
    PendingIndependentCheck,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QbfSolverMetadata {
    pub solver: String,
    pub version: String,
    pub platform: String,
    pub source_revision: String,
    pub source_sha256: String,
    pub binary_sha256: String,
    pub manifest_sha256: String,
    pub program: String,
    pub argv: Vec<String>,
    pub timeout_ms: u64,
    pub seed: u64,
    pub bounds: QdimacsBounds,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QbfSolverResultArtifact {
    pub schema_version: String,
    pub metadata: QbfSolverMetadata,
    pub qdimacs_sha256: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub result: QbfSolverStatus,
    pub candidate_status: QbfCandidateStatus,
    pub candidate_accepted: bool,
    pub bounded_only: bool,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QbfSolverRun {
    pub artifact: QbfSolverResultArtifact,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Error)]
pub enum QbfSolverError {
    #[error("QBF solver manifest is invalid: {0}")]
    InvalidManifest(&'static str),
    #[error("QBF solver install receipt is invalid: {0}")]
    InvalidReceipt(&'static str),
    #[error("QBF solver binary SHA-256 does not match its receipt")]
    BinaryHashMismatch,
    #[error("QBF solver I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("QBF solver JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("QDIMACS validation failed: {0}")]
    Qdimacs(String),
    #[error("bounded QBF process failed: {0}")]
    Process(String),
}

impl QbfSolverManifest {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, QbfSolverError> {
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(QbfSolverError::InvalidManifest("document exceeds 1 MiB"));
        }
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn from_path(path: &Path) -> Result<Self, QbfSolverError> {
        require_regular_file(path, MAX_MANIFEST_BYTES)?;
        Self::from_slice(&fs::read(path)?)
    }

    pub fn validate(&self) -> Result<(), QbfSolverError> {
        if self.schema_version != QBF_SOLVER_MANIFEST_SCHEMA_V1
            || self.solver != "caqe"
            || self.version != "4.0.2"
            || self.source_revision != "62ee7692dada5236307f8652234ed7a743651eb7"
            || self.source_tag != "4.0.2"
            || self.source_archive_name != "caqe-4.0.2.zip"
            || self.source_url != "https://github.com/ltentrup/caqe/archive/refs/tags/4.0.2.zip"
            || self.source_sha256
                != "d09ad720a29eedb27b64182eadd51820b5ac8f30784051f033cdf3972b4e5d37"
        {
            return Err(QbfSolverError::InvalidManifest(
                "official source pin mismatch",
            ));
        }
        if self.network_policy != "DOWNLOAD_SOURCE_ONLY_WITH_SHA256"
            || self.security_interpretation != "CANDIDATE_GENERATOR_NOT_SECURITY_ORACLE"
        {
            return Err(QbfSolverError::InvalidManifest("trust policy mismatch"));
        }
        validate_argv(&self.commands.version)?;
        validate_argv(&self.commands.solve)?;
        if self.platforms.len() != 2
            || self.asset(QbfPlatform::LinuxX86_64).is_none()
            || self.asset(QbfPlatform::WindowsX86_64).is_none()
        {
            return Err(QbfSolverError::InvalidManifest("platform matrix mismatch"));
        }
        for asset in &self.platforms {
            validate_relative_path(&asset.executable_path)?;
            if (asset.platform == QbfPlatform::WindowsX86_64)
                != asset.executable_path.ends_with(".exe")
            {
                return Err(QbfSolverError::InvalidManifest(
                    "platform executable mismatch",
                ));
            }
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> Result<String, QbfSolverError> {
        self.validate()?;
        Ok(sha256(&serde_json::to_vec(self)?))
    }

    pub fn asset(&self, platform: QbfPlatform) -> Option<&QbfPlatformAsset> {
        self.platforms
            .iter()
            .find(|asset| asset.platform == platform)
    }
}

impl QbfInstallReceipt {
    pub fn from_path(path: &Path) -> Result<Self, QbfSolverError> {
        require_regular_file(path, MAX_MANIFEST_BYTES)?;
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }
}

#[derive(Clone, Debug)]
pub struct QbfSolverAdapter {
    manifest: QbfSolverManifest,
    program: PathBuf,
    binary_sha256: String,
    manifest_sha256: String,
    platform: QbfPlatform,
    limits: ProcessLimits,
}

impl QbfSolverAdapter {
    pub fn from_installation(
        manifest: QbfSolverManifest,
        installation_root: &Path,
        receipt_path: &Path,
        platform: QbfPlatform,
        limits: ProcessLimits,
    ) -> Result<Self, QbfSolverError> {
        manifest.validate()?;
        limits
            .validate()
            .map_err(|error| QbfSolverError::Process(format!("{error:?}")))?;
        let receipt = QbfInstallReceipt::from_path(receipt_path)?;
        let manifest_sha256 = manifest.digest_sha256()?;
        let asset = manifest
            .asset(platform)
            .ok_or(QbfSolverError::InvalidManifest("platform asset missing"))?;
        if receipt.schema_version != QBF_INSTALL_SCHEMA_V1
            || receipt.solver != manifest.solver
            || receipt.version != manifest.version
            || receipt.platform != platform
            || receipt.source_revision != manifest.source_revision
            || receipt.source_sha256 != manifest.source_sha256
            || receipt.manifest_sha256 != manifest_sha256
            || receipt.executable_path != asset.executable_path
            || !is_sha256(&receipt.binary_sha256)
        {
            return Err(QbfSolverError::InvalidReceipt("provenance fields mismatch"));
        }
        let program = installation_root.join(asset.executable_path.split('/').collect::<PathBuf>());
        if hash_regular_file(&program)? != receipt.binary_sha256 {
            return Err(QbfSolverError::BinaryHashMismatch);
        }
        Ok(Self {
            manifest,
            program,
            binary_sha256: receipt.binary_sha256,
            manifest_sha256,
            platform,
            limits,
        })
    }

    pub fn run(
        &self,
        qdimacs: &str,
        bounds: QdimacsBounds,
        seed: u64,
        timeout: Duration,
    ) -> Result<QbfSolverRun, QbfSolverError> {
        validate_qdimacs(qdimacs).map_err(|error| QbfSolverError::Qdimacs(error.to_string()))?;
        if hash_regular_file(&self.program)? != self.binary_sha256 {
            return Err(QbfSolverError::BinaryHashMismatch);
        }
        let query = TemporaryQuery::create(qdimacs)?;
        let mut argv = self.manifest.commands.solve.clone();
        argv.push(query.path.display().to_string());
        let output = run_bounded_process(&self.program, &argv, b"", timeout, self.limits)
            .map_err(|error| QbfSolverError::Process(format!("{error:?}")))?;
        let metadata = QbfSolverMetadata {
            solver: self.manifest.solver.clone(),
            version: self.manifest.version.clone(),
            platform: self.platform.label().to_owned(),
            source_revision: self.manifest.source_revision.clone(),
            source_sha256: self.manifest.source_sha256.clone(),
            binary_sha256: self.binary_sha256.clone(),
            manifest_sha256: self.manifest_sha256.clone(),
            program: self.program.display().to_string(),
            argv,
            timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            seed,
            bounds,
        };
        QbfSolverResultArtifact::from_output(metadata, qdimacs, output)
    }
}

impl QbfSolverResultArtifact {
    pub fn from_output(
        metadata: QbfSolverMetadata,
        qdimacs: &str,
        output: BoundedProcessOutput,
    ) -> Result<QbfSolverRun, QbfSolverError> {
        if metadata.timeout_ms == 0
            || !is_sha256(&metadata.binary_sha256)
            || !is_sha256(&metadata.manifest_sha256)
            || !is_sha256(&metadata.source_sha256)
        {
            return Err(QbfSolverError::InvalidReceipt("result metadata"));
        }
        let result = classify_qbf_output(&output);
        let (stdout, stderr, diagnostic) = decompose(output, result);
        let candidate_status = if result == QbfSolverStatus::Sat {
            QbfCandidateStatus::PendingIndependentCheck
        } else {
            QbfCandidateStatus::NotApplicable
        };
        let artifact = Self {
            schema_version: QBF_SOLVER_RESULT_SCHEMA_V1.to_owned(),
            metadata,
            qdimacs_sha256: sha256(qdimacs.as_bytes()),
            stdout_sha256: sha256(stdout.as_bytes()),
            stderr_sha256: sha256(stderr.as_bytes()),
            result,
            candidate_status,
            candidate_accepted: false,
            bounded_only: true,
            diagnostic,
        };
        Ok(QbfSolverRun {
            artifact,
            stdout,
            stderr,
        })
    }

    pub fn write_canonical(&self, path: &Path) -> Result<(), QbfSolverError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        fs::write(path, bytes)?;
        Ok(())
    }
}

pub fn classify_qbf_output(output: &BoundedProcessOutput) -> QbfSolverStatus {
    match output {
        BoundedProcessOutput::TimedOut => QbfSolverStatus::Timeout,
        BoundedProcessOutput::OutputLimitExceeded { .. } => QbfSolverStatus::Malformed,
        BoundedProcessOutput::Completed { stdout, .. } => {
            let statuses = stdout.lines().filter_map(parse_status).collect::<Vec<_>>();
            if statuses.is_empty() || statuses.iter().any(|status| *status != statuses[0]) {
                QbfSolverStatus::Malformed
            } else {
                statuses[0]
            }
        }
    }
}

fn parse_status(line: &str) -> Option<QbfSolverStatus> {
    let line = line.trim().to_ascii_lowercase();
    match line.as_str() {
        "sat" | "s sat" | "s satisfiable" => Some(QbfSolverStatus::Sat),
        "unsat" | "s unsat" | "s unsatisfiable" => Some(QbfSolverStatus::UnsatAtBound),
        "unknown" | "s unknown" => Some(QbfSolverStatus::Unknown),
        _ if line.starts_with("s cnf 1 ") || line == "s cnf 1" => Some(QbfSolverStatus::Sat),
        _ if line.starts_with("s cnf 0 ") || line == "s cnf 0" => {
            Some(QbfSolverStatus::UnsatAtBound)
        }
        _ => None,
    }
}

fn decompose(
    output: BoundedProcessOutput,
    result: QbfSolverStatus,
) -> (String, String, Option<String>) {
    match output {
        BoundedProcessOutput::Completed { stdout, stderr, .. } => {
            let diagnostic = (result == QbfSolverStatus::Malformed)
                .then(|| "UNRECOGNIZED_OR_CONFLICTING_QBF_OUTPUT".to_owned());
            (stdout, stderr, diagnostic)
        }
        BoundedProcessOutput::TimedOut => (
            String::new(),
            String::new(),
            Some("PROCESS_TIMEOUT".to_owned()),
        ),
        BoundedProcessOutput::OutputLimitExceeded { stream } => (
            String::new(),
            String::new(),
            Some(match stream {
                OutputStream::Stdout => "OUTPUT_LIMIT_STDOUT".to_owned(),
                OutputStream::Stderr => "OUTPUT_LIMIT_STDERR".to_owned(),
            }),
        ),
    }
}

struct TemporaryQuery {
    path: PathBuf,
}

impl TemporaryQuery {
    fn create(qdimacs: &str) -> Result<Self, QbfSolverError> {
        let nonce = QUERY_NONCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "noticer-qbf-{}-{nonce}.qdimacs",
            std::process::id()
        ));
        fs::write(&path, qdimacs.as_bytes())?;
        Ok(Self { path })
    }
}

impl Drop for TemporaryQuery {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn require_regular_file(path: &Path, max_bytes: u64) -> Result<(), QbfSolverError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(QbfSolverError::InvalidReceipt(
            "path is not a bounded regular file",
        ));
    }
    Ok(())
}

fn hash_regular_file(path: &Path) -> Result<String, QbfSolverError> {
    require_regular_file(path, MAX_BINARY_BYTES)?;
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_argv(argv: &[String]) -> Result<(), QbfSolverError> {
    if argv.len() > 16
        || argv.iter().any(|argument| {
            argument.is_empty()
                || argument.len() > 128
                || argument.contains(['\r', '\n', '\0'])
                || matches!(argument.as_str(), "sh" | "bash" | "cmd" | "powershell")
        })
    {
        return Err(QbfSolverError::InvalidManifest("unsafe command argv"));
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), QbfSolverError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(['\\', ':'])
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(QbfSolverError::InvalidManifest("unsafe executable path"));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
