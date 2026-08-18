use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::planner::CommandSpec;

pub const RUN_MANIFEST_SCHEMA_VERSION: &str = "quotient-seal-matrix-run/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MatrixVerdict {
    Accept,
    Reject,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReproducibilityStatus {
    ByteIdentical,
    Diverged,
    NotMeasured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducibilityRecord {
    pub status: ReproducibilityStatus,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolEvidence {
    pub requested_binary: String,
    pub resolved_path: Option<PathBuf>,
    pub sha256: Option<String>,
    pub version: Option<String>,
    pub version_command: CommandSpec,
    pub inspection_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDigest {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckerRecord {
    pub command: CommandSpec,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunManifest {
    pub schema_version: String,
    pub plan_fingerprint_sha256: String,
    pub configuration_id: String,
    pub role: crate::config::ToolchainRole,
    pub held_out: bool,
    pub target: String,
    pub source: Option<ArtifactDigest>,
    pub rustc: ToolEvidence,
    pub wasm_opt: Option<ToolEvidence>,
    pub compile_commands: [CommandSpec; 2],
    pub wasm_opt_commands: Option<[CommandSpec; 2]>,
    pub outputs: Vec<ArtifactDigest>,
    pub reproducibility: ReproducibilityRecord,
    pub checker: Option<CheckerRecord>,
    pub verdict: MatrixVerdict,
    pub reason: String,
}

impl RunManifest {
    pub fn write_json(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let encoded = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        fs::write(path, encoded)
    }
}

