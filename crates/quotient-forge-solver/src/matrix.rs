use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SOLVER_MATRIX_SCHEMA_V1: &str = "quotient-forge-solver-matrix/v1";
pub const MAX_SOLVER_MATRIX_BYTES: usize = 1024 * 1024;

const ARTIFACT_FIELDS_V1: [&str; 6] = [
    "solver",
    "version",
    "platform",
    "asset_sha256",
    "matrix_sha256",
    "argv",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SolverId {
    Cvc5,
    Z3,
}

impl SolverId {
    fn repository(self) -> &'static str {
        match self {
            Self::Cvc5 => "cvc5/cvc5",
            Self::Z3 => "Z3Prover/z3",
        }
    }

    fn tag_prefix(self) -> &'static str {
        match self {
            Self::Cvc5 => "cvc5-",
            Self::Z3 => "z3-",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum SolverPlatform {
    #[serde(rename = "linux-x86_64")]
    LinuxX86_64,
    #[serde(rename = "windows-x86_64")]
    WindowsX86_64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SolverCommands {
    pub version: Vec<String>,
    pub probe: Vec<String>,
    pub solve: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SolverAsset {
    pub platform: SolverPlatform,
    pub archive_name: String,
    pub download_url: String,
    pub sha256: String,
    pub executable_path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SolverPin {
    pub id: SolverId,
    pub version: String,
    pub release_tag: String,
    pub release_url: String,
    pub version_output_prefix: String,
    pub commands: SolverCommands,
    pub assets: Vec<SolverAsset>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SolverMatrix {
    pub schema_version: String,
    pub selection_order: Vec<SolverId>,
    pub artifact_fields: Vec<String>,
    pub solvers: Vec<SolverPin>,
    pub network_policy: String,
    pub security_interpretation: String,
}

#[derive(Debug, Error)]
pub enum SolverMatrixError {
    #[error("solver matrix I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("solver matrix JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid solver matrix: {0}")]
    Invalid(String),
}

impl SolverMatrix {
    pub fn from_slice(encoded: &[u8]) -> Result<Self, SolverMatrixError> {
        if encoded.len() > MAX_SOLVER_MATRIX_BYTES {
            return Err(SolverMatrixError::Invalid(
                "document exceeds the 1 MiB bound".to_owned(),
            ));
        }
        let matrix: Self = serde_json::from_slice(encoded)?;
        matrix.validate()?;
        Ok(matrix)
    }

    pub fn from_path(path: &Path) -> Result<Self, SolverMatrixError> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(SolverMatrixError::Invalid(
                "matrix path must be a regular non-symlink file".to_owned(),
            ));
        }
        if metadata.len() > MAX_SOLVER_MATRIX_BYTES as u64 {
            return Err(SolverMatrixError::Invalid(
                "document exceeds the 1 MiB bound".to_owned(),
            ));
        }
        Self::from_slice(&fs::read(path)?)
    }

    pub fn validate(&self) -> Result<(), SolverMatrixError> {
        if self.schema_version != SOLVER_MATRIX_SCHEMA_V1 {
            return invalid("unsupported schema_version");
        }
        if self.selection_order != [SolverId::Cvc5, SolverId::Z3] {
            return invalid("selection_order must be cvc5 then z3");
        }
        if self.artifact_fields != ARTIFACT_FIELDS_V1 {
            return invalid("artifact_fields differ from the v1 contract");
        }
        if self.network_policy != "DOWNLOAD_ONLY_WITH_SHA256" {
            return invalid("network_policy must require download hash verification");
        }
        if self.security_interpretation != "CANDIDATE_GENERATOR_NOT_SECURITY_ORACLE" {
            return invalid("security_interpretation weakens the trust boundary");
        }
        if self.solvers.len() != 2 {
            return invalid("exactly two solver pins are required");
        }
        let ids = self
            .solvers
            .iter()
            .map(|solver| solver.id)
            .collect::<BTreeSet<_>>();
        if ids != BTreeSet::from([SolverId::Cvc5, SolverId::Z3]) {
            return invalid("solver pins must contain cvc5 and z3 exactly once");
        }
        for solver in &self.solvers {
            validate_solver(solver)?;
        }
        Ok(())
    }

    pub fn solver(&self, id: SolverId) -> &SolverPin {
        self.solvers
            .iter()
            .find(|solver| solver.id == id)
            .expect("validated matrices contain both solver pins")
    }

    pub fn asset(&self, id: SolverId, platform: SolverPlatform) -> &SolverAsset {
        self.solver(id)
            .assets
            .iter()
            .find(|asset| asset.platform == platform)
            .expect("validated solver pins contain both platforms")
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SolverMatrixError> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    pub fn digest_sha256(&self) -> Result<String, SolverMatrixError> {
        let digest = Sha256::digest(self.canonical_bytes()?);
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

fn validate_solver(solver: &SolverPin) -> Result<(), SolverMatrixError> {
    if !is_semver_triplet(&solver.version) {
        return invalid("solver version must be a numeric major.minor.patch triplet");
    }
    let expected_tag = format!(
        "{}{version}",
        solver.id.tag_prefix(),
        version = solver.version
    );
    if solver.release_tag != expected_tag {
        return invalid("release_tag does not match solver id and version");
    }
    let expected_release = format!(
        "https://github.com/{}/releases/tag/{}",
        solver.id.repository(),
        solver.release_tag
    );
    if solver.release_url != expected_release {
        return invalid("release_url is not the official tagged GitHub release");
    }
    if solver.version_output_prefix.is_empty()
        || solver.version_output_prefix.len() > 128
        || solver.version_output_prefix.contains(['\r', '\n', '\0'])
    {
        return invalid("version_output_prefix is invalid");
    }
    validate_argv(&solver.commands.version)?;
    validate_argv(&solver.commands.probe)?;
    validate_argv(&solver.commands.solve)?;
    if solver.assets.len() != 2 {
        return invalid("each solver must pin exactly two platform assets");
    }
    let platforms = solver
        .assets
        .iter()
        .map(|asset| asset.platform)
        .collect::<BTreeSet<_>>();
    if platforms != BTreeSet::from([SolverPlatform::LinuxX86_64, SolverPlatform::WindowsX86_64]) {
        return invalid("solver assets must cover Linux and Windows x86_64 exactly once");
    }
    for asset in &solver.assets {
        validate_asset(solver, asset)?;
    }
    Ok(())
}

fn validate_asset(solver: &SolverPin, asset: &SolverAsset) -> Result<(), SolverMatrixError> {
    if !asset.archive_name.ends_with(".zip")
        || asset.archive_name.is_empty()
        || asset
            .archive_name
            .chars()
            .any(|character| !character.is_ascii_alphanumeric() && !"._-".contains(character))
    {
        return invalid("archive_name is not a portable ZIP name");
    }
    let expected_url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        solver.id.repository(),
        solver.release_tag,
        asset.archive_name
    );
    if asset.download_url != expected_url {
        return invalid("asset URL is not under the pinned official release");
    }
    if asset.sha256.len() != 64
        || !asset
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid("asset sha256 must be 64 lowercase hexadecimal characters");
    }
    validate_relative_path(&asset.executable_path)?;
    match asset.platform {
        SolverPlatform::LinuxX86_64 if asset.executable_path.ends_with(".exe") => {
            invalid("Linux executable_path may not end in .exe")
        }
        SolverPlatform::WindowsX86_64 if !asset.executable_path.ends_with(".exe") => {
            invalid("Windows executable_path must end in .exe")
        }
        _ => Ok(()),
    }
}

fn validate_argv(argv: &[String]) -> Result<(), SolverMatrixError> {
    if argv.is_empty() || argv.len() > 16 {
        return invalid("each command must contain 1 to 16 fixed arguments");
    }
    if argv.iter().any(|argument| {
        argument.is_empty()
            || argument.len() > 128
            || argument.contains(['\r', '\n', '\0'])
            || matches!(argument.as_str(), "sh" | "bash" | "cmd" | "powershell")
    }) {
        return invalid("command arguments are empty, oversized, or shell-bearing");
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), SolverMatrixError> {
    if path.is_empty()
        || path.len() > 240
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || path
            .chars()
            .any(|character| !character.is_ascii_alphanumeric() && !"._-/".contains(character))
    {
        return invalid("executable_path must be a canonical relative POSIX path");
    }
    Ok(())
}

fn is_semver_triplet(version: &str) -> bool {
    let parts = version.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn invalid<T>(message: &str) -> Result<T, SolverMatrixError> {
    Err(SolverMatrixError::Invalid(message.to_owned()))
}
