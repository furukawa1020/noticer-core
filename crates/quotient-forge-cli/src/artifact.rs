use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use crate::SolverMode;

const FORBIDDEN_PUBLIC_ARTIFACT_TERMS: [&str; 7] = [
    "raw_ppg",
    "baseline",
    "stable_identifier",
    "subject_id",
    "user_id",
    "device_id",
    "private_history",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolverRecord {
    pub mode: SolverMode,
    pub name: Option<String>,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestContext<'a> {
    pub command: &'a str,
    pub engine: &'a str,
    pub seed: u64,
    pub solver: &'a SolverRecord,
    pub status: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileRecord {
    path: String,
    media_type: &'static str,
    bytes: u64,
}

#[derive(Debug)]
pub enum ArtifactError {
    OutputExists(PathBuf),
    InvalidRelativePath(PathBuf),
    Io(std::io::Error),
    PrivateTerm { path: PathBuf, term: &'static str },
    RequiredSolverUnavailable,
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputExists(path) => {
                write!(formatter, "出力先は既に存在します: {}", path.display())
            }
            Self::InvalidRelativePath(path) => {
                write!(formatter, "artifact相対pathが不正です: {}", path.display())
            }
            Self::Io(error) => write!(formatter, "artifact I/O error: {error}"),
            Self::PrivateTerm { path, term } => write!(
                formatter,
                "public artifact {} に禁止語 {term} が含まれます",
                path.display()
            ),
            Self::RequiredSolverUnavailable => {
                formatter.write_str("必須solverが見つかりません（z3またはcvc5が必要です）")
            }
        }
    }
}

impl std::error::Error for ArtifactError {}

impl From<std::io::Error> for ArtifactError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn create_output_root(output: &Path) -> Result<(), ArtifactError> {
    if output.exists() {
        return Err(ArtifactError::OutputExists(output.to_path_buf()));
    }
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(output)?;
    Ok(())
}

pub fn write_text(
    output: &Path,
    relative: impl AsRef<Path>,
    contents: &str,
) -> Result<PathBuf, ArtifactError> {
    let relative = checked_relative(relative.as_ref())?;
    reject_private_terms(&relative, contents.as_bytes())?;
    let destination = output.join(&relative);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(destination, contents.as_bytes())?;
    Ok(relative)
}

pub fn write_binary(
    output: &Path,
    relative: impl AsRef<Path>,
    contents: &[u8],
) -> Result<PathBuf, ArtifactError> {
    let relative = checked_relative(relative.as_ref())?;
    if relative.extension().and_then(|value| value.to_str()) != Some("caqt") {
        reject_private_terms(&relative, contents)?;
    }
    let destination = output.join(&relative);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(destination, contents)?;
    Ok(relative)
}

pub fn resolve_solver(mode: SolverMode) -> Result<SolverRecord, ArtifactError> {
    if mode == SolverMode::Off {
        return Ok(SolverRecord {
            mode,
            name: None,
            version: None,
        });
    }

    for executable in ["z3", "cvc5"] {
        if let Ok(output) = Command::new(executable).arg("--version").output() {
            if output.status.success() {
                return Ok(SolverRecord {
                    mode,
                    name: Some(executable.to_owned()),
                    version: Some(String::from_utf8_lossy(&output.stdout).trim().to_owned()),
                });
            }
        }
    }

    if mode == SolverMode::Required {
        Err(ArtifactError::RequiredSolverUnavailable)
    } else {
        Ok(SolverRecord {
            mode,
            name: None,
            version: None,
        })
    }
}

pub fn finalize_manifest(
    output: &Path,
    context: ManifestContext<'_>,
    files: &[PathBuf],
) -> Result<PathBuf, ArtifactError> {
    let mut relative_files = files
        .iter()
        .map(|path| checked_relative(path))
        .collect::<Result<Vec<_>, _>>()?;
    relative_files.sort();
    relative_files.dedup();

    let records = relative_files
        .iter()
        .map(|relative| file_record(output, relative))
        .collect::<Result<Vec<_>, _>>()?;
    let compiler = command_version("rustc").unwrap_or_else(|| "unavailable".to_owned());
    let manifest = canonical_manifest_json(&context, &compiler, &records);
    reject_private_terms(Path::new("manifest.json"), manifest.as_bytes())?;
    let path = output.join("manifest.json");
    fs::write(&path, manifest.as_bytes())?;
    Ok(path)
}

fn checked_relative(path: &Path) -> Result<PathBuf, ArtifactError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ArtifactError::InvalidRelativePath(path.to_path_buf()));
    }
    Ok(path.to_path_buf())
}

fn reject_private_terms(path: &Path, contents: &[u8]) -> Result<(), ArtifactError> {
    let path_text = path.to_string_lossy().to_ascii_lowercase();
    let body = String::from_utf8_lossy(contents).to_ascii_lowercase();
    for term in FORBIDDEN_PUBLIC_ARTIFACT_TERMS {
        if path_text.contains(term) || body.contains(term) {
            return Err(ArtifactError::PrivateTerm {
                path: path.to_path_buf(),
                term,
            });
        }
    }
    Ok(())
}

fn file_record(output: &Path, relative: &Path) -> Result<FileRecord, ArtifactError> {
    let path = output.join(relative);
    let contents = fs::read(&path)?;
    if relative.extension().and_then(|value| value.to_str()) != Some("caqt") {
        reject_private_terms(relative, &contents)?;
    }
    Ok(FileRecord {
        path: relative.to_string_lossy().replace('\\', "/"),
        media_type: media_type(relative),
        bytes: contents.len() as u64,
    })
}

fn media_type(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("caqt") => "application/vnd.quotient-forge.caqt",
        Some("json") => "application/json",
        Some("rs") => "text/rust",
        Some("toml") => "application/toml",
        Some("tsv") => "text/tab-separated-values",
        _ => "application/octet-stream",
    }
}

fn command_version(executable: &str) -> Option<String> {
    let output = Command::new(executable).arg("--version").output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn canonical_manifest_json(
    context: &ManifestContext<'_>,
    compiler: &str,
    files: &[FileRecord],
) -> String {
    let file_entries = files
        .iter()
        .map(|record| {
            format!(
                "{{\"bytes\":{},\"media_type\":{},\"path\":{}}}",
                record.bytes,
                quote(record.media_type),
                quote(&record.path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let solver_name = optional_quote(context.solver.name.as_deref());
    let solver_version = optional_quote(context.solver.version.as_deref());
    format!(
        concat!(
            "{{\n",
            "  \"artifact_files\":[{}],\n",
            "  \"command\":{},\n",
            "  \"compiler\":{},\n",
            "  \"engine\":{},\n",
            "  \"privacy_contract\":\"public-only-v1\",\n",
            "  \"schema\":\"quotient-forge-artifact-v1\",\n",
            "  \"seed\":{},\n",
            "  \"solver\":{{\"mode\":{},\"name\":{},\"version\":{}}},\n",
            "  \"status\":{},\n",
            "  \"tool_version\":{}\n",
            "}}\n"
        ),
        file_entries,
        quote(context.command),
        quote(compiler),
        quote(context.engine),
        context.seed,
        quote(context.solver.mode.as_str()),
        solver_name,
        solver_version,
        quote(context.status),
        quote(env!("CARGO_PKG_VERSION")),
    )
}

pub(crate) fn quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            value if value < ' ' => {
                write!(&mut quoted, "\\u{:04x}", value as u32)
                    .expect("writing to a String cannot fail");
            }
            value => quoted.push(value),
        }
    }
    quoted.push('"');
    quoted
}

fn optional_quote(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), quote)
}
