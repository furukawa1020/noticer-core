use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MUTATION_SPLIT_VERSION: &str = "quotient-seal-mutation-split/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetSplit {
    Development,
    HeldOut,
}

impl DatasetSplit {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::HeldOut => "held_out",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitSide {
    pub module_families: Vec<String>,
    pub compiler_configurations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitContract {
    pub schema_version: String,
    pub development: SplitSide,
    pub held_out: SplitSide,
}

impl SplitContract {
    pub fn from_path(path: &Path) -> Result<Self, SplitError> {
        let bytes = fs::read(path).map_err(|source| SplitError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        serde_json::from_slice(&bytes).map_err(SplitError::Parse)
    }

    pub fn validate(&self) -> Result<(), SplitError> {
        if self.schema_version != MUTATION_SPLIT_VERSION {
            return Err(SplitError::SchemaVersion(self.schema_version.clone()));
        }
        validate_side(DatasetSplit::Development, &self.development)?;
        validate_side(DatasetSplit::HeldOut, &self.held_out)?;
        reject_overlap(
            "module family",
            &self.development.module_families,
            &self.held_out.module_families,
        )?;
        reject_overlap(
            "compiler configuration",
            &self.development.compiler_configurations,
            &self.held_out.compiler_configurations,
        )
    }

    pub fn classify(
        &self,
        module_family: &str,
        compiler_configuration: &str,
    ) -> Result<DatasetSplit, SplitError> {
        self.validate()?;
        let module = membership(
            module_family,
            &self.development.module_families,
            &self.held_out.module_families,
        )
        .ok_or_else(|| SplitError::UnknownModuleFamily(module_family.to_owned()))?;
        let compiler = membership(
            compiler_configuration,
            &self.development.compiler_configurations,
            &self.held_out.compiler_configurations,
        )
        .ok_or_else(|| {
            SplitError::UnknownCompilerConfiguration(compiler_configuration.to_owned())
        })?;
        if module != compiler {
            return Err(SplitError::CrossSplitPair {
                module_family: module_family.to_owned(),
                module_split: module,
                compiler_configuration: compiler_configuration.to_owned(),
                compiler_split: compiler,
            });
        }
        Ok(module)
    }
}

fn validate_side(split: DatasetSplit, side: &SplitSide) -> Result<(), SplitError> {
    if side.module_families.is_empty() || side.compiler_configurations.is_empty() {
        return Err(SplitError::EmptySide(split));
    }
    reject_duplicates(split, "module family", &side.module_families)?;
    reject_duplicates(
        split,
        "compiler configuration",
        &side.compiler_configurations,
    )?;
    for identifier in side
        .module_families
        .iter()
        .chain(side.compiler_configurations.iter())
    {
        if identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(SplitError::InvalidIdentifier(identifier.clone()));
        }
    }
    Ok(())
}

fn reject_duplicates(
    split: DatasetSplit,
    kind: &'static str,
    values: &[String],
) -> Result<(), SplitError> {
    let unique: BTreeSet<_> = values.iter().collect();
    if unique.len() == values.len() {
        Ok(())
    } else {
        Err(SplitError::Duplicate { split, kind })
    }
}

fn reject_overlap(
    kind: &'static str,
    development: &[String],
    held_out: &[String],
) -> Result<(), SplitError> {
    let development: BTreeSet<_> = development.iter().collect();
    if let Some(value) = held_out.iter().find(|value| development.contains(value)) {
        Err(SplitError::Overlap {
            kind,
            value: value.clone(),
        })
    } else {
        Ok(())
    }
}

fn membership(value: &str, development: &[String], held_out: &[String]) -> Option<DatasetSplit> {
    if development.iter().any(|candidate| candidate == value) {
        Some(DatasetSplit::Development)
    } else if held_out.iter().any(|candidate| candidate == value) {
        Some(DatasetSplit::HeldOut)
    } else {
        None
    }
}

#[derive(Debug, Error)]
pub enum SplitError {
    #[error("failed to read split contract at {path}: {source}")]
    Read {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("split contract is not strict JSON-compatible YAML: {0}")]
    Parse(serde_json::Error),
    #[error("unsupported split schema version: {0}")]
    SchemaVersion(String),
    #[error("{0:?} split must contain module and compiler members")]
    EmptySide(DatasetSplit),
    #[error("duplicate {kind} in {split:?} split")]
    Duplicate {
        split: DatasetSplit,
        kind: &'static str,
    },
    #[error("invalid split identifier: {0}")]
    InvalidIdentifier(String),
    #[error("{kind} occurs in development and held-out splits: {value}")]
    Overlap { kind: &'static str, value: String },
    #[error("unknown module family: {0}")]
    UnknownModuleFamily(String),
    #[error("unknown compiler configuration: {0}")]
    UnknownCompilerConfiguration(String),
    #[error(
        "cross-split seed pair: module {module_family} is {module_split:?}, compiler {compiler_configuration} is {compiler_split:?}"
    )]
    CrossSplitPair {
        module_family: String,
        module_split: DatasetSplit,
        compiler_configuration: String,
        compiler_split: DatasetSplit,
    },
}
