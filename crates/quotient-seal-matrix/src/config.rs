use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MATRIX_SCHEMA_VERSION: &str = "quotient-seal-compilation-matrix/v1";
pub const WASM_TARGET: &str = "wasm32-unknown-unknown";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolchainRole {
    Development,
    HeldOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainSpec {
    pub id: String,
    pub channel: String,
    pub role: ToolchainRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OptLevel {
    #[serde(rename = "0")]
    O0,
    #[serde(rename = "1")]
    O1,
    #[serde(rename = "2")]
    O2,
    #[serde(rename = "3")]
    O3,
    #[serde(rename = "s")]
    Size,
    #[serde(rename = "z")]
    SizeMin,
}

impl OptLevel {
    #[must_use]
    pub const fn rustc_value(self) -> &'static str {
        match self {
            Self::O0 => "0",
            Self::O1 => "1",
            Self::O2 => "2",
            Self::O3 => "3",
            Self::Size => "s",
            Self::SizeMin => "z",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LtoMode {
    Off,
    Thin,
    Fat,
}

impl LtoMode {
    #[must_use]
    pub const fn rustc_value(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Thin => "thin",
            Self::Fat => "fat",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CodegenUnits {
    #[serde(rename = "default")]
    Default,
    #[serde(rename = "1")]
    One,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WasmOptLevel {
    None,
    O1,
    O2,
    Os,
    Oz,
}

impl WasmOptLevel {
    #[must_use]
    pub const fn flag(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::O1 => Some("-O1"),
            Self::O2 => Some("-O2"),
            Self::Os => Some("-Os"),
            Self::Oz => Some("-Oz"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilationConfig {
    pub id: String,
    pub toolchain: String,
    pub opt_level: OptLevel,
    pub lto: LtoMode,
    pub codegen_units: CodegenUnits,
    pub wasm_opt: WasmOptLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilationMatrix {
    pub schema_version: String,
    pub target: String,
    pub rustup_binary: String,
    pub wasm_opt_binary: String,
    pub wasm_opt_expected_version: String,
    pub toolchains: Vec<ToolchainSpec>,
    pub configurations: Vec<CompilationConfig>,
}

impl CompilationMatrix {
    pub fn from_path(path: &Path) -> Result<Self, MatrixError> {
        let source = fs::read_to_string(path).map_err(|source| MatrixError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let matrix = serde_json::from_str(&source).map_err(MatrixError::Parse)?;
        Ok(matrix)
    }

    pub fn validate(&self) -> Result<(), MatrixError> {
        if self.schema_version != MATRIX_SCHEMA_VERSION {
            return Err(MatrixError::SchemaVersion(self.schema_version.clone()));
        }
        if self.target != WASM_TARGET {
            return Err(MatrixError::Target(self.target.clone()));
        }
        if self.configurations.len() < 12 {
            return Err(MatrixError::TooFewConfigurations(self.configurations.len()));
        }
        if self.rustup_binary.is_empty()
            || self.wasm_opt_binary.is_empty()
            || self.wasm_opt_expected_version.is_empty()
        {
            return Err(MatrixError::EmptyToolContract);
        }

        let mut toolchain_ids = HashSet::new();
        for toolchain in &self.toolchains {
            if !toolchain_ids.insert(toolchain.id.as_str()) {
                return Err(MatrixError::DuplicateToolchain(toolchain.id.clone()));
            }
        }
        if !self
            .toolchains
            .iter()
            .any(|toolchain| toolchain.role == ToolchainRole::Development)
            || !self
                .toolchains
                .iter()
                .any(|toolchain| toolchain.role == ToolchainRole::HeldOut)
        {
            return Err(MatrixError::MissingToolchainRole);
        }
        if !self
            .toolchains
            .iter()
            .any(|toolchain| toolchain.channel.starts_with("nightly-"))
            || !self
                .toolchains
                .iter()
                .any(|toolchain| !toolchain.channel.starts_with("nightly-"))
        {
            return Err(MatrixError::MissingPinnedStableOrNightly);
        }

        let mut config_ids = HashSet::new();
        let mut opt_levels = HashSet::new();
        let mut lto_modes = HashSet::new();
        let mut codegen_units = HashSet::new();
        let mut wasm_opt_levels = HashSet::new();
        for config in &self.configurations {
            if !config_ids.insert(config.id.as_str()) {
                return Err(MatrixError::DuplicateConfiguration(config.id.clone()));
            }
            if !toolchain_ids.contains(config.toolchain.as_str()) {
                return Err(MatrixError::UnknownToolchain {
                    configuration: config.id.clone(),
                    toolchain: config.toolchain.clone(),
                });
            }
            opt_levels.insert(config.opt_level);
            lto_modes.insert(config.lto);
            codegen_units.insert(config.codegen_units);
            wasm_opt_levels.insert(config.wasm_opt);
        }

        if opt_levels.len() != 6
            || lto_modes.len() != 3
            || codegen_units.len() != 2
            || wasm_opt_levels.len() != 5
        {
            return Err(MatrixError::IncompleteAxisCoverage);
        }
        Ok(())
    }

    #[must_use]
    pub fn configuration(&self, id: &str) -> Option<&CompilationConfig> {
        self.configurations.iter().find(|config| config.id == id)
    }

    #[must_use]
    pub fn toolchain(&self, id: &str) -> Option<&ToolchainSpec> {
        self.toolchains.iter().find(|toolchain| toolchain.id == id)
    }
}

#[derive(Debug, Error)]
pub enum MatrixError {
    #[error("failed to read matrix at {path}: {source}")]
    Read {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("matrix is not strict JSON-compatible YAML: {0}")]
    Parse(serde_json::Error),
    #[error("unsupported matrix schema version: {0}")]
    SchemaVersion(String),
    #[error("unsupported compilation target: {0}")]
    Target(String),
    #[error("at least 12 configurations are required, found {0}")]
    TooFewConfigurations(usize),
    #[error("tool binary and version contracts must not be empty")]
    EmptyToolContract,
    #[error("duplicate toolchain id: {0}")]
    DuplicateToolchain(String),
    #[error("both development and held-out toolchains are required")]
    MissingToolchainRole,
    #[error("an exact stable and an exact nightly toolchain are required")]
    MissingPinnedStableOrNightly,
    #[error("duplicate configuration id: {0}")]
    DuplicateConfiguration(String),
    #[error("configuration {configuration} references unknown toolchain {toolchain}")]
    UnknownToolchain {
        configuration: String,
        toolchain: String,
    },
    #[error("matrix does not cover every frozen compilation axis")]
    IncompleteAxisCoverage,
}
