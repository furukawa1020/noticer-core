//! Deterministic, resource-bounded smoke fuzzing for DSL and import parsing.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::{parse_module, parse_module_graph, LoadedSource, ModuleLoader, ParseLimits};

pub const DSL_FUZZ_REPORT_SCHEMA: &str = "noticer.k7.dsl-import-fuzz-report.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DslFuzzLimits {
    pub max_input_bytes: usize,
    pub max_cases: usize,
    pub max_tokens: usize,
    pub max_imports: usize,
    pub max_import_depth: usize,
}

impl DslFuzzLimits {
    pub fn validate(self) -> Result<Self, DslFuzzError> {
        if self.max_input_bytes == 0
            || self.max_cases == 0
            || self.max_tokens == 0
            || self.max_imports < 2
            || self.max_import_depth == 0
            || self.max_input_bytes > 65_536
            || self.max_cases > 4_096
            || self.max_tokens > 16_384
            || self.max_imports > 256
            || self.max_import_depth > 64
        {
            return Err(DslFuzzError::InvalidLimits);
        }
        Ok(self)
    }

    fn parse_limits(self) -> ParseLimits {
        ParseLimits {
            max_source_bytes: self.max_input_bytes,
            max_tokens: self.max_tokens,
            max_imports: self.max_imports,
            max_import_depth: self.max_import_depth,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DslFuzzReport {
    pub schema: &'static str,
    pub seed: u64,
    pub supplied_cases: usize,
    pub executed_cases: usize,
    pub resource_rejections: usize,
    pub invalid_utf8_cases: usize,
    pub accepted_modules: usize,
    pub rejected_modules: usize,
    pub graph_acceptances: usize,
    pub graph_rejections: usize,
    pub coverage: BTreeSet<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DslFuzzError {
    InvalidLimits,
    TooManyCases,
}

impl Display for DslFuzzError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("DSL fuzz limits are invalid"),
            Self::TooManyCases => formatter.write_str("DSL fuzz corpus exceeds the case budget"),
        }
    }
}

impl Error for DslFuzzError {}

pub fn run_dsl_import_fuzz(
    seed: u64,
    corpus: &[Vec<u8>],
    limits: DslFuzzLimits,
) -> Result<DslFuzzReport, DslFuzzError> {
    let limits = limits.validate()?;
    if corpus.len() > limits.max_cases {
        return Err(DslFuzzError::TooManyCases);
    }
    let parse_limits = limits.parse_limits();
    let mut report = DslFuzzReport {
        schema: DSL_FUZZ_REPORT_SCHEMA,
        seed,
        supplied_cases: corpus.len(),
        executed_cases: 0,
        resource_rejections: 0,
        invalid_utf8_cases: 0,
        accepted_modules: 0,
        rejected_modules: 0,
        graph_acceptances: 0,
        graph_rejections: 0,
        coverage: BTreeSet::new(),
    };

    for bytes in corpus {
        if bytes.len() > limits.max_input_bytes {
            report.resource_rejections += 1;
            report.coverage.insert("input_limit");
            continue;
        }
        report.executed_cases += 1;
        let source = match std::str::from_utf8(bytes) {
            Ok(source) => source.to_owned(),
            Err(_) => {
                report.invalid_utf8_cases += 1;
                report.coverage.insert("invalid_utf8");
                String::from_utf8_lossy(bytes).into_owned()
            }
        };
        if parse_module("fuzz-input.qf", &source, parse_limits).is_ok() {
            report.accepted_modules += 1;
            report.coverage.insert("module_accept");
        } else {
            report.rejected_modules += 1;
            report.coverage.insert("module_reject");
        }
    }

    for mutation in shuffled_mutations(seed) {
        let loader = mutation.loader(limits.max_import_depth);
        if parse_module_graph("root.qf", &loader, parse_limits).is_ok() {
            report.graph_acceptances += 1;
            report.coverage.insert(mutation.accept_coverage());
        } else {
            report.graph_rejections += 1;
            report.coverage.insert(mutation.reject_coverage());
        }
    }
    Ok(report)
}

#[derive(Clone, Copy)]
enum GraphMutation {
    Acyclic,
    Cycle,
    ParentEscape,
    AbsoluteEscape,
    BackslashEscape,
    DepthOverflow,
}

impl GraphMutation {
    fn loader(self, max_depth: usize) -> SandboxedLoader {
        let mut sources = BTreeMap::new();
        match self {
            Self::Acyclic => {
                sources.insert("root.qf".to_owned(), module("root", Some("leaf.qf")));
                sources.insert("leaf.qf".to_owned(), module("leaf", None));
            }
            Self::Cycle => {
                sources.insert("root.qf".to_owned(), module("root", Some("leaf.qf")));
                sources.insert("leaf.qf".to_owned(), module("leaf", Some("root.qf")));
            }
            Self::ParentEscape => {
                sources.insert("root.qf".to_owned(), module("root", Some("../secret.qf")));
            }
            Self::AbsoluteEscape => {
                sources.insert("root.qf".to_owned(), module("root", Some("/secret.qf")));
            }
            Self::BackslashEscape => {
                sources.insert("root.qf".to_owned(), module("root", Some("..\\secret.qf")));
            }
            Self::DepthOverflow => {
                for depth in 0..=max_depth + 1 {
                    let name = if depth == 0 {
                        "root.qf".to_owned()
                    } else {
                        format!("depth-{depth}.qf")
                    };
                    let next = (depth <= max_depth).then(|| format!("depth-{}.qf", depth + 1));
                    sources.insert(name, module(&format!("depth_{depth}"), next.as_deref()));
                }
            }
        }
        SandboxedLoader { sources }
    }

    const fn accept_coverage(self) -> &'static str {
        match self {
            Self::Acyclic => "graph_acyclic_accept",
            _ => "unexpected_graph_accept",
        }
    }

    const fn reject_coverage(self) -> &'static str {
        match self {
            Self::Acyclic => "unexpected_graph_reject",
            Self::Cycle => "import_cycle",
            Self::ParentEscape => "parent_path_escape",
            Self::AbsoluteEscape => "absolute_path_escape",
            Self::BackslashEscape => "backslash_path_escape",
            Self::DepthOverflow => "import_depth",
        }
    }
}

fn shuffled_mutations(seed: u64) -> [GraphMutation; 6] {
    let mut mutations = [
        GraphMutation::Acyclic,
        GraphMutation::Cycle,
        GraphMutation::ParentEscape,
        GraphMutation::AbsoluteEscape,
        GraphMutation::BackslashEscape,
        GraphMutation::DepthOverflow,
    ];
    let mut state = seed;
    for index in (1..mutations.len()).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        mutations.swap(index, (state as usize) % (index + 1));
    }
    mutations
}

fn module(name: &str, import: Option<&str>) -> String {
    import.map_or_else(
        || format!("module {name} version 1 {{ horizon 1; }}"),
        |path| format!("module {name} version 1 {{ import \"{path}\"; horizon 1; }}"),
    )
}

struct SandboxedLoader {
    sources: BTreeMap<String, String>,
}

impl ModuleLoader for SandboxedLoader {
    fn load(&self, _importer: Option<&str>, requested: &str) -> Result<LoadedSource, String> {
        if !safe_import_path(requested) {
            return Err("import path leaves the fuzz sandbox".to_owned());
        }
        self.sources
            .get(requested)
            .cloned()
            .map(|source| LoadedSource {
                canonical_name: requested.to_owned(),
                source,
            })
            .ok_or_else(|| "module is absent from the fuzz sandbox".to_owned())
    }
}

fn safe_import_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}
