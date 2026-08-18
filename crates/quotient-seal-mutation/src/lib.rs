//! Deterministic binary-level mutation operators for restricted WebAssembly.
//!
//! This crate mutates compiled bytes directly. It does not alter or invoke the
//! source generator, and it does not interpret a generated mutant as a
//! successful attack or a successful defense.

mod campaign;
mod operator;
mod split;
mod wasm;

pub use campaign::{
    run_campaign, CampaignError, CampaignManifest, CampaignRequest, Evaluation,
    InconclusiveEvaluator, MutantEvaluator, MutantRecord, MutationVerdict,
    MUTATION_CAMPAIGN_VERSION,
};
pub use operator::{
    MutationFamily, MutationOperator, MutationRecipe, ALL_MUTATION_OPERATORS,
    MUTATION_TAXONOMY_VERSION,
};
pub use split::{DatasetSplit, SplitContract, SplitError, SplitSide, MUTATION_SPLIT_VERSION};
pub use wasm::{
    mutate_wasm, validate_wasm_container, MutationArtifact, MutationEdit, MutationError,
};
