#![forbid(unsafe_code)]

//! Public-only adapters from existing Noticer contracts to QuotientForge.
//!
//! Existing domain types are re-exported or borrowed. This crate deliberately
//! does not depend on acquisition, private evidence, or K1 bridge crates.

mod benchmark;
mod binding;

pub use benchmark::{
    run_handwritten_benchmark, AdapterEvaluation, AdapterVerdict, HandwrittenPlan,
};
pub use binding::{
    connect_generated_plan, CertifiedGeneratedPlan, ConnectedGeneratedPlan, ConnectionError,
    ExistingContractRefs,
};

pub use noticer_aetp::{ActionObligation, ActionSemantics, PublicContext};
pub use noticer_menfugu_core as menfugu;
pub use noticer_protocol as atv2_protocol;
pub use noticer_provenance as aepa;
pub use noticer_token as atv2_token;
pub use noticer_trace_shaper as aets;
pub use noticer_transport_core as aplot;
pub use noticer_transport_sim::PublicLossTape;

/// Type-level audit helper. It proves the four shared AETP contracts are the
/// existing Noticer types rather than adapter-owned copies.
#[must_use]
pub fn shared_contract_type_names() -> [&'static str; 4] {
    [
        core::any::type_name::<ActionSemantics>(),
        core::any::type_name::<ActionObligation>(),
        core::any::type_name::<PublicContext>(),
        core::any::type_name::<PublicLossTape>(),
    ]
}
