#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//! Certificate for Action-Quotient Transducers (CAQT).
//!
//! The core parser and checker use only `core` and `alloc`. Solver libraries,
//! synthesis engines, platform I/O, and private acquisition types are outside
//! the trusted checker boundary.

extern crate alloc;

mod checker;
mod format;
mod inductive;
mod sha256;

pub use checker::{
    local_checker_contract_hash, recompute_cost, recompute_hashes, verify, CanonicalViolation,
    CertificateVerdict, ExpectedContract, IncompatibleReason, InvalidReason, UtilityViolation,
    ValidationReport,
};
pub use format::{
    Certificate, CertificateLimits, CostVector, Digest, DomainHashes, HashDomain, ObserverRecord,
    OutputRecord, ParseError, RelationPair, TransitionRecord, FORMAT_VERSION,
};
pub use inductive::{
    build_inductive_certificate, verify_inductive, ClosureRecord, ExpectedInductiveContract,
    InductiveBuildError, InductiveCanonicalViolation, InductiveCertificate, InductiveDecodeError,
    InductiveIncompatibleReason, InductiveInvalidReason, InductiveLimits, InductiveParseError,
    InductiveResourceBound, InductiveValidationReport, InductiveVerdict, INDUCTIVE_FORMAT_VERSION,
};
#[cfg(feature = "std")]
pub use inductive::{verify_inductive_timed, TimedInductiveVerification};

/// Computes a domain-separated SHA-256 digest for generated build artifacts.
///
/// The function remains available in the minimal no_std checker build so a
/// deployment validator can bind a certificate to its build manifest without
/// introducing a second digest implementation.
#[must_use]
pub fn artifact_digest(domain: &[u8], payload: &[u8]) -> Digest {
    let domain_length = u64::try_from(domain.len()).unwrap_or(u64::MAX);
    let payload_length = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    let mut material = alloc::vec::Vec::with_capacity(
        14_usize
            .saturating_add(domain.len())
            .saturating_add(payload.len()),
    );
    material.extend_from_slice(b"CAQT-ARTIFACT\0");
    material.extend_from_slice(&domain_length.to_le_bytes());
    material.extend_from_slice(domain);
    material.extend_from_slice(&payload_length.to_le_bytes());
    material.extend_from_slice(payload);
    Digest::new(sha256::sha256(&material))
}

#[cfg(feature = "ir-compat")]
use core::marker::PhantomData;

/// Compile-time marker for the K6-03 canonical IR. It is omitted from the
/// minimal no-default-features checker build.
#[cfg(feature = "ir-compat")]
#[derive(Clone, Copy, Debug, Default)]
pub struct IrCompatibility(PhantomData<fn() -> quotient_forge_ir::CompiledModel>);

#[cfg(feature = "ir-compat")]
impl IrCompatibility {
    #[must_use]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}
