#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod canonical;
mod parser;

pub use canonical::{
    BlockType, CanonicalTargetIr, ConstValue, DataSegment, FixedMemory, Function, FunctionExport,
    FunctionImport, FunctionType, Global, Instruction, InstructionImmediate, LocalDecl, ValueType,
};
pub use parser::{
    local_parser_decision, parse_and_lower, reconcile_parser_decisions, ConsensusVerdict,
    ExternalParserDecision, InvalidReason, LocalParserDecision, ParserLimits, ResourceBound,
    ResourceKind, TargetIrError, UnsupportedFeature,
};

use quotient_forge_caqt::{artifact_digest, Digest};

pub const QUOTIENT_SEAL_TARGET_IR_V1: &str = "QUOTIENT_SEAL_TARGET_IR_V1";
pub const TARGET_IR_HASH_DOMAIN: &[u8] = b"noticer-core/quotient-seal/target-ir/v1";
pub const TARGET_IR_DESCRIPTOR: &str = concat!(
    "id=QUOTIENT_SEAL_TARGET_IR_V1\n",
    "wasm=core-v1-binary\n",
    "values=i32,i64\n",
    "calls=direct-only\n",
    "memory=one-local-fixed-min-equals-max\n",
    "data=active-memory-zero-non-overlap\n",
    "custom-sections=validated-and-erased\n",
    "consensus=quotient-seal+wasmparser+wasm-tools\n",
    "disagreement=UNRESOLVED\n",
);

#[must_use]
pub fn target_ir_contract_hash() -> Digest {
    artifact_digest(TARGET_IR_HASH_DOMAIN, TARGET_IR_DESCRIPTOR.as_bytes())
}

#[must_use]
pub fn target_ir_hash(ir: &CanonicalTargetIr) -> Digest {
    let canonical = ir.canonical_bytes();
    artifact_digest(TARGET_IR_HASH_DOMAIN, &canonical)
}
