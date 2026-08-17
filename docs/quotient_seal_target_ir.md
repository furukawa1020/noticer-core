# QuotientSeal Target IR v1

## Status

QUOTIENT_SEAL_TARGET_IR_V1 is the frozen restricted-WASM lowering contract for
K8-03. It is a component of a candidate robust-compilation mechanism, not a
claim of priority or a general WebAssembly verifier.

## Security boundary

The parser reads the actual WebAssembly binary. A manifest cannot declare away
an import, export, memory, instruction, data segment, or section. Every length,
LEB128 integer, UTF-8 name, index, and resource count is checked before use.

Accepted modules contain only:

- i32 and i64 function, local, and global values;
- direct calls and bounded structured control;
- one locally defined memory whose minimum equals its maximum;
- fixed-width integer loads and stores;
- active, non-overlapping data segments for memory zero;
- K8-02 host-import and public-export names.

Float, SIMD, threads, atomics, memory.grow, memory.size, call_indirect,
WASI, tables, shared or 64-bit memory, imported or exported memory, passive
data, unknown sections, duplicate sections, and trailing section bytes fail
closed.

## Canonicalization

The canonical encoding starts with QSTI and a fixed little-endian version.
Custom sections are bounded, their names are strict UTF-8, and duplicate names
are rejected; their non-semantic payload is erased. Function-index-bearing
imports and definitions retain binary order. Exports are sorted by name, and
data segments are sorted by offset after overlap checks.

The contract and each accepted IR are domain-separated with
noticer-core/quotient-seal/target-ir/v1 through the K7 CAQT artifact digest.
Equal canonical IR therefore has a byte-reproducible digest.

## Three-parser gate

Local lowering is provisional. A release may be VALID only when QuotientSeal,
wasmparser, and wasm-tools all accept the same binary. Any accept/reject
difference, resource classification difference, or unavailable independent
tool is UNRESOLVED; it is never converted into success.

This gate intentionally separates binary lowering from K8-04 execution
semantics. Full Wasm stack typing remains the responsibility of the independent
validators until a later independent checker consumes the complete QSM.

## Non-goals

This issue does not implement K8-04 small-step execution, K8-05 relational
translation validation, arbitrary Rust or WebAssembly, native code, JIT
validation, malicious runtime or OS resistance, cache/power/EM protection, or
hardware attestation. Sensor, BLE, wearable, and physical hardware behavior is
NOT_VERIFIED.
