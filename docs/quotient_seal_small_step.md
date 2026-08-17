# QuotientSeal deterministic small-step semantics

## Status

QUOTIENT_SEAL_SMALL_STEP_V1 freezes the K8-04 execution semantics for the
canonical target IR from K8-03. It is part of a candidate robust-compilation
mechanism. It is not a priority claim and is not a general WebAssembly engine.

## Deterministic machine

WasmState contains the current program counter, operand stack, locals, globals,
fixed linear memory, structured-control stack, direct-call stack, complete
semantic event trace, remaining fuel, and terminal status. The machine owns a
canonical target IR and an ordered public host tape, so the same module, entry
state, tape, limits, and fuel produce the same state and trace.

Each target instruction costs one unit of fuel. The only host capabilities are
qseal.emit_frame, qseal.emit_action, and qseal.public_failure. Their public costs
are respectively 8, 8, and 4. A missing or differently ordered tape directive
traps instead of selecting an implicit host behavior.

## Outcomes

The machine distinguishes:

- RETURNED: a normal function return with typed results;
- TERMINATED: an explicit public host termination;
- TRAPPED: a semantic fault such as unreachable, divide by zero, signed divide
  overflow, type mismatch, invalid conversion, invalid control, or memory
  bounds failure;
- RESOURCE_BOUND: fuel, event, stack, call-depth, memory, or host-call budget
  exhaustion.

RESOURCE_BOUND is INCONCLUSIVE. It is never interpreted as a successful
termination or a valid translation.

## Event model

The trace records API invocation, fuel charge, instruction, control transfer,
function entry and return, memory address and width, host call and public
outcome, trap, termination, and resource-bound events. Memory contents are
machine state; observer events record addresses and widths without serializing
private bytes.

## Security boundary

The interpreter consumes CanonicalTargetIr directly and has no private-ingress
API. Unknown future opcodes, undeclared imports, malformed stack values, and
unsupported control states trap rather than execute through a fallback path.

K8-05 source-target relational validation, arbitrary Wasm, JIT/native
validation, a malicious runtime or operating system, microarchitectural
observation, sensor/BLE behavior, and physical hardware are outside this issue.
Hardware remains NOT_VERIFIED.
