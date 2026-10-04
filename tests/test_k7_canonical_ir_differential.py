import json

from noticer_core.evaluation.canonical_ir_differential import (
    SCHEMA,
    DifferentialStatus,
    evaluate_canonical_ir,
)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def test_canonical_envelope_is_accepted_and_round_trips() -> None:
    payload = canonical(
        {"kind": "compiled_model", "payload": {"states": [0, 1]}, "schema": SCHEMA, "version": 1}
    )
    result = evaluate_canonical_ir(payload)
    assert result.status is DifferentialStatus.ACCEPT
    assert result.canonical == payload


def test_duplicate_unknown_version_float_and_trailing_data_fail_closed() -> None:
    cases = [
        b'{"kind":"compiled_model","kind":"release_transducer","payload":{},"schema":"noticer.k7.canonical-ir.v1","version":1}',
        canonical({"kind": "compiled_model", "payload": {}, "schema": SCHEMA, "version": 2}),
        b'{"kind":"compiled_model","payload":{"x":1.5},"schema":"noticer.k7.canonical-ir.v1","version":1}',
        canonical({"kind": "compiled_model", "payload": {}, "schema": SCHEMA, "version": 1}) + b"x",
    ]
    for payload in cases:
        assert evaluate_canonical_ir(payload).status is not DifferentialStatus.ACCEPT


def test_noncanonical_order_integer_overflow_and_resource_limit_are_rejected() -> None:
    unordered = (
        b'{"version":1,"schema":"noticer.k7.canonical-ir.v1",'
        b'"payload":{},"kind":"compiled_model"}'
    )
    overflow = canonical(
        {"kind": "compiled_model", "payload": {"x": 1 << 63}, "schema": SCHEMA, "version": 1}
    )
    assert evaluate_canonical_ir(unordered).category == "non_canonical"
    assert evaluate_canonical_ir(overflow).category == "contract"
    assert evaluate_canonical_ir(b"{" * 65_537).category == "byte_limit"
