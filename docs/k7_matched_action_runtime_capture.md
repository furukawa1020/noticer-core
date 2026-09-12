# K7 matched-action runtime capture

`capture_matched_action_runtime` drives both private histories through the Rust
admission boundary and then through `ActionEquivalentTraceShaper`. The returned
capture contains only observer-visible data:

- ciphertext bytes and frame length
- scheduled release time and sequence
- public service binding
- silence, retry count, and failure observations
- pair ID, counterfactual family, and sanitized pair hash

Raw subject, session, evidence-ready, and score-path values remain private to
the generator. They have no getter and are not copied into the capture. The
`Debug` representation remains redacted.

The current trace shaper emits every scheduled frame and has no application
retry path, so `silence`, `retry_count`, and `failure` are respectively false,
zero, and false. These explicit fields allow later public schedule and fault
variants without changing the data contract. They must not be interpreted as
hardware observations.

This capture is implementation-derived synthetic evidence from the Rust runtime,
not a deployment or physical-device result. Hardware status is `NOT_VERIFIED`.
