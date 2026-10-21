# Privacy-Safe Recovery Telemetry

`RecoveryTelemetrySnapshot` exports only aggregate operational health: counts by durable state, attempts by recovery action, success and failure totals, fixed latency buckets, and typed failure counts.

The public schema deliberately excludes transaction identifiers, trace digests, sealed payloads, authenticators, subject identifiers, biosignal data, and timestamps. It therefore cannot be joined back to an individual recovery event through fields emitted by this component.

`canonical_json` has fixed field order and no randomness, enabling byte-stable Studio exports and regression tests. Redaction tests reject forbidden identifier-bearing field names.

This telemetry reports operational health; it is not evidence that a particular private history produced a release.
