# Privacy-Safe Recovery Telemetry Budget

Recovery telemetry exposes only fixed logarithmic buckets for completed ceremonies, aborts, restarts, and backlog halts. It contains no transaction, device, subject, identity, or biosignal identifier. Each authenticated release consumes a policy-bounded allowance; once exhausted, publication fails closed. Adjacent exact counts intentionally collapse to the same public bucket.
