# Implementation-derived adaptive attacker

`quotient-adaptive-attacker` consumes normalized events emitted by the implementation boundary and produces deterministic, index-addressed attack findings.

The analyzer searches for six attack families: repeated budget shopping across services or mechanisms, service splitting inside one coalition, service rebinding across coalitions, shared randomness commitments, policy generation churn, and crash recovery rollback or hash-chain forks.

Findings identify the first relevant event and the adaptive follow-up event. Malformed traces, duplicate reservation identifiers, missing policy state, release without reservation, recovery without crash, and configured resource-limit exhaustion fail closed.

The analyzer detects attack-shaped trace behavior; it does not prove exploitation or privacy loss by itself. Evaluation must preserve the original receipts and map each normalized event back to implementation evidence.
