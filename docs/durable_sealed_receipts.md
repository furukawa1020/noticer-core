# Durable Sealed Receipt Boundary

`DurableSealedReceiptVault` preserves the complete public `SealedReceipt` needed to resume audit after a process crash. It is paired with the authenticated `DELIVERED` outbox record that authorized the payload.

The vault accepts a payload only when transaction ID, public trace digest, release sequence, policy epoch, receipt epoch, and receipt authenticator exactly match the outbox record. The outbox record must be in `DELIVERED` state. The vault additionally authenticates the payload and the originating outbox authenticator with a domain-separated key.

An identical retry is idempotent. A different payload or outbox binding for an existing transaction is rejected. On restart, malformed, truncated, duplicated, or authentication-invalid records fail closed.

The durable payload contains only the public delivery receipt: transaction ID, public trace digest, release sequence, policy epoch, delivery outcome, sink epoch, and receipt authenticator. It does not contain biosignal samples, private evidence, subject identifiers, or detector internals.

This component does not itself run audit recovery or decide whether a sink should be contacted again. Those orchestration steps remain a separate recovery boundary.
