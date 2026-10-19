# Vaulted Live Delivery Ceremony

`deliver_with_vault` is the live release path that preserves a sealed public receipt across every post-delivery crash boundary.

Its durable order is: synchronize `PENDING`, consume the one-shot permit, contact the idempotent sink, seal the public receipt, synchronize the receipt vault, synchronize `DELIVERED`, append the durable audit, then synchronize `AUDITED`.

If vault synchronization fails, pending delivery recovery may reconcile the idempotent sink. If `DELIVERED` synchronization fails after the vault succeeds, pending delivery recovery uses the vaulted receipt without contacting the sink. Failures after `DELIVERED` hand off to audit recovery.

The original outbox ceremony remains available for compatibility, while deployments requiring complete crash recovery should use the vaulted ceremony.
