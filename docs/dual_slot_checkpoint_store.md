# Dual-Slot Ceremony Checkpoint Store

Ceremony checkpoints alternate between logical A and B slots. Each slot update is an immutable generation file created by one atomic rename after data sync. Startup verifies both the slot HMAC and the ceremony checkpoint HMAC, then selects the highest complete generation. A torn latest write falls back to the prior slot; if neither slot verifies, startup fails closed.
