# Retired Epoch Manifest

Retired key epochs are persisted as a monotonic chain of immutable, HMAC-authenticated manifests. Each generation contains the complete sorted retired set and binds its predecessor authenticator. Startup supplies a minimum generation from the rollback anchor; deletion of newer manifests therefore fails closed. A restarted keyring is initialized from the verified set and cannot register retired key material again.
