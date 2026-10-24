# Cross-Device Recovery Handoff

The handoff certificate transfers only a verified proof-bundle authenticator and public recovery head. It binds strictly increasing source/target epochs and a one-shot nonce. The target rejects replay, epoch downgrade, wrong-target delivery, and component substitution; no biosignal, identity, subject, or transaction identifier is exported.
