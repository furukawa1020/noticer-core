# Recovery Proof Bundle

The versioned recovery proof bundle binds the cross-store certificate, rollback anchor, admission permit, recovery witness, and completed ceremony checkpoint into one HMAC-authenticated canonical artifact. It exports only generations, policy epoch, and public authenticators; transaction, subject, identity, and biosignal fields are absent. Component substitution or an incomplete ceremony fails closed.
