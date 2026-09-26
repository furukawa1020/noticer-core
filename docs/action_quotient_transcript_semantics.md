# Action-quotient transcript semantics

The quotient-privacy-semantics crate separates intentional declassification from
the complete observable release trace. Authorized action events bind public
epoch, service, action, release window, and policy. Observable segments retain
public token, silence, failure, retry, reconnect, receipt, and action-execution
categories without accepting private biosignal values.

Action equivalence requires equal action quotient, authorized transcript,
public policy, public context, and secret-model version. Secret families and
observer scopes remain explicit. Coalitions must be non-empty, sorted, unique,
bounded, and bound to a nonzero canonical hash.

Private world identifiers are intentionally absent from runtime APIs. They
belong only in simulation and formal models. Adaptive mechanism selectors
receive only a public transcript hash, public budget state, public utility
obligation, public network state, and public context hash.
