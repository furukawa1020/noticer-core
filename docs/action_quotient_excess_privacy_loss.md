# Action-Quotient Excess Privacy Loss

Action-Quotient Excess Privacy Loss (AQEPL) is the privacy quantity frozen for
QuotientOdometer. It measures distinguishability added by an observable release
segment after conditioning on authorized action semantics, the prior public
transcript, and the selected certified mechanism.

Authorized actions are explicit declassification and are not charged twice.
Token bytes, timing, silence, size, failure, retry, service correlation,
receipts, and action execution timing remain observable and are charged when
they distinguish action-equivalent private histories.

For an action-equivalent pair h0 and h1, public prefix tau, mechanism M, and
segment r, AQEPL uses bidirectional conditional privacy loss. A support mismatch
is unbounded; it is never rounded to a large finite value.

The frozen runtime profile uses Renyi orders 2, 3, 4, 8, 16, 32, and 64 with
directed upper rounding. Exact finite and analytic derivations may enter
production. Empirical profiles are lab-only.

This is a candidate action-conditioned privacy accountant and a proposed
action-quotient privacy profile. Privacy odometers, filters, RDP, f-DP, PLD,
concurrent composition, and Pufferfish privacy are prior concepts and are not
claimed as new.
