# QuotientOdometer threat and evaluation contract

The adaptive adversary may choose service, release timing, declared coalition,
public faults, candidate mechanism requests, public utility demand, stop time,
and interleaving from the prior public transcript. It cannot directly read a
private history, score, margin, ready time, identity, or baseline.

The frozen attack registry is A0 budget shopping, A1 service splitting, A2
coalition escalation, A3 mechanism switching, A4 shared randomness, A5 policy
version churn, A6 crash rollback, A7 concurrent double spend, A8 receipt side
channel, and A9 stop-time attack.

Evaluation is split by benchmark family. Variants of one family cannot cross
development and held-out partitions. Held-out evaluation must include adaptive
mechanism selection, concurrent services, collusion, model change, and crash.
At least 24 benchmark families and 10,000 releases are required.

All bypass, double-spend, untracked-coalition allow, incompatible-profile allow,
rollback-undercharge, and private-dependent selection targets are zero. A
negative result is not privacy proof beyond the declared secret families,
coalitions, public context, model version, and resource bounds.

Generated artifacts must not contain private biosignals, baselines, identities,
or exact private timing and are not committed to Git. Frozen values are defined
canonically in specs/quotient_odometer/frozen_contract.json; weakening them
requires a new contract ID rather than silently editing the existing protocol.
