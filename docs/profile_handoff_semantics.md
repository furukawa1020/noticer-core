# Profile handoff and version invalidation

`quotient-profile-handoff` controls whether privacy profiles may be composed across a public handoff.

A profile commits to schema, policy, model, mechanism, and alpha-grid digests. These are protected dimensions. A generation change that preserves all protected dimensions may cross only an explicitly declared public-state transition. Such profiles remain composition-compatible.

Changing any protected dimension creates an invalidating rebootstrap. The previous profile is marked invalid and cannot participate in later handoff or composition. This prevents an accountant from silently combining bounds derived under different models, schemas, policies, mechanisms, or alpha grids.

Handoff identifiers are single-use and bind the source profile, active target profile, and boundary trace commitment. Unknown, inactive, replayed, invalidated, or incompatible profiles fail closed.
