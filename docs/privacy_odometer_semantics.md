# AQPO time-uniform odometer

AQPO tracks certified conditional log-moment upper bounds. For each registered
Renyi order it adds the preregistered log inverse beta penalty, divides upward
by alpha minus one, and reports the smallest conservative bound.

Every accepted prefix retains a monotone published bound, so an observer cannot
obtain a lower report by choosing an adaptive stopping time. Budget-key changes,
moment rollback, transcript replay, release gaps, alpha-grid changes, resource
limits, and arithmetic overflow fail closed without advancing state.

The report is explicitly a profile-based time-uniform upper bound. AQPO does not
observe a private secret pair and does not claim to measure realized privacy
loss. The beta value and its directed-upper logarithm are configuration inputs
that must be frozen and independently certified.
