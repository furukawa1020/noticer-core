import QuotientLimit.Basic

namespace QuotientLimit

example : (ReadinessPoint.mk 4 4).Feasible := by
  exact deadline_at_or_after_ready_span_feasible _ (by decide)

end QuotientLimit
