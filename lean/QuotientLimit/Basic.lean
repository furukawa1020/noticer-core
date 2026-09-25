namespace QuotientLimit

structure ReadinessPoint where
  readySpan : Nat
  deadline : Nat

def ReadinessPoint.Feasible (point : ReadinessPoint) : Prop :=
  point.readySpan ≤ point.deadline

def ReadinessPoint.minimumWorstCaseLatency (point : ReadinessPoint) : Nat :=
  point.readySpan

theorem deadline_before_ready_span_infeasible
    (point : ReadinessPoint)
    (before : point.deadline < point.readySpan) :
    ¬ point.Feasible := by
  exact Nat.not_le_of_lt before

theorem deadline_at_or_after_ready_span_feasible
    (point : ReadinessPoint)
    (atOrAfter : point.readySpan ≤ point.deadline) :
    point.Feasible := by
  exact atOrAfter

theorem readiness_frontier_lower_bound
    (point : ReadinessPoint)
    (feasible : point.Feasible) :
    point.minimumWorstCaseLatency = point.readySpan ∧
      point.readySpan ≤ point.deadline := by
  exact ⟨rfl, feasible⟩

theorem latest_readiness_support_bound
    {History : Type}
    (ready : History → Nat)
    (latest release deadline : Nat)
    (latestAttained : ∃ history, ready history = latest)
    (causalUtility : ∀ history, ready history ≤ release)
    (deadlineUtility : release ≤ deadline) :
    latest ≤ release ∧ release ≤ deadline := by
  obtain ⟨history, historyIsLatest⟩ := latestAttained
  constructor
  · simpa [historyIsLatest] using causalUtility history
  · exact deadlineUtility

end QuotientLimit
