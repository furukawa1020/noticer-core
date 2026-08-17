import Aqrs.Soundness

namespace AQRS

def requiredAtZero : ActionObligation Unit Unit :=
  {
    id := ()
    action := ()
    triggerSlot := 0
    deadlineSlot := 0
  }

def suppressAllModel : Model :=
  {
    State := Unit
    Input := Unit
    Public := Unit
    Private := Unit
    Semantic := Unit
    Obligation := Unit
    Fault := Empty
    Action := Unit
    Payload := Unit
    Observer := Unit
    Observation := Unit
    step := fun _ _ => ()
    publicSymbol := fun _ => ()
    privateHistory := fun _ => ()
    semantic := fun _ => ()
    obligations := fun _ => [requiredAtZero]
    fault := fun _ => none
    recovery := fun fault => nomatch fault
    release := fun _ _ => { emitted := true, payload := (), actions := [] }
    observe := fun _ _ => ()
  }

def suppressAllInputs : Nat -> suppressAllModel.Input := fun _ => ()

theorem suppressAll_misses_required :
    MissedDeadlineAt suppressAllModel () suppressAllInputs 0 := by
  refine
    ⟨0, requiredAtZero, Nat.le_refl 0, ?_, rfl, ?_⟩
  · exact List.Mem.head []
  · intro exactlyOnce
    rcases exactlyOnce with
      ⟨witnessSlot, witnessIndex, _, _, occurs, _⟩
    change
      (none :
          Option
            (Emission
              (ObligationRef
                suppressAllModel.Obligation
                suppressAllModel.Fault)
              suppressAllModel.Action)) =
        some
          (Emission.mk
            (ObligationRef.authorized requiredAtZero.id)
            requiredAtZero.action) at occurs
    nomatch occurs

theorem suppressAll_not_utility_safe :
    Not (UtilitySafeThrough suppressAllModel () () suppressAllInputs 1) := by
  intro safe
  exact
    safe.missedDeadlineLeft
      0
      (by decide)
      suppressAll_misses_required

theorem suppressAll_has_reachable_bad :
    Not (NoReachableBad suppressAllModel () () suppressAllInputs 1) := by
  intro noBad
  exact
    noBad
      (productAt suppressAllModel () () suppressAllInputs 0)
      (productAt_reachable suppressAllModel () () suppressAllInputs 0)
      (by decide)
      (BadAt.missedDeadlineLeft suppressAll_misses_required)

end AQRS
