import Aqrs.Negative
import Aqrs.QuotientSeal.Preservation

namespace AQRS.QuotientSeal

def requiredActionSource : Model :=
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
    release := fun _ _ =>
      {
        emitted := true
        payload := ()
        actions := [Emission.mk (ObligationRef.authorized ()) ()]
      }
    observe := fun _ _ => ()
  }

def requiredActionInputs : Nat -> requiredActionSource.Input := fun _ => ()

def suppressAllTarget : TargetMachine requiredActionSource :=
  {
    State := Unit
    Context := Unit
    step := fun _ _ _ => ()
    contextStep := fun _ _ _ => ()
    semantic := fun _ => ()
    release := fun _ _ => { emitted := true, payload := (), actions := [] }
    observe := fun _ _ _ _ => ()
    divergence := fun _ _ _ => none
    resourceTrace := fun _ _ _ => 0
  }

def suppressAllInitial :
    CoupledConfiguration requiredActionSource suppressAllTarget :=
  {
    sourceLeft := ()
    sourceRight := ()
    targetLeft := ()
    targetRight := ()
    contextLeft := ()
    contextRight := ()
  }

theorem suppressAll_observation_is_silent :
    suppressAllTarget.observe () () () () =
      requiredActionSource.observe
        ()
        (requiredActionSource.release () ()) := by
  rfl

theorem suppressAll_action_mismatch :
    Not
      ((suppressAllTarget.release () ()).actions =
        (requiredActionSource.release () ()).actions) := by
  intro same
  change
    ([] : List (Emission (ObligationRef Unit Empty) Unit)) =
      [Emission.mk (ObligationRef.authorized ()) ()] at same
  nomatch same

theorem suppressAll_has_no_validated_initial_relation :
    forall relation :
      ValidatedRelation requiredActionSource suppressAllTarget,
      Not (relation.relates () ()) := by
  intro relation related
  exact
    suppressAll_action_mismatch
      (relation.actionsPreserved related ())

theorem suppressAll_not_target_utility :
    Not
      (TargetUtilityPreserved
        requiredActionSource
        suppressAllTarget
        ()
        suppressAllInitial
        requiredActionInputs
        1) := by
  intro preserved
  exact
    suppressAll_action_mismatch
      (preserved.leftActions 0 (by decide))

def resourceLeakSource : Model :=
  {
    State := Bool
    Input := Unit
    Public := Unit
    Private := Bool
    Semantic := Unit
    Obligation := Empty
    Fault := Empty
    Action := Unit
    Payload := Unit
    Observer := Unit
    Observation := Unit
    step := fun state _ => state
    publicSymbol := fun _ => ()
    privateHistory := fun state => state
    semantic := fun _ => ()
    obligations := fun _ => []
    fault := fun _ => none
    recovery := fun fault => nomatch fault
    release := fun _ _ => { emitted := false, payload := (), actions := [] }
    observe := fun _ _ => ()
  }

def resourceLeakInputs : Nat -> resourceLeakSource.Input := fun _ => ()

def resourceLeakTarget : TargetMachine resourceLeakSource :=
  {
    State := Bool
    Context := Unit
    step := fun state _ _ => state
    contextStep := fun _ _ _ => ()
    semantic := fun _ => ()
    release := fun _ _ => { emitted := false, payload := (), actions := [] }
    observe := fun _ _ _ _ => ()
    divergence := fun _ _ _ => none
    resourceTrace := fun state _ _ => if state then 1 else 0
  }

def resourceLeakInitial :
    CoupledConfiguration resourceLeakSource resourceLeakTarget :=
  {
    sourceLeft := false
    sourceRight := true
    targetLeft := false
    targetRight := true
    contextLeft := ()
    contextRight := ()
  }

theorem resourceLeak_action_equivalent :
    ActionEquivalent
      resourceLeakSource
      resourceLeakInitial.sourceLeft
      resourceLeakInitial.sourceRight := by
  rfl

theorem resourceLeak_private_distinct :
    PrivateDistinct
      resourceLeakSource
      resourceLeakInitial.sourceLeft
      resourceLeakInitial.sourceRight := by
  intro same
  change false = true at same
  nomatch same

theorem resourceLeak_public_observation_equal :
    resourceLeakTarget.observe () false () () =
      resourceLeakTarget.observe () true () () := by
  rfl

theorem resourceLeak_actions_equal :
    (resourceLeakTarget.release false ()).actions =
      (resourceLeakTarget.release true ()).actions := by
  rfl

theorem resourceLeak_resource_difference :
    Not
      (resourceLeakTarget.resourceTrace false () () =
        resourceLeakTarget.resourceTrace true () ()) := by
  decide

theorem resourceLeak_is_bad :
    RobustBadAt
      resourceLeakSource
      resourceLeakTarget
      ()
      ()
      resourceLeakInitial :=
  RobustBadAt.resourceMismatch resourceLeak_resource_difference

theorem resourceLeak_has_no_safe_certificate :
    Not
      (Nonempty
        (FiniteProductCertificate
          resourceLeakSource
          resourceLeakTarget
          ()
          resourceLeakInputs
          resourceLeakInitial)) := by
  intro witness
  cases witness with
  | intro certificate =>
      exact
        (certificate.safe
          0
          resourceLeakInitial
          certificate.initialMember)
          resourceLeak_is_bad

end AQRS.QuotientSeal
