import Aqrs.Trace

namespace AQRS

structure ProductState (State : Type) where
  left : State
  right : State
  slot : Nat
deriving Repr

def productAt
    (model : Model)
    (left right : model.State)
    (inputs : Nat -> model.Input)
    (slot : Nat) : ProductState model.State :=
  {
    left := stateAt model left inputs slot
    right := stateAt model right inputs slot
    slot := slot
  }

inductive Reachable
    (model : Model)
    (initialLeft initialRight : model.State)
    (inputs : Nat -> model.Input) : ProductState model.State -> Prop
  | root :
      Reachable model initialLeft initialRight inputs
        { left := initialLeft, right := initialRight, slot := 0 }
  | step {product : ProductState model.State} :
      Reachable model initialLeft initialRight inputs product ->
        Reachable model initialLeft initialRight inputs
          {
            left := model.step product.left (inputs product.slot)
            right := model.step product.right (inputs product.slot)
            slot := product.slot + 1
          }

theorem productAt_reachable
    (model : Model)
    (left right : model.State)
    (inputs : Nat -> model.Input)
    (slot : Nat) :
    Reachable model left right inputs (productAt model left right inputs slot) := by
  induction slot with
  | zero =>
      exact Reachable.root
  | succ previous inductionHypothesis =>
      simpa [productAt, stateAt] using Reachable.step inductionHypothesis

inductive BadAt
    (model : Model)
    (initialLeft initialRight : model.State)
    (inputs : Nat -> model.Input)
    (product : ProductState model.State) : Prop
  | observer
      (bad :
        Not
          (ObserverEquivalentNow
            model
            product.left
            product.right
            inputs
            product.slot))
  | unauthorizedLeft
      (bad : UnauthorizedAt model initialLeft inputs product.slot)
  | unauthorizedRight
      (bad : UnauthorizedAt model initialRight inputs product.slot)
  | duplicateLeft
      (bad : DuplicateBy model initialLeft inputs product.slot)
  | duplicateRight
      (bad : DuplicateBy model initialRight inputs product.slot)
  | missedDeadlineLeft
      (bad : MissedDeadlineAt model initialLeft inputs product.slot)
  | missedDeadlineRight
      (bad : MissedDeadlineAt model initialRight inputs product.slot)
  | recoveryLeft
      (bad : RecoveryMissedAt model initialLeft inputs product.slot)
  | recoveryRight
      (bad : RecoveryMissedAt model initialRight inputs product.slot)

def NoReachableBad
    (model : Model)
    (left right : model.State)
    (inputs : Nat -> model.Input)
    (horizon : Nat) : Prop :=
  forall product,
    Reachable model left right inputs product ->
      product.slot < horizon ->
        Not (BadAt model left right inputs product)

structure BoundedAQNI
    (model : Model)
    (left right : model.State)
    (inputs : Nat -> model.Input)
    (horizon : Nat) : Prop where
  actionEquivalent : ActionEquivalent model left right
  privateDistinct : PrivateDistinct model left right
  observerEquivalent :
    forall slot, slot < horizon -> ObserverEquivalentAt model left right inputs slot

structure UtilitySafeThrough
    (model : Model)
    (left right : model.State)
    (inputs : Nat -> model.Input)
    (horizon : Nat) : Prop where
  unauthorizedLeft :
    forall slot, slot < horizon -> Not (UnauthorizedAt model left inputs slot)
  unauthorizedRight :
    forall slot, slot < horizon -> Not (UnauthorizedAt model right inputs slot)
  duplicateLeft :
    forall slot, slot < horizon -> Not (DuplicateBy model left inputs slot)
  duplicateRight :
    forall slot, slot < horizon -> Not (DuplicateBy model right inputs slot)
  missedDeadlineLeft :
    forall slot, slot < horizon -> Not (MissedDeadlineAt model left inputs slot)
  missedDeadlineRight :
    forall slot, slot < horizon -> Not (MissedDeadlineAt model right inputs slot)
  recoveryLeft :
    forall slot, slot < horizon -> Not (RecoveryMissedAt model left inputs slot)
  recoveryRight :
    forall slot, slot < horizon -> Not (RecoveryMissedAt model right inputs slot)

/--
Soundness of the bounded bad-state checker. The horizon and every finite domain
are explicit theorem parameters. The theorem does not cover infinite traces or
the correctness of a frontend that lowers another language into this model.
-/
theorem boundedCheckerSound
    (model : Model)
    [DecidableEq model.Observation]
    (_finiteDomains : FiniteDomains model)
    (left right : model.State)
    (inputs : Nat -> model.Input)
    (horizon : Nat)
    (actionEquivalent : ActionEquivalent model left right)
    (privateDistinct : PrivateDistinct model left right)
    (noBad : NoReachableBad model left right inputs horizon) :
    BoundedAQNI model left right inputs horizon ∧
      UtilitySafeThrough model left right inputs horizon := by
  constructor
  · refine
      {
        actionEquivalent := actionEquivalent
        privateDistinct := privateDistinct
        observerEquivalent := ?_
      }
    intro slot inHorizon observer
    by_cases sameObservation :
        model.observe
            observer
            (model.release
              (stateAt model left inputs slot)
              (inputs slot)) =
          model.observe
            observer
            (model.release
              (stateAt model right inputs slot)
              (inputs slot))
    · exact sameObservation
    · exfalso
      have observerBad :
          Not (ObserverEquivalentAt model left right inputs slot) := by
        intro allObservers
        exact sameObservation (allObservers observer)
      exact
        noBad
          (productAt model left right inputs slot)
          (productAt_reachable model left right inputs slot)
          inHorizon
          (BadAt.observer observerBad)
  · refine
      {
        unauthorizedLeft := ?_
        unauthorizedRight := ?_
        duplicateLeft := ?_
        duplicateRight := ?_
        missedDeadlineLeft := ?_
        missedDeadlineRight := ?_
        recoveryLeft := ?_
        recoveryRight := ?_
      }
    · intro slot inHorizon bad
      exact
        noBad
          (productAt model left right inputs slot)
          (productAt_reachable model left right inputs slot)
          inHorizon
          (BadAt.unauthorizedLeft bad)
    · intro slot inHorizon bad
      exact
        noBad
          (productAt model left right inputs slot)
          (productAt_reachable model left right inputs slot)
          inHorizon
          (BadAt.unauthorizedRight bad)
    · intro slot inHorizon bad
      exact
        noBad
          (productAt model left right inputs slot)
          (productAt_reachable model left right inputs slot)
          inHorizon
          (BadAt.duplicateLeft bad)
    · intro slot inHorizon bad
      exact
        noBad
          (productAt model left right inputs slot)
          (productAt_reachable model left right inputs slot)
          inHorizon
          (BadAt.duplicateRight bad)
    · intro slot inHorizon bad
      exact
        noBad
          (productAt model left right inputs slot)
          (productAt_reachable model left right inputs slot)
          inHorizon
          (BadAt.missedDeadlineLeft bad)
    · intro slot inHorizon bad
      exact
        noBad
          (productAt model left right inputs slot)
          (productAt_reachable model left right inputs slot)
          inHorizon
          (BadAt.missedDeadlineRight bad)
    · intro slot inHorizon bad
      exact
        noBad
          (productAt model left right inputs slot)
          (productAt_reachable model left right inputs slot)
          inHorizon
          (BadAt.recoveryLeft bad)
    · intro slot inHorizon bad
      exact
        noBad
          (productAt model left right inputs slot)
          (productAt_reachable model left right inputs slot)
          inHorizon
          (BadAt.recoveryRight bad)

end AQRS
