import Aqrs.QuotientSeal.Trace

namespace AQRS.QuotientSeal

/--
Robust target guarantee for one observer profile and one arbitrary finite
prefix. The finite abstraction size and accepted product bound are recorded in
the proposition rather than hidden in checker implementation details.
-/
structure RAQTR
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (productBound horizon : Nat) : Prop where
  finiteProductStates : Nat
  finiteProductWithinBound : finiteProductStates <= productBound
  observerEquivalent :
    forall slot,
      slot < horizon ->
        target.observe
            observer
            (coupledAt source target observer initial inputs slot).targetLeft
            (coupledAt source target observer initial inputs slot).contextLeft
            (inputs slot) =
          target.observe
            observer
            (coupledAt source target observer initial inputs slot).targetRight
            (coupledAt source target observer initial inputs slot).contextRight
            (inputs slot)
  contextsCoupled :
    forall slot,
      slot < horizon ->
        (coupledAt
            source
            target
            observer
            initial
            inputs
            slot).contextLeft =
          (coupledAt
            source
            target
            observer
            initial
            inputs
            slot).contextRight
  resourceEquivalent :
    forall slot,
      slot < horizon ->
        target.resourceTrace
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).targetLeft
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).contextLeft
            (inputs slot) =
          target.resourceTrace
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).targetRight
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).contextRight
            (inputs slot)
  divergenceAbsentLeft :
    forall slot,
      slot < horizon ->
        target.divergence
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).targetLeft
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).contextLeft
            (inputs slot) =
          none
  divergenceAbsentRight :
    forall slot,
      slot < horizon ->
        target.divergence
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).targetRight
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).contextRight
            (inputs slot) =
          none

/--
Target action utility is inherited only through exact action projection from a
K7 utility-safe source run. This excludes suppress-all as a degenerate result.
-/
structure TargetUtilityPreserved
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (horizon : Nat) : Prop where
  sourceUtility :
    UtilitySafeThrough
      source
      initial.sourceLeft
      initial.sourceRight
      inputs
      horizon
  leftActions :
    forall slot,
      slot < horizon ->
        (target.release
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).targetLeft
            (inputs slot)).actions =
          (releaseAt source initial.sourceLeft inputs slot).actions
  rightActions :
    forall slot,
      slot < horizon ->
        (target.release
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).targetRight
            (inputs slot)).actions =
          (releaseAt source initial.sourceRight inputs slot).actions

/--
An accepted finite product preserves RAQTR and action utility for any supplied
finite horizon. Infinite-trace liveness and frontend lowering are not theorem
conclusions.
-/
theorem finiteProductPreservesRAQTR
    (source : Model)
    [DecidableEq source.Observation]
    (_finiteDomains : FiniteDomains source)
    (target : TargetMachine source)
    (relation : ValidatedRelation source target)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (initialLeftRelated :
      relation.relates initial.sourceLeft initial.targetLeft)
    (initialRightRelated :
      relation.relates initial.sourceRight initial.targetRight)
    (certificate :
      FiniteProductCertificate source target observer inputs initial)
    (productBound horizon : Nat)
    (boundAgrees : certificate.productBound = productBound)
    (sourcePrivacy :
      BoundedAQNI
        source
        initial.sourceLeft
        initial.sourceRight
        inputs
        horizon)
    (sourceUtility :
      UtilitySafeThrough
        source
        initial.sourceLeft
        initial.sourceRight
        inputs
        horizon) :
    RAQTR
        source
        target
        observer
        initial
        inputs
        productBound
        horizon /
      TargetUtilityPreserved
        source
        target
        observer
        initial
        inputs
        horizon := by
  constructor
  · refine
      {
        finiteProductStates := certificate.entries.length
        finiteProductWithinBound := ?_
        observerEquivalent := ?_
        contextsCoupled := ?_
        resourceEquivalent := ?_
        divergenceAbsentLeft := ?_
        divergenceAbsentRight := ?_
      }
    · calc
        certificate.entries.length <= certificate.productBound :=
          certificate.bounded
        _ = productBound := boundAgrees
    · intro slot inHorizon
      calc
        target.observe
              observer
              (coupledAt
                source
                target
                observer
                initial
                inputs
                slot).targetLeft
              (coupledAt
                source
                target
                observer
                initial
                inputs
                slot).contextLeft
              (inputs slot) =
            source.observe
              observer
              (releaseAt source initial.sourceLeft inputs slot) :=
          targetLeft_projects_to_source
            source
            target
            relation
            observer
            initial
            inputs
            initialLeftRelated
            slot
        _ = source.observe
              observer
              (releaseAt source initial.sourceRight inputs slot) := by
          simpa [ObserverEquivalentAt, ObserverEquivalentNow, releaseAt] using
            sourcePrivacy.observerEquivalent slot inHorizon observer
        _ = target.observe
              observer
              (coupledAt
                source
                target
                observer
                initial
                inputs
                slot).targetRight
              (coupledAt
                source
                target
                observer
                initial
                inputs
                slot).contextRight
              (inputs slot) :=
          (targetRight_projects_to_source
            source
            target
            relation
            observer
            initial
            inputs
            initialRightRelated
            slot).symm
    · intro slot _
      exact
        finiteProduct_contexts_coupled
          source
          target
          observer
          initial
          inputs
          certificate
          slot
    · intro slot _
      exact
        finiteProduct_resources_equal
          source
          target
          observer
          initial
          inputs
          certificate
          slot
    · intro slot _
      exact
        relation.divergenceAbsent
          (relation_left_at
            source
            target
            relation
            observer
            initial
            inputs
            initialLeftRelated
            slot)
          (coupledAt
            source
            target
            observer
            initial
            inputs
            slot).contextLeft
          (inputs slot)
    · intro slot _
      exact
        relation.divergenceAbsent
          (relation_right_at
            source
            target
            relation
            observer
            initial
            inputs
            initialRightRelated
            slot)
          (coupledAt
            source
            target
            observer
            initial
            inputs
            slot).contextRight
          (inputs slot)
  · refine
      {
        sourceUtility := sourceUtility
        leftActions := ?_
        rightActions := ?_
      }
    · intro slot _
      exact
        targetLeft_actions_project_to_source
          source
          target
          relation
          observer
          initial
          inputs
          initialLeftRelated
          slot
    · intro slot _
      exact
        targetRight_actions_project_to_source
          source
          target
          relation
          observer
          initial
          inputs
          initialRightRelated
          slot

end AQRS.QuotientSeal
