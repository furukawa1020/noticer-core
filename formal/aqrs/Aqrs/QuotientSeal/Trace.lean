import Aqrs.QuotientSeal.Model

namespace AQRS.QuotientSeal

def coupledAt
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input) : Nat -> CoupledConfiguration source target
  | 0 => initial
  | slot + 1 =>
      stepCoupled
        source
        target
        observer
        (coupledAt source target observer initial inputs slot)
        (inputs slot)

theorem finiteProduct_member
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (certificate :
      FiniteProductCertificate source target observer inputs initial)
    (slot : Nat) :
    List.Mem
      (coupledAt source target observer initial inputs slot)
      certificate.entries := by
  induction slot with
  | zero =>
      simpa [coupledAt] using certificate.initialMember
  | succ previous inductionHypothesis =>
      simpa [coupledAt] using
        certificate.closed
          previous
          (coupledAt source target observer initial inputs previous)
          inductionHypothesis

theorem coupledAt_sourceLeft
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (slot : Nat) :
    (coupledAt source target observer initial inputs slot).sourceLeft =
      stateAt source initial.sourceLeft inputs slot := by
  induction slot with
  | zero => rfl
  | succ previous inductionHypothesis =>
      simp only [coupledAt, stepCoupled, stateAt, inductionHypothesis]

theorem coupledAt_sourceRight
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (slot : Nat) :
    (coupledAt source target observer initial inputs slot).sourceRight =
      stateAt source initial.sourceRight inputs slot := by
  induction slot with
  | zero => rfl
  | succ previous inductionHypothesis =>
      simp only [coupledAt, stepCoupled, stateAt, inductionHypothesis]

theorem relation_step
    (source : Model)
    (target : TargetMachine source)
    (relation : ValidatedRelation source target)
    {sourceState : source.State}
    {targetState : target.State}
    (related : relation.relates sourceState targetState)
    (context : target.Context)
    (input : source.Input) :
    relation.relates
      (source.step sourceState input)
      (target.step targetState context input) :=
  relation.stepPreserved related context input

theorem relation_left_at
    (source : Model)
    (target : TargetMachine source)
    (relation : ValidatedRelation source target)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (initialRelated :
      relation.relates initial.sourceLeft initial.targetLeft)
    (slot : Nat) :
    relation.relates
      (coupledAt source target observer initial inputs slot).sourceLeft
      (coupledAt source target observer initial inputs slot).targetLeft := by
  induction slot with
  | zero =>
      simpa [coupledAt] using initialRelated
  | succ previous inductionHypothesis =>
      simpa [coupledAt, stepCoupled] using
        relation.stepPreserved
          inductionHypothesis
          (coupledAt
            source
            target
            observer
            initial
            inputs
            previous).contextLeft
          (inputs previous)

theorem relation_right_at
    (source : Model)
    (target : TargetMachine source)
    (relation : ValidatedRelation source target)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (initialRelated :
      relation.relates initial.sourceRight initial.targetRight)
    (slot : Nat) :
    relation.relates
      (coupledAt source target observer initial inputs slot).sourceRight
      (coupledAt source target observer initial inputs slot).targetRight := by
  induction slot with
  | zero =>
      simpa [coupledAt] using initialRelated
  | succ previous inductionHypothesis =>
      simpa [coupledAt, stepCoupled] using
        relation.stepPreserved
          inductionHypothesis
          (coupledAt
            source
            target
            observer
            initial
            inputs
            previous).contextRight
          (inputs previous)

theorem targetLeft_projects_to_source
    (source : Model)
    (target : TargetMachine source)
    (relation : ValidatedRelation source target)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (initialRelated :
      relation.relates initial.sourceLeft initial.targetLeft)
    (slot : Nat) :
    target.observe
        observer
        (coupledAt source target observer initial inputs slot).targetLeft
        (coupledAt source target observer initial inputs slot).contextLeft
        (inputs slot) =
      source.observe
        observer
        (releaseAt source initial.sourceLeft inputs slot) := by
  calc
    target.observe
          observer
          (coupledAt source target observer initial inputs slot).targetLeft
          (coupledAt source target observer initial inputs slot).contextLeft
          (inputs slot) =
        source.observe
          observer
          (source.release
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).sourceLeft
            (inputs slot)) :=
      relation.observationPreserved
        (relation_left_at
          source
          target
          relation
          observer
          initial
          inputs
          initialRelated
          slot)
        observer
        (coupledAt
          source
          target
          observer
          initial
          inputs
          slot).contextLeft
        (inputs slot)
    _ = source.observe
          observer
          (releaseAt source initial.sourceLeft inputs slot) := by
      have stateEquality :=
        coupledAt_sourceLeft source target observer initial inputs slot
      rw [stateEquality]
      rfl

theorem targetRight_projects_to_source
    (source : Model)
    (target : TargetMachine source)
    (relation : ValidatedRelation source target)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (initialRelated :
      relation.relates initial.sourceRight initial.targetRight)
    (slot : Nat) :
    target.observe
        observer
        (coupledAt source target observer initial inputs slot).targetRight
        (coupledAt source target observer initial inputs slot).contextRight
        (inputs slot) =
      source.observe
        observer
        (releaseAt source initial.sourceRight inputs slot) := by
  calc
    target.observe
          observer
          (coupledAt source target observer initial inputs slot).targetRight
          (coupledAt source target observer initial inputs slot).contextRight
          (inputs slot) =
        source.observe
          observer
          (source.release
            (coupledAt
              source
              target
              observer
              initial
              inputs
              slot).sourceRight
            (inputs slot)) :=
      relation.observationPreserved
        (relation_right_at
          source
          target
          relation
          observer
          initial
          inputs
          initialRelated
          slot)
        observer
        (coupledAt
          source
          target
          observer
          initial
          inputs
          slot).contextRight
        (inputs slot)
    _ = source.observe
          observer
          (releaseAt source initial.sourceRight inputs slot) := by
      have stateEquality :=
        coupledAt_sourceRight source target observer initial inputs slot
      rw [stateEquality]
      rfl

theorem targetLeft_actions_project_to_source
    (source : Model)
    (target : TargetMachine source)
    (relation : ValidatedRelation source target)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (initialRelated :
      relation.relates initial.sourceLeft initial.targetLeft)
    (slot : Nat) :
    (target.release
        (coupledAt source target observer initial inputs slot).targetLeft
        (inputs slot)).actions =
      (releaseAt source initial.sourceLeft inputs slot).actions := by
  calc
    (target.release
          (coupledAt source target observer initial inputs slot).targetLeft
          (inputs slot)).actions =
        (source.release
          (coupledAt
            source
            target
            observer
            initial
            inputs
            slot).sourceLeft
          (inputs slot)).actions :=
      relation.actionsPreserved
        (relation_left_at
          source
          target
          relation
          observer
          initial
          inputs
          initialRelated
          slot)
        (inputs slot)
    _ = (releaseAt source initial.sourceLeft inputs slot).actions := by
      have stateEquality :=
        coupledAt_sourceLeft source target observer initial inputs slot
      rw [stateEquality]
      rfl

theorem targetRight_actions_project_to_source
    (source : Model)
    (target : TargetMachine source)
    (relation : ValidatedRelation source target)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (initialRelated :
      relation.relates initial.sourceRight initial.targetRight)
    (slot : Nat) :
    (target.release
        (coupledAt source target observer initial inputs slot).targetRight
        (inputs slot)).actions =
      (releaseAt source initial.sourceRight inputs slot).actions := by
  calc
    (target.release
          (coupledAt source target observer initial inputs slot).targetRight
          (inputs slot)).actions =
        (source.release
          (coupledAt
            source
            target
            observer
            initial
            inputs
            slot).sourceRight
          (inputs slot)).actions :=
      relation.actionsPreserved
        (relation_right_at
          source
          target
          relation
          observer
          initial
          inputs
          initialRelated
          slot)
        (inputs slot)
    _ = (releaseAt source initial.sourceRight inputs slot).actions := by
      have stateEquality :=
        coupledAt_sourceRight source target observer initial inputs slot
      rw [stateEquality]
      rfl

theorem context_step_coupled
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (configuration : CoupledConfiguration source target)
    (input : source.Input)
    (contexts : configuration.contextLeft = configuration.contextRight)
    (observations :
      target.observe
          observer
          configuration.targetLeft
          configuration.contextLeft
          input =
        target.observe
          observer
          configuration.targetRight
          configuration.contextRight
          input) :
    (stepCoupled source target observer configuration input).contextLeft =
      (stepCoupled source target observer configuration input).contextRight := by
  change
    target.contextStep
          configuration.contextLeft
          (source.publicSymbol input)
          (target.observe
            observer
            configuration.targetLeft
            configuration.contextLeft
            input) =
      target.contextStep
        configuration.contextRight
        (source.publicSymbol input)
        (target.observe
          observer
          configuration.targetRight
          configuration.contextRight
          input)
  rw [contexts, observations]

theorem finiteProduct_contexts_coupled
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (certificate :
      FiniteProductCertificate source target observer inputs initial)
    (slot : Nat) :
    (coupledAt source target observer initial inputs slot).contextLeft =
      (coupledAt source target observer initial inputs slot).contextRight := by
  by_contra different
  exact
    (certificate.safe
      slot
      (coupledAt source target observer initial inputs slot)
      (finiteProduct_member
        source
        target
        observer
        initial
        inputs
        certificate
        slot))
      (RobustBadAt.contextMismatch different)

theorem finiteProduct_resources_equal
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (initial : CoupledConfiguration source target)
    (inputs : Nat -> source.Input)
    (certificate :
      FiniteProductCertificate source target observer inputs initial)
    (slot : Nat) :
    target.resourceTrace
        (coupledAt source target observer initial inputs slot).targetLeft
        (coupledAt source target observer initial inputs slot).contextLeft
        (inputs slot) =
      target.resourceTrace
        (coupledAt source target observer initial inputs slot).targetRight
        (coupledAt source target observer initial inputs slot).contextRight
        (inputs slot) := by
  by_contra different
  exact
    (certificate.safe
      slot
      (coupledAt source target observer initial inputs slot)
      (finiteProduct_member
        source
        target
        observer
        initial
        inputs
        certificate
        slot))
      (RobustBadAt.resourceMismatch different)

theorem targetDivergence_is_bad_left
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (input : source.Input)
    (configuration : CoupledConfiguration source target)
    (kind : TargetDivergence)
    (diverged :
      target.divergence
          configuration.targetLeft
          configuration.contextLeft
          input =
        some kind) :
    RobustBadAt source target observer input configuration :=
  RobustBadAt.divergenceLeft kind diverged

theorem targetDivergence_is_bad_right
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (input : source.Input)
    (configuration : CoupledConfiguration source target)
    (kind : TargetDivergence)
    (diverged :
      target.divergence
          configuration.targetRight
          configuration.contextRight
          input =
        some kind) :
    RobustBadAt source target observer input configuration :=
  RobustBadAt.divergenceRight kind diverged

theorem resourceDifference_is_bad
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (input : source.Input)
    (configuration : CoupledConfiguration source target)
    (different :
      Not
        (target.resourceTrace
            configuration.targetLeft
            configuration.contextLeft
            input =
          target.resourceTrace
            configuration.targetRight
            configuration.contextRight
            input)) :
    RobustBadAt source target observer input configuration :=
  RobustBadAt.resourceMismatch different

end AQRS.QuotientSeal
