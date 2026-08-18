import Aqrs.Soundness

namespace AQRS.QuotientSeal

/-- Target-only outcomes that cannot be silently identified with a source step. -/
inductive TargetDivergence where
  | trap
  | forbiddenImport
  | resourceBound
deriving DecidableEq, Repr

/--
Restricted target semantics. Public observations may include API, control,
instruction, memory, or resource projections selected by the observer profile.
-/
structure TargetMachine (source : Model) where
  State : Type
  Context : Type
  step : State -> Context -> source.Input -> State
  contextStep :
    Context -> source.Public -> source.Observation -> Context
  semantic : State -> source.Semantic
  release :
    State ->
      source.Input ->
        Release
          (ObligationRef source.Obligation source.Fault)
          source.Action
          source.Payload
  observe :
    source.Observer ->
      State -> Context -> source.Input -> source.Observation
  divergence :
    State -> Context -> source.Input -> Option TargetDivergence
  resourceTrace : State -> Context -> source.Input -> Nat

structure Configuration
    (source : Model)
    (target : TargetMachine source) where
  state : target.State
  context : target.Context

def stepConfiguration
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (configuration : Configuration source target)
    (input : source.Input) : Configuration source target :=
  {
    state := target.step configuration.state configuration.context input
    context :=
      target.contextStep
        configuration.context
        (source.publicSymbol input)
        (target.observe
          observer
          configuration.state
          configuration.context
          input)
  }

/--
The relation evidence recomputed by an independent checker. Every field is a
semantic obligation; compiler metadata is not an argument to this structure.
-/
structure ValidatedRelation
    (source : Model)
    (target : TargetMachine source) where
  relates : source.State -> target.State -> Prop
  semanticPreserved :
    forall {sourceState targetState},
      relates sourceState targetState ->
        source.semantic sourceState = target.semantic targetState
  stepPreserved :
    forall {sourceState targetState},
      relates sourceState targetState ->
        forall context input,
          relates
            (source.step sourceState input)
            (target.step targetState context input)
  observationPreserved :
    forall {sourceState targetState},
      relates sourceState targetState ->
        forall observer context input,
          target.observe observer targetState context input =
            source.observe observer (source.release sourceState input)
  actionsPreserved :
    forall {sourceState targetState},
      relates sourceState targetState ->
        forall input,
          (target.release targetState input).actions =
            (source.release sourceState input).actions
  divergenceAbsent :
    forall {sourceState targetState},
      relates sourceState targetState ->
        forall context input,
          target.divergence targetState context input = none

/-- Two private runs coupled to one public input tape. -/
structure CoupledConfiguration
    (source : Model)
    (target : TargetMachine source) where
  sourceLeft : source.State
  sourceRight : source.State
  targetLeft : target.State
  targetRight : target.State
  contextLeft : target.Context
  contextRight : target.Context

def stepCoupled
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (configuration : CoupledConfiguration source target)
    (input : source.Input) : CoupledConfiguration source target :=
  {
    sourceLeft := source.step configuration.sourceLeft input
    sourceRight := source.step configuration.sourceRight input
    targetLeft :=
      target.step
        configuration.targetLeft
        configuration.contextLeft
        input
    targetRight :=
      target.step
        configuration.targetRight
        configuration.contextRight
        input
    contextLeft :=
      target.contextStep
        configuration.contextLeft
        (source.publicSymbol input)
        (target.observe
          observer
          configuration.targetLeft
          configuration.contextLeft
          input)
    contextRight :=
      target.contextStep
        configuration.contextRight
        (source.publicSymbol input)
        (target.observe
          observer
          configuration.targetRight
          configuration.contextRight
          input)
  }

/-- Every target-only observable failure is represented as an explicit bad state. -/
inductive RobustBadAt
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (input : source.Input)
    (configuration : CoupledConfiguration source target) : Prop where
  | observerMismatch
      (bad :
        Not
          (target.observe
              observer
              configuration.targetLeft
              configuration.contextLeft
              input =
            target.observe
              observer
              configuration.targetRight
              configuration.contextRight
              input))
  | contextMismatch
      (bad : Not (configuration.contextLeft = configuration.contextRight))
  | divergenceLeft
      (kind : TargetDivergence)
      (bad :
        target.divergence
            configuration.targetLeft
            configuration.contextLeft
            input =
          some kind)
  | divergenceRight
      (kind : TargetDivergence)
      (bad :
        target.divergence
            configuration.targetRight
            configuration.contextRight
            input =
          some kind)
  | resourceMismatch
      (bad :
        Not
          (target.resourceTrace
              configuration.targetLeft
              configuration.contextLeft
              input =
            target.resourceTrace
              configuration.targetRight
              configuration.contextRight
              input))

/--
Finite abstraction accepted by the context-product checker. Closure is over
every slot of the supplied public input tape, not merely the listed prefix.
-/
structure FiniteProductCertificate
    (source : Model)
    (target : TargetMachine source)
    (observer : source.Observer)
    (inputs : Nat -> source.Input)
    (initial : CoupledConfiguration source target) where
  entries : List (CoupledConfiguration source target)
  productBound : Nat
  bounded : entries.length <= productBound
  initialMember : List.Mem initial entries
  closed :
    forall slot configuration,
      List.Mem configuration entries ->
        List.Mem
          (stepCoupled source target observer configuration (inputs slot))
          entries
  safe :
    forall slot configuration,
      List.Mem configuration entries ->
        Not
          (RobustBadAt
            source
            target
            observer
            (inputs slot)
            configuration)

end AQRS.QuotientSeal
