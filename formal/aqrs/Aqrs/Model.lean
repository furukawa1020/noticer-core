namespace AQRS

inductive Side where
  | left
  | right
deriving DecidableEq, Repr

inductive ObligationRef (Obligation Fault : Type) where
  | authorized (id : Obligation)
  | recovery (fault : Fault) (triggeredAt : Nat)
deriving DecidableEq, Repr

structure Emission (Reference Action : Type) where
  reference : Reference
  action : Action
deriving DecidableEq, Repr

structure Release (Reference Action Payload : Type) where
  emitted : Bool
  payload : Payload
  actions : List (Emission Reference Action)
deriving Repr

structure ActionObligation (Obligation Action : Type) where
  id : Obligation
  action : Action
  triggerSlot : Nat
  deadlineSlot : Nat
deriving Repr

structure RecoveryRequirement (Action : Type) where
  action : Action
  deadlineAfterSlots : Nat
deriving Repr

/--
The finite abstraction consumed by the proof. Finiteness is carried explicitly
as type-class assumptions by the soundness theorem rather than hidden here.
-/
structure Model where
  State : Type
  Input : Type
  Public : Type
  Private : Type
  Semantic : Type
  Obligation : Type
  Fault : Type
  Action : Type
  Payload : Type
  Observer : Type
  Observation : Type
  step : State -> Input -> State
  publicSymbol : Input -> Public
  privateHistory : State -> Private
  semantic : State -> Semantic
  obligations : Semantic -> List (ActionObligation Obligation Action)
  fault : Input -> Option Fault
  recovery : Fault -> Option (RecoveryRequirement Action)
  release :
    State ->
      Input ->
        Release (ObligationRef Obligation Fault) Action Payload
  observe :
    Observer ->
      Release (ObligationRef Obligation Fault) Action Payload ->
        Observation

/-- Explicit finite enumerations for every abstract domain in a model. -/
structure FiniteDomains (model : Model) where
  states : List model.State
  statesComplete : forall value, List.Mem value states
  inputs : List model.Input
  inputsComplete : forall value, List.Mem value inputs
  publicSymbols : List model.Public
  publicSymbolsComplete : forall value, List.Mem value publicSymbols
  privateHistories : List model.Private
  privateHistoriesComplete : forall value, List.Mem value privateHistories
  semantics : List model.Semantic
  semanticsComplete : forall value, List.Mem value semantics
  obligations : List model.Obligation
  obligationsComplete : forall value, List.Mem value obligations
  faults : List model.Fault
  faultsComplete : forall value, List.Mem value faults
  actions : List model.Action
  actionsComplete : forall value, List.Mem value actions
  payloads : List model.Payload
  payloadsComplete : forall value, List.Mem value payloads
  observers : List model.Observer
  observersComplete : forall value, List.Mem value observers
  observations : List model.Observation
  observationsComplete : forall value, List.Mem value observations

def ActionEquivalent (model : Model) (left right : model.State) : Prop :=
  model.semantic left = model.semantic right

def PrivateDistinct (model : Model) (left right : model.State) : Prop :=
  Not (model.privateHistory left = model.privateHistory right)

def QuotientAdmissible
    (model : Model)
    (relation : model.State -> model.State -> Prop) : Prop :=
  forall left right, relation left right -> ActionEquivalent model left right

theorem QuotientAdmissible.not_related_of_semantic_ne
    {model : Model}
    {relation : model.State -> model.State -> Prop}
    (admissible : QuotientAdmissible model relation)
    {left right : model.State}
    (different : Not (model.semantic left = model.semantic right)) :
    Not (relation left right) := by
  intro related
  exact different (admissible left right related)

end AQRS
