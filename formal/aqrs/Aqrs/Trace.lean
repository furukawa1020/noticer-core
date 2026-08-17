import Aqrs.Model

namespace AQRS

def stateAt
    (model : Model)
    (initial : model.State)
    (inputs : Nat -> model.Input) : Nat -> model.State
  | 0 => initial
  | slot + 1 => model.step (stateAt model initial inputs slot) (inputs slot)

def releaseAt
    (model : Model)
    (initial : model.State)
    (inputs : Nat -> model.Input)
    (slot : Nat) :
    Release
      (ObligationRef model.Obligation model.Fault)
      model.Action
      model.Payload :=
  model.release (stateAt model initial inputs slot) (inputs slot)

def OccursAt
    (model : Model)
    (initial : model.State)
    (inputs : Nat -> model.Input)
    (reference : ObligationRef model.Obligation model.Fault)
    (action : model.Action)
    (slot index : Nat) : Prop :=
  (releaseAt model initial inputs slot).actions[index]? =
    some (Emission.mk reference action)

def DeclaredAuthorization
    (model : Model)
    (initial : model.State)
    (inputs : Nat -> model.Input)
    (id : model.Obligation)
    (action : model.Action)
    (slot : Nat) : Prop :=
  exists origin, origin <= slot ∧
    exists obligation,
      List.Mem obligation
          (model.obligations (model.semantic (stateAt model initial inputs origin))) ∧
        obligation.id = id ∧
          obligation.action = action ∧
            obligation.triggerSlot <= slot ∧
              slot <= obligation.deadlineSlot

def RecoveryAuthorization
    (model : Model)
    (inputs : Nat -> model.Input)
    (fault : model.Fault)
    (triggeredAt : Nat)
    (action : model.Action)
    (slot : Nat) : Prop :=
  exists requirement,
    model.fault (inputs triggeredAt) = some fault ∧
      model.recovery fault = some requirement ∧
        requirement.action = action ∧
          triggeredAt <= slot ∧
            slot <= triggeredAt + requirement.deadlineAfterSlots

def EmissionAuthorizedAt
    (model : Model)
    (initial : model.State)
    (inputs : Nat -> model.Input)
    (reference : ObligationRef model.Obligation model.Fault)
    (action : model.Action)
    (slot : Nat) : Prop :=
  match reference with
  | .authorized id =>
      DeclaredAuthorization model initial inputs id action slot
  | .recovery fault triggeredAt =>
      RecoveryAuthorization model inputs fault triggeredAt action slot

def UnauthorizedAt
    (model : Model)
    (initial : model.State)
    (inputs : Nat -> model.Input)
    (slot : Nat) : Prop :=
  exists index reference action,
    OccursAt model initial inputs reference action slot index ∧
      Not (EmissionAuthorizedAt model initial inputs reference action slot)

def DuplicateBy
    (model : Model)
    (initial : model.State)
    (inputs : Nat -> model.Input)
    (slot : Nat) : Prop :=
  exists reference actionOne actionTwo slotOne indexOne slotTwo indexTwo,
    slotOne <= slot ∧
      slotTwo <= slot ∧
        OccursAt model initial inputs reference actionOne slotOne indexOne ∧
          OccursAt model initial inputs reference actionTwo slotTwo indexTwo ∧
            (Not (slotOne = slotTwo) ∨ Not (indexOne = indexTwo))

def ExactlyOnceBetween
    (model : Model)
    (initial : model.State)
    (inputs : Nat -> model.Input)
    (reference : ObligationRef model.Obligation model.Fault)
    (action : model.Action)
    (firstSlot deadlineSlot : Nat) : Prop :=
  exists witnessSlot witnessIndex,
    firstSlot <= witnessSlot ∧
      witnessSlot <= deadlineSlot ∧
        OccursAt model initial inputs reference action witnessSlot witnessIndex ∧
          forall otherSlot otherIndex otherAction,
            firstSlot <= otherSlot ->
              otherSlot <= deadlineSlot ->
                OccursAt
                    model
                    initial
                    inputs
                    reference
                    otherAction
                    otherSlot
                    otherIndex ->
                  otherSlot = witnessSlot ∧
                    otherIndex = witnessIndex ∧
                      otherAction = action

def MissedDeadlineAt
    (model : Model)
    (initial : model.State)
    (inputs : Nat -> model.Input)
    (slot : Nat) : Prop :=
  exists origin obligation,
    origin <= slot ∧
      List.Mem obligation
          (model.obligations (model.semantic (stateAt model initial inputs origin))) ∧
        obligation.deadlineSlot = slot ∧
          Not
            (ExactlyOnceBetween
              model
              initial
              inputs
              (.authorized obligation.id)
              obligation.action
              obligation.triggerSlot
              obligation.deadlineSlot)

def RecoveryMissedAt
    (model : Model)
    (initial : model.State)
    (inputs : Nat -> model.Input)
    (slot : Nat) : Prop :=
  exists triggeredAt fault requirement,
    triggeredAt <= slot ∧
      model.fault (inputs triggeredAt) = some fault ∧
        model.recovery fault = some requirement ∧
          triggeredAt + requirement.deadlineAfterSlots = slot ∧
            Not
              (ExactlyOnceBetween
                model
                initial
                inputs
                (.recovery fault triggeredAt)
                requirement.action
                triggeredAt
                (triggeredAt + requirement.deadlineAfterSlots))

def ObserverEquivalentNow
    (model : Model)
    (left right : model.State)
    (inputs : Nat -> model.Input)
    (slot : Nat) : Prop :=
  forall observer,
    model.observe observer (model.release left (inputs slot)) =
      model.observe observer (model.release right (inputs slot))

def ObserverEquivalentAt
    (model : Model)
    (left right : model.State)
    (inputs : Nat -> model.Input)
    (slot : Nat) : Prop :=
  ObserverEquivalentNow
    model
    (stateAt model left inputs slot)
    (stateAt model right inputs slot)
    inputs
    slot

end AQRS
