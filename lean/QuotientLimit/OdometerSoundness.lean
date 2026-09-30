namespace QuotientLimit.Odometer

def Profile := Nat → Nat

def zeroProfile : Profile := fun _ => 0

def compose (left right : Profile) : Profile := fun index => left index + right index

def SoundUpperBound (profile reported : Profile) : Prop :=
  ∀ index, profile index ≤ reported index

@[simp] theorem zero_profile_sound : SoundUpperBound zeroProfile zeroProfile := by
  intro index
  exact Nat.le_refl 0

inductive PointwiseLe : List Nat → List Nat → Prop
  | nil : PointwiseLe [] []
  | cons {cost bound : Nat} {costs bounds : List Nat} :
      cost ≤ bound → PointwiseLe costs bounds → PointwiseLe (cost :: costs) (bound :: bounds)

theorem adaptive_composition_sound
    {costs bounds : List Nat}
    (sound : PointwiseLe costs bounds) :
    costs.sum ≤ bounds.sum := by
  induction sound with
  | nil => exact Nat.le_refl 0
  | cons head tail inductionHypothesis =>
      simp only [List.sum_cons]
      exact Nat.add_le_add head inductionHypothesis

inductive Disposition
  | allow
  | delay
  | coarsen
  | localOnly
  | deny
  deriving DecidableEq

def FilterAllows (disposition : Disposition) : Prop :=
  disposition = Disposition.allow

def FilterDecisionSound (reported budget : Nat) (disposition : Disposition) : Prop :=
  FilterAllows disposition → reported ≤ budget

theorem pre_release_filter_soundness
    {reported budget : Nat}
    {disposition : Disposition}
    (decisionSound : FilterDecisionSound reported budget disposition)
    (allows : FilterAllows disposition) :
    reported ≤ budget := by
  exact decisionSound allows

structure Ledger where
  committed : Nat
  reserved : Nat
  capacity : Nat

abbrev Ledger.Valid (ledger : Ledger) : Prop :=
  ledger.committed + ledger.reserved ≤ ledger.capacity

def reserve (ledger : Ledger) (amount : Nat) : Ledger :=
  { ledger with reserved := ledger.reserved + amount }

theorem atomic_reservation_preserves_capacity
    (ledger : Ledger)
    (amount : Nat)
    (linearizedCheck : ledger.committed + (ledger.reserved + amount) ≤ ledger.capacity) :
    (reserve ledger amount).Valid := by
  exact linearizedCheck

theorem two_atomic_reservations_do_not_double_spend
    (ledger : Ledger)
    (first second : Nat)
    (linearizedCheck : ledger.committed + ((ledger.reserved + first) + second) ≤ ledger.capacity) :
    (reserve (reserve ledger first) second).Valid := by
  exact linearizedCheck

structure ProfileDescriptor where
  schema : Nat
  policy : Nat
  model : Nat
  mechanism : Nat
  alphaGrid : Nat
  publicState : Nat

structure ProtectedCompatible (left right : ProfileDescriptor) : Prop where
  schema : left.schema = right.schema
  policy : left.policy = right.policy
  model : left.model = right.model
  mechanism : left.mechanism = right.mechanism
  alphaGrid : left.alphaGrid = right.alphaGrid

structure PublicHandoffCompatible (left right : ProfileDescriptor) : Prop where
  protectedDims : ProtectedCompatible left right
  publicTransitionAllowed : left.publicState = right.publicState ∨ left.publicState ≠ right.publicState

theorem public_handoff_preserves_protected_dimensions
    {left right : ProfileDescriptor}
    (compatible : PublicHandoffCompatible left right) :
    left.schema = right.schema ∧
      left.policy = right.policy ∧
      left.model = right.model ∧
      left.mechanism = right.mechanism ∧
      left.alphaGrid = right.alphaGrid := by
  exact ⟨compatible.protectedDims.schema,
    compatible.protectedDims.policy,
    compatible.protectedDims.model,
    compatible.protectedDims.mechanism,
    compatible.protectedDims.alphaGrid⟩

structure CoalitionLedger where
  spent : Nat
  capacity : Nat

abbrev CoalitionLedger.Valid (ledger : CoalitionLedger) : Prop :=
  ledger.spent ≤ ledger.capacity

def chargeServices (ledger : CoalitionLedger) (serviceCosts : List Nat) : CoalitionLedger :=
  { ledger with spent := ledger.spent + serviceCosts.sum }

theorem coalition_service_splitting_cannot_exceed_joint_budget
    (ledger : CoalitionLedger)
    (serviceCosts : List Nat)
    (jointCheck : ledger.spent + serviceCosts.sum ≤ ledger.capacity) :
    (chargeServices ledger serviceCosts).Valid := by
  exact jointCheck

end QuotientLimit.Odometer
