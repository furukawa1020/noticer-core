use serde::{Deserialize, Serialize};

pub const MUTATION_TAXONOMY_VERSION: &str = "quotient-seal-wasm-mutation/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationFamily {
    Action,
    State,
    Context,
    Trap,
    Memory,
    Resource,
    Binding,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationRecipe {
    IncrementI32Constant,
    InjectConstDrop,
    FlipCodeOpcode,
    DuplicateCall,
    DropCall,
    IncrementCallIndex,
    InsertCall,
    ReorderCalls,
    AppendFunctionExport,
    AppendFunctionImport,
    InsertUnreachable,
    InsertDivisionByZero,
    InsertSignedOverflow,
    AppendMemoryExport,
    InsertMemoryGrow,
    IncrementMemoryOffset,
    AppendMutableGlobal,
    ShiftDataOffset,
    InsertPrivateBranch,
    InflateOpcodeCost,
    InsertLoopBackedge,
    AppendBindingSection,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationOperator {
    ActionConstantFlip,
    ActionToCover,
    PolicyBypass,
    DuplicateActionCall,
    DropActionCall,
    NextStateIncrement,
    StaleStateRestore,
    ResetDrop,
    ResetDuplicate,
    HandoffTargetFlip,
    ExtraHostCall,
    MissingHostCall,
    ReorderHostCalls,
    PrivateExport,
    UnknownImport,
    PrivateDependentTrap,
    BoundsCheckDrop,
    DivisionGuardDrop,
    SignedOverflowPath,
    UnreachableInsert,
    ExportedMemory,
    MemoryGrowInsert,
    AddressOffsetIncrement,
    MutableGlobal,
    DataOffsetShift,
    PrivateBranch,
    OpcodeCostInflate,
    FuelDecrementDrop,
    AddressTraceAlias,
    FailurePathShortcut,
    LoopBackedge,
    WrongAbiImport,
    WrongSourceBinding,
    WrongObserverBinding,
    ExtraExport,
    ClockImport,
    RandomImport,
}

pub const ALL_MUTATION_OPERATORS: [MutationOperator; 37] = [
    MutationOperator::ActionConstantFlip,
    MutationOperator::ActionToCover,
    MutationOperator::PolicyBypass,
    MutationOperator::DuplicateActionCall,
    MutationOperator::DropActionCall,
    MutationOperator::NextStateIncrement,
    MutationOperator::StaleStateRestore,
    MutationOperator::ResetDrop,
    MutationOperator::ResetDuplicate,
    MutationOperator::HandoffTargetFlip,
    MutationOperator::ExtraHostCall,
    MutationOperator::MissingHostCall,
    MutationOperator::ReorderHostCalls,
    MutationOperator::PrivateExport,
    MutationOperator::UnknownImport,
    MutationOperator::PrivateDependentTrap,
    MutationOperator::BoundsCheckDrop,
    MutationOperator::DivisionGuardDrop,
    MutationOperator::SignedOverflowPath,
    MutationOperator::UnreachableInsert,
    MutationOperator::ExportedMemory,
    MutationOperator::MemoryGrowInsert,
    MutationOperator::AddressOffsetIncrement,
    MutationOperator::MutableGlobal,
    MutationOperator::DataOffsetShift,
    MutationOperator::PrivateBranch,
    MutationOperator::OpcodeCostInflate,
    MutationOperator::FuelDecrementDrop,
    MutationOperator::AddressTraceAlias,
    MutationOperator::FailurePathShortcut,
    MutationOperator::LoopBackedge,
    MutationOperator::WrongAbiImport,
    MutationOperator::WrongSourceBinding,
    MutationOperator::WrongObserverBinding,
    MutationOperator::ExtraExport,
    MutationOperator::ClockImport,
    MutationOperator::RandomImport,
];

impl MutationOperator {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::ActionConstantFlip => "action_constant_flip",
            Self::ActionToCover => "action_to_cover",
            Self::PolicyBypass => "policy_bypass",
            Self::DuplicateActionCall => "duplicate_action_call",
            Self::DropActionCall => "drop_action_call",
            Self::NextStateIncrement => "next_state_increment",
            Self::StaleStateRestore => "stale_state_restore",
            Self::ResetDrop => "reset_drop",
            Self::ResetDuplicate => "reset_duplicate",
            Self::HandoffTargetFlip => "handoff_target_flip",
            Self::ExtraHostCall => "extra_host_call",
            Self::MissingHostCall => "missing_host_call",
            Self::ReorderHostCalls => "reorder_host_calls",
            Self::PrivateExport => "private_export",
            Self::UnknownImport => "unknown_import",
            Self::PrivateDependentTrap => "private_dependent_trap",
            Self::BoundsCheckDrop => "bounds_check_drop",
            Self::DivisionGuardDrop => "division_guard_drop",
            Self::SignedOverflowPath => "signed_overflow_path",
            Self::UnreachableInsert => "unreachable_insert",
            Self::ExportedMemory => "exported_memory",
            Self::MemoryGrowInsert => "memory_grow_insert",
            Self::AddressOffsetIncrement => "address_offset_increment",
            Self::MutableGlobal => "mutable_global",
            Self::DataOffsetShift => "data_offset_shift",
            Self::PrivateBranch => "private_branch",
            Self::OpcodeCostInflate => "opcode_cost_inflate",
            Self::FuelDecrementDrop => "fuel_decrement_drop",
            Self::AddressTraceAlias => "address_trace_alias",
            Self::FailurePathShortcut => "failure_path_shortcut",
            Self::LoopBackedge => "loop_backedge",
            Self::WrongAbiImport => "wrong_abi_import",
            Self::WrongSourceBinding => "wrong_source_binding",
            Self::WrongObserverBinding => "wrong_observer_binding",
            Self::ExtraExport => "extra_export",
            Self::ClockImport => "clock_import",
            Self::RandomImport => "random_import",
        }
    }

    #[must_use]
    pub const fn ordinal(self) -> u8 {
        match self {
            Self::ActionConstantFlip => 1,
            Self::ActionToCover => 2,
            Self::PolicyBypass => 3,
            Self::DuplicateActionCall => 4,
            Self::DropActionCall => 5,
            Self::NextStateIncrement => 6,
            Self::StaleStateRestore => 7,
            Self::ResetDrop => 8,
            Self::ResetDuplicate => 9,
            Self::HandoffTargetFlip => 10,
            Self::ExtraHostCall => 11,
            Self::MissingHostCall => 12,
            Self::ReorderHostCalls => 13,
            Self::PrivateExport => 14,
            Self::UnknownImport => 15,
            Self::PrivateDependentTrap => 16,
            Self::BoundsCheckDrop => 17,
            Self::DivisionGuardDrop => 18,
            Self::SignedOverflowPath => 19,
            Self::UnreachableInsert => 20,
            Self::ExportedMemory => 21,
            Self::MemoryGrowInsert => 22,
            Self::AddressOffsetIncrement => 23,
            Self::MutableGlobal => 24,
            Self::DataOffsetShift => 25,
            Self::PrivateBranch => 26,
            Self::OpcodeCostInflate => 27,
            Self::FuelDecrementDrop => 28,
            Self::AddressTraceAlias => 29,
            Self::FailurePathShortcut => 30,
            Self::LoopBackedge => 31,
            Self::WrongAbiImport => 32,
            Self::WrongSourceBinding => 33,
            Self::WrongObserverBinding => 34,
            Self::ExtraExport => 35,
            Self::ClockImport => 36,
            Self::RandomImport => 37,
        }
    }

    #[must_use]
    pub const fn family(self) -> MutationFamily {
        match self.ordinal() {
            1..=5 => MutationFamily::Action,
            6..=10 => MutationFamily::State,
            11..=15 => MutationFamily::Context,
            16..=20 => MutationFamily::Trap,
            21..=25 => MutationFamily::Memory,
            26..=31 => MutationFamily::Resource,
            _ => MutationFamily::Binding,
        }
    }

    #[must_use]
    pub const fn recipe(self) -> MutationRecipe {
        match self {
            Self::ActionConstantFlip | Self::NextStateIncrement => {
                MutationRecipe::IncrementI32Constant
            }
            Self::ActionToCover | Self::StaleStateRestore | Self::FuelDecrementDrop => {
                MutationRecipe::InjectConstDrop
            }
            Self::PolicyBypass | Self::BoundsCheckDrop => MutationRecipe::FlipCodeOpcode,
            Self::DuplicateActionCall | Self::ResetDuplicate => MutationRecipe::DuplicateCall,
            Self::DropActionCall | Self::ResetDrop | Self::MissingHostCall => {
                MutationRecipe::DropCall
            }
            Self::HandoffTargetFlip => MutationRecipe::IncrementCallIndex,
            Self::ExtraHostCall => MutationRecipe::InsertCall,
            Self::ReorderHostCalls => MutationRecipe::ReorderCalls,
            Self::PrivateExport | Self::ExtraExport => MutationRecipe::AppendFunctionExport,
            Self::UnknownImport | Self::WrongAbiImport | Self::ClockImport | Self::RandomImport => {
                MutationRecipe::AppendFunctionImport
            }
            Self::PrivateDependentTrap | Self::UnreachableInsert => {
                MutationRecipe::InsertUnreachable
            }
            Self::DivisionGuardDrop => MutationRecipe::InsertDivisionByZero,
            Self::SignedOverflowPath => MutationRecipe::InsertSignedOverflow,
            Self::ExportedMemory => MutationRecipe::AppendMemoryExport,
            Self::MemoryGrowInsert => MutationRecipe::InsertMemoryGrow,
            Self::AddressOffsetIncrement | Self::AddressTraceAlias => {
                MutationRecipe::IncrementMemoryOffset
            }
            Self::MutableGlobal => MutationRecipe::AppendMutableGlobal,
            Self::DataOffsetShift => MutationRecipe::ShiftDataOffset,
            Self::PrivateBranch | Self::FailurePathShortcut => MutationRecipe::InsertPrivateBranch,
            Self::OpcodeCostInflate => MutationRecipe::InflateOpcodeCost,
            Self::LoopBackedge => MutationRecipe::InsertLoopBackedge,
            Self::WrongSourceBinding | Self::WrongObserverBinding => {
                MutationRecipe::AppendBindingSection
            }
        }
    }
}
