macro_rules! state_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub u16);
    };
}

state_id!(PlantStateId);
state_id!(QuotientStateId);
state_id!(UtilityStateId);
state_id!(FaultStateId);
state_id!(ReleaseStateId);
