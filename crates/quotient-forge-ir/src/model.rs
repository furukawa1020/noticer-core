use crate::canonical::{canonical_hash, CanonicalEncode, Encoder};
use crate::{
    FaultAutomaton, IrError, IrLimits, ObserverModel, PrivatePlant, QuotientMonitor,
    ReleaseTransducer, UtilityAutomaton, DOMAIN_IR,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledModel {
    pub plant: PrivatePlant,
    pub quotient: QuotientMonitor,
    pub observers: ObserverModel,
    pub utility: UtilityAutomaton,
    pub fault: FaultAutomaton,
    pub horizon: u16,
}

impl CompiledModel {
    pub fn validate(&self, limits: IrLimits) -> Result<(), IrError> {
        self.plant.validate(limits)?;
        self.quotient.validate(limits)?;
        self.observers.validate(limits)?;
        self.utility.validate(limits)?;
        self.fault.validate(limits)?;
        if self.horizon == 0 || self.horizon > limits.max_horizon {
            return Err(IrError::LimitExceeded {
                component: "compiled model",
            });
        }
        if usize::from(self.quotient.plant_state_count) != self.plant.states.len() {
            return Err(IrError::DimensionMismatch);
        }
        if !self.plant.is_canonical(limits)? {
            return Err(IrError::NonCanonical {
                component: "private plant",
            });
        }
        if !self.quotient.is_canonical(limits)? {
            return Err(IrError::NonCanonical {
                component: "quotient monitor",
            });
        }
        if !self.observers.is_canonical(limits)? {
            return Err(IrError::NonCanonical {
                component: "observer model",
            });
        }
        if !self.utility.is_canonical(limits)? {
            return Err(IrError::NonCanonical {
                component: "utility automaton",
            });
        }
        if !self.fault.is_canonical(limits)? {
            return Err(IrError::NonCanonical {
                component: "fault automaton",
            });
        }
        Ok(())
    }

    pub fn validate_transducer(
        &self,
        transducer: &ReleaseTransducer,
        limits: IrLimits,
    ) -> Result<(), IrError> {
        self.validate(limits)?;
        transducer.validate(limits)?;
        if usize::from(transducer.quotient_state_count) != self.quotient.states.len()
            || usize::from(transducer.public_input_count)
                != usize::from(self.plant.public_input_count)
            || usize::from(transducer.fault_state_count) != self.fault.states.len()
            || transducer.horizon != self.horizon
        {
            return Err(IrError::DimensionMismatch);
        }
        Ok(())
    }

    pub fn canonical_hash(&self, limits: IrLimits) -> Result<[u8; 32], IrError> {
        self.validate(limits)?;
        let hashes = ModelHashes {
            plant: self.plant.canonical_hash(limits)?,
            quotient: self.quotient.canonical_hash(limits)?,
            observers: self.observers.canonical_hash(limits)?,
            utility: self.utility.canonical_hash(limits)?,
            fault: self.fault.canonical_hash(limits)?,
            horizon: self.horizon,
        };
        Ok(canonical_hash(DOMAIN_IR, &hashes))
    }
}

struct ModelHashes {
    plant: [u8; 32],
    quotient: [u8; 32],
    observers: [u8; 32],
    utility: [u8; 32],
    fault: [u8; 32],
    horizon: u16,
}

impl CanonicalEncode for ModelHashes {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(&self.plant);
        encoder.fixed(&self.quotient);
        encoder.fixed(&self.observers);
        encoder.fixed(&self.utility);
        encoder.fixed(&self.fault);
        encoder.u16(self.horizon);
    }
}
