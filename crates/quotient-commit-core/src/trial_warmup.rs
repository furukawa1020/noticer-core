//! Explicit separation of initialization, warmup, and measured slots.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WarmupMeasurementPlan {
    pub initialization_slots: u32,
    pub warmup_slots: u32,
    pub measurement_slots: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WarmupPlanError {
    ZeroMeasurement,
    Overflow,
}

impl WarmupMeasurementPlan {
    pub fn new(
        initialization_slots: u32,
        warmup_slots: u32,
        measurement_slots: u32,
    ) -> Result<Self, WarmupPlanError> {
        if measurement_slots == 0 {
            return Err(WarmupPlanError::ZeroMeasurement);
        }
        initialization_slots
            .checked_add(warmup_slots)
            .and_then(|v| v.checked_add(measurement_slots))
            .ok_or(WarmupPlanError::Overflow)?;
        Ok(Self {
            initialization_slots,
            warmup_slots,
            measurement_slots,
        })
    }

    pub fn measured(self, slot: u32) -> bool {
        let start = self.initialization_slots.saturating_add(self.warmup_slots);
        slot >= start && slot < start.saturating_add(self.measurement_slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn warmup_never_enters_measurement() {
        let plan = WarmupMeasurementPlan::new(2, 3, 4).unwrap();
        assert!(!plan.measured(4));
        assert!(plan.measured(5));
        assert!(!plan.measured(9));
    }
}
