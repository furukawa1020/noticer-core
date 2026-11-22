//! Slot delays from attack onset to detection and quarantine.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetectionDelayMetric {
    pub detection_slots: u32,
    pub quarantine_slots: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionDelayError {
    BeforeAttack,
    QuarantineBeforeDetection,
}

pub fn measure(
    attack_slot: u32,
    detection_slot: u32,
    quarantine_slot: u32,
) -> Result<DetectionDelayMetric, DetectionDelayError> {
    if detection_slot < attack_slot {
        return Err(DetectionDelayError::BeforeAttack);
    }
    if quarantine_slot < detection_slot {
        return Err(DetectionDelayError::QuarantineBeforeDetection);
    }
    Ok(DetectionDelayMetric {
        detection_slots: detection_slot - attack_slot,
        quarantine_slots: quarantine_slot - attack_slot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delays_share_attack_origin() {
        assert_eq!(
            measure(10, 12, 13),
            Ok(DetectionDelayMetric {
                detection_slots: 2,
                quarantine_slots: 3
            })
        );
    }
}
