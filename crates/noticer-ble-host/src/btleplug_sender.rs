use btleplug::{
    api::{Characteristic, Peripheral as _, WriteType},
    platform::Peripheral,
};
use noticer_transport_core::{Fragment, TOTAL_FRAGMENT_COUNT};
use tokio::time::{sleep_until, Duration, Instant};

use crate::SendReport;

pub struct BtleplugSender {
    peripheral: Peripheral,
    characteristic: Characteristic,
    cadence: Duration,
}

impl BtleplugSender {
    pub fn new(peripheral: Peripheral, characteristic: Characteristic, cadence: Duration) -> Self {
        Self {
            peripheral,
            characteristic,
            cadence,
        }
    }

    /// Uses Write Without Response once per public slot and never retries.
    pub async fn send(&self, fragments: &[Fragment; TOTAL_FRAGMENT_COUNT]) -> SendReport {
        let start = Instant::now();
        let mut failed_mask = 0_u32;
        for (ordinal, fragment) in fragments.iter().enumerate() {
            sleep_until(start + self.cadence * ordinal as u32).await;
            if self
                .peripheral
                .write(
                    &self.characteristic,
                    &fragment.encode(),
                    WriteType::WithoutResponse,
                )
                .await
                .is_err()
            {
                failed_mask |= 1_u32 << ordinal;
            }
        }
        SendReport {
            attempted: TOTAL_FRAGMENT_COUNT as u8,
            failed_mask,
        }
    }
}
