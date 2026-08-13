#![no_std]
#![forbid(unsafe_code)]

//! Thin callback boundary to be wired to esp-idf-svc by the hardware project.

pub use noticer_menfugu_firmware::{
    EnvelopeVerifier, MenfuguRuntime, PumpOutput, RuntimeEvent,
};

/// ESP-IDF GPIO drivers implement this trait without exposing the driver type
/// to the platform-neutral runtime.
pub trait EspIdfPumpPin {
    fn drive_low(&mut self);
    fn drive_high(&mut self);
}

pub struct EspIdfPumpOutput<P> {
    pin: P,
}

impl<P: EspIdfPumpPin> EspIdfPumpOutput<P> {
    pub fn new(mut pin: P) -> Self {
        pin.drive_low();
        Self { pin }
    }
}

impl<P: EspIdfPumpPin> PumpOutput for EspIdfPumpOutput<P> {
    fn set_pump(&mut self, enabled: bool) {
        if enabled {
            self.pin.drive_high();
        } else {
            self.pin.drive_low();
        }
    }
}
