use noticer_baseline::PrivateObservation;

fn serialize(observation: &PrivateObservation) {
    let _ = serde_json::to_string(observation);
}

fn main() {}

