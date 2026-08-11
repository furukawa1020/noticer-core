use noticer_aetp_sim::PrivateHistory;

fn serialize(history: &PrivateHistory) {
    let _ = serde_json::to_string(history);
}

fn main() {}
