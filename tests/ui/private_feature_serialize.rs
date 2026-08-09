use noticer_baseline::PrivateFeatureVector;

fn main() {
    let feature = PrivateFeatureVector::new(vec![1.0]).unwrap();
    let _ = serde_json::to_string(&feature);
}

