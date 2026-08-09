use noticer_baseline::PrivateFeatureVector;

fn main() {
    let feature = PrivateFeatureVector::new(vec![1.0]).unwrap();
    let _ = feature.values[0];
}

