#![forbid(unsafe_code)]

use noticer_aetp_sim::{
    capture_matched_action_runtime, coupled_simulation_witness, default_public_context,
    generate_action_equivalent_pairs, RuntimeTraceCapture,
};
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize)]
struct PublicFrameMetadata {
    scheduled_ms: u64,
    ciphertext_bytes: usize,
    retry_count: u16,
    failure: bool,
    silence: bool,
}

#[derive(Serialize)]
struct ComparisonPair {
    left: Vec<PublicFrameMetadata>,
    right: Vec<PublicFrameMetadata>,
}

#[derive(Serialize)]
struct ComparisonExport {
    schema: &'static str,
    evidence_class: &'static str,
    seed: u64,
    pairs: Vec<ComparisonPair>,
}

fn metadata(capture: &RuntimeTraceCapture) -> Vec<PublicFrameMetadata> {
    capture
        .observations
        .iter()
        .map(|frame| PublicFrameMetadata {
            scheduled_ms: frame.scheduled_time_ms,
            ciphertext_bytes: frame.ciphertext.len(),
            retry_count: frame.retry_count,
            failure: frame.failure,
            silence: frame.silence,
        })
        .collect()
}

fn comparison_export(
    seed: u64,
    count: usize,
) -> Result<ComparisonExport, Box<dyn std::error::Error>> {
    let context = default_public_context();
    let generated = generate_action_equivalent_pairs(count, seed, &context)?;
    let mut pairs = Vec::with_capacity(generated.len());
    for pair in &generated {
        let capture = capture_matched_action_runtime(pair, [8; 32])?;
        pairs.push(ComparisonPair {
            left: metadata(&capture.left),
            right: metadata(&capture.right),
        });
    }
    Ok(ComparisonExport {
        schema: "noticer.k20.aetp-metadata.v1",
        evidence_class: "synthetic-control",
        seed,
        pairs,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("--k20-metadata") {
        let export = comparison_export(42, 100)?;
        println!("{}", serde_json::to_string(&export)?);
        return Ok(());
    }

    let context = default_public_context();
    let pairs = generate_action_equivalent_pairs(100, 42, &context)?;
    let mut equal = 0_usize;
    for pair in &pairs {
        equal += usize::from(coupled_simulation_witness(pair, [8; 32])?.equal);
    }
    println!("AETP simulation witnesses: {equal}/{} equal", pairs.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_is_deterministic_and_contains_only_projected_frames() {
        let export = comparison_export(42, 8).unwrap();
        assert_eq!(export.pairs.len(), 8);
        for pair in &export.pairs {
            assert!(!pair.left.is_empty());
            assert_eq!(pair.left, pair.right);
        }
        let json = serde_json::to_value(&export).unwrap();
        assert_eq!(json["evidence_class"], "synthetic-control");
        let frame = json["pairs"][0]["left"][0].as_object().unwrap();
        assert_eq!(frame.len(), 5);
        assert!(!frame.contains_key("ciphertext"));
        assert!(!frame.contains_key("subject_id"));
        let repeat = comparison_export(42, 8).unwrap();
        assert_eq!(json, serde_json::to_value(repeat).unwrap());
    }
}
