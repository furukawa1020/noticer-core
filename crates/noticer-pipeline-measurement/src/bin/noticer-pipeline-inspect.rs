#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;

use noticer_pipeline_measurement::PublicPipelineManifest;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: noticer-pipeline-inspect <public-manifest.json>")?;
    let source = fs::read_to_string(path)?;
    let measurement = PublicPipelineManifest::parse_json(&source)?.measure()?;
    println!("{}", serde_json::to_string_pretty(&measurement.inspect())?);
    Ok(())
}
