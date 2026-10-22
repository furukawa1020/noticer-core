use quotient_commit_core::chaos_campaign::{canonical_json, run_campaign, CampaignConfig};
use std::path::PathBuf;

fn main() {
    match parse(std::env::args().skip(1).collect()).and_then(|(config, output)| {
        run_campaign(config)
            .map(|artifact| (artifact, output))
            .map_err(|error| format!("campaign error: {error:?}"))
    }) {
        Ok((artifact, Some(path))) => {
            if let Err(error) = std::fs::write(&path, canonical_json(&artifact)) {
                eprintln!("write error: {error}");
                std::process::exit(1);
            }
        }
        Ok((artifact, None)) => println!("{}", canonical_json(&artifact)),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

fn parse(args: Vec<String>) -> Result<(CampaignConfig, Option<PathBuf>), String> {
    let mut seed = None;
    let mut iterations = None;
    let mut maximum_failures = None;
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        let flag = &args[index];
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        index += 1;
        match flag.as_str() {
            "--seed" => seed = Some(value.parse().map_err(|_| "invalid seed".to_owned())?),
            "--iterations" => {
                iterations = Some(value.parse().map_err(|_| "invalid iterations".to_owned())?)
            }
            "--maximum-failures" => {
                maximum_failures = Some(
                    value
                        .parse()
                        .map_err(|_| "invalid maximum-failures".to_owned())?,
                )
            }
            "--output" => output = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }
    Ok((
        CampaignConfig {
            seed: seed.ok_or("--seed is required")?,
            iterations: iterations.ok_or("--iterations is required")?,
            maximum_failures: maximum_failures.ok_or("--maximum-failures is required")?,
        },
        output,
    ))
}
