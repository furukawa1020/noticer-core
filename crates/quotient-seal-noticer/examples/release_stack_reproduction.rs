use std::env;
use std::error::Error;
use std::path::PathBuf;

use quotient_seal_noticer::{injected_reproduction_fixture_inputs, ReleaseStackReproductionBundle};

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return Err("usage: release_stack_reproduction --output <directory>".into());
    }
    let output = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("missing output directory")?;
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    let inputs = injected_reproduction_fixture_inputs()?;
    let bundle = ReleaseStackReproductionBundle::build(inputs.clone())?;
    bundle.verify_complete_recomputation(&inputs)?;
    let (bundle_path, summary_path) = bundle.write_artifacts(&output)?;
    println!("fixture bundle: {}", bundle_path.display());
    println!("fixture summary: {}", summary_path.display());
    println!("hardware status: NOT_VERIFIED");
    Ok(())
}
