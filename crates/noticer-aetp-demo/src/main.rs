#![forbid(unsafe_code)]

use noticer_aetp_sim::{
    coupled_simulation_witness, default_public_context, generate_action_equivalent_pairs,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let context = default_public_context();
    let pairs = generate_action_equivalent_pairs(100, 42, &context)?;
    let mut equal = 0_usize;
    for pair in &pairs {
        equal += usize::from(coupled_simulation_witness(pair, [8; 32])?.equal);
    }
    println!("AETP simulation witnesses: {equal}/{} equal", pairs.len());
    Ok(())
}
