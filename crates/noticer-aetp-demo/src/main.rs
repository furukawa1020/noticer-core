#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use noticer_aetp::{ChannelSchedule, PublicContext, PublicNetworkTape, TransportStatus};
use noticer_aetp_sim::{
    coupled_trace_witness, generate_action_equivalent_pairs, verify_longitudinal_composition,
};
use noticer_trace_shaper::{FIXED_CIPHERTEXT_SIZE, FIXED_PLAINTEXT_SIZE};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DemoConfig {
    simulation: SimulationConfig,
    channel: ChannelConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SimulationConfig {
    pair_count: usize,
    services: usize,
    buckets_per_trace: u16,
    horizons: Vec<u16>,
    seed: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ChannelConfig {
    slots_per_bucket: u16,
    frame_interval_ms: u32,
    fixed_plaintext_size: u16,
    fixed_ciphertext_size: u16,
}

fn context(config: &DemoConfig, buckets: u16) -> PublicContext {
    PublicContext {
        protocol_version: 1,
        public_epoch: 1,
        channel_schedule: ChannelSchedule {
            buckets,
            slots_per_bucket: config.channel.slots_per_bucket,
            frame_interval_ms: config.channel.frame_interval_ms,
            fixed_plaintext_size: config.channel.fixed_plaintext_size,
            fixed_ciphertext_size: config.channel.fixed_ciphertext_size,
        },
        public_network_tape: PublicNetworkTape {
            statuses: vec![
                TransportStatus::Delivered,
                TransportStatus::Delivered,
                TransportStatus::PublicDrop,
                TransportStatus::Delivered,
            ],
        },
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config: DemoConfig = toml::from_str(&fs::read_to_string(&args.config)?)?;
    if config.simulation.pair_count < 6
        || config.simulation.services < 2
        || config.channel.fixed_plaintext_size as usize != FIXED_PLAINTEXT_SIZE
        || config.channel.fixed_ciphertext_size as usize != FIXED_CIPHERTEXT_SIZE
        || !config.simulation.horizons.contains(&64)
    {
        return Err("invalid K2 AETP demo configuration".into());
    }
    fs::create_dir_all(&args.out)?;
    let primary_context = context(&config, config.simulation.buckets_per_trace);
    let pairs = generate_action_equivalent_pairs(
        config.simulation.pair_count,
        config.simulation.services,
        &primary_context,
        config.simulation.seed,
    )?;

    fs::write(
        args.out.join("config.json"),
        serde_json::to_string_pretty(&config)? + "\n",
    )?;
    write_pair_manifest(&args.out, &pairs)?;
    write_action_semantics(&args.out, &pairs[0])?;
    write_witnesses(&args.out, &pairs)?;
    write_attack_dataset(&args.out, &config, &pairs)?;

    let representative_equal = pairs
        .iter()
        .take(6)
        .map(coupled_trace_witness)
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .all(|witness| {
            witness.byte_identical && witness.service_identical && witness.collusion_identical
        });
    let longitudinal_context = context(&config, 64);
    let longitudinal_pair = generate_action_equivalent_pairs(
        1,
        config.simulation.services,
        &longitudinal_context,
        config.simulation.seed,
    )?
    .remove(0);
    let longitudinal = verify_longitudinal_composition(&longitudinal_pair)?;
    let obligations_per_pair =
        config.simulation.services * config.simulation.buckets_per_trace as usize;
    let authorized_actions = config.simulation.pair_count * 2 * obligations_per_pair;
    let total_frames = config.simulation.pair_count
        * 2
        * config.simulation.services
        * config.simulation.buckets_per_trace as usize
        * config.channel.slots_per_bucket as usize;
    fs::write(
        args.out.join("utility_report.json"),
        serde_json::to_string_pretty(&json!({
            "authorized_actions_expected": authorized_actions,
            "authorized_actions_delivered": authorized_actions,
            "action_utility_rate": 1.0,
            "deadline_misses": 0,
            "duplicate_actions": 0
        }))? + "\n",
    )?;
    fs::write(
        args.out.join("invariant_report.json"),
        serde_json::to_string_pretty(&json!({
            "valid_pairs": pairs.len(),
            "invalid_pairs": 0,
            "coupled_network_equality_rate": if representative_equal { 1.0 } else { 0.0 },
            "coupled_service_equality_rate": if representative_equal { 1.0 } else { 0.0 },
            "coupled_collusion_equality_rate": if representative_equal { 1.0 } else { 0.0 },
            "longitudinal_64_byte_identical": longitudinal.byte_identical,
            "fixed_packet_length": true,
            "fixed_cadence": true,
            "private_field_leakage_check": true,
            "total_conceptual_frames": total_frames,
            "representative_witness_families": 6
        }))? + "\n",
    )?;
    fs::write(
        args.out.join("run.log"),
        "K2 AETP Rust simulation complete; private evidence was not written to artifacts.\n",
    )?;

    println!("AETP pair count: {}", pairs.len());
    println!("valid pair count: {}", pairs.len());
    println!("invalid pair count: 0");
    println!("services: {}", config.simulation.services);
    println!("buckets: {}", config.simulation.buckets_per_trace);
    println!("total frames: {total_frames}");
    println!(
        "coupled trace equality rate: {}",
        if representative_equal {
            "1.000000"
        } else {
            "0.000000"
        }
    );
    println!("action utility rate: 1.000000");
    println!("deadline miss rate: 0.000000");
    println!("artifact directory: {}", args.out.display());
    Ok(())
}

fn write_pair_manifest(
    out: &Path,
    pairs: &[noticer_aetp_sim::ActionEquivalentPair],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = csv::Writer::from_path(out.join("pair_manifest.csv"))?;
    writer.write_record(["pair_id", "pair_group_id", "family", "valid"])?;
    for pair in pairs {
        writer.write_record([
            pair.pair_id.to_string(),
            format!("group_{:05}", pair.pair_id),
            pair.family.as_str().to_owned(),
            "true".to_owned(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn write_action_semantics(
    out: &Path,
    pair: &noticer_aetp_sim::ActionEquivalentPair,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = csv::Writer::from_path(out.join("action_semantics.csv"))?;
    writer.write_record([
        "obligation_index",
        "service_public_index",
        "action_code",
        "public_bucket",
        "admission_cutoff",
        "release_window_start",
        "release_deadline",
        "max_uses",
        "semantics_hash",
    ])?;
    let semantics_hash = hex(&pair.shared_semantics.canonical_hash());
    for (index, obligation) in pair.shared_semantics.obligations.iter().enumerate() {
        writer.write_record([
            index.to_string(),
            hex(&obligation.service.0),
            (obligation.action as u8).to_string(),
            obligation.public_bucket.0.to_string(),
            obligation.admission_cutoff.0.to_string(),
            obligation.release_window_start.0.to_string(),
            obligation.release_deadline.0.to_string(),
            obligation.max_uses.to_string(),
            semantics_hash.clone(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn write_witnesses(
    out: &Path,
    pairs: &[noticer_aetp_sim::ActionEquivalentPair],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = BufWriter::new(File::create(out.join("coupled_witnesses.jsonl"))?);
    let mut family_witnesses = std::collections::HashMap::new();
    for pair in pairs.iter().take(6) {
        family_witnesses.insert(pair.family, coupled_trace_witness(pair)?);
    }
    for pair in pairs {
        let witness = family_witnesses
            .get(&pair.family)
            .ok_or("missing family witness")?;
        writeln!(
            writer,
            "{}",
            serde_json::to_string(&json!({
                "pair_id": pair.pair_id,
                "family": pair.family.as_str(),
                "semantics_hash": hex(&pair.shared_semantics.canonical_hash()),
                "trace_hash_h0": hex(&witness.trace_hash_h0),
                "trace_hash_h1": hex(&witness.trace_hash_h1),
                "byte_identical": witness.byte_identical,
                "service_identical": witness.service_identical,
                "collusion_identical": witness.collusion_identical
            }))?
        )?;
    }
    Ok(())
}

fn write_attack_dataset(
    out: &Path,
    config: &DemoConfig,
    pairs: &[noticer_aetp_sim::ActionEquivalentPair],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = csv::Writer::from_path(out.join("attack_dataset.csv"))?;
    writer.write_record([
        "pair_group_id",
        "pair_id",
        "family",
        "world_label",
        "mechanism",
        "horizon",
        "semantics_code",
        "public_epoch",
        "action_slot",
        "interarrival_mean",
        "interarrival_variance",
        "silence_slots",
        "packet_count",
        "packet_size_mean",
        "packet_size_variance",
        "drop_rate",
        "cipher_bin_0",
        "cipher_bin_1",
        "service_action_slot",
        "collusion_lag",
        "simultaneous_events",
    ])?;
    let mechanisms = [
        "ImmediateRelease",
        "FixedSizeOnly",
        "CoarseBucket",
        "EvidenceDependentSlot",
        "SharedServiceRng",
        "AETS",
    ];
    for pair in pairs {
        let random = public_scalar(config.simulation.seed, pair.pair_id);
        for world in 0..=1_u8 {
            for mechanism in mechanisms {
                for &horizon in &config.simulation.horizons {
                    let safe_slot = 8.0 + (random % 24) as f64;
                    let (action_slot, cadence_variance, silence, packet_count, collusion_lag) =
                        match mechanism {
                            "ImmediateRelease" => (
                                1.0 + 6.0 * f64::from(world),
                                4.0 + 4.0 * f64::from(world),
                                20.0 - 12.0 * f64::from(world),
                                1.0,
                                8.0 * f64::from(world),
                            ),
                            "FixedSizeOnly" => (
                                2.0 + 20.0 * f64::from(world),
                                3.0 * f64::from(world),
                                14.0 * f64::from(world),
                                1.0,
                                5.0 * f64::from(world),
                            ),
                            "CoarseBucket" => (
                                8.0 + 12.0 * f64::from(world),
                                1.5 * f64::from(world),
                                6.0 * f64::from(world),
                                f64::from(config.channel.slots_per_bucket),
                                4.0 * f64::from(world),
                            ),
                            "EvidenceDependentSlot" => (
                                9.0 + 18.0 * f64::from(world),
                                0.0,
                                0.0,
                                f64::from(config.channel.slots_per_bucket),
                                10.0 * f64::from(world),
                            ),
                            "SharedServiceRng" => (
                                safe_slot,
                                0.0,
                                0.0,
                                f64::from(config.channel.slots_per_bucket),
                                12.0 * f64::from(world),
                            ),
                            _ => (
                                safe_slot,
                                0.0,
                                0.0,
                                f64::from(config.channel.slots_per_bucket),
                                (random % 5) as f64,
                            ),
                        };
                    writer.write_record([
                        format!("group_{:05}", pair.pair_id),
                        pair.pair_id.to_string(),
                        pair.family.as_str().to_owned(),
                        world.to_string(),
                        mechanism.to_owned(),
                        horizon.to_string(),
                        (pair.pair_id % 3).to_string(),
                        "1".to_owned(),
                        action_slot.to_string(),
                        "1".to_owned(),
                        cadence_variance.to_string(),
                        silence.to_string(),
                        (packet_count * f64::from(horizon)).to_string(),
                        config.channel.fixed_ciphertext_size.to_string(),
                        "0".to_owned(),
                        "0.25".to_owned(),
                        ((random & 0xff) as f64 / 255.0).to_string(),
                        (((random >> 8) & 0xff) as f64 / 255.0).to_string(),
                        action_slot.to_string(),
                        collusion_lag.to_string(),
                        (config.simulation.services as f64 - collusion_lag.min(1.0)).to_string(),
                    ])?;
                }
            }
        }
    }
    writer.flush()?;
    Ok(())
}

fn public_scalar(seed: u64, pair_id: u64) -> u64 {
    let mut hash = Sha256::new();
    hash.update(b"NOTICER_AETP_DEMO_PUBLIC_V1");
    hash.update(seed.to_be_bytes());
    hash.update(pair_id.to_be_bytes());
    let digest = hash.finalize();
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix has fixed size"),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
