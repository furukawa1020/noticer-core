#!/usr/bin/env sh
set -eu

output="artifacts/k3_token_v2"
cargo run --release -p noticer-token-demo -- --config configs/token/k3_demo.toml --output "$output"
python -m noticer_core.evaluation.token_attacks --witnesses "$output/counterfactual_witnesses.csv" --output "$output" --seed 42 --horizons 1,4,16,64 --bootstrap-samples 100
