$ErrorActionPreference = "Stop"

$Output = "artifacts/k3_token_v2"
cargo run --release -p noticer-token-demo -- --config configs/token/k3_demo.toml --output $Output
python -m noticer_core.evaluation.token_attacks --witnesses "$Output/counterfactual_witnesses.csv" --output $Output --seed 42 --horizons 1,4,16,64 --bootstrap-samples 100
