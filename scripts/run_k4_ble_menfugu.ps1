$ErrorActionPreference = "Stop"
cargo run -p noticer-k4-demo -- --config configs/k4/ble_menfugu.toml --output artifacts/k4/latest
python -m noticer_core.evaluation.k4_transport artifacts/k4/latest
