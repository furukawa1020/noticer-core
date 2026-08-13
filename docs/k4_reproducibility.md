# K4 再現手順

## Tier A

Windows PowerShell:

    ./scripts/run_k4_ble_menfugu.ps1

Linux:

    ./scripts/run_k4_ble_menfugu.sh

個別実行:

    cargo run -p noticer-k4-demo -- --config configs/k4/ble_menfugu.toml --output artifacts/k4/latest
    python -m noticer_core.evaluation.k4_transport artifacts/k4/latest

期待結果はTier A VERIFIED、Tier B NOT_VERIFIEDである。K4 demoは同じ公開planから二つの
action-equivalent ATv2を発行し、20 fragmentsへ変換する。public loss tapeはdata indices
0、5、10、15をdropし、各parity groupで一個だけのlossを作る。両側を別receiverで再構成、
検証、実行し、observer traceとpump transitionを比較する。同じframeの二回目deliveryは
replayとしてpumpを増やさない。

## Artifact

artifacts/k4/latestは生成物でありGitへcommitしない。

summary.jsonに保存するもの:

- schema versionとpublic seed
- profile名と許可action semantics
- fragment count、length、drop count
- pair equality、reassembly、authorization、execution、replayのboolean
- Tier A/B判定

transport_trace.csvに保存するもの:

- counterfactual side
- ordinal、scheduled tick
- short public frame ID
- fragment index、delivery、wire length

保存しないもの:

- tokenまたはfragment payload
- ciphertext、nonce、token ID
- issuer key、transport ID key
- private evidence、biosignal、baseline

Python evaluatorはschema、20 rows/side、20-byte固定長、pair equality、禁止fieldを検査し、
aggregateだけをevaluation.jsonへ書く。

## CI

    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace --all-features
    python -m ruff check .
    python -m pytest -q

## Tier B

Tier Bには実BLE peripheral、実controller scheduling、ESP-IDF firmware、実pumpを使う。
このrepositoryのCPU/mock実行だけではTier Bを満たさない。機材とESP-IDF toolchainを接続して
いないrunは必ずNOT_VERIFIEDと報告する。
