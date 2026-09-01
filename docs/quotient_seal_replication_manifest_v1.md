# QuotientSeal Replication Manifest v1

## 目的

replication manifestは、QuotientSealの主要software evidenceを再生成するために必要なtoolchain、lockfile、K7 provenance、config、schema、source contract、formal auditを決定的に列挙する。manifest自体はsecurity verdictではない。

## Provenance baseline

- repository: `furukawa1020/noticer-core`
- K8 baseline: K8-17完了時のfull commit SHA
- revision policy: `DESCENDANT_OF_BASELINE`
- K7 dependencies: #76、#77、#88に対応するmerge provenanceをfull commit SHAで固定

生成器はGitの現在状態を推測しない。実行時revisionは次のreproduction runnerが別artifactとして記録し、baselineの子孫かを確認する。

## Toolchains

| Tool | Frozen version | Source of truth |
|---|---:|---|
| Rust | 1.93.0 | `rust-toolchain.toml` |
| Python | 3.11 | CI workflow |
| Node | 24 | CI workflow |
| Lean | 4.30.0 | `formal/aqrs/lean-toolchain` |
| WASM target | `wasm32-unknown-unknown` | CI workflow |

各toolchain recordはversion文字列だけでなく、source file、必須marker、source SHA-256を持つ。marker欠落とsource digest不一致はエラーとする。

## Inventory

inventoryは固定allowlistであり、path、kind、byte length、SHA-256を持つ。pathはrepository-relativeなPOSIX形式だけを許可する。

- absolute path、`..`、`.`、backslashを拒否する。
- symlinkを拒否する。
- repository外へ解決されるpathを拒否する。
- 1 fileあたり512 MiB、全256 entriesを上限とする。
- missing file、unknown kind、duplicate pathを拒否する。

RustとNodeは既存lockfileを参照する。PythonはCPython 3.11用のcross-platform exact-version lockを参照する。Python wheel hashはplatform固有のためこのlockでは主張せず、選択されたdistribution digestはreproduction log側で記録する。

## Canonical encoding

UTF-8 JSONをkey sort、空白なし、末尾改行ありでencodeする。`artifact_sha256`を空文字へ置換したcanonical bytesのSHA-256をmanifest digestとする。生成後は全inventory digestとmanifest digestを再計算する。

## 実行

```bash
python -m noticer_core.replication.manifest
```

既定出力は`artifacts/replication/manifest.json`であり、Gitへcommitしない。

## Claim boundary

- `evidence_origin = REPOSITORY_CONTRACT`
- `security_interpretation = NOT_A_SECURITY_VERDICT`
- `hardware_status = NOT_VERIFIED`
- Polar Verity Sense実機、実biosignal、実時間性能は検証しない。
- manifestは再現入力の完全性を限定範囲で検査するもので、world-firstや一般的安全性を主張しない。

