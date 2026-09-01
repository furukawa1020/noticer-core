# QuotientSeal Reproduction Runner v1

## 目的

reproduction runnerは、replication manifestへ固定したsoftware evidenceをWindows / Linux共通の一つのPython commandから依存順に再実行する。runner成功はsecurity PASSではない。

## 実行

```bash
python scripts/reproduce_quotient_seal.py --profile smoke
python scripts/reproduce_quotient_seal.py --profile core
python scripts/reproduce_quotient_seal.py --profile full
```

実行せずexact command graphだけを生成する場合:

```bash
python scripts/reproduce_quotient_seal.py --profile full --dry-run
```

同じplan digestとmanifest digestを持つ前回reportから、log digestまで一致するPASS stepだけを再利用する場合:

```bash
python scripts/reproduce_quotient_seal.py --profile full --resume
```

## Profiles

### smoke

- replication manifest生成
- manifest / runner専用Python test
- capsule / relation Rust contract smoke
- Studio evidence runtime test

### core

smokeに加えて、context、resource、engine、mutation、fuzz、benchmark、performance、Lean audit、Studio checkを実行する。

### full

coreに加えて、全Python test、Rust workspace全target、Studio production buildを実行する。

## Execution boundary

- commandはversioned JSON planのargv配列だけを許可する。
- `shell=False`で実行し、shell control tokenを拒否する。
- user-supplied commandと自由入力codeを受け取らない。
- pip / npm / Cargo install、curl、wget、git cloneをplan内で拒否する。
- `CARGO_NET_OFFLINE=true`、`PIP_NO_INDEX=1`、`NPM_CONFIG_OFFLINE=true`を既定にする。
- process environmentはtool実行に必要なpath/cacheだけをallowlistし、credentialを継承しない。

## Verdict

| Condition | Reproduction verdict |
|---|---|
| 全step PASS、baseline子孫、clean tree | PASS |
| nonzero exit、timeout、baseline非子孫 | FAIL |
| missing tool、dependency skip、provenance未解決、dirty tree | INCONCLUSIVE |
| dry-run | NOT_RUN |

unsupported、resource exhaustion、missing tool、engine disagreementをPASSとして扱わない。

## Logs and resume

stdout / stderrはUTF-8へ正規化し、repository rootとhome pathをplaceholderへ置換してから各1 MiBへ制限する。reportにはrelative path、byte length、SHA-256、truncated flagを残す。resumeはplan、manifest、log digestが一致するPASS stepだけを再利用する。

既定出力は`artifacts/replication/<profile>/`であり、Gitへcommitしない。

## Claim boundary

- `evidence_origin = SOFTWARE_REPRODUCTION`
- `security_interpretation = NOT_A_SECURITY_VERDICT`
- `hardware_status = NOT_VERIFIED`
- Polar Verity Sense実機、実biosignal、priority claimは検証しない。

