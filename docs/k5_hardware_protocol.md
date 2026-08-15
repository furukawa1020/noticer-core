# K5 hardware evidence protocol

## 位置づけ

この文書は、K5の実機検証で残す証拠の形式、昇格条件、公開境界を固定する。
schemaやvalidatorのテスト成功は、実機検証の成功を意味しない。CI、synthetic input、
mock、emulatorだけではTier B、C、D、S3を`VERIFIED`へ変更できない。

初期状態はすべて`NOT_VERIFIED`である。実機、必要なtoolchain、同意、安全手順、
private storageが揃い、対象Tierの物理計測を完了するまで、この状態を維持する。

## 追跡単位

| Tier | 実測内容 | Issue | 現在値 |
|---|---|---:|---|
| B | Verity Sense PPG+ACCの30分取得とK1入力 | #39 | `NOT_VERIFIED` |
| C | Android hardware attestationとproduction lease | #37 | `NOT_VERIFIED` |
| D | live PPGから実機Menfugu actionまで | #40 | `NOT_VERIFIED` |
| S3 | physical optical spoofの安全試験 | #41 | `NOT_VERIFIED` |

親追跡Issueは#19、artifact契約の実装Issueは#38である。

## 状態機械

| 現在値 | 次状態 | 条件 |
|---|---|---|
| `NOT_VERIFIED` | `VERIFIED` | 全preflightとTier別実測を満たす物理計測だけ |
| `NOT_VERIFIED` | `FAILED` | 物理計測を実施し、判定条件を満たさなかった場合 |
| `NOT_VERIFIED` | `NOT_VERIFIED` | 未実施、準備中、CIで契約だけを検査した場合 |
| `VERIFIED` | `VERIFIED` | 同一artifactの再検証だけ |
| `FAILED` | `FAILED` | 同一artifactの再検証だけ |

再試験は既存artifactを書き換えず、新しい`public_run_id`で作る。CI由来の証拠は
`NOT_VERIFIED`だけを生成できる。`VERIFIED`と`FAILED`は
`PHYSICAL_MEASUREMENT`由来に限定する。

## Preflight

実測前に次の全項目を確認する。

- 対象機材が利用可能である
- 固定したtoolchainが再現できる
- 必要な同意が記録されている
- 安全手順が承認されている
- private evidenceを保存する暗号化領域がある
- 中止条件が事前に記録されている

S3では人体への危険な刺激を禁止し、安全なfixtureと承認済みscenarioだけを使う。
中止条件に達した場合は計測を止め、未完了のTierを`VERIFIED`にしない。

## 公開境界

公開artifactは集約値とboolean判定だけを持つ。`private_field_count`は常に`0`である。
raw PPG、raw ACC、baseline、participant/device identifier、attestation chain、証明書、
署名、lease/token bytes、鍵、同意文書はprivate evidence bundleだけに保存する。

private bundleの内容は公開しない。実測が成立した場合に限り、そのbundleのSHA-256
commitmentを`measurement_bundle_sha256`へ記録する。公開用`public_run_id`はparticipant、
device、日時を復元できない無関係なlabelとする。

validatorはroot、preflight、Tier別measurementをallowlistで制限する。既知のprivate keyは
入れ子でも拒否する。この制約は未知の値が安全だと自動証明するものではないため、公開前に
人手でもdata minimizationを確認する。

## Tier別の成立条件

Tier Bは55 Hz PPGと52 Hz ACCを30分以上取得し、SDK/firmware、gap、rollback、window、
quality、latency、memory、CPU、batteryを記録する。live PPGがK1判定へ到達することも必要である。

Tier Cはfresh challenge、attestation chain検証結果、hardware security level、verified boot、
device lock、app identity、revocation、production leaseを確認する。stale challenge、replay、
downgrade、wrong appはすべて拒否されなければならない。chain本体は公開しない。

Tier Dはlive PPG、EvidencePermit、production lease、ATv2、APLOTを通過し、実機Menfuguで
許可actionをちょうど1回だけ実行する。replayは拒否し、未許可action数は0とする。

S3は承認済みの安全試験だけを行い、false permitとfalse actionがともに0であることを確認する。
このprotocolは安全性審査や倫理審査の代替ではない。

## 契約のローカル検査

初期artifactは実測結果ではなく、`NOT_VERIFIED`状態のtemplateである。

```powershell
$env:PYTHONPATH = "src"
python tools/validate_k5_hardware_evidence.py init `
  --tier B `
  --output artifacts/k5-hardware/tier-b.json `
  --public-run-id local-b
python tools/validate_k5_hardware_evidence.py validate `
  --input artifacts/k5-hardware/tier-b.json
python -m pytest tests/test_k5_hardware_evidence.py
```

Linuxでは同じ引数を`\`で継続するか、1行で実行する。生成物は`artifacts/`以下へ置き、
Gitへcommitしない。schemaは`schemas/k5_hardware_evidence_public.schema.json`、機械可読な
protocolは`configs/k5/hardware_protocol.yaml`に固定する。

## CIで保証できる範囲

専用CIはvalidator、状態遷移、allowlist、private field拒否、Tier別必須指標を検査する。
CIが作る4つのtemplateはすべて`NOT_VERIFIED`のままであり、生成物がGit対象にならないことも
確認する。CIはBluetooth接続、sensor firmware、Android hardware root of trust、
実機Menfugu、物理spoof、安全性を検証しない。
