# Menfugu公開実行semanticsとK7 binding v1

## 位置づけ

本仕様は、Menfugu public execution plannerをQuotient-Sealed Module（QSM）へ統合する前段として、compile対象となる公開source machineとK7成果物のbindingを固定する。対象profileは`P0_PUBLIC_QUOTIENT_ONLY`だけであり、P1 sealed admissionは後続Issueで扱う。

これはAETPをNoticer release stackへ貫通させるための候補設計である。世界初を断定するものではない。実機検証状態は`NOT_VERIFIED`である。

## 公開source machine

source machineは次の4状態を持つ。

| State | 意味 |
|---|---|
| `READY` | 新しい正規actionを受理できる |
| `EXECUTING` | 1回のactionを実行中である |
| `COOLDOWN` | 公開cooldown中である |
| `FAIL_CLOSED` | trusted resetまたはhandoffまでactionを禁止する |

14入力との直積56遷移をcanonical順序で保持する。欠落、並べ替え、追加、書換えはsource digest検証で拒否する。これによりsource semanticsは全域かつ決定的になる。

## Exactly-once規則

`READY + AUTHORIZED_ACTION`だけが`EXECUTE_ONCE`を出力する。`EXECUTING`、`COOLDOWN`、`FAIL_CLOSED`での追加authorizationはactionを実行しない。replay、expiry、wrong service、wrong policy、wrong key、transport duplicateもactionを実行しない。

拒否理由はsource入力として試験できるが、外部出力ではすべて`REJECT`へ畳む。したがって攻撃者は拒否traceから、replay状態やbinding不一致の種類を区別できない。

`DEADLINE`、`RESET`、`HANDOFF`は実行中なら停止を伴う。`FAULT`後は`FAIL_CLOSED`となり、trusted resetまたはhandoffまでactionを出力しない。

## 公開policy binding

K7 packageは次の公開値を1つの`public_policy_digest`へcommitする。

- service alias
- epoch
- policy hash
- verifier key ID
- 許可action（`MenfuguInflateSoft`のみ）
- pump上限、cooldown、公開execution slot
- 公開deadline

同じ値から既存`noticer-menfugu-core::ExecutionPolicy`を生成する。無効なpump時間、slot設定、action、deadlineはcompile前にfail closedとなる。

## K7とmanifestのbinding

Menfugu module entryは次の値を独立に照合する。

| Binding | 検査 |
|---|---|
| module | `MenfuguExecutionPlanner`である |
| profile | `P0PublicQuotientOnly`である |
| public identity | service、epoch、policyが一致する |
| source | canonical source digestが一致する |
| K7 | certificateとgenerated runtime digestが一致する |
| QSM | capsuleとobserver registry digestが一致する |
| P1 | resource evidenceが存在しない |

一部成果物だけを差し替えたmanifestは受理しない。certificateの意味検証と実際のQSM code generationは後続K8-13f2で実装する。

## Privacy boundary

このmoduleの公開型、config、canonical bytesには以下を含めない。

- token ID、token ciphertext、署名本文
- replay集合、replay counter、consumption cursor
- raw PPGその他のraw biosignal
- private baseline、K1 raw feature、private evidence

replay判定はshared verifier coreの責務であり、plannerには`REPLAY_REJECTED`という値なしの結果だけが渡る。action実行に必要なprivate token materialをQSMへ複製しない。

## 検証境界

自動テストはcanonical totality、exactly-once、拒否のzero-action、reset/handoff/deadline/fault、既存executor policyへの写像、source/K7/manifest tamper拒否を確認する。物理pump、BLE、Polar Verity Senseとの接続は本仕様の検証対象外であり、`NOT_VERIFIED`を維持する。
