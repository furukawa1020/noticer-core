# Menfugu exactly-once adversarial matrix v1

## 目的

Issue #200では、Menfugu public execution plannerのexactly-once性を、固定seedから再計算できるcanonical adversarial matrixとして定義する。単発の成功例ではなく、authorization、cover、拒否、lifecycle、deadline、resource境界を同じartifact契約で比較する。

本matrixは提案中のsecurity notionを検証するものであり、world-firstを断定しない。物理pump、BLE、Polar Verity Senseの実機状態は`NOT_VERIFIED`である。

## Case空間

13 scenarioと2 profileの直積26ケースを必須とする。

| Axis | Cases |
|---|---|
| semantics | valid action、cover、replay、expiry、wrong service、wrong policy、wrong key、duplicate |
| lifecycle | reset、handoff、deadline |
| resource | fuel boundary、host-call boundary |
| profile | P0 Public Quotient Only、P1 Sealed Admission |

case IDはseed、source、transition、module、capsule、profile、scenario、public sequence digestへcommitする。順序、欠落、重複、別buildへの差替えはmatrix validationで拒否する。

## Typed action classification

- valid actionはaction countがちょうど1である
- coverはframeを維持しつつaction countが0である
- replay、expiry、wrong service/policy/keyはaction count 0かつ同じpublic rejectionである
- duplicate caseは最初の正規action 1回だけを許し、duplicateを追加実行しない
- resetとhandoffはactionを生成しない
- deadlineは正規action後に追加actionを生成せず停止stateへ進む

各P0 semantic caseはsource referenceと3 engineが`MATCH`したうえで、action、frame、failure数をtraceから再集計する。

## Resourceとprofileの分離

fuelまたはhost-call上限に到達したケースは`UNRESOLVED`であり、semantic successへ数えない。

Menfugu用P1 sealed-admission resource witnessは未実装である。P1の13ケースはcase ID空間から削除せず、実行artifactを持たない`PROFILE_UNRESOLVED`として保存する。P1をP0へ暗黙downgradeして結果を流用することは禁止する。

## Privacy boundary

matrixが保持するのは公開command、resource limit、digest、observable countだけである。token ID、ciphertext、replay集合、raw biosignal、private baseline、private evidenceはcase ID、sequence、JSONへ入れない。

## 後続

本Issueはcanonical matrixとfull recomputationを固定する。実行由来target-only差分の最小化とcounterexample bundleはIssue #201で扱う。実機検証は別作業であり、現時点では`NOT_VERIFIED`である。
