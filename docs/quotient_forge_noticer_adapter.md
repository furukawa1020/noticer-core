# QuotientForge Noticer Adapter

## 1. 目的

`quotient-forge-noticer`は、既存Noticer contractとhandwritten implementationをQuotientForge checkerへ接続するpublic-only adapterである。

adapterは既存型を複製しない。次を`noticer-aetp`から直接re-exportする。

- `ActionSemantics`
- `ActionObligation`
- `PublicContext`

`PublicLossTape`は実tree上の所有crateである`noticer-transport-sim`から直接re-exportする。

APLOT、AEPA、ATv2、Menfugu、AETSは既存crateをmodule aliasとしてre-exportする。

## 2. Dependency boundary

adapterのCargo dependencyはpublic release/transport/provenance/token contractとQF checker/certificateだけである。

次へ依存しない。

- `noticer-acquisition-core`
- `noticer-evidence`
- `noticer-evidence-bridge`
- `noticer-ppg-features`
- raw PPG/IBI/ACC sample型

manifest testでこの禁止listを固定する。

## 3. Handwritten benchmark

同一のK6-04 product checkerへ次を接続する。

- `ImmediateRelease`: release presenceがprivate historyへ依存するため反例
- `FixedSizeOnly`: size固定でもpayload identityが異なるため反例
- `CoarseBucket`: private historyに応じたbucket差から反例
- `EvidenceDependentSlot`: slot presenceがprivate evidenceに依存するため反例
- handwritten `AETS`: fixed public slotで左右観測が等しくvalid
- handwritten `APLOT`: 共通`PublicLossTape`に相当するbounded public loss下でvalid

bad planを特別扱いして失敗させない。すべて同じfinite checker modelとobserver projectionで判定する。

## 4. Certified generated plan binding

generated planはCAQT certificateを再検証してからbinding可能になる。

`CertifiedGeneratedPlan`は`VALID` certificate digestだけを保持する。`connect_generated_plan`は次を参照で束ねる。

- existing ATv2 frame plan
- existing Menfugu action window
- existing AEPA requirement

値をcopy、serialize、adapter-owned型へ変換しない。実際のNoticer型はre-exportされた`atv2_protocol`、`atv2_token`、`menfugu`、`aepa` moduleから渡す。

## 5. Assurance interpretation

bindingが保証するのは、接続対象planが`VALID` CAQT digestへ紐づくことと、既存Noticer valuesを参照で保持することだけである。

AEPA requirement自体の成立、ATv2署名、Menfugu実行許可、APLOT deliveryは各既存crateのchecker/verifierが判定する。QF adapterがその判定を代替しない。

## 6. 非保証事項

- hardware timing、BLE radio、OS scheduling
- raw acquisitionからActionSemanticsへのprivate lowering
- generic referenceへ渡された値のdomain correctness
- generated runtimeを変更した後のcertificate対応
- unbounded packet loss

CLI/artifact bundleで実型とcertificateを固定する処理はK6-11で追加する。
