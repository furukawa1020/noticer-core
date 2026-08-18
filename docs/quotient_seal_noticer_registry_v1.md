# QuotientSeal Noticer QSM registry v1

## 目的

このregistryはAETS、ATv2 frame planner、APLOT、AEPA、Menfugu public execution plannerをQuotientSealへ接続する公開bindingを凍結する。各moduleのsource machine実装やcertificateを複製せず、既存artifactのdigestを参照する。

## 固定binary schema

manifestは`NQSMREG1` magic、version 1、5件固定のmodule entryからなる。任意文字列、任意field、extension mapは持たない。decodeは長さ、magic、version、module順、reserved bit、profile、digest、P1 evidenceを検証し、再encodeが一致しない入力を拒否する。

各entryは既存の`WireServiceAlias`、`Epoch`、`PolicyHash`、`DeploymentProfile`を直接使用し、source、K7 certificate、generated runtime、QSM capsule、observer registryのdigestをbindする。

## privacy boundary

manifestが保持できるのは公開alias、公開epoch、policy hash、公開artifact digestだけである。raw PPG、private baseline、K1 raw feature、private evidence、sensor identityを表現するfieldは存在しない。固定長末尾へデータを追加した入力も拒否する。

crateはacquisition、evidence、baseline、PPG feature crateへ依存しない。この依存境界はtestで固定する。

## deployment profile

- P0 Public Quotient OnlyではP1 resource evidenceを禁止する。
- P1 Sealed Admissionではresource-equivalence certificate digest、relation binding digest、checked case数を要求する。

P1 evidenceはprivate trace値やそのpairを格納しない。後続module統合は独立checkerが証拠を検証した場合だけP1 bindingを作成できるようにする。

実sensor、実機、hardware-backed key、TEE上の検証は`NOT_VERIFIED`である。優先権や世界初は主張しない。
