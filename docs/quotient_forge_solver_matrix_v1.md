# QuotientForge Pinned Solver Matrix v1

## 目的

外部SMT solverをPATH上の暗黙依存ではなく、version、公式release、platform asset、SHA-256、実行file相対path、固定argvを持つ再現可能な候補生成器として扱う。

v1は次を固定する。

| Solver | Version | Platform |
|---|---:|---|
| cvc5 | 1.3.4 | Linux x86_64 static / Windows x86_64 static |
| z3 | 4.16.0 | Linux x86_64 glibc 2.39 / Windows x86_64 |

asset URLとSHA-256は各projectの公式GitHub Releaseに公開された値を使用する。matrix loaderはrelease repository、tag、asset名、URLの対応を検証し、redirect先や任意mirrorをpinned artifactとして受理しない。

## Trust boundary

`CANDIDATE_GENERATOR_NOT_SECURITY_ORACLE`を固定する。hash一致は取得byteの同一性だけを示し、solverのsoundnessや完全性を証明しない。SAT候補は後続runtimeから既存の独立checkerへ戻す。UNSATは有限bound内の結果としてのみ扱う。

## Network boundary

`DOWNLOAD_ONLY_WITH_SHA256`は、network accessをsolver取得段階に限定し、実行前にasset SHA-256を照合する契約である。本Issueはdownload処理を実装せず、通常CIもnetwork上のsolverへ依存させない。

## Canonical digest

Rust loaderは未知field、1 MiB超過、solver/platform重複、platform欠落、非公式URL、不正hash、path escape、shell-bearing argvを拒否する。検証済みtyped structureをfield順でJSON化し、SHA-256をmatrix identityとする。入力JSONの空白やobject key順はidentityへ影響しない。

## 対象外

- solver binaryのdownloadと展開
- capability probeの実行
- process timeoutとI/O上限
- solver結果artifact
- solver soundness proof

これらはK7-04b以降で、独立PRとして追加する。
