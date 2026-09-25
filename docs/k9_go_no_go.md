# K9 QuotientLimit Go / Pivot / Kill

このgateは、研究結果を見てから基準を変更しないための非補償型判定契約である。優先順位は`KILL > PIVOT > GO`であり、1件のKILL条件を他の成功で相殺できない。

## 判定境界

- `GO`: 13個のGO条件がすべてdigest付き証拠で成立し、PIVOT/KILL条件が成立しない。
- `PIVOT`: GO証拠の欠測、KILL条件の未確認、または10個のPIVOT兆候のいずれかがある。
- `KILL`: 13個の致命条件のいずれかが成立する。
- software-only評価であり、Polar Verity Sense hardwareは`NOT_VERIFIED`のままとする。
- 判定reportは証明ではない。primal、dual、Farkas等の独立certificateを参照する索引である。

## 再現手順

生成物は`artifacts/k9_quotient_limit/replication/`へ出し、Gitへcommitしない。

```bash
python tools/validate_quotient_limit_package.py manifest --commit <FULL_GIT_SHA> --out artifacts/k9_quotient_limit/replication/manifest.json
python tools/validate_quotient_limit_package.py blank-evidence --out artifacts/k9_quotient_limit/replication/evidence.json
python tools/validate_quotient_limit_package.py decide --evidence artifacts/k9_quotient_limit/replication/evidence.json --manifest-sha256 <MANIFEST_SHA256> --out artifacts/k9_quotient_limit/replication/decision.json
```

`blank-evidence`は意図的に`PIVOT`となる。各観測を外部artifactのSHA-256へ結び付けた後だけ`GO`が可能になる。private biosignal、baseline、subject ID、stable identifier、secret keyはpackageへ含めない。
