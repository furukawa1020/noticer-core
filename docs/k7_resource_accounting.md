# K7 cross-platform resource accounting v1

## 目的

K7-09bは、scalability runのwall time、user CPU time、system CPU time、peak RSSを同じ単位とartifact形状で記録するdirect-child samplerである。これはbenchmark結果ではなく計測機構であり、hardware statusや12x8x64達成を主張しない。

## OS境界

- Linuxでは`/proc/<pid>/stat`と`/proc/<pid>/status`を読む
- Windowsでは`GetProcessTimes`と`GetProcessMemoryInfo`を使う
- wall timeとCPU timeはnanoseconds、peak RSSはbytesで保存する
- OSが値を提供しない場合は推測せず`NOT_AVAILABLE`を保存する
- samplerが追跡するのは起動済みdirect childだけで、descendant processは合算しない

計測中の読取り失敗はrunそのものを成功や失敗へ分類しない。利用可能だったcounterだけを単調に保持し、wall timeとprocess exitを別に記録する。timeout時はdirect childをkillして`timed_out: true`とする。

## Privacyと再現性

artifactにはPID、hostname、username、実行command、payload、biosignal、subject IDを含めない。case IDだけで凍結済みscalability caseへ結合する。JSONはcanonical順序でidempotentに書き、既存内容と異なる上書きを拒否する。

schemaは`schemas/k7_resource_accounting_v1.schema.json`である。generated artifactは`artifacts/`以下へ置き、Gitへcommitしない。

## 非主張

短時間processのpeak RSSはpolling granularityに依存する。direct childがさらにprocessを作るbackendでは全treeの消費量ではない。計測値の比較には同一protocol、warmup、反復、実行順、環境manifestが必要であり、それらは後続Issueで固定する。
