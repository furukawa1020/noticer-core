# Recovery backlog admission controller

未完了recovery backlogが安全上限を超えた場合、新規releaseをfail closedで停止する。

- `weighted_backlog = pending * pending_weight + delivered * delivered_weight`をsaturating arithmeticで計算する。
- high watermarkを超えると`Halted`へ移行する。
- backlogがlow watermark以下になるまで再開しない。
- policyはepoch、weight、high/low watermarkをHMACで束縛する。
- runtime snapshotもpolicy authenticatorと状態をHMACで束縛し、restart後の状態緩和を防ぐ。

controllerは新規releaseのadmissionだけを拒否し、backlogを減らすrecovery workerは停止しない。
