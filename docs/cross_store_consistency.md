# Cross-store整合性certificate

起動時にoutbox、sealed receipt vault、audit logの状態積を検証し、到達不能状態をrelease処理前に拒否する。

| Outbox | Vault | Audit | 判定 |
|---|---:|---:|---|
| `PENDING` | なし/あり | なし | 到達可能 |
| `DELIVERED` | あり | なし/あり | 到達可能 |
| `AUDITED` | あり | あり | 到達可能 |

その他の組合せ、孤立record、重複transaction、intentとreceiptのbinding不一致はtransaction ID付きの反例として拒否する。certificateはtransaction ID順へ正規化した状態digestと件数をHMACで束縛する。
