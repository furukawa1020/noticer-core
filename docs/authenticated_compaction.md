# 認証付きcompaction

`authenticated_compaction`は、監査完了済みtransactionだけを削除し、未完了のrelease状態を認証済みsnapshotへ正規化する。

- `PENDING`と`DELIVERED`は必ず保持する。
- `DELIVERED`に対応するsealed receiptが欠けていればfail closedとする。
- checkpointは世代、前checkpoint、変換前digest、保持後digest、件数をHMACで束縛する。
- verifierは外部から渡されたminimum generationより古いimageをrollbackとして拒否する。
- store契約はcandidateをdurable stagingした後にactive generationをatomicに切り替える。
- 起動時は未commitのstagingだけを破棄し、最後のactive imageを再検証する。

checkpointは秘密のbiosignalを保存しない。rollback floorの永続化と鍵rotationは別の信頼境界として扱う。
