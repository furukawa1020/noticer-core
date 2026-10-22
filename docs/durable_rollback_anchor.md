# Durable rollback検知anchor

`rollback_anchor`はoutbox、sealed receipt vault、audit checkpointのheadを同一generationへHMACで束縛する。

- generationは1から単調増加し、各recordは前recordのauthenticatorを含む。
- 現在generationより古いsnapshotをrollback、未来generationを未承認forkとして拒否する。
- generationが一致しても3 storeのheadが一致しなければcross-store mixとして拒否する。
- `append_and_sync`完了後だけmemory上のheadを進めるため、partial advanceでは直前のanchorが有効なまま残る。
- 起動時は全chainを再認証し、欠落、改ざん、forkをfail closedに扱う。

production backendは`RollbackAnchorStore`の`append_and_sync`をdurable atomic appendとして実装しなければならない。
