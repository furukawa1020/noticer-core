# QuotientGuard fault state machine

9種のruntime faultを有界状態機械で処理する。bounded missing、delay、reorderは`NO_RELEASE` holdまたは継続とし、bound超過、duplicate、resource exhaustion、rollback、unknown faultはsticky fail-closed sinkへ送る。

disconnect後の復帰には次の全条件を要求する。

- 新しいcapsuleが検証済み
- runtime epochが単調増加
- explicit public reset

復帰時は旧sequenceとmissing counterを破棄する。sink遷移後の自動復帰はない。
