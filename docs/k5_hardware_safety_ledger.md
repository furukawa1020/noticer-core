# K5 hardware safety interlock ledger

Tier DのMenfugu actionとTier S3のoptical spoof試験は、実行前にharmless fixture、安全protocol、
承認済みscenario、停止条件commitmentを固定する。S3では危険な光源を明示的に拒否する。

実行eventは`START`から始まるdomain-separated SHA-256 digest chainへ追記する。action、rejection、
incident、operator abort、stopをsequenceとmonotonic timeへ束縛し、改変、順序変更、時刻rollback、
terminal後の追記を拒否する。incidentまたはoperator abort後はactionをfail-closedで禁止する。

公開summaryはaction/incident count、abort状態、ledger head、preflight/private bundle commitmentだけを
含む。fixture内容、biosignal、device identifier、operator identityは公開しない。ledger成功は物理試験の
成功を意味せず、`hardware_status`は常に`NOT_VERIFIED`である。
