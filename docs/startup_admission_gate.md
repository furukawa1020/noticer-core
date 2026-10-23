# Startup admission gate

起動時にdurable outboxの`PENDING`と`DELIVERED`を集計し、recovery backlog policyへ入力する。

- `AUDITED`はbacklogへ加算しない。
- high watermark超過時は認証snapshotを保存するがrelease permitを発行しない。
- halted状態はrestart後も維持する。
- recoveryでlow watermark以下になった場合だけ、snapshotに束縛されたpermitを発行する。
- permit検証はpolicy、snapshot、weighted backlogを再検証する。

backlog解消用workerはpermitなしでも動作できるが、新規releaseはpermitを必須とする。
