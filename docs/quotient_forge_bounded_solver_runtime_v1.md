# QuotientForge Bounded Solver Runtime v1

## 目的

外部solverをshell commandとして実行せず、K7-04aのmatrixから導出したprogram pathと固定argvだけで起動する。process、stdin、stdout、stderr、wall-clockを有界化し、solverの停止や巨大出力が評価harness全体を停止させない。

## 実行境界

- `std::process::Command`へprogramとargvを分離して渡す
- shell、command文字列結合、PATH fallbackを使わない
- stdin既定上限は16 MiB
- stdout/stderr既定上限は各1 MiB
- version probe既定timeoutは2秒
- solve timeoutは呼出側が明示する
- poll intervalは5 ms

上限値自体にも安全ceilingを設ける。0、24時間超timeout、64 MiB超stdin、16 MiB超stdout/stderr、1秒超poll intervalを拒否する。

## Pipe drain

stdoutとstderrを独立threadで同時にdrainする。保持bufferは上限までとし、超過後のbyteは保存しない。親threadは超過flag、timeout、process終了を監視し、超過またはtimeout時にchildをkillしてwaitする。これによりpipe飽和によるwait deadlockを避ける。

## 型付き結果

- `Completed`: bounded UTF-8 stdout/stderrとexit success
- `TimedOut`: wall-clock超過後にkill/reap済み
- `OutputLimitExceeded`: stdout/stderrを区別
- `InputLimitExceeded`: spawn前に拒否
- `NonUtf8Output`: streamを区別
- `NotFound` / `Io` / `InvalidLimits`: process boundary error

solverの`UNKNOWN`など意味上の分類はK7-04cで実装する。本runtimeはprocess transport上の状態を勝手にSAT/UNSATへ変換しない。

## Trust boundary

matrix SHA-256とasset SHA-256をruntime bindingへ保持するが、これはsolver soundnessを保証しない。SAT候補の独立checker再検査は既存backendから外さない。実binary downloadとarchive hash照合はoptional CIを含む後続Issueで行う。
