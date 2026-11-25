# PoPETs: 受信者結託下の有限回復機構と強い手書き対照

## 比較したもの

同じ二つの許可済み行動、同じ期限、同じ公開入力で、手書き機構を
QuotientForgeの有限合成機構と比較する。対照は期限まで意図的に待つ方式ではなく、
最初の利用可能枠で二つの正規化済み通知を送信し、送信済みなら再送しない方式。
初回が利用不可なら最後の枠で回復できると仮定する。最終枠の継続障害、ACK、
送信後の損失、実ネットワークによる再接続はこのモデルの外にある。

Rustの実際の `optimize_cost` を用い、候補の表と `lower_candidate` による
チェッカーモデルを別々に出力する。観測面は二つの受信者が読める行動・論理時刻と
B宛ての診断欄に限定する。許可行動を持つ私的履歴のペアと、許可行動のない
負の認可対照のペアを検査する。

独立したPythonオラクルとRustのJSONチェッカーでモデル判定を比べる。
その後、機械の表と入力列を別に解釈し、二つのローカルソケットへ
長さ付きJSONを送信する。受信側で組み立てた順序付きログをチェッカー対象の
モデル射影と照合する。これはローカル実行の照合であって、実機・本番通信への
形式的なリファインメント証明ではない。

## 今回の結果

| 方式 | 状態数 | 結託ビューが一致した動作ペア | 期限内に一度だけ届いた行動 | 平均アプリバイト/動作ケース | 平均受信スロット |
|---|---:|---:|---:|---:|---:|
| 手書きの正規化回復 | 2 | 2/2 | 8/8 | 98 | 0.5 |
| QuotientForge合成 | 1 | 2/2 | 8/8 | 98 | 1.0 |
| 故意に診断欄を変えた合成対照 | 2 | 1/2 | 8/8 | 105 | 0.5 |

全方式でローカル受信ログは対象のモデル射影と一致し、認可されていない
空ケースでの通知はなかった。バイト数は長さ部を含むローカルアプリフレームで、
ネットワーク全体のバイト数ではない。時刻は到着タイムスタンプではなく論理スロット。

合成器は当該条件で候補256件を生成し、65回チェッカーを呼んだ。
この目的は状態数等の辞書順で、遅延最小化ではない。合成は1状態で済んだが、
手書きの方が平均遅延が短かった。プライバシーまたは通信量の優位は示していない。

両チェッカーが正常な二方式に `verified`、故意の欠陥対照に
`counterexample` を返した。最短反例はスロット0の `loss` からスロット1の
`available` へ進み、左 `p1:m0` と右 `p3:m0` で `receipt-b` が分岐する。
この対照は第三者実装に発見した脆弱性ではない。

## 再現

リポジトリのルートから実行する。出力先は新しいディレクトリを指定する。

```sh
mkdir -p artifacts/checked-recovery-example
cargo run --locked -p quotient-forge-cli --bin compare-recovery \
  > artifacts/checked-recovery-example/native.json
cargo build --locked -p quotient-forge-check --bin aqrs-check-json
PYTHONPATH=src python tools/run_popets_checked_recovery.py \
  artifacts/checked-recovery-example/native.json \
  target/debug/aqrs-check-json artifacts/checked-recovery-example
```

Windowsでは既存のGNUツールチェーンを使い、Cargoに
`+stable-x86_64-pc-windows-gnu` を指定して実行した。
PowerShellでは `PYTHONPATH` を `$env:PYTHONPATH = 'src'` で設定し、
チェッカーのパスには `.exe` を付ける。
