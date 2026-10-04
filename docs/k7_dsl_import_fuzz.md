# K7-15b DSL / import graph bounded fuzz

AQRS DSLのlexer、parser、import graphを、再現seedと有限resource budgetの下でsmoke fuzzする。これはparserの堅牢性検査であり、科学的な攻撃評価結果ではない。

`run_dsl_import_fuzz`はarbitrary bytesをUTF-8境界を含めて処理し、入力byte数、case数、token数、import数、import深さを実行前に制限する。固定graph suiteは正常な非循環graphに加え、cycle、深さ超過、`..`、絶対path、backslashによるsandbox escapeを毎回検査する。

同じseed、corpus、limitsからは同一の`DslFuzzReport`が得られる。oversized inputはparseせずresource rejectionとして記録し、cycle・depth・path escapeは成功へfallbackしない。panicはtest failureとして扱い、crashを正常なrejectへ変換しない。

共通resource contractとの接続は依存cycleを避けるため値の受け渡しで行う。hard maximumは共通契約以下に固定され、凍結済みworkspace依存とheld-out ledger bindingは変更しない。
