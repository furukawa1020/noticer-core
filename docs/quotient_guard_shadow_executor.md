# QuotientGuard counterfactual shadow executor

`quotient-guard-shadow`は、同じrelease machineを複数のaction-equivalent private historyで並行実行する有界`no_std`核である。

公開APIが返す情報は次に限定される。

- 全shadowで同一だった共通public projection
- 比較slotとshadow数
- divergenceの分類

個別private input、個別shadow state、相違したshadow index、private readiness値は返さない。divergence、入力数不一致、step bound超過はterminalとなり、同じexecutorで実行を継続できない。

このcrateはrelation monitorへ入力を供給する実行核であり、単独ではcertificate bindingや最終security verdictを行わない。
