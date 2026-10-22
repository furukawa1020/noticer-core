# Privacy-safe recovery witness

復旧判断を第三者検証可能にしつつ、biosignal、subject ID、transaction ID、raw receipt payloadをartifactへ出さない。

- 各entryはordinal、public binding digest、入力state、action、結果だけを持つ。
- entryは前authenticatorを含むHMAC chainで、改ざんと並べ替えを検出する。
- batch summaryは件数、成功/failed-closed件数、chain headを別domainのHMACで認証する。
- canonical JSONはbatch summaryだけを固定順序で出力する。

public binding digestの生成元にprivate evidenceを含めないことは呼び出し側の責務であり、このmoduleはzero digestを拒否する。
