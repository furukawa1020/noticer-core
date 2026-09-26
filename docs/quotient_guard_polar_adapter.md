# QuotientGuard Polar/replay privacy boundary

Polar live observed streamとsynthetic replayを同じprivate event schemaへ正規化する。live接続はsensor authenticityを意味せず、hardware statusは常に`NOT_VERIFIED`である。

raw samples、session nonce、device timestamp、source sequenceはprivate型に保持し、Debugではredactし、Drop時にzero化する。公開receiptはruntime epoch、session-local ordinal、stream class、保守的source assuranceだけを含む。

stable identifier、device ID、participant IDを入力するfield自体を提供しない。生成artifactへraw biosignalを出力するAPIも提供しない。
