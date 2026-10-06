# K5 Tier B public receipt

Tier B receipt builderは、Polar/Android collectorのprivate metadata logから公開可能な集約値を
決定的に再計算する。frameのsequence、monotonic timestamp、sample countからduration、rate、
gap、rollbackを検査し、window/resource metadataからquality、K1 decision、latency、memory、CPU、
battery dropを集約する。

公開receiptはpreflight digestとprivate bundle SHA-256へ束縛される。firmware version、raw PPG/ACC、
participant/device identifier、frame timestamp列は公開しない。入力schema外のfieldは、出力へ透過
させずfail-closedで拒否する。

`PHYSICAL_MEASUREMENT`入力でもreceipt生成だけではTier Bを昇格しない。出力は常に
`hardware_status = NOT_VERIFIED`であり、物理入力は`READY_FOR_PHYSICAL_REVIEW`、fixtureは
`SOFTWARE_FIXTURE_ONLY`になる。30分実測、同意、安全条件、private evidence review、既存public
artifact validatorをすべて完了した後に限り、別ceremonyでTier B判定を行う。
