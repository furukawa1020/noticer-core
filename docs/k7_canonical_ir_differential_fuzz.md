# K7-15c canonical JSON / IR differential fuzz

canonical IR envelopeをPython標準JSON parserとstrict PyYAML loaderの独立2系統で読み、accept/reject、復元値、canonical再encodeを照合する。disagreementは正常なrejectへ丸めず、独立したfailure categoryとして残す。

envelopeは`schema`、`version`、`kind`、`payload`だけを許可する。duplicate field、未知version/kind、float、非有限値、64-bit範囲外integer、trailing data、非canonical key順、深さ・要素数・byte上限超過をfail closedにする。これはparser smoke testであり科学的な攻撃結果ではない。
