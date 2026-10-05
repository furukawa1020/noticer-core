# K7-15d CAQT binary bounded fuzz

CAQT binary decoderへarbitrary bytesと、原文、空入力、truncation、seed固定bit flip、trailing byte、oversized length相当の6 mutationを投入する再現可能なsmoke fuzz harnessである。

case数、入力byte数、certificate byte数、record数、payload長、action数はdecode前または既存decoder内で制限される。accepted入力は再encode・再decodeの安定性を検査し、非canonical acceptanceとunstable round-tripを成功へ丸めない。panicはtest failureとして扱う。これはparser堅牢性のsmoke testであり、科学的な攻撃評価結果ではない。
