# K7-15e SMT-LIB / QDIMACS model differential fuzz

外部solver出力を信頼せず、SMT-LIB modelとQDIMACS assignmentを独立decoderで同じ変数mapへ復元し、statusと値が一致した場合だけ`AGREE`とする。片側reject、duplicate/conflicting assignment、partial model、status差は`DISAGREEMENT`または共通rejectとして保持する。

両decoderは入力byte数、token数、atom長、nest深さ、期待変数数をparse前またはparse中に制限する。既存`parse_solver_output`は互換性を維持し、default bound付き実装へ委譲する。これはsolver model parserのsmoke testであり、solverの正しさや科学的結果を主張しない。
