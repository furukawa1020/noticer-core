# K7 Logical Transport Cost

K7-14aはruntime eventをplatform非依存のlogical costへ写像する。security、utility、unauthorized action、deadline遵守はhard gateであり、costへ合算しない。

閉じたevent集合は`frame`、`delivery`、`retry`、`reconnect`、`radio_on`、`state_count`である。出力は既存QuotientForge `CostVector`の8軸を維持し、校正用の送信bytesを独立軸として追加する。latency平均は`1_000_000`倍の整数で記録する。

未知event、fieldの多重解釈、時系列逆行、radio slot重複、state countの欠落・重複、u32/u64 overflowはfail-closedとなる。artifactはevent traceのSHA-256と固定単位を含むcanonical JSONであり、platform profileやenergy推定は含まない。
