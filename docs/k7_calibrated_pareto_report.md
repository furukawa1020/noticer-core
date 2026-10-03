# K7 Calibrated Pareto Report

K7-14fはhard gate通過候補のlogical Pareto frontierを生成し、logical costとplatform measurement intervalを別表で保存する。欠測候補は削除せず`missing_measurement_ids`へ残す。

判定は核心gate失敗を`KILL`、校正・監査・独立再現の不足を`PIVOT`、全evidence gate通過だけを`GO`とする。CI greenはdecision evidenceではなく、reportもsecurity proofではない。

frontierに複数候補があればすべて保持する。単一候補または空でないfrontierという事実を、優越性やhardware energyの証明へ読み替えない。
