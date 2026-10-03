# K7 Transport Cost Simulator

K7-14cは公開request、公開network availability、固定config、整数seedからbounded transport eventを生成するCPU-only simulatorである。出力eventはK7-14aで再集計され、config、入力、platform profileの各digestとともにcanonical artifactへ保存される。

availability低下中のpending requestはretry、復帰はreconnect、送信slotはradio-onとして記録する。idle cover frameだけが固定seedの整数PRNGに依存する。

未配信request、event上限超過、不正request順序はsuccessへ変換しない。生成artifactは`artifacts/`へ出力する対象でありGitへcommitしない。
