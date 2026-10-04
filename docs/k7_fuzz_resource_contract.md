# K7 Fuzz Resource Contract

K7-15aはDSL、canonical IR、CAQT、codegen manifest、SMT-LIB、QDIMACSの全fuzz targetが共有する事前resource gateを固定する。

各targetはparserや大規模allocationへ入る前に、input bytes、depth、integer bits、collection items、state-productを`quotient-seal-fuzz`の`preflight`へ渡す。上限超過と積overflowは安定したfailure categoryで拒否する。

run reportはcontract digest、target、seed、runtime、execution数、coverage proxy、statusを保持する。timeout、failure、checker disagreementを`COMPLETED`へ変換することは禁止する。生成reportとcrash artifactはGitへcommitしない。
