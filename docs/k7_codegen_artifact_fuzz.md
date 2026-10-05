# K7-15f codegen manifest / artifact validator fuzz

生成済みpackageを再利用する前に、固定21-field manifest、domain-separated manifest digest、7 artifactのexact allowlist、safe relative path、重複・欠落・余剰、個別/総byte上限を同時に検証する。

path traversal、backslash、digest substitution、target/profile固定値差、unknown field、CRLF・trailing data、manifest artifact差はfail closedになる。generated artifact自体はtest時にmemory fixtureとして作り、Gitへcommitしない。これはvalidator smoke testであり、生成runtimeの科学的評価結果ではない。
