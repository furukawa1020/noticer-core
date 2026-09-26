# QuotientGuard binding capsule

`quotient-guard-binding`は、K9 certificate、generated mechanism、observer projection、runtime configuration、epoch、previous capsuleを`QUOTIENT_GUARD_BINDING_V1` domainでSHA-256結合する`no_std` crateである。

検証は次を個別に拒否する。

- capsule内容とcapsule digestの不一致
- certificate、mechanism、observer、runtime configurationの差し替え
- minimum epoch未満へのrollback
- previous capsule chainのsplice
- zero component digest

previous capsuleだけはgenesisでzeroを許可する。component digestのzeroは未設定値として常に拒否する。binding acceptanceはcertificate自体の意味論的妥当性を代替せず、先にK9 exact checkerで検証されていることを要求する。
