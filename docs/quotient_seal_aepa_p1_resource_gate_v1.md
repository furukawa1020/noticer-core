# AEPA P1 Resource Trace Equality Gate v1

## 目的

この文書はIssue #190で固定するP1 Sealed Admission gateを定義する。P1はprivate resource trace equalityをstrict checkerで再計算し、同じcasesからfresh revalidation handleを得た場合だけ受理する。

P0 Public Quotient OnlyとP1 Sealed Admissionは別profileである。P0 manifestやP0 authorizationをwitnessの存在だけでP1へupgradeしてはならない。P1 manifest、P1 resource evidence、fresh revalidationの三つが揃わない場合はfail closedとする。

## Strict equalityのみ

既存QuotientSeal resource checkerの6軸、opcode、branch、memory address、import、fuel、memory pagesを利用する。受理できるverdictはStrictだけである。

Normalized、Counterexample、InconclusiveはP1成功ではない。QuotientPadやその他のresource normalizationをこのgate内部で生成または受理しない。

## Opaque witness

private resource casesはtrusted checkerとrevalidatorの入力にだけ使う。witness artifactへresource event、axis value、raw trace、private appraisal、biosignal、baseline、lease bytes、nonceを保存しない。

代わりに、pairwise service aliasとepochをdomain separationへ含むopaque case commitmentを保存する。このcommitmentは同じprivate casesを再計算したことを照合するためのものであり、resource値そのものではない。manifestへはwitness digest、relation binding digest、checked case countだけを公開する。

witnessはsource、36遷移、K7 certificate、generated runtime、module、target IR、ABI、capsule、service、policy、epoch、lease verifier、pipeline、assurance、ATv2 issuer、public admission windowへ束縛する。

## Fresh revalidation

最初のstrict checkだけではP1 authorization capabilityを得られない。受理直前に同じrelation、context、private cases、limitsからwitnessを再計算し、byte-identicalな場合だけsealed revalidation handleを生成する。

public stepがwitness validity window外ならstaleとして拒否する。source、policy、service、epoch、lease、pipeline、relation、capsule、manifest evidenceのいずれかが異なる場合も拒否する。

## 非主張

このgateが検証するのはsoftware上のstrict resource equalityとartifact bindingである。実端末、Polar、Android attestation、hardware-backed key、実CPU・radioのresource equalityはNOT_VERIFIEDである。

この成果物はcandidate P1 gateであり、文献・特許上の優先権またはworld-firstを主張しない。
