# K5 Tier C attestation verdict bridge

Tier C bridgeは、private appraiserがAndroid key attestation chainを検証した後のbounded verdictを
公開receiptへ変換する。appraiserはfresh challenge、chainとtrusted hardware root、TEE/StrongBox、
Verified boot、device lock、package/signing/version identity、全certificateのrevocation status、
lease key/profile bindingを検査する。stale、replay、downgrade、wrong appも拒否する。

certificate chain、serial、challenge、package name、signing digest、key material、revocation snapshotは
private bundleから公開しない。public receiptはpreflight digestとprivate bundle SHA-256だけへ束縛し、
既存Tier C artifactが要求するboolean verdictとsecurity levelを出力する。

bridgeはchain parserやX.509 verifierではない。暗号検証は端末外のprivate appraiserで行い、bridgeは
verdict間の整合性とdata minimizationをfail-closedで検査する。fixture、emulator、CIは常に
`hardware_status = NOT_VERIFIED`であり、physical verdictも人手review前には昇格しない。

検証項目はAndroid公式のhardware-backed key attestation guidanceに従い、root trustとcertificate
revocation status listの確認を省略しない。
