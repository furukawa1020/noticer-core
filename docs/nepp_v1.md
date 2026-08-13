# NEPP-v1 Provenance Evidence Profile

## Status

NEPP-v1はNoticer Core用のEAT-inspired application profileである。汎用EAT実装、RATS architecture全体、またはhardware attestationそのものではない。

reference attesterはCIとTier A再現用のP-256 software keyを使う。署名が検証できても、Collector Key Assuranceは`Software`を超えない。

## Canonical wire format

NEPP-v1は固定384 bytesである。

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | profile ID `NEPP` |
| 4 | 1 | version `1` |
| 5 | 3 | flags/reserved、全て0 |
| 8 | 8 | epoch、big endian |
| 16 | 8 | created public slot |
| 24 | 8 | expires public slot |
| 32 | 32 | verifier challenge |
| 64 | 16 | pairwise service alias |
| 80 | 32 | public pipeline measurement hash |
| 112 | 32 | Assurance Profile digest |
| 144 | 32 | collector signing key ID |
| 176 | 32 | collector session public-key hash |
| 208 | 8 | ATv2 issuer key ID |
| 216 | 32 | ATv2 issuer public-key hash |
| 248 | 32 | policy hash |
| 280 | 32 | verifier-only claims digest |
| 312 | 8 | reserved、全て0 |
| 320 | 64 | fixed-width P-256 ECDSA signature |

flagsまたはreservedが非0、profile/versionが未知、必須bindingが全0、lifetimeが逆転したencodingは拒否する。署名messageはdomain separatorと320-byte bodyの連結である。

## Fresh verifier challenge

verifierは32-byte challengeを事前発行し、public slot expiryとともにbounded `ChallengeStore`へ保持する。NEPP検証成功時にchallengeを単回消費する。

- evidence内challengeと期待challengeが違えば拒否
- 未発行challengeは拒否
- challenge expiry後は拒否
- 一度成功したchallengeのreplayは拒否
- evidence自身のcreated/expires slot外でも拒否

challengeはbiosignal時刻ではなくpublic verifier slotへ結合する。

## Bound semantics

署名は少なくとも次を同時にbindする。

- verifier challenge
- pairwise service alias
- epoch
- public pipeline measurement
- claimed Assurance Profile digest
- collector key IDとsession public key
- ATv2 issuer key IDとpublic-key hash
- policy hash
- creation/expiry public slot
- verifier-only claims container digest

これにより、別service、別epoch、別pipeline、別ATv2 issuer key、別policyへのevidence転用を検証時に拒否できる。

## Verifier-only claims

boot report、app certificate、platform attestation response等は固定NEPP bodyへ直接載せず、canonical private containerのdigestだけをbindする。containerは非Serialize、redacted Debug、drop時上書きで扱う。

後続appraiserはcontainer本体をverifier-only入力として検査し、digest一致後にAssurance Profileを導出する。自己申告digestだけで強いassuranceへ格上げしない。

## Private-field exclusion

NEPP-v1は次を含まない。

- raw PPG / ACC
- private feature values
- exact biosignal timing
- personal baseline values
- K1 p-valueまたはe-process state
- `EvidencePermit`
- private action history

NEPPは取得・実行provenanceのevidenceであり、biosignal内容のproofではない。

## Cryptographic nonclaims

- software reference keyはTEE/StrongBox-backedではない
- P-256署名だけでboot stateを証明しない
- paired commercial sensorはsensor-signed sourceではない
- pipeline hashはruntime proof of executionではない
- NEPP validityだけでproduction ATv2発行を許可しない。appraisalとNPL1 leaseが別途必要である
