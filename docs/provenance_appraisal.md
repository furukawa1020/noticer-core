# Provenance Appraisal and Android Adapter

## Verification order

`noticer-provenance-verifier`は次の順序でNEPP-v1をappraiseする。

1. collector key endorsementとrevocationを確認する
2. pipeline、policy、ATv2 issuer keyをreference valueと照合する
3. NEPP canonical encoding、P-256署名、challenge、service、epoch、key bindingを検証する
4. challengeを単回消費する
5. verifier-only claims container digestを照合する
6. source recordとplatform recordからAssurance Profileを保守的に導出する
7. 導出profile digestと署名済みdigestを照合する
8. 各保証軸がminimum policyを満たすか確認する
9. 成功時だけopaque `AppraisedProvenance`を返す

raw `AssuranceProfile`は記述値でありauthority tokenではない。NPL1発行は公開constructorを持たない`AppraisedProvenance`だけを入力にする。

## Android certificate record adapter

Tier Aの公開adapterはAndroid certificate extensionから次のreported値を受け取れる。

- requested security level
- reported key security level
- reported verified boot state
- reported device locked state
- app signing certificate SHA-256

しかし、certificate chain、Google root、revocation、challenge、application identityを実際に検証していないため、公開constructorが作るrecordは常にunverifiedである。

| Input | Unverified mapping |
|---|---|
| StrongBox requested/reported | Collector Key = `Software` |
| TEE requested/reported | Collector Key = `Software` |
| Verified + locked reported | Boot State = `Reported` |
| app certificate hash reported | Pipeline = `SelfDeclared` |

要求値と報告値だけでは保証を上げない。

## Verified mapping boundary

将来のK5-14 chain verifierが、pinned root、certificate signatures、attestation challenge、security level、boot state、application ID、revocationを検証したrecordだけを内部`VerifiedAndroidRecord`へ変換する。

検証済みrecordでは次のmappingが可能になる。

- verified TEE level -> `TeeBacked`
- verified StrongBox level -> `StrongBoxBacked`
- verified boot + locked -> `HardwareAttestedLocked`
- verified app identity + approved pipeline -> `StaticManifestBound`

現在、このverified recordを作る公開APIはない。unit test内のfixtureはmapping logicを検証するだけで、実機保証の証拠ではない。

## Conservative failure behavior

- revoked collector keyはNEPP署名前提でも拒否
- unknown collector keyは拒否
- unapproved pipeline/policy/ATv2 keyはchallenge検証前に拒否
- stale/replayed challengeは拒否
- verifier-only digest mismatchは拒否
- signed profileとderived profileが違えば拒否
- minimum profile未達は拒否
- verified Android certificateのrevocation unknownはSoftware/Reported/SelfDeclaredへ低下
- verified Android certificateのrevocation revokedは拒否
- app identity mismatchは拒否

## Nonclaim

Android key attestationはcollector keyとplatform stateについてのevidenceになり得るが、PPG sample-origin proof、sensor-native signature、human liveness proofではない。paired Polar streamのSource Assurance上限は別軸で`PairedCommercialSensor`のままである。
