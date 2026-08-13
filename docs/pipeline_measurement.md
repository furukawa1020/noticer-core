# Public Pipeline Measurement and Pairwise Sensor Alias

## Public measurement

`noticer-pipeline-measurement`は、private biosignal historyに依存しない公開pipeline定義をdomain-separated SHA-256へ固定する。

対象componentは次の5つである。

- collector
- feature pipeline
- quality gate
- baseline algorithm
- evidence engine

各componentは公開可能な`id`、`version`、`config_sha256`だけを持つ。baselineはalgorithmと公開configだけを測定し、個人baselineのcenter、scale、sample、commitmentを含めない。

JSONは`deny_unknown_fields`でparseし、schema version、ASCII label、64桁SHA-256を検証する。その後、固定role順と長さ付きfield encodingで測定するため、JSON field順と空白はhashへ影響しない。

## Public inspector

次でmanifestを検査できる。

~~~bash
cargo run -p noticer-pipeline-measurement --bin noticer-pipeline-inspect -- public-pipeline.json
~~~

出力にはpipeline hashと5 componentの公開情報だけが含まれる。sensor serial、BLE address、global sensor ID、private baseline、collector key IDはschema上受理されない。

## Verifier-only measurement

`VerifierOnlyMeasurement`は公開pipeline hashへcollector key IDとapp signing certificate SHA-256を別domainで結合する。この型はSerializeせず、`Debug`でも値を`VERIFIER_ONLY`として伏せる。

公開measurementとverifier-only measurementを分離することで、公開再現性に必要なpipeline定義と、verifier policyだけが知るidentity情報を同じartifactへ混入させない。

## Pairwise sensor alias

raw sensor identityは`PrivateSensorIdentity`へ閉じ込め、次のHMAC-SHA-256入力から16-byte aliasを導出する。

~~~text
HMAC(alias_key,
     domain || len(service) || service || epoch || len(sensor_identity) || sensor_identity)
~~~

serviceまたはepochが変わればaliasも変わる。同一service・epoch内では安定し、allowlist照合に利用できる。alias keyとraw identityは非Serialize、redacted Debug、drop時上書きの対象である。

pairwise aliasはセンサー真正性の証明ではない。秘密鍵を持つappraiserが同じprivate identityをscope別に仮名化したことだけを表す。

## 非主張

- public pipeline measurementはruntime proof of executionではない
- app certificate hashだけでhardware-backed keyを証明しない
- pairwise aliasはsensor-native signatureではない
- private baseline変更がpublic hashへ反映されないことは意図したprivacy boundaryである
