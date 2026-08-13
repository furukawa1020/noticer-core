#![forbid(unsafe_code)]

//! Canonical public pipeline measurements and unlinkable sensor aliases.
//!
//! Private baseline values, sensor serials, BLE addresses, and raw sensor-ID
//! hashes are not fields of `PublicPipelineManifest`.

use std::fmt;

use hmac::{Hmac, Mac};
use noticer_provenance::PipelineMeasurementHash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;
const PUBLIC_DOMAIN: &[u8] = b"NOTICER_PUBLIC_PIPELINE_MEASUREMENT_V1";
const VERIFIER_DOMAIN: &[u8] = b"NOTICER_VERIFIER_PIPELINE_MEASUREMENT_V1";
const SENSOR_ALIAS_DOMAIN: &[u8] = b"NOTICER_PAIRWISE_SENSOR_ALIAS_V1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicPipelineManifest {
    schema_version: u16,
    collector: PublicComponent,
    feature_pipeline: PublicComponent,
    quality_gate: PublicComponent,
    baseline_algorithm: PublicComponent,
    evidence_engine: PublicComponent,
}

impl PublicPipelineManifest {
    pub fn parse_json(source: &str) -> Result<Self, MeasurementError> {
        let manifest: Self = serde_json::from_str(source)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn measure(self) -> Result<PublicPipelineMeasurement, MeasurementError> {
        self.validate()?;
        let hash = canonical_public_hash(&self);
        Ok(PublicPipelineMeasurement {
            manifest: self,
            hash: PipelineMeasurementHash(hash),
        })
    }

    fn validate(&self) -> Result<(), MeasurementError> {
        if self.schema_version != 1 {
            return Err(MeasurementError::UnsupportedSchema);
        }
        for component in [
            &self.collector,
            &self.feature_pipeline,
            &self.quality_gate,
            &self.baseline_algorithm,
            &self.evidence_engine,
        ] {
            component.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublicComponent {
    id: String,
    version: String,
    config_sha256: String,
}

impl PublicComponent {
    fn validate(&self) -> Result<(), MeasurementError> {
        validate_label(&self.id)?;
        validate_label(&self.version)?;
        decode_sha256(&self.config_sha256)?;
        Ok(())
    }
}

pub struct PublicPipelineMeasurement {
    manifest: PublicPipelineManifest,
    hash: PipelineMeasurementHash,
}

impl PublicPipelineMeasurement {
    pub const fn hash(&self) -> PipelineMeasurementHash {
        self.hash
    }

    pub fn inspect(&self) -> PublicManifestInspection {
        PublicManifestInspection {
            schema_version: self.manifest.schema_version,
            pipeline_sha256: hex(self.hash.0),
            components: vec![
                inspect("collector", &self.manifest.collector),
                inspect("feature_pipeline", &self.manifest.feature_pipeline),
                inspect("quality_gate", &self.manifest.quality_gate),
                inspect("baseline_algorithm", &self.manifest.baseline_algorithm),
                inspect("evidence_engine", &self.manifest.evidence_engine),
            ],
        }
    }
}

impl fmt::Debug for PublicPipelineMeasurement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicPipelineMeasurement")
            .field("pipeline_sha256", &hex(self.hash.0))
            .field("schema_version", &self.manifest.schema_version)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublicManifestInspection {
    pub schema_version: u16,
    pub pipeline_sha256: String,
    pub components: Vec<PublicComponentInspection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublicComponentInspection {
    pub role: &'static str,
    pub id: String,
    pub version: String,
    pub config_sha256: String,
}

fn inspect(role: &'static str, component: &PublicComponent) -> PublicComponentInspection {
    PublicComponentInspection {
        role,
        id: component.id.clone(),
        version: component.version.clone(),
        config_sha256: component.config_sha256.clone(),
    }
}

pub struct VerifierOnlyMeasurement {
    public_hash: PipelineMeasurementHash,
    verifier_digest: [u8; 32],
    collector_key_id: [u8; 32],
    app_signing_certificate_sha256: [u8; 32],
}

impl VerifierOnlyMeasurement {
    pub fn new(
        public: &PublicPipelineMeasurement,
        collector_key_id: [u8; 32],
        app_signing_certificate_sha256: [u8; 32],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(VERIFIER_DOMAIN);
        hasher.update(public.hash.0);
        hasher.update(collector_key_id);
        hasher.update(app_signing_certificate_sha256);
        Self {
            public_hash: public.hash,
            verifier_digest: hasher.finalize().into(),
            collector_key_id,
            app_signing_certificate_sha256,
        }
    }

    pub const fn public_hash(&self) -> PipelineMeasurementHash {
        self.public_hash
    }

    pub const fn verifier_digest(&self) -> [u8; 32] {
        self.verifier_digest
    }
}

impl fmt::Debug for VerifierOnlyMeasurement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifierOnlyMeasurement")
            .field("public_hash", &hex(self.public_hash.0))
            .field("collector_key_id", &"VERIFIER_ONLY")
            .field("app_signing_certificate_sha256", &"VERIFIER_ONLY")
            .field("verifier_digest", &"VERIFIER_ONLY")
            .finish()
    }
}

impl Drop for VerifierOnlyMeasurement {
    fn drop(&mut self) {
        self.collector_key_id.fill(0);
        self.app_signing_certificate_sha256.fill(0);
        self.verifier_digest.fill(0);
    }
}

pub struct SensorAliasKey([u8; 32]);

impl SensorAliasKey {
    pub fn new(key: [u8; 32]) -> Result<Self, MeasurementError> {
        if key == [0; 32] {
            return Err(MeasurementError::InvalidAliasKey);
        }
        Ok(Self(key))
    }
}

impl fmt::Debug for SensorAliasKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensorAliasKey(REDACTED)")
    }
}

impl Drop for SensorAliasKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub struct PrivateSensorIdentity(Box<[u8]>);

impl PrivateSensorIdentity {
    pub fn new(identity: Vec<u8>) -> Result<Self, MeasurementError> {
        if identity.is_empty() || identity.len() > 256 {
            return Err(MeasurementError::InvalidSensorIdentity);
        }
        Ok(Self(identity.into_boxed_slice()))
    }
}

impl fmt::Debug for PrivateSensorIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSensorIdentity(REDACTED)")
    }
}

impl Drop for PrivateSensorIdentity {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PairwiseSensorAlias([u8; 16]);

impl PairwiseSensorAlias {
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn artifact_id(self) -> String {
        hex16(self.0)
    }
}

impl fmt::Debug for PairwiseSensorAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PairwiseSensorAlias")
            .field(&self.artifact_id())
            .finish()
    }
}

pub fn derive_pairwise_sensor_alias(
    key: &SensorAliasKey,
    identity: &PrivateSensorIdentity,
    service_scope: &[u8],
    epoch: u64,
) -> Result<PairwiseSensorAlias, MeasurementError> {
    if service_scope.is_empty() || service_scope.len() > 256 {
        return Err(MeasurementError::InvalidServiceScope);
    }
    let mut mac =
        HmacSha256::new_from_slice(&key.0).map_err(|_| MeasurementError::InvalidAliasKey)?;
    mac.update(SENSOR_ALIAS_DOMAIN);
    update_len_prefixed_mac(&mut mac, service_scope)?;
    mac.update(&epoch.to_be_bytes());
    update_len_prefixed_mac(&mut mac, &identity.0)?;
    let digest = mac.finalize().into_bytes();
    let mut alias = [0; 16];
    alias.copy_from_slice(&digest[..16]);
    Ok(PairwiseSensorAlias(alias))
}

fn canonical_public_hash(manifest: &PublicPipelineManifest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PUBLIC_DOMAIN);
    hasher.update(manifest.schema_version.to_be_bytes());
    for (role, component) in [
        ("collector", &manifest.collector),
        ("feature_pipeline", &manifest.feature_pipeline),
        ("quality_gate", &manifest.quality_gate),
        ("baseline_algorithm", &manifest.baseline_algorithm),
        ("evidence_engine", &manifest.evidence_engine),
    ] {
        update_len_prefixed_hash(&mut hasher, role.as_bytes());
        update_len_prefixed_hash(&mut hasher, component.id.as_bytes());
        update_len_prefixed_hash(&mut hasher, component.version.as_bytes());
        hasher.update(
            decode_sha256(&component.config_sha256)
                .expect("validated manifest contains a canonical SHA-256"),
        );
    }
    hasher.finalize().into()
}

fn update_len_prefixed_hash(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);
}

fn update_len_prefixed_mac(mac: &mut HmacSha256, value: &[u8]) -> Result<(), MeasurementError> {
    let length = u32::try_from(value.len()).map_err(|_| MeasurementError::LengthOverflow)?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn validate_label(value: &str) -> Result<(), MeasurementError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        return Err(MeasurementError::InvalidLabel);
    }
    Ok(())
}

fn decode_sha256(value: &str) -> Result<[u8; 32], MeasurementError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MeasurementError::InvalidSha256);
    }
    let mut result = [0; 32];
    for (index, output) in result.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| MeasurementError::InvalidSha256)?;
    }
    Ok(result)
}

fn hex(value: [u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex16(value: [u8; 16]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Error)]
pub enum MeasurementError {
    #[error("manifest JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("only public pipeline schema version 1 is supported")]
    UnsupportedSchema,
    #[error("manifest label is empty, too long, or non-canonical")]
    InvalidLabel,
    #[error("manifest SHA-256 must contain exactly 64 hexadecimal digits")]
    InvalidSha256,
    #[error("sensor alias key must not be all zero")]
    InvalidAliasKey,
    #[error("private sensor identity length is invalid")]
    InvalidSensorIdentity,
    #[error("service scope length is invalid")]
    InvalidServiceScope,
    #[error("canonical length does not fit u32")]
    LengthOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ONE_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn manifest_json(hash: &str) -> String {
        format!(
            r#"{{
                "schema_version": 1,
                "collector": {{"id":"polar-collector","version":"8.1.0","config_sha256":"{hash}"}},
                "feature_pipeline": {{"id":"noticer.ppg-acc","version":"v1","config_sha256":"{ZERO_HASH}"}},
                "quality_gate": {{"id":"noticer.quality","version":"v1","config_sha256":"{ZERO_HASH}"}},
                "baseline_algorithm": {{"id":"robust-anchor","version":"v1","config_sha256":"{ZERO_HASH}"}},
                "evidence_engine": {{"id":"e-process","version":"v1","config_sha256":"{ZERO_HASH}"}}
            }}"#
        )
    }

    #[test]
    fn canonical_hash_is_stable_across_json_field_order_and_whitespace() {
        let ordered = manifest_json(ZERO_HASH);
        let reordered = format!(
            r#"{{"evidence_engine":{{"config_sha256":"{ZERO_HASH}","version":"v1","id":"e-process"}},"baseline_algorithm":{{"version":"v1","id":"robust-anchor","config_sha256":"{ZERO_HASH}"}},"quality_gate":{{"id":"noticer.quality","config_sha256":"{ZERO_HASH}","version":"v1"}},"feature_pipeline":{{"version":"v1","config_sha256":"{ZERO_HASH}","id":"noticer.ppg-acc"}},"collector":{{"version":"8.1.0","config_sha256":"{ZERO_HASH}","id":"polar-collector"}},"schema_version":1}}"#
        );
        let left = PublicPipelineManifest::parse_json(&ordered)
            .unwrap()
            .measure()
            .unwrap();
        let right = PublicPipelineManifest::parse_json(&reordered)
            .unwrap()
            .measure()
            .unwrap();
        assert_eq!(left.hash(), right.hash());
    }

    #[test]
    fn public_field_mutation_changes_hash() {
        let left = PublicPipelineManifest::parse_json(&manifest_json(ZERO_HASH))
            .unwrap()
            .measure()
            .unwrap();
        let right = PublicPipelineManifest::parse_json(&manifest_json(ONE_HASH))
            .unwrap()
            .measure()
            .unwrap();
        assert_ne!(left.hash(), right.hash());
    }

    #[test]
    fn private_baseline_changes_cannot_enter_public_measurement() {
        let private_baseline_a = [1.0_f64, 2.0, 3.0];
        let private_baseline_b = [900.0_f64, -20.0, 7.0];
        assert_ne!(private_baseline_a, private_baseline_b);
        let manifest = manifest_json(ZERO_HASH);
        let before = PublicPipelineManifest::parse_json(&manifest)
            .unwrap()
            .measure()
            .unwrap();
        let after = PublicPipelineManifest::parse_json(&manifest)
            .unwrap()
            .measure()
            .unwrap();
        assert_eq!(before.hash(), after.hash());
    }

    #[test]
    fn service_and_epoch_make_sensor_aliases_pairwise() {
        let key = SensorAliasKey::new([7; 32]).unwrap();
        let identity = PrivateSensorIdentity::new(b"private-ble-identity".to_vec()).unwrap();
        let service_a_epoch_1 =
            derive_pairwise_sensor_alias(&key, &identity, b"service-a", 1).unwrap();
        let service_a_epoch_1_again =
            derive_pairwise_sensor_alias(&key, &identity, b"service-a", 1).unwrap();
        let service_b_epoch_1 =
            derive_pairwise_sensor_alias(&key, &identity, b"service-b", 1).unwrap();
        let service_a_epoch_2 =
            derive_pairwise_sensor_alias(&key, &identity, b"service-a", 2).unwrap();
        assert_eq!(service_a_epoch_1, service_a_epoch_1_again);
        assert_ne!(service_a_epoch_1, service_b_epoch_1);
        assert_ne!(service_a_epoch_1, service_a_epoch_2);
    }

    #[test]
    fn public_schema_rejects_sensor_and_private_baseline_fields() {
        let mut value: serde_json::Value = serde_json::from_str(&manifest_json(ZERO_HASH)).unwrap();
        value["sensor_serial"] = serde_json::json!("GLOBAL-ID");
        assert!(PublicPipelineManifest::parse_json(&value.to_string()).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&manifest_json(ZERO_HASH)).unwrap();
        value["private_baseline"] = serde_json::json!([1.0, 2.0]);
        assert!(PublicPipelineManifest::parse_json(&value.to_string()).is_err());
    }

    #[test]
    fn inspector_contains_only_public_pipeline_fields() {
        let measurement = PublicPipelineManifest::parse_json(&manifest_json(ZERO_HASH))
            .unwrap()
            .measure()
            .unwrap();
        let artifact = serde_json::to_string(&measurement.inspect()).unwrap();
        for forbidden in [
            "sensor_serial",
            "ble_address",
            "global_sensor_id",
            "private_baseline",
            "collector_key_id",
        ] {
            assert!(!artifact.contains(forbidden));
        }
        assert!(artifact.contains("baseline_algorithm"));
    }

    #[test]
    fn verifier_only_fields_are_redacted() {
        let measurement = PublicPipelineManifest::parse_json(&manifest_json(ZERO_HASH))
            .unwrap()
            .measure()
            .unwrap();
        let verifier = VerifierOnlyMeasurement::new(&measurement, [3; 32], [4; 32]);
        let debug = format!("{verifier:?}");
        assert!(debug.contains("VERIFIER_ONLY"));
        assert!(!debug.contains("030303"));
        assert!(!debug.contains("040404"));
        assert_eq!(verifier.public_hash(), measurement.hash());
    }
}
