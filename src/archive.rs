use std::{collections::BTreeMap, env, io::Cursor, path::PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    config::{Builder as S3ConfigBuilder, Region},
    primitives::ByteStream,
    Client,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zstd::stream::{decode_all, encode_all};

use crate::{
    config::{AppConfig, ArchiveConfig},
    core::{
        ArchiveBackendKind, ArchiveJobRecord, ArchivePointerRecord, ArchivePressureMode,
        ArchiveRecordKind, FindingRecord, ScanRunRecord,
    },
    store::AnyScanStore,
};

const ARCHIVE_DATA_SCHEMA_VERSION: u32 = 1;
const ARCHIVE_ENCRYPTION_ALGORITHM: &str = "aes_256_gcm";
const ARCHIVE_COMPRESSION_ALGORITHM: &str = "zstd";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveManifest {
    pub schema_version: u32,
    pub kind: ArchiveRecordKind,
    pub source_namespace: String,
    pub count: usize,
    #[serde(default)]
    pub min_record_id: Option<i64>,
    #[serde(default)]
    pub max_record_id: Option<i64>,
    #[serde(default)]
    pub min_timestamp: Option<DateTime<Utc>>,
    #[serde(default)]
    pub max_timestamp: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub sha256_hex: String,
    pub size_bytes: u64,
    pub compression: String,
    pub encryption: String,
    pub nonce_b64: String,
    pub object_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedArchivePayload {
    pub kind: ArchiveRecordKind,
    pub namespace: String,
    pub records: Vec<serde_json::Value>,
    pub min_record_id: Option<i64>,
    pub max_record_id: Option<i64>,
    pub min_timestamp: Option<DateTime<Utc>>,
    pub max_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedObject {
    pub manifest: ArchiveManifest,
    pub data_object_key: String,
    pub manifest_object_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchivePressureDecision {
    pub pressure_mode: ArchivePressureMode,
    pub hot_retention_days: u64,
    pub used_memory_bytes: u64,
    pub namespace_estimated_bytes: u64,
    pub pressure_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct BackblazeArchiveBackend {
    client: Client,
    bucket: String,
    object_prefix: String,
    encryption_master_key: String,
}

impl BackblazeArchiveBackend {
    pub fn from_config(config: &AppConfig) -> Result<Self> {
        let archive = &config.archive;
        if !archive.enabled {
            return Err(anyhow!("archive backend is disabled"));
        }
        if archive.backend != ArchiveBackendKind::B2S3 {
            return Err(anyhow!(
                "unsupported archive backend {}",
                archive.backend.as_str()
            ));
        }

        let key_id = archive
            .key_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("archive.key_id is required"))?;
        let application_key = archive
            .application_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("archive.application_key is required"))?;
        let encryption_master_key = archive
            .encryption_master_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("archive.encryption_master_key is required"))?
            .to_string();

        let credentials = Credentials::new(key_id, application_key, None, None, "anyscan-archive");
        let region = Region::new(archive.region.clone());
        let conf = S3ConfigBuilder::new()
            .region(region)
            .endpoint_url(archive.endpoint.clone())
            .credentials_provider(credentials)
            .force_path_style(true)
            .build();
        let client = Client::from_conf(conf);

        Ok(Self {
            client,
            bucket: archive.bucket.clone(),
            object_prefix: normalize_object_prefix(&archive.object_prefix),
            encryption_master_key,
        })
    }

    pub async fn upload_archive_payload(
        &self,
        archive: &ArchiveConfig,
        prepared: &PreparedArchivePayload,
        now: DateTime<Utc>,
    ) -> Result<ArchivedObject> {
        let serialized = serialize_archive_records(&prepared.records)?;
        let sha256_hex = sha256_hex(&serialized);
        let (ciphertext, nonce_b64) =
            compress_and_encrypt(&serialized, &self.encryption_master_key)?;
        let data_key = format!(
            "{}{}/{}/{}.data",
            self.object_prefix,
            prepared.kind.as_str(),
            now.format("%Y/%m/%d"),
            now.timestamp_millis()
        );
        let manifest_key = format!(
            "{}{}/{}/{}.manifest.json",
            self.object_prefix,
            prepared.kind.as_str(),
            now.format("%Y/%m/%d"),
            now.timestamp_millis()
        );
        let manifest = ArchiveManifest {
            schema_version: ARCHIVE_DATA_SCHEMA_VERSION,
            kind: prepared.kind,
            source_namespace: prepared.namespace.clone(),
            count: prepared.records.len(),
            min_record_id: prepared.min_record_id,
            max_record_id: prepared.max_record_id,
            min_timestamp: prepared.min_timestamp,
            max_timestamp: prepared.max_timestamp,
            created_at: now,
            sha256_hex,
            size_bytes: ciphertext.len() as u64,
            compression: ARCHIVE_COMPRESSION_ALGORITHM.to_string(),
            encryption: ARCHIVE_ENCRYPTION_ALGORITHM.to_string(),
            nonce_b64,
            object_prefix: archive.object_prefix.clone(),
        };
        let manifest_bytes =
            serde_json::to_vec_pretty(&manifest).context("failed to serialize archive manifest")?;

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&data_key)
            .body(ByteStream::from(ciphertext))
            .send()
            .await
            .context("failed to upload archive data object")?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&manifest_key)
            .body(ByteStream::from(manifest_bytes))
            .content_type("application/json")
            .send()
            .await
            .context("failed to upload archive manifest object")?;

        Ok(ArchivedObject {
            manifest,
            data_object_key: data_key,
            manifest_object_key: manifest_key,
        })
    }

    pub async fn download_manifest(&self, object_key: &str) -> Result<ArchiveManifest> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(object_key)
            .send()
            .await
            .context("failed to download archive manifest")?;
        let bytes = output
            .body
            .collect()
            .await
            .context("failed to collect archive manifest body")?
            .into_bytes();
        serde_json::from_slice(&bytes).context("failed to deserialize archive manifest")
    }

    pub async fn list_object_keys(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let effective_prefix = prefix
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("{}{}", self.object_prefix, value.trim_start_matches('/')))
            .unwrap_or_else(|| self.object_prefix.clone());
        let mut continuation_token = None;
        let mut keys = Vec::new();

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&effective_prefix);
            if let Some(token) = continuation_token.take() {
                request = request.continuation_token(token);
            }
            let response = request
                .send()
                .await
                .context("failed to list archive objects")?;
            for object in response.contents() {
                if let Some(key) = object.key() {
                    keys.push(key.to_string());
                }
            }
            if response.is_truncated().unwrap_or(false) {
                continuation_token = response
                    .next_continuation_token()
                    .map(|token| token.to_string());
            } else {
                break;
            }
        }

        Ok(keys)
    }

    pub async fn download_archive_records(
        &self,
        manifest: &ArchiveManifest,
        data_object_key: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(data_object_key)
            .send()
            .await
            .context("failed to download archive data object")?;
        let bytes = output
            .body
            .collect()
            .await
            .context("failed to collect archive data body")?
            .into_bytes();
        let plaintext =
            decrypt_and_decompress(&bytes, &self.encryption_master_key, &manifest.nonce_b64)?;
        deserialize_archive_records(&plaintext)
    }
}

pub fn decide_archive_pressure(
    archive: &ArchiveConfig,
    used_memory_bytes: u64,
    namespace_estimated_bytes: u64,
) -> ArchivePressureDecision {
    let pressure_bytes = used_memory_bytes.max(namespace_estimated_bytes);
    if pressure_bytes >= archive.hard_max_used_memory_bytes {
        ArchivePressureDecision {
            pressure_mode: ArchivePressureMode::Hard,
            hot_retention_days: archive
                .hard_hot_retention_days
                .max(archive.min_hot_retention_days),
            used_memory_bytes,
            namespace_estimated_bytes,
            pressure_bytes,
        }
    } else if pressure_bytes >= archive.soft_max_used_memory_bytes {
        ArchivePressureDecision {
            pressure_mode: ArchivePressureMode::Soft,
            hot_retention_days: archive
                .soft_hot_retention_days
                .max(archive.min_hot_retention_days),
            used_memory_bytes,
            namespace_estimated_bytes,
            pressure_bytes,
        }
    } else {
        ArchivePressureDecision {
            pressure_mode: ArchivePressureMode::Normal,
            hot_retention_days: archive
                .target_hot_retention_days
                .max(archive.min_hot_retention_days),
            used_memory_bytes,
            namespace_estimated_bytes,
            pressure_bytes,
        }
    }
}

pub fn serialize_archive_records(records: &[serde_json::Value]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for record in records {
        serde_json::to_writer(&mut bytes, record)
            .context("failed to encode archive JSONL record")?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

pub fn deserialize_archive_records(bytes: &[u8]) -> Result<Vec<serde_json::Value>> {
    let mut records = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        records.push(
            serde_json::from_slice::<serde_json::Value>(line)
                .context("failed to decode archive JSONL record")?,
        );
    }
    Ok(records)
}

pub fn default_bootstrap_artifact_dir() -> PathBuf {
    env::var("ANYSCAN_LOCAL_BOOTSTRAP_ARTIFACT_DIR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/anyscan/bootstrap-artifacts"))
}

pub async fn maybe_run_archive_pass(
    config: &AppConfig,
    store: &AnyScanStore,
    owner: &str,
) -> Result<Option<ArchiveJobRecord>> {
    if !config.archive.enabled {
        return Ok(None);
    }
    let now = Utc::now();
    if !store.archive_due(config.archive.cadence_seconds, now)? {
        return Ok(None);
    }
    run_archive_pass_internal(config, store, owner, false).await
}

pub async fn run_archive_pass(
    config: &AppConfig,
    store: &AnyScanStore,
    owner: &str,
) -> Result<Option<ArchiveJobRecord>> {
    if !config.archive.enabled {
        return Ok(None);
    }
    run_archive_pass_internal(config, store, owner, true).await
}

pub async fn download_archive_pointer_manifest(
    config: &AppConfig,
    pointer: &ArchivePointerRecord,
) -> Result<ArchiveManifest> {
    let backend = BackblazeArchiveBackend::from_config(config)?;
    backend
        .download_manifest(&pointer.manifest_object_key)
        .await
}

pub async fn download_archive_pointer_records(
    config: &AppConfig,
    pointer: &ArchivePointerRecord,
) -> Result<Vec<serde_json::Value>> {
    let backend = BackblazeArchiveBackend::from_config(config)?;
    let manifest = backend
        .download_manifest(&pointer.manifest_object_key)
        .await?;
    backend
        .download_archive_records(&manifest, &pointer.data_object_key)
        .await
}

pub async fn hydrate_archive_pointer(
    config: &AppConfig,
    store: &AnyScanStore,
    pointer: &ArchivePointerRecord,
) -> Result<usize> {
    let records = download_archive_pointer_records(config, pointer).await?;
    store.hydrate_archive_records(pointer.kind, &records)
}

pub async fn search_archived_findings(
    config: &AppConfig,
    pointers: &[ArchivePointerRecord],
) -> Result<Vec<FindingRecord>> {
    let backend = BackblazeArchiveBackend::from_config(config)?;
    let mut findings = Vec::new();
    for pointer in pointers
        .iter()
        .filter(|pointer| pointer.kind == ArchiveRecordKind::Findings)
    {
        let manifest = backend
            .download_manifest(&pointer.manifest_object_key)
            .await?;
        let records = backend
            .download_archive_records(&manifest, &pointer.data_object_key)
            .await?;
        for value in records {
            findings.push(
                serde_json::from_value::<FindingRecord>(value)
                    .context("failed to decode archived finding record")?,
            );
        }
    }
    Ok(findings)
}

pub async fn list_archived_runs(
    config: &AppConfig,
    pointers: &[ArchivePointerRecord],
) -> Result<Vec<ScanRunRecord>> {
    let backend = BackblazeArchiveBackend::from_config(config)?;
    let mut runs = Vec::new();
    for pointer in pointers
        .iter()
        .filter(|pointer| pointer.kind == ArchiveRecordKind::Runs)
    {
        let manifest = backend
            .download_manifest(&pointer.manifest_object_key)
            .await?;
        let records = backend
            .download_archive_records(&manifest, &pointer.data_object_key)
            .await?;
        for value in records {
            if let Ok(run) = serde_json::from_value::<ScanRunRecord>(value.clone()) {
                runs.push(run);
                continue;
            }
            let stored = value
                .as_object()
                .ok_or_else(|| anyhow!("archived run payload is not an object"))?;
            if let Some(run_value) = stored.get("run") {
                runs.push(
                    serde_json::from_value::<ScanRunRecord>(run_value.clone())
                        .context("failed to decode archived stored run payload")?,
                );
            }
        }
    }
    Ok(runs)
}

async fn run_archive_pass_internal(
    config: &AppConfig,
    store: &AnyScanStore,
    owner: &str,
    force: bool,
) -> Result<Option<ArchiveJobRecord>> {
    if !force {
        let now = Utc::now();
        if !store.archive_due(config.archive.cadence_seconds, now)? {
            return Ok(None);
        }
    }

    let lease_token = format!(
        "{}:{}:{}",
        owner,
        Utc::now().timestamp_millis(),
        std::process::id()
    );
    let lease_ttl_ms = config
        .archive
        .cadence_seconds
        .saturating_mul(1_000)
        .max(300_000);
    if !store.try_acquire_archive_lease(&lease_token, lease_ttl_ms)? {
        return Ok(None);
    }

    let mut archived_counts = BTreeMap::new();
    let mut archived_object_count = 0usize;
    let mut started_job: Option<ArchiveJobRecord> = None;
    let pass_result: Result<ArchiveJobRecord> = async {
        let used_memory_bytes = store.used_memory_bytes()?;
        let namespace_estimated_bytes = store.namespace_storage_estimate_bytes()?;
        let decision = decide_archive_pressure(
            &config.archive,
            used_memory_bytes,
            namespace_estimated_bytes,
        );
        let backend = BackblazeArchiveBackend::from_config(config)?;
        let started_at = Utc::now();
        let job = store.begin_archive_job(&decision, started_at)?;
        started_job = Some(job.clone());

        let artifact_dir = default_bootstrap_artifact_dir();
        let payloads = store.plan_archive_payloads(
            decision.hot_retention_days,
            config.archive.max_records_per_batch,
            Some(artifact_dir.as_path()),
        )?;
        for payload in payloads {
            let archived = backend
                .upload_archive_payload(&config.archive, &payload, Utc::now())
                .await?;
            store.record_archived_payload(&payload, &archived)?;
            *archived_counts.entry(payload.kind).or_insert(0usize) += payload.records.len();
            archived_object_count += 1;
        }

        store.complete_archive_job(job.id, &archived_counts, archived_object_count, Utc::now())
    }
    .await;

    if let Err(error) = &pass_result {
        if let Some(job) = &started_job {
            let _ = store.fail_archive_job(
                job.id,
                &archived_counts,
                archived_object_count,
                &error.to_string(),
                Utc::now(),
            );
        }
    }

    let release_result = store.release_archive_lease(&lease_token);
    match (pass_result, release_result) {
        (Ok(job), Ok(())) => Ok(Some(job)),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(release_error)) => Err(error)
            .with_context(|| format!("also failed to release archive lease: {release_error}")),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn compress_and_encrypt(bytes: &[u8], master_key: &str) -> Result<(Vec<u8>, String)> {
    let compressed =
        encode_all(Cursor::new(bytes), 3).context("failed to zstd-compress archive")?;
    let key = derive_archive_key(master_key);
    let cipher = Aes256Gcm::new_from_slice(&key).context("failed to create archive cipher")?;
    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut nonce_bytes).context("failed to generate archive nonce")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, compressed.as_ref())
        .map_err(|_| anyhow!("failed to encrypt archive payload"))?;
    Ok((ciphertext, BASE64.encode(nonce_bytes)))
}

fn decrypt_and_decompress(bytes: &[u8], master_key: &str, nonce_b64: &str) -> Result<Vec<u8>> {
    let nonce_raw = BASE64
        .decode(nonce_b64)
        .context("failed to decode archive nonce")?;
    let key = derive_archive_key(master_key);
    let cipher = Aes256Gcm::new_from_slice(&key).context("failed to create archive cipher")?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_raw), bytes)
        .map_err(|_| anyhow!("failed to decrypt archive payload"))?;
    decode_all(Cursor::new(plaintext)).context("failed to zstd-decompress archive")
}

fn derive_archive_key(master_key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(master_key.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    key
}

fn normalize_object_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim().trim_matches('/');
    if trimmed.is_empty() {
        "anyscan/".to_string()
    } else {
        format!("{trimmed}/")
    }
}

pub fn archive_kind_counts(
    counts: impl IntoIterator<Item = (ArchiveRecordKind, usize)>,
) -> Vec<crate::core::ArchiveKindCount> {
    let mut grouped = BTreeMap::new();
    for (kind, count) in counts {
        *grouped.entry(kind.as_str().to_string()).or_insert(0usize) += count;
    }
    grouped
        .into_iter()
        .map(|(kind, record_count)| crate::core::ArchiveKindCount { kind, record_count })
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::{decide_archive_pressure, PreparedArchivePayload};
    use crate::config::ArchiveConfig;
    use crate::core::{ArchivePressureMode, ArchiveRecordKind};

    #[test]
    fn archive_pressure_selects_dynamic_hot_window() {
        let config = ArchiveConfig::default();
        let normal = decide_archive_pressure(&config, 128 * 1024 * 1024, 64 * 1024 * 1024);
        assert_eq!(normal.pressure_mode, ArchivePressureMode::Normal);
        assert_eq!(normal.hot_retention_days, 30);
        assert_eq!(normal.pressure_bytes, 128 * 1024 * 1024);

        let soft = decide_archive_pressure(
            &config,
            config.soft_max_used_memory_bytes,
            128 * 1024 * 1024,
        );
        assert_eq!(soft.pressure_mode, ArchivePressureMode::Soft);
        assert_eq!(soft.hot_retention_days, 14);

        let hard = decide_archive_pressure(
            &config,
            128 * 1024 * 1024,
            config.hard_max_used_memory_bytes,
        );
        assert_eq!(hard.pressure_mode, ArchivePressureMode::Hard);
        assert_eq!(hard.hot_retention_days, 7);
        assert_eq!(hard.pressure_bytes, config.hard_max_used_memory_bytes);
    }

    #[test]
    fn archive_encryption_round_trip_preserves_records() {
        let payload = PreparedArchivePayload {
            kind: ArchiveRecordKind::Findings,
            namespace: "anyscan:test".to_string(),
            records: vec![serde_json::json!({"id": 1, "value": "redacted"})],
            min_record_id: Some(1),
            max_record_id: Some(1),
            min_timestamp: Some(Utc::now()),
            max_timestamp: Some(Utc::now()),
        };
        let bytes = super::serialize_archive_records(&payload.records).expect("records serialize");
        let (ciphertext, nonce_b64) =
            super::compress_and_encrypt(&bytes, "test-master-key").expect("encrypt");
        let restored = super::decrypt_and_decompress(&ciphertext, "test-master-key", &nonce_b64)
            .expect("decrypt");
        let records =
            super::deserialize_archive_records(&restored).expect("decode archive records");
        assert_eq!(records, payload.records);
        let plaintext = String::from_utf8(restored).expect("jsonl plaintext should be utf-8");
        assert!(plaintext.contains('\n'));
    }
}
