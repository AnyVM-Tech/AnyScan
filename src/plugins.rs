use std::collections::{BTreeMap, BTreeSet};

use once_cell::sync::Lazy;
use serde::{Deserialize, Deserializer, Serialize};

const DEFAULT_PLUGIN_CATALOG_LIMIT: usize = 500;
const BUNDLED_HTTP_RULES: &str = include_str!("../extensions/bundled/rules/http-plugin-rules.json");
const BUNDLED_VERSION_RULES: &str =
    include_str!("../extensions/bundled/rules/version-plugin-rules.json");
const BUNDLED_PROTOCOL_ADAPTER_MANIFEST: &str =
    include_str!("../extensions/bundled/manifests/bundled-protocol-plugin-adapter.json");
const BUNDLED_PROTOCOL_ADAPTER_RULES: &str =
    include_str!("../extensions/bundled/rules/protocol-plugin-rules.json");

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PluginLeakixLabel {
    Public,
    TrustedPro,
}

impl PluginLeakixLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::TrustedPro => "trusted_pro",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PluginFamily {
    AiLlmVector,
    DatabasesSearch,
    EnterpriseWebApps,
    InfraPlatformData,
    LeakageDebugConfig,
    NetworkSecurityAppliances,
    OtIcsIot,
    OpsObservability,
    ExposureVulnerabilityMisc,
}

impl PluginFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AiLlmVector => "ai_llm_vector",
            Self::DatabasesSearch => "databases_search",
            Self::EnterpriseWebApps => "enterprise_web_apps",
            Self::InfraPlatformData => "infra_platform_data",
            Self::LeakageDebugConfig => "leakage_debug_config",
            Self::NetworkSecurityAppliances => "network_security_appliances",
            Self::OtIcsIot => "ot_ics_iot",
            Self::OpsObservability => "ops_observability",
            Self::ExposureVulnerabilityMisc => "exposure_vulnerability_misc",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PluginExecutionMode {
    PassiveHttp,
    AuthlessProtocol,
    VersionCorrelation,
    ActiveAuthorized,
}

impl PluginExecutionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PassiveHttp => "passive_http",
            Self::AuthlessProtocol => "authless_protocol",
            Self::VersionCorrelation => "version_correlation",
            Self::ActiveAuthorized => "active_authorized",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PluginStatus {
    Implemented,
    Planned,
    NotSupported,
}

impl PluginStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::Planned => "planned",
            Self::NotSupported => "not_supported",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PluginImplementationSource {
    BuiltIn,
    BundledDetectorPack,
    BundledScannerAdapter,
    BundledVersionRule,
    ExternalReported,
}

impl PluginImplementationSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BuiltIn => "built_in",
            Self::BundledDetectorPack => "bundled_detector_pack",
            Self::BundledScannerAdapter => "bundled_scanner_adapter",
            Self::BundledVersionRule => "bundled_version_rule",
            Self::ExternalReported => "external_reported",
        }
    }
}

impl Default for PluginImplementationSource {
    fn default() -> Self {
        Self::BuiltIn
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PluginCoverageStatus {
    FirstClass,
    ExternalScannerOnly,
    DeclaredButInactive,
}

impl PluginCoverageStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FirstClass => "first_class",
            Self::ExternalScannerOnly => "external_scanner_only",
            Self::DeclaredButInactive => "declared_but_inactive",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginCatalogEntry {
    pub plugin_id: String,
    pub display_name: String,
    pub leakix_label: PluginLeakixLabel,
    pub family: PluginFamily,
    pub execution_mode: PluginExecutionMode,
    pub status: PluginStatus,
    pub implementation_source: PluginImplementationSource,
    pub default_severity: String,
    #[serde(default)]
    pub requires_authorized_active_mode: bool,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginCatalogRenderedEntry {
    #[serde(flatten)]
    pub entry: PluginCatalogEntry,
    pub coverage_status: PluginCoverageStatus,
    pub actionable: bool,
    #[serde(default)]
    pub coverage_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FindingPluginMetadata {
    pub plugin_id: String,
    pub plugin_display_name: String,
    pub plugin_family: PluginFamily,
    pub execution_mode: PluginExecutionMode,
    pub leakix_label: PluginLeakixLabel,
    pub implementation_source: PluginImplementationSource,
    #[serde(default)]
    pub product_name: Option<String>,
    #[serde(default)]
    pub product_version: Option<String>,
    #[serde(default)]
    pub cpe: Option<String>,
    #[serde(default)]
    pub cve_ids: Vec<String>,
    #[serde(default)]
    pub kev_matched: Option<bool>,
    #[serde(default)]
    pub service_protocol: Option<String>,
    #[serde(default)]
    pub service_port: Option<u16>,
}

impl<'de> Deserialize<'de> for FindingPluginMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawFindingPluginMetadata {
            plugin_id: String,
            plugin_display_name: String,
            plugin_family: PluginFamily,
            execution_mode: PluginExecutionMode,
            leakix_label: PluginLeakixLabel,
            #[serde(default)]
            implementation_source: Option<PluginImplementationSource>,
            #[serde(default)]
            product_name: Option<String>,
            #[serde(default)]
            product_version: Option<String>,
            #[serde(default)]
            cpe: Option<String>,
            #[serde(default)]
            cve_ids: Vec<String>,
            #[serde(default)]
            kev_matched: Option<bool>,
            #[serde(default)]
            service_protocol: Option<String>,
            #[serde(default)]
            service_port: Option<u16>,
        }

        let raw = RawFindingPluginMetadata::deserialize(deserializer)?;
        let implementation_source = raw.implementation_source.unwrap_or_else(|| {
            lookup_plugin(&raw.plugin_id)
                .map(resolved_implementation_source)
                .unwrap_or_default()
        });

        Ok(Self {
            plugin_id: raw.plugin_id,
            plugin_display_name: raw.plugin_display_name,
            plugin_family: raw.plugin_family,
            execution_mode: raw.execution_mode,
            leakix_label: raw.leakix_label,
            implementation_source,
            product_name: raw.product_name,
            product_version: raw.product_version,
            cpe: raw.cpe,
            cve_ids: raw.cve_ids,
            kev_matched: raw.kev_matched,
            service_protocol: raw.service_protocol,
            service_port: raw.service_port,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginCatalogQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub family: Option<PluginFamily>,
    #[serde(default)]
    pub leakix_label: Option<PluginLeakixLabel>,
    #[serde(default)]
    pub execution_mode: Option<PluginExecutionMode>,
    #[serde(default)]
    pub status: Option<PluginStatus>,
    #[serde(default)]
    pub implementation_source: Option<PluginImplementationSource>,
    #[serde(default)]
    pub coverage_status: Option<PluginCoverageStatus>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginCatalogBucketCount {
    pub key: String,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginCatalogSummary {
    pub total: usize,
    pub public_total: usize,
    pub trusted_pro_total: usize,
    pub implemented_total: usize,
    pub planned_total: usize,
    pub not_supported_total: usize,
    pub first_class_total: usize,
    pub external_scanner_only_total: usize,
    pub declared_but_inactive_total: usize,
    #[serde(default)]
    pub by_family: Vec<PluginCatalogBucketCount>,
    #[serde(default)]
    pub by_execution_mode: Vec<PluginCatalogBucketCount>,
    #[serde(default)]
    pub by_status: Vec<PluginCatalogBucketCount>,
    #[serde(default)]
    pub by_label: Vec<PluginCatalogBucketCount>,
    #[serde(default)]
    pub by_implementation_source: Vec<PluginCatalogBucketCount>,
    #[serde(default)]
    pub by_coverage_status: Vec<PluginCatalogBucketCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginCatalogResponse {
    pub summary: PluginCatalogSummary,
    #[serde(default)]
    pub plugins: Vec<PluginCatalogRenderedEntry>,
}

static PLUGIN_CATALOG: Lazy<Vec<PluginCatalogEntry>> = Lazy::new(|| {
    serde_json::from_str(include_str!("../data/leakix_plugin_catalog.json"))
        .expect("valid bundled LeakIX-style AnyScan plugin catalog")
});
static BUNDLED_HTTP_RULE_PLUGIN_IDS: Lazy<BTreeSet<String>> =
    Lazy::new(|| bundled_rule_plugin_ids(BUNDLED_HTTP_RULES));
static BUNDLED_VERSION_RULE_PLUGIN_IDS: Lazy<BTreeSet<String>> =
    Lazy::new(|| bundled_rule_plugin_ids(BUNDLED_VERSION_RULES));
static BUNDLED_PROTOCOL_RULE_PLUGIN_IDS: Lazy<BTreeSet<String>> =
    Lazy::new(|| bundled_rule_plugin_ids(BUNDLED_PROTOCOL_ADAPTER_RULES));
static BUILT_IN_PROTOCOL_PROMOTION_PLUGIN_IDS: Lazy<BTreeSet<String>> = Lazy::new(|| {
    [
        "FirebirdPlugin",
        "FreeSWITCHOpenPlugin",
        "JdwpPlugin",
        "OpenEdgePlugin",
        "PostgreSQLOpenPlugin",
        "SshRegresshionPlugin",
        "TelnetAuthBypassPlugin",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
});

pub fn plugin_catalog_entries() -> &'static [PluginCatalogEntry] {
    PLUGIN_CATALOG.as_slice()
}

pub fn lookup_plugin(plugin_id: &str) -> Option<&'static PluginCatalogEntry> {
    let trimmed = plugin_id.trim();
    if trimmed.is_empty() {
        return None;
    }
    PLUGIN_CATALOG
        .iter()
        .find(|entry| entry.plugin_id.eq_ignore_ascii_case(trimmed))
}

pub fn normalize_plugin_catalog_query(mut query: PluginCatalogQuery) -> PluginCatalogQuery {
    query.q = query
        .q
        .take()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    query.limit = Some(query.limit.unwrap_or(DEFAULT_PLUGIN_CATALOG_LIMIT).max(1));
    query
}

pub fn search_plugin_catalog(query: &PluginCatalogQuery) -> PluginCatalogResponse {
    let query = normalize_plugin_catalog_query(query.clone());
    let mut filtered = PLUGIN_CATALOG
        .iter()
        .filter(|entry| plugin_catalog_entry_matches(entry, &query))
        .map(render_plugin_catalog_entry)
        .collect::<Vec<_>>();
    filtered.sort_by(|left, right| {
        left.entry
            .family
            .cmp(&right.entry.family)
            .then(left.entry.plugin_id.cmp(&right.entry.plugin_id))
    });
    filtered.truncate(query.limit.unwrap_or(DEFAULT_PLUGIN_CATALOG_LIMIT));

    PluginCatalogResponse {
        summary: plugin_catalog_summary(plugin_catalog_entries()),
        plugins: filtered,
    }
}

pub fn plugin_catalog_summary(entries: &[PluginCatalogEntry]) -> PluginCatalogSummary {
    let mut by_family = BTreeMap::<String, usize>::new();
    let mut by_execution_mode = BTreeMap::<String, usize>::new();
    let mut by_status = BTreeMap::<String, usize>::new();
    let mut by_label = BTreeMap::<String, usize>::new();
    let mut by_implementation_source = BTreeMap::<String, usize>::new();
    let mut by_coverage_status = BTreeMap::<String, usize>::new();

    let mut public_total = 0usize;
    let mut trusted_pro_total = 0usize;
    let mut implemented_total = 0usize;
    let mut planned_total = 0usize;
    let mut not_supported_total = 0usize;
    let mut first_class_total = 0usize;
    let mut external_scanner_only_total = 0usize;
    let mut declared_but_inactive_total = 0usize;

    for entry in entries {
        let coverage_status = derive_plugin_coverage_status(entry);
        let implementation_source = resolved_implementation_source(entry);
        *by_family
            .entry(entry.family.as_str().to_string())
            .or_default() += 1;
        *by_execution_mode
            .entry(entry.execution_mode.as_str().to_string())
            .or_default() += 1;
        *by_status
            .entry(entry.status.as_str().to_string())
            .or_default() += 1;
        *by_label
            .entry(entry.leakix_label.as_str().to_string())
            .or_default() += 1;
        *by_implementation_source
            .entry(implementation_source.as_str().to_string())
            .or_default() += 1;
        *by_coverage_status
            .entry(coverage_status.as_str().to_string())
            .or_default() += 1;

        match entry.leakix_label {
            PluginLeakixLabel::Public => public_total += 1,
            PluginLeakixLabel::TrustedPro => trusted_pro_total += 1,
        }
        match entry.status {
            PluginStatus::Implemented => implemented_total += 1,
            PluginStatus::Planned => planned_total += 1,
            PluginStatus::NotSupported => not_supported_total += 1,
        }
        match coverage_status {
            PluginCoverageStatus::FirstClass => first_class_total += 1,
            PluginCoverageStatus::ExternalScannerOnly => external_scanner_only_total += 1,
            PluginCoverageStatus::DeclaredButInactive => declared_but_inactive_total += 1,
        }
    }

    PluginCatalogSummary {
        total: entries.len(),
        public_total,
        trusted_pro_total,
        implemented_total,
        planned_total,
        not_supported_total,
        first_class_total,
        external_scanner_only_total,
        declared_but_inactive_total,
        by_family: bucket_counts(by_family),
        by_execution_mode: bucket_counts(by_execution_mode),
        by_status: bucket_counts(by_status),
        by_label: bucket_counts(by_label),
        by_implementation_source: bucket_counts(by_implementation_source),
        by_coverage_status: bucket_counts(by_coverage_status),
    }
}

fn render_plugin_catalog_entry(entry: &PluginCatalogEntry) -> PluginCatalogRenderedEntry {
    let mut rendered_entry = entry.clone();
    rendered_entry.implementation_source = resolved_implementation_source(entry);
    let coverage_status = derive_plugin_coverage_status(entry);
    let coverage_note = plugin_coverage_note(entry, coverage_status);
    PluginCatalogRenderedEntry {
        entry: rendered_entry,
        coverage_status,
        actionable: coverage_status == PluginCoverageStatus::FirstClass,
        coverage_note,
    }
}

fn derive_plugin_coverage_status(entry: &PluginCatalogEntry) -> PluginCoverageStatus {
    match resolved_implementation_source(entry) {
        PluginImplementationSource::BuiltIn => PluginCoverageStatus::FirstClass,
        PluginImplementationSource::ExternalReported => PluginCoverageStatus::ExternalScannerOnly,
        PluginImplementationSource::BundledDetectorPack => {
            if BUNDLED_HTTP_RULE_PLUGIN_IDS.contains(&entry.plugin_id) {
                PluginCoverageStatus::FirstClass
            } else {
                PluginCoverageStatus::DeclaredButInactive
            }
        }
        PluginImplementationSource::BundledVersionRule => {
            if BUNDLED_VERSION_RULE_PLUGIN_IDS.contains(&entry.plugin_id) {
                PluginCoverageStatus::FirstClass
            } else {
                PluginCoverageStatus::DeclaredButInactive
            }
        }
        PluginImplementationSource::BundledScannerAdapter => {
            if bundled_protocol_adapter_enabled()
                && BUNDLED_PROTOCOL_RULE_PLUGIN_IDS.contains(&entry.plugin_id)
            {
                PluginCoverageStatus::FirstClass
            } else {
                PluginCoverageStatus::DeclaredButInactive
            }
        }
    }
}

fn plugin_coverage_note(
    entry: &PluginCatalogEntry,
    coverage_status: PluginCoverageStatus,
) -> Option<String> {
    let implementation_source = resolved_implementation_source(entry);
    Some(match coverage_status {
        PluginCoverageStatus::FirstClass => match implementation_source {
            PluginImplementationSource::BuiltIn => {
                "Detected directly by the built-in AnyScan engine.".to_string()
            }
            PluginImplementationSource::BundledDetectorPack => {
                "Detected by a bundled detector pack rule.".to_string()
            }
            PluginImplementationSource::BundledVersionRule => {
                "Detected by a bundled version-correlation rule.".to_string()
            }
            PluginImplementationSource::BundledScannerAdapter => {
                "Detected by a bundled scanner-adapter mapping.".to_string()
            }
            PluginImplementationSource::ExternalReported => {
                "Detected through scanner-reported plugin metadata.".to_string()
            }
        },
        PluginCoverageStatus::ExternalScannerOnly => {
            "Only emitted when a scanner adapter explicitly reports this plugin.".to_string()
        }
        PluginCoverageStatus::DeclaredButInactive => {
            "Cataloged for bundled coverage, but no active bundled rule/adapter content is configured yet.".to_string()
        }
    })
}

fn bundled_rule_plugin_ids(raw: &str) -> BTreeSet<String> {
    serde_json::from_str::<Vec<serde_json::Value>>(raw)
        .map(|entries| {
            entries
                .into_iter()
                .filter_map(|entry| {
                    entry
                        .get("plugin_id")
                        .and_then(|value| value.as_str())
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default()
}

fn bundled_protocol_adapter_enabled() -> bool {
    serde_json::from_str::<serde_json::Value>(BUNDLED_PROTOCOL_ADAPTER_MANIFEST)
        .ok()
        .and_then(|value| value.get("enabled").and_then(|enabled| enabled.as_bool()))
        .unwrap_or(false)
}

pub fn build_plugin_metadata(
    plugin_id: &str,
    product_name: Option<&str>,
    product_version: Option<&str>,
    cpe: Option<&str>,
    cve_ids: &[&str],
    kev_matched: Option<bool>,
    service_protocol: Option<&str>,
    service_port: Option<u16>,
) -> Option<FindingPluginMetadata> {
    let entry = lookup_plugin(plugin_id)?;
    Some(FindingPluginMetadata {
        plugin_id: entry.plugin_id.clone(),
        plugin_display_name: entry.display_name.clone(),
        plugin_family: entry.family,
        execution_mode: entry.execution_mode,
        leakix_label: entry.leakix_label,
        implementation_source: resolved_implementation_source(entry),
        product_name: normalize_metadata_text(product_name),
        product_version: normalize_metadata_text(product_version),
        cpe: normalize_metadata_text(cpe),
        cve_ids: normalize_cve_ids(cve_ids),
        kev_matched,
        service_protocol: normalize_metadata_text(service_protocol),
        service_port,
    })
}

fn resolved_implementation_source(entry: &PluginCatalogEntry) -> PluginImplementationSource {
    match entry.implementation_source {
        PluginImplementationSource::ExternalReported => {
            if BUILT_IN_PROTOCOL_PROMOTION_PLUGIN_IDS.contains(&entry.plugin_id) {
                PluginImplementationSource::BuiltIn
            } else if BUNDLED_HTTP_RULE_PLUGIN_IDS.contains(&entry.plugin_id) {
                PluginImplementationSource::BundledDetectorPack
            } else if BUNDLED_VERSION_RULE_PLUGIN_IDS.contains(&entry.plugin_id) {
                PluginImplementationSource::BundledVersionRule
            } else if bundled_protocol_adapter_enabled()
                && BUNDLED_PROTOCOL_RULE_PLUGIN_IDS.contains(&entry.plugin_id)
            {
                PluginImplementationSource::BundledScannerAdapter
            } else {
                PluginImplementationSource::ExternalReported
            }
        }
        other => other,
    }
}

fn plugin_catalog_entry_matches(entry: &PluginCatalogEntry, query: &PluginCatalogQuery) -> bool {
    if query.family.is_some_and(|family| entry.family != family) {
        return false;
    }
    if query
        .leakix_label
        .is_some_and(|label| entry.leakix_label != label)
    {
        return false;
    }
    if query
        .execution_mode
        .is_some_and(|mode| entry.execution_mode != mode)
    {
        return false;
    }
    if query.status.is_some_and(|status| entry.status != status) {
        return false;
    }
    let resolved_source = resolved_implementation_source(entry);
    if query
        .implementation_source
        .is_some_and(|source| resolved_source != source)
    {
        return false;
    }
    if query
        .coverage_status
        .is_some_and(|status| derive_plugin_coverage_status(entry) != status)
    {
        return false;
    }
    if let Some(search) = query.q.as_deref() {
        let coverage_status = derive_plugin_coverage_status(entry);
        let searchable = format!(
            "{} {} {} {} {} {} {} {}",
            entry.plugin_id,
            entry.display_name,
            entry.family.as_str(),
            entry.execution_mode.as_str(),
            entry.status.as_str(),
            entry.leakix_label.as_str(),
            resolved_source.as_str(),
            coverage_status.as_str()
        )
        .to_ascii_lowercase();
        if !searchable.contains(search) {
            return false;
        }
    }
    true
}

fn bucket_counts(values: BTreeMap<String, usize>) -> Vec<PluginCatalogBucketCount> {
    values
        .into_iter()
        .map(|(key, total)| PluginCatalogBucketCount { key, total })
        .collect()
}

fn normalize_metadata_text(value: Option<&str>) -> Option<String> {
    let trimmed = value?.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_cve_ids(values: &[&str]) -> Vec<String> {
    let mut normalized = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let rendered = trimmed.to_ascii_uppercase();
        if !normalized.contains(&rendered) {
            normalized.push(rendered);
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        FindingPluginMetadata, PluginCatalogQuery, PluginCoverageStatus, PluginExecutionMode,
        PluginFamily, PluginImplementationSource, PluginLeakixLabel, PluginStatus,
        build_plugin_metadata, lookup_plugin, plugin_catalog_entries, search_plugin_catalog,
    };

    #[test]
    fn bundled_catalog_matches_expected_counts() {
        let entries = plugin_catalog_entries();
        assert_eq!(entries.len(), 239);
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.leakix_label == PluginLeakixLabel::Public)
                .count(),
            57
        );
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.leakix_label == PluginLeakixLabel::TrustedPro)
                .count(),
            182
        );
    }

    #[test]
    fn bundled_catalog_contains_expected_plugin_ids() {
        for plugin_id in [
            "ApacheStatusPlugin",
            "DotEnvConfigPlugin",
            "JenkinsVersionPlugin",
            "RedisOpenPlugin",
            "OllamaPlugin",
            "ZoneMinderPlugin",
        ] {
            assert!(lookup_plugin(plugin_id).is_some(), "missing {plugin_id}");
        }
    }

    #[test]
    fn plugin_catalog_search_filters_by_query_and_family() {
        let response = search_plugin_catalog(&PluginCatalogQuery {
            q: Some("jenkins".to_string()),
            family: Some(PluginFamily::EnterpriseWebApps),
            ..PluginCatalogQuery::default()
        });
        assert!(
            response
                .plugins
                .iter()
                .any(|entry| entry.entry.plugin_id == "JenkinsOpenPlugin")
        );
        assert!(
            response
                .plugins
                .iter()
                .any(|entry| entry.entry.plugin_id == "JenkinsVersionPlugin")
        );
        assert!(
            response
                .plugins
                .iter()
                .all(|entry| entry.entry.family == PluginFamily::EnterpriseWebApps)
        );
    }

    #[test]
    fn plugin_catalog_search_filters_by_mode_and_status() {
        let response = search_plugin_catalog(&PluginCatalogQuery {
            execution_mode: Some(PluginExecutionMode::PassiveHttp),
            status: Some(PluginStatus::Implemented),
            limit: Some(100),
            ..PluginCatalogQuery::default()
        });
        assert!(
            response
                .plugins
                .iter()
                .any(|entry| entry.entry.plugin_id == "ApacheStatusPlugin")
        );
        assert!(response.plugins.iter().all(|entry| {
            entry.entry.execution_mode == PluginExecutionMode::PassiveHttp
                && entry.entry.status == PluginStatus::Implemented
        }));
    }

    #[test]
    fn plugin_catalog_search_filters_by_implementation_source() {
        let response = search_plugin_catalog(&PluginCatalogQuery {
            implementation_source: Some(PluginImplementationSource::BundledVersionRule),
            status: Some(PluginStatus::Implemented),
            limit: Some(500),
            ..PluginCatalogQuery::default()
        });
        assert!(
            response
                .plugins
                .iter()
                .any(|entry| entry.entry.plugin_id == "AppsmithPlugin")
        );
        assert!(
            response
                .plugins
                .iter()
                .all(|entry| entry.entry.implementation_source
                    == PluginImplementationSource::BundledVersionRule)
        );
    }

    #[test]
    fn plugin_catalog_summary_tracks_implementation_sources() {
        let summary = search_plugin_catalog(&PluginCatalogQuery::default()).summary;
        let by_source = summary
            .by_implementation_source
            .iter()
            .map(|bucket| (bucket.key.as_str(), bucket.total))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(by_source.get("built_in"), Some(&128));
        assert!(!by_source.contains_key("external_reported"));
        assert_eq!(by_source.get("bundled_detector_pack"), Some(&28));
        assert_eq!(by_source.get("bundled_version_rule"), Some(&83));
        assert!(!by_source.contains_key("bundled_scanner_adapter"));
        assert_eq!(summary.first_class_total, 239);
        assert_eq!(summary.external_scanner_only_total, 0);
        assert_eq!(summary.declared_but_inactive_total, 0);
    }

    #[test]
    fn plugin_catalog_search_filters_by_coverage_status() {
        let response = search_plugin_catalog(&PluginCatalogQuery {
            coverage_status: Some(PluginCoverageStatus::FirstClass),
            limit: Some(500),
            ..PluginCatalogQuery::default()
        });

        assert!(!response.plugins.is_empty());
        assert!(
            response
                .plugins
                .iter()
                .any(|entry| entry.entry.plugin_id == "AppsmithPlugin")
        );
        assert!(
            response
                .plugins
                .iter()
                .all(|entry| entry.coverage_status == PluginCoverageStatus::FirstClass)
        );
    }

    #[test]
    fn build_plugin_metadata_enriches_runtime_finding_shape() {
        let metadata = build_plugin_metadata(
            "ApacheStatusPlugin",
            Some("Apache HTTP Server"),
            Some("2.4.62"),
            Some("cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*"),
            &["cve-2024-9999", "CVE-2024-9999", "cve-2024-1111"],
            Some(true),
            Some("http"),
            Some(80),
        )
        .expect("plugin metadata");

        assert_eq!(metadata.plugin_id, "ApacheStatusPlugin");
        assert_eq!(metadata.plugin_family, PluginFamily::OpsObservability);
        assert_eq!(metadata.execution_mode, PluginExecutionMode::PassiveHttp);
        assert_eq!(
            metadata.implementation_source,
            PluginImplementationSource::BuiltIn
        );
        assert_eq!(metadata.product_name.as_deref(), Some("Apache HTTP Server"));
        assert_eq!(metadata.product_version.as_deref(), Some("2.4.62"));
        assert_eq!(metadata.service_protocol.as_deref(), Some("http"));
        assert_eq!(metadata.service_port, Some(80));
        assert_eq!(
            metadata.cve_ids,
            vec!["CVE-2024-9999".to_string(), "CVE-2024-1111".to_string()]
        );
    }

    #[test]
    fn legacy_runtime_plugin_metadata_defaults_to_catalog_implementation_source() {
        let metadata: FindingPluginMetadata = serde_json::from_str(
            r#"{
                "plugin_id":"ApacheActiveMQ",
                "plugin_display_name":"Apache ActiveMQ is outdated",
                "plugin_family":"infra_platform_data",
                "execution_mode":"version_correlation",
                "leakix_label":"trusted_pro",
                "product_name":"Apache ActiveMQ",
                "product_version":"5.18.3",
                "cve_ids":["CVE-2025-0001"]
            }"#,
        )
        .expect("legacy metadata should deserialize");

        assert_eq!(
            metadata.implementation_source,
            PluginImplementationSource::BuiltIn
        );
        assert_eq!(metadata.plugin_id, "ApacheActiveMQ");
    }

    #[test]
    fn active_authorized_lane_is_implemented_but_requires_explicit_gate() {
        let response = search_plugin_catalog(&PluginCatalogQuery {
            execution_mode: Some(PluginExecutionMode::ActiveAuthorized),
            limit: Some(500),
            ..PluginCatalogQuery::default()
        });

        assert!(!response.plugins.is_empty());
        assert!(
            response
                .plugins
                .iter()
                .all(|entry| entry.entry.requires_authorized_active_mode)
        );
        assert!(
            response
                .plugins
                .iter()
                .all(|entry| entry.entry.status == PluginStatus::Implemented)
        );
        assert!(
            response
                .plugins
                .iter()
                .all(|entry| entry.coverage_status == PluginCoverageStatus::FirstClass)
        );
    }

    #[test]
    fn h2_console_plugin_is_first_class_passive_http() {
        let response = search_plugin_catalog(&PluginCatalogQuery {
            q: Some("h2consoleplugin".to_string()),
            ..PluginCatalogQuery::default()
        });
        let entry = response
            .plugins
            .iter()
            .find(|entry| entry.entry.plugin_id == "H2ConsolePlugin")
            .expect("h2 console plugin should be present");
        assert_eq!(entry.entry.execution_mode, PluginExecutionMode::PassiveHttp);
        assert_eq!(
            entry.entry.implementation_source,
            PluginImplementationSource::BuiltIn
        );
        assert_eq!(entry.coverage_status, PluginCoverageStatus::FirstClass);
    }

    #[test]
    fn bundled_http_rules_include_graphql_discovery_signatures() {
        let rules: Vec<serde_json::Value> =
            serde_json::from_str(super::BUNDLED_HTTP_RULES).expect("bundled http rules parse");

        let find_rule = |plugin_id: &str| -> &serde_json::Value {
            rules
                .iter()
                .find(|rule| rule.get("plugin_id").and_then(|v| v.as_str()) == Some(plugin_id))
                .unwrap_or_else(|| panic!("missing bundled http rule {plugin_id}"))
        };
        let rule_string =
            |rule: &serde_json::Value, key: &str| -> Option<String> {
                rule.get(key).and_then(|v| v.as_str()).map(str::to_string)
            };

        for (plugin_id, expected_severity) in [
            ("GraphQLEndpointPlugin", "low"),
            ("GraphiQLConsolePlugin", "medium"),
            ("GraphQLPlaygroundConsolePlugin", "medium"),
            ("GraphQLIntrospectionResponsePlugin", "medium"),
            ("GraphQLErrorEnvelopePlugin", "medium"),
        ] {
            let rule = find_rule(plugin_id);
            assert_eq!(
                rule_string(rule, "severity").as_deref(),
                Some(expected_severity),
                "{plugin_id} severity"
            );
        }

        let endpoint_rule = find_rule("GraphQLEndpointPlugin");
        let endpoint_paths: Vec<&str> = endpoint_rule
            .get("any_of_path_contains")
            .and_then(|v| v.as_array())
            .map(|values| values.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        for expected_path in [
            "/graphql",
            "/graphiql",
            "/playground",
            "/altair",
            "/voyager",
            "/api/graphql",
            "/v1/graphql",
            "/v2/graphql",
            "/__graphql",
            "/api/graphql/console",
            "/.netlify/functions/graphql",
            "/api/2018-09-25/graphql",
        ] {
            assert!(
                endpoint_paths.contains(&expected_path),
                "endpoint discovery rule missing {expected_path}"
            );
        }

        let graphiql_regex_src = rule_string(find_rule("GraphiQLConsolePlugin"), "body_regex")
            .expect("graphiql rule body_regex");
        let graphiql_regex =
            regex::Regex::new(&graphiql_regex_src).expect("graphiql body_regex compiles");
        for graphiql_fixture in [
            "<html><head><title>GraphiQL</title></head><body></body></html>",
            "<div id=\"graphiql\"></div>",
            "<script src=\"//cdn.example.test/react-graphiql/index.js\"></script>",
        ] {
            assert!(
                graphiql_regex.is_match(graphiql_fixture),
                "graphiql body_regex must match: {graphiql_fixture}"
            );
        }

        // Privacy invariant: rules carry tags/metadata only; reviewer_notes is moderator-only and
        // must never reach non-moderator sessions, so it must not be embedded in bundled rules.
        for rule in &rules {
            if let Some(object) = rule.as_object() {
                assert!(
                    !object.contains_key("reviewer_notes"),
                    "bundled http rules must not embed reviewer_notes"
                );
            }
        }
    }
}
