use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::PermissionsExt,
    path::{Path as FsPath, PathBuf},
    process::Command as ProcessCommand,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, anyhow};
use anyscan::{
    archive::{
        ArchiveManifest, download_archive_pointer_manifest, download_archive_pointer_records,
        hydrate_archive_pointer, list_archived_runs, run_archive_pass, search_archived_findings,
    },
    config::AppConfig,
    core::{
        AbuseReportRecord, AbuseReportRequest, ActiveAuthorizedPluginExecution, ApiEvent,
        ArchiveJobRecord, ArchivePointerRecord, ArchiveRecordKind, ArchiveStatusSnapshot,
        BinDatasetImportRequest, BinDatasetStatus, BinLookupLinePreview, BinLookupMatch,
        BinLookupRequest, BinLookupResponse, DashboardSnapshot, FindingRecord, FindingsQuery,
        HybridFindingsRanker, OperatorRole, OptOutRecord, OptOutRequest, OwnershipClaimRecord,
        OwnershipClaimRequest, PortScanRecord, PortScanRequest, PublicFindingModerationRecord,
        PublicFindingModerationRequest, PublicFindingRecord, PublicFindingSearchQuery,
        PublicWorkflowKind, PublicWorkflowStatusUpdate, RecurringScheduleRecord,
        RepositoryDefinition, RepositoryRecord, RunScope, RunSummary, ScanDefaultsSummary,
        ScanRunRecord, TargetDefinition, TargetRecord, WorkerBootstrapCandidateApproval,
        WorkerBootstrapCandidateApprovalRequest, WorkerBootstrapCandidateRecord,
        WorkerBootstrapCandidateRejectionRequest, WorkerBootstrapCodeExchange,
        WorkerBootstrapCodeExchangeRequest, WorkerBootstrapCodeIssueRequest,
        WorkerBootstrapCodeIssued, WorkerBootstrapJobRecord, WorkerEnrollmentTokenIssueRequest,
        WorkerEnrollmentTokenIssued, WorkerEnrollmentTokenRecord, WorkerLifecycleUpdateRequest,
        WorkerPoolRecord, WorkerRecord, WorkerRemoteCommandRecord, WorkerRemoteCommandRequest,
        bin_lookup_line_preview, normalized_bin_lookup_limit, parse_bin_lookup_candidates,
        run_findings_query,
    },
    ops::init_tracing,
    plugins::{PluginCatalogQuery, PluginCatalogResponse, search_plugin_catalog},
    public_verification::verify_public_resource_control,
    store::AnyScanStore,
    worker_api::{
        QueuedRunWithSummary, QueuedScheduleRunRecord, WorkerControlEnvelope, WorkerControlRequest,
        WorkerControlResponse,
    },
};
use async_stream::stream;
use axum::body::Bytes;
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{Html, IntoResponse, Response, Sse},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine as _;
use chrono::Utc;
use clap::Parser;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::Duration as CookieDuration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{info, warn};

mod operator_pages {
    include!("../operator_pages.rs");
}

const SESSION_COOKIE: &str = "anyscan_session";
const HOSTED_AGENT_BUNDLE_OUTPUT_DIR: &str = "/var/lib/anyscan/agent-bundles";
const HOSTED_AGENT_BUNDLE_BUILD_ROOT: &str = "/var/lib/anyscan/agent-bundle-build";
const INSTALLED_AGENT_BINARY_PATH: &str = "/opt/anyscan/bin/anyscan-worker";
const INSTALLED_SCANNER_BINARY_PATH: &str = "/opt/anyscan/bin/scanner";
const INSTALLED_RUNTIME_ENV_PATH: &str = "/etc/anyscan/runtime.env";
const HOSTED_INSTALL_SCRIPT_PATH: &str = "/api/agent/install.sh";
const HOSTED_BOOTSTRAP_SCRIPT_PATH: &str = "/api/agent/bootstrap-agent-host.sh";
const HOSTED_AGENT_BUNDLE_REFRESH_PATH: &str = "/api/agent/bundles/refresh";
const HOSTED_AGENT_BUNDLE_ARTIFACT_PATH_PREFIX: &str = "/api/agent/bundles";
const HOSTED_AGENT_BUNDLE_CHUNK_SIZE: usize = 64 * 1024;
const HOSTED_AGENT_BUNDLE_KEEP_COUNT: usize = 5;
const HOSTED_AGENT_BUNDLE_FINGERPRINT_LEN: usize = 12;
const HOSTED_OPENWRT_OPAL_OUTPUT_DIR: &str = "/var/lib/anyscan/openwrt-opal";
const HOSTED_OPENWRT_OPAL_INSTALL_PATH: &str = "/api/openwrt/opal/install.sh";
const HOSTED_OPENWRT_OPAL_FILE_PATH_PREFIX: &str = "/api/openwrt/opal/files";
const HOSTED_OPENWRT_OPAL_ALLOWED_FILES: &[&str] = &[
    "install-opal-agent.sh",
    "SHA256SUMS",
    "anyscan-agent-core.ipk",
    "anyscan-agent-helpers.ipk",
    "anyscan-agent-scanner.ipk",
    "anyscan-agent-opal-full.ipk",
];

#[derive(Debug, Clone, Copy)]
struct EmbeddedBundleAsset {
    relative_path: &'static str,
    contents: &'static [u8],
    executable: bool,
}

const HOSTED_AGENT_BUNDLE_ASSETS: &[EmbeddedBundleAsset] = &[
    EmbeddedBundleAsset {
        relative_path: "package-worker-bundle.sh",
        contents: include_bytes!("../../package-worker-bundle.sh"),
        executable: true,
    },
    EmbeddedBundleAsset {
        relative_path: "bootstrap-agent-host.sh",
        contents: include_bytes!("../../bootstrap-agent-host.sh"),
        executable: true,
    },
    EmbeddedBundleAsset {
        relative_path: "install-worker-bundle.sh",
        contents: include_bytes!("../../install-worker-bundle.sh"),
        executable: true,
    },
    EmbeddedBundleAsset {
        relative_path: "runtime.worker.env.template",
        contents: include_bytes!("../../runtime.worker.env.template"),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "anyscan-worker-only.service",
        contents: include_bytes!("../../anyscan-worker-only.service"),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "anyscan-worker-tor.service",
        contents: include_bytes!("../../anyscan-worker-tor.service"),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "anyscan-worker-remote-update.service",
        contents: include_bytes!("../../anyscan-worker-remote-update.service"),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "anyscan-worker-remote-update.path",
        contents: include_bytes!("../../anyscan-worker-remote-update.path"),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "agentd-remote-update.sh",
        contents: include_bytes!("../../agentd-remote-update.sh"),
        executable: true,
    },
    EmbeddedBundleAsset {
        relative_path: "local-bootstrap-provisioner.json",
        contents: include_bytes!("../../local-bootstrap-provisioner.json"),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "local-bootstrap-provisioner.py",
        contents: include_bytes!("../../local-bootstrap-provisioner.py"),
        executable: true,
    },
    EmbeddedBundleAsset {
        relative_path: "vulnscanner-zmap-adapter.json",
        contents: include_bytes!("../../vulnscanner-zmap-adapter.json"),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "vulnscanner-zmap-adapter.py",
        contents: include_bytes!("../../vulnscanner-zmap-adapter.py"),
        executable: true,
    },
    EmbeddedBundleAsset {
        relative_path: "extensions/bundled/manifests/bundled-http-plugin-pack.json",
        contents: include_bytes!(
            "../../extensions/bundled/manifests/bundled-http-plugin-pack.json"
        ),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "extensions/bundled/manifests/bundled-protocol-plugin-adapter.json",
        contents: include_bytes!(
            "../../extensions/bundled/manifests/bundled-protocol-plugin-adapter.json"
        ),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "extensions/bundled/manifests/bundled-version-rule-pack.json",
        contents: include_bytes!(
            "../../extensions/bundled/manifests/bundled-version-rule-pack.json"
        ),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "extensions/bundled/rules/http-plugin-rules.json",
        contents: include_bytes!("../../extensions/bundled/rules/http-plugin-rules.json"),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "extensions/bundled/rules/version-plugin-rules.json",
        contents: include_bytes!("../../extensions/bundled/rules/version-plugin-rules.json"),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "extensions/bundled/rules/protocol-plugin-rules.json",
        contents: include_bytes!("../../extensions/bundled/rules/protocol-plugin-rules.json"),
        executable: false,
    },
    EmbeddedBundleAsset {
        relative_path: "extensions/bundled/scripts/bundled-http-plugin-pack.py",
        contents: include_bytes!("../../extensions/bundled/scripts/bundled-http-plugin-pack.py"),
        executable: true,
    },
    EmbeddedBundleAsset {
        relative_path: "extensions/bundled/scripts/bundled-protocol-plugin-adapter.py",
        contents: include_bytes!(
            "../../extensions/bundled/scripts/bundled-protocol-plugin-adapter.py"
        ),
        executable: true,
    },
    EmbeddedBundleAsset {
        relative_path: "extensions/bundled/scripts/bundled-version-rule-pack.py",
        contents: include_bytes!("../../extensions/bundled/scripts/bundled-version-rule-pack.py"),
        executable: true,
    },
];

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, env = "ANYSCAN_CONFIG")]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct AppState {
    config: AppConfig,
    store: AnyScanStore,
    hosted_agent_bundle_build_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    username: String,
    password: String,
}

#[derive(Debug, Clone, Serialize)]
struct SessionPermissions {
    write: bool,
    manage_settings: bool,
    manage_operators: bool,
    manage_workers: bool,
    approve_bootstrap_candidates: bool,
    moderate_public_findings: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SessionResponse {
    username: String,
    role: OperatorRole,
    permissions: SessionPermissions,
}

#[derive(Debug, Default, Deserialize)]
struct RunRequest {
    #[serde(default)]
    scope: Option<RunScope>,
    #[serde(default, alias = "active_authorized_execution")]
    active_authorized_plugins: ActiveAuthorizedPluginExecution,
}

#[derive(Debug, Deserialize)]
struct ScheduleRequest {
    label: String,
    interval_seconds: u64,
    enabled: Option<bool>,
    #[serde(default)]
    scope: Option<RunScope>,
    #[serde(default, alias = "active_authorized_execution")]
    active_authorized_plugins: ActiveAuthorizedPluginExecution,
}

#[derive(Debug, Deserialize)]
struct PortScanQueueRequest {
    #[serde(flatten)]
    request: PortScanRequest,
    #[serde(default, alias = "active_authorized_execution")]
    active_authorized_plugins: ActiveAuthorizedPluginExecution,
}

#[derive(Debug, Clone)]
struct SessionContext {
    username: String,
    role: OperatorRole,
}

#[derive(Debug, Default, Deserialize)]
struct HostedAgentBundleAccessQuery {
    access_token: Option<String>,
    base_url: Option<String>,
    rebuild: Option<bool>,
    platform: Option<String>,
}

#[derive(Debug, Clone)]
struct HostedAgentBundleInfo {
    platform_key: String,
    bundle_name: String,
    sha256_name: String,
    bundle_path: PathBuf,
    sha256_path: PathBuf,
    metadata_path: PathBuf,
    lease_marker_path: PathBuf,
    leased: bool,
    source_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostedAgentBundleMetadata {
    platform_key: String,
    bundle_name: String,
    source_fingerprint: String,
    built_at: String,
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    cursor: Option<i64>,
    run_id: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct RunsQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    include_archive: bool,
}

#[derive(Debug, Default, Deserialize)]
struct ArchivePointersQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    kind: Option<ArchiveRecordKind>,
}

#[derive(Debug, Default, Deserialize)]
struct WorkerRemoteCommandsQuery {
    #[serde(default)]
    worker_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ArchiveHydrateResponse {
    pointer_id: i64,
    restored_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionClaims {
    sub: String,
    role: OperatorRole,
    iat: usize,
    exp: usize,
}

#[derive(Debug, Clone, Serialize)]
struct PublicProfileResponse {
    service_name: String,
    base_url: Option<String>,
    security_email: String,
    abuse_email: String,
    opt_out_email: String,
    scanner_ip_ranges: Vec<String>,
    scanner_asns: Vec<String>,
    reverse_dns_patterns: Vec<String>,
    user_agent_examples: Vec<String>,
    published_search_scope: Vec<String>,
    data_retention_days: u64,
    opt_out_response_sla_hours: u64,
    max_concurrent_requests_per_host: usize,
    allow_authenticated_request_profiles: bool,
    rate_limit_policy: String,
    scanning_policy_url: String,
    scanner_identity_url: String,
    data_policy_url: String,
    claim_url: String,
    opt_out_url: String,
    abuse_url: String,
    security_txt_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::load(cli.config.as_deref())?;
    init_tracing("anyscan-api");

    let store = AnyScanStore::from_config(&config)?;
    store.initialize()?;
    seed_bootstrap_inventory(&store, &config)?;

    let state = Arc::new(AppState {
        config,
        store,
        hosted_agent_bundle_build_lock: Arc::new(Mutex::new(())),
    });
    let app = Router::new()
        .route("/", get(public_index))
        .route("/app", get(operator_app))
        .route("/app/overview", get(operator_pages::operator_overview))
        .route("/app/runs", get(operator_pages::operator_runs))
        .route("/scanning-policy", get(public_page))
        .route("/scanner-identity", get(public_page))
        .route("/opt-out", get(public_page))
        .route("/claim", get(public_page))
        .route("/abuse", get(public_page))
        .route("/data-policy", get(public_page))
        .route("/.well-known/security.txt", get(security_txt))
        .route("/api/public/profile", get(public_profile))
        .route("/api/public/findings", get(list_public_findings))
        .route(
            "/api/public/claims",
            get(list_ownership_claims).post(create_ownership_claim),
        )
        .route(
            "/api/public/claims/{claim_id}/status",
            post(update_ownership_claim_status),
        )
        .route(
            "/api/public/opt-outs",
            get(list_opt_out_requests).post(create_opt_out_request),
        )
        .route(
            "/api/public/opt-outs/{opt_out_id}/status",
            post(update_opt_out_status),
        )
        .route(
            "/api/public/abuse-reports",
            get(list_abuse_reports).post(create_abuse_report),
        )
        .route(
            "/api/public/abuse-reports/{report_id}/status",
            post(update_abuse_report_status),
        )
        .route(HOSTED_INSTALL_SCRIPT_PATH, get(hosted_agent_install_script))
        .route(
            HOSTED_BOOTSTRAP_SCRIPT_PATH,
            get(hosted_agent_bootstrap_script),
        )
        .route(
            HOSTED_AGENT_BUNDLE_REFRESH_PATH,
            get(refresh_hosted_agent_bundle),
        )
        .route(
            "/api/agent/bundles/{filename}/manifest",
            get(get_hosted_agent_bundle_manifest),
        )
        .route(
            "/api/agent/bundles/{filename}/chunks/{chunk_index}",
            get(get_hosted_agent_bundle_chunk),
        )
        .route(
            "/api/agent/bundles/{filename}",
            get(download_hosted_agent_bundle_artifact),
        )
        .route(
            HOSTED_OPENWRT_OPAL_INSTALL_PATH,
            get(hosted_openwrt_opal_install_script),
        )
        .route(
            "/api/openwrt/opal/files/{filename}",
            get(download_hosted_openwrt_opal_file),
        )
        .route("/api/session", post(login).delete(logout))
        .route("/api/me", get(me))
        .route("/api/worker/control", post(worker_control))
        .route("/api/dashboard", get(dashboard))
        .route("/api/archive/status", get(get_archive_status))
        .route("/api/archive/jobs", get(list_archive_jobs))
        .route("/api/archive/pointers", get(list_archive_pointers))
        .route(
            "/api/archive/pointers/{pointer_id}/manifest",
            get(get_archive_manifest),
        )
        .route(
            "/api/archive/pointers/{pointer_id}/records",
            get(get_archive_records),
        )
        .route(
            "/api/archive/pointers/{pointer_id}/hydrate",
            post(hydrate_archive_segment),
        )
        .route("/api/archive/run", post(trigger_archive_run))
        .route(
            "/api/scan-settings",
            get(get_scan_settings).post(update_scan_settings),
        )
        .route("/api/bin-dataset", get(get_bin_dataset_status))
        .route("/api/bin-dataset/import", post(import_bin_dataset))
        .route("/api/bin-lookup", post(bin_lookup))
        .route("/api/plugins", get(list_plugins))
        .route("/api/targets", get(list_targets).post(create_target))
        .route(
            "/api/repositories",
            get(list_repositories).post(create_repository),
        )
        .route(
            "/api/port-scans",
            get(list_port_scans).post(queue_port_scan),
        )
        .route("/api/port-scans/{port_scan_id}/stop", post(stop_port_scan))
        .route("/api/worker-pools", get(list_worker_pools))
        .route("/api/workers", get(list_workers))
        .route(
            "/api/worker-remote-commands",
            get(list_worker_remote_commands),
        )
        .route(
            "/api/workers/remote-update-all",
            post(request_all_worker_remote_updates),
        )
        .route("/api/workers/{worker_id}", get(get_worker))
        .route(
            "/api/workers/{worker_id}/lifecycle",
            post(update_worker_lifecycle),
        )
        .route(
            "/api/workers/{worker_id}/remote-commands",
            post(queue_worker_remote_command),
        )
        .route(
            "/api/workers/{worker_id}/remote-update",
            post(request_worker_remote_update),
        )
        .route(
            "/api/worker-bootstrap-codes",
            post(issue_worker_bootstrap_code),
        )
        .route(
            "/api/worker/bootstrap/exchange",
            post(exchange_worker_bootstrap_code),
        )
        .route(
            "/api/worker-enrollment-tokens",
            get(list_worker_enrollment_tokens).post(issue_worker_enrollment_token),
        )
        .route(
            "/api/worker-enrollment-tokens/{token_id}/revoke",
            post(revoke_worker_enrollment_token),
        )
        .route("/api/bootstrap-candidates", get(list_bootstrap_candidates))
        .route("/api/bootstrap-jobs", get(list_bootstrap_jobs))
        .route(
            "/api/bootstrap-candidates/{candidate_id}/approve",
            post(approve_bootstrap_candidate),
        )
        .route(
            "/api/bootstrap-candidates/{candidate_id}/reject",
            post(reject_bootstrap_candidate),
        )
        .route("/api/runs", get(list_runs).post(queue_run))
        .route("/api/runs/{run_id}/stop", post(stop_run))
        .route("/api/schedules", get(list_schedules).post(create_schedule))
        .route("/api/findings", get(list_findings))
        .route("/api/findings/publications", get(list_finding_publications))
        .route(
            "/api/findings/{finding_id}/publication",
            post(moderate_public_finding),
        )
        .route("/api/events/stream", get(event_stream))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_worker_only_host_routes,
        ))
        .with_state(state.clone());

    let listener = TcpListener::bind(&state.config.server.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", state.config.server.bind_addr))?;
    info!(bind = %state.config.server.bind_addr, "anyscan api listening");
    axum::serve(listener, app)
        .await
        .context("api server failed")?;
    Ok(())
}

async fn public_index() -> Html<&'static str> {
    Html(include_str!("../../public-site.html"))
}

async fn operator_app() -> Html<&'static str> {
    Html(include_str!("../../index.html"))
}

async fn public_page() -> Html<&'static str> {
    Html(include_str!("../../public-site.html"))
}

async fn enforce_worker_only_host_routes(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if request_targets_worker_only_host(request.headers(), &state.config)
        && !worker_only_host_allows_request(request.method(), request.uri().path())
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

fn request_targets_worker_only_host(headers: &HeaderMap, config: &AppConfig) -> bool {
    let Some(host) = request_host(headers) else {
        return false;
    };
    config
        .server
        .worker_only_hosts
        .iter()
        .any(|candidate| candidate == &host)
}

fn request_host(headers: &HeaderMap) -> Option<String> {
    let raw_host = forwarded_header_value(headers, "x-forwarded-host")
        .or_else(|| forwarded_header_value(headers, "host"))?;
    normalize_request_host(&raw_host)
}

fn normalize_request_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(url) = url::Url::parse(&format!("http://{trimmed}")) {
        if let Some(host) = url.host_str() {
            let normalized = host
                .trim()
                .trim_matches(['[', ']'])
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !normalized.is_empty() {
                return Some(normalized);
            }
        }
    }
    let host_without_port = if trimmed.starts_with('[') {
        trimmed
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(trimmed)
    } else if trimmed.matches(':').count() == 1 {
        trimmed
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(trimmed)
    } else {
        trimmed
    };
    let normalized = host_without_port
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

fn worker_only_host_allows_request(method: &Method, path: &str) -> bool {
    if matches!(method, &Method::GET | &Method::HEAD)
        && (path == HOSTED_INSTALL_SCRIPT_PATH
            || path == HOSTED_BOOTSTRAP_SCRIPT_PATH
            || path.starts_with(HOSTED_AGENT_BUNDLE_ARTIFACT_PATH_PREFIX))
    {
        return true;
    }

    matches!(
        (method, path),
        (&Method::POST, "/api/worker/control") | (&Method::POST, "/api/worker/bootstrap/exchange")
    )
}

async fn hosted_agent_install_script(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HostedAgentBundleAccessQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_hosted_agent_bundle_access(query.access_token.as_deref())?;
    let base_url = hosted_agent_effective_base_url(&state, &headers, query.base_url.as_deref())?;
    let rebuild_requested = query.rebuild.unwrap_or(false);
    let install_url_base = hosted_agent_endpoint_url(
        &base_url,
        HOSTED_INSTALL_SCRIPT_PATH,
        query.access_token.as_deref(),
    )?;
    let install_url_base = append_query_parameter(
        install_url_base,
        "rebuild",
        if rebuild_requested { "true" } else { "false" },
    )?;
    let install_url_base =
        append_optional_query_parameter(install_url_base, "base_url", query.base_url.as_deref())?;
    let runtime_management_url = query
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_base_url)
        .or_else(|| Some(base_url.clone()));

    let Some(platform_key) = query
        .platform
        .as_deref()
        .map(normalize_platform_key)
        .transpose()?
    else {
        let script = format!(
            r#"#!/usr/bin/env bash
set -euo pipefail

if [ "${{EUID:-$(id -u)}}" -ne 0 ]; then
    printf '[!] Please run as root. Example: curl -fsSL {install_url} | sudo bash\n' >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    printf '[!] curl is required to fetch the hosted agent bundle.\n' >&2
    exit 1
fi

WORKDIR="$(mktemp -d)"
cleanup() {{
    rm -rf "$WORKDIR"
}}
trap cleanup EXIT
{runtime_env_exports}

normalize_platform_os() {{
    local value="${{1:-}}"
    value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
    case "$value" in
        macos) printf 'darwin\n' ;;
        *) printf '%s\n' "$value" ;;
    esac
}}

normalize_platform_arch() {{
    local value="${{1:-}}"
    value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
    case "$value" in
        amd64|x64) printf 'x86_64\n' ;;
        arm64) printf 'aarch64\n' ;;
        armv7l) printf 'armv7\n' ;;
        armv6l) printf 'armv6\n' ;;
        *) printf '%s\n' "$value" ;;
    esac
}}

TARGET_PLATFORM="$(normalize_platform_os "$(uname -s)")-$(normalize_platform_arch "$(uname -m)")"
PLATFORM_INSTALL_URL={install_url}
case "$PLATFORM_INSTALL_URL" in
    *\?*) PLATFORM_INSTALL_URL="${{PLATFORM_INSTALL_URL}}&platform=${{TARGET_PLATFORM}}" ;;
    *) PLATFORM_INSTALL_URL="${{PLATFORM_INSTALL_URL}}?platform=${{TARGET_PLATFORM}}" ;;
esac

curl -fsSL \
    --retry 8 \
    --retry-delay 2 \
    --retry-all-errors \
    --connect-timeout 20 \
    --max-time 180 \
    "$PLATFORM_INSTALL_URL" -o "$WORKDIR/agent-install.sh"
exec bash "$WORKDIR/agent-install.sh"
"#,
            install_url = shell_single_quote(&install_url_base),
            runtime_env_exports =
                render_install_runtime_overrides_script(runtime_management_url.as_deref()),
        );
        return Ok((
            [
                (
                    header::CONTENT_TYPE,
                    "text/x-shellscript; charset=utf-8".to_string(),
                ),
                (
                    header::CACHE_CONTROL,
                    "no-store, no-cache, private".to_string(),
                ),
            ],
            script,
        ));
    };

    let bundle = if rebuild_requested {
        allocate_fresh_hosted_agent_bundle(&state, &platform_key).await?
    } else {
        lease_cached_hosted_agent_bundle(&state, &platform_key).await?
    };
    if !rebuild_requested {
        trigger_hosted_agent_bundle_rebuild(state.clone(), platform_key.clone());
    }
    let bootstrap_url = hosted_agent_endpoint_url(
        &base_url,
        HOSTED_BOOTSTRAP_SCRIPT_PATH,
        query.access_token.as_deref(),
    )?;
    let install_url = append_query_parameter(install_url_base, "platform", &platform_key)?;
    let bundle_url = hosted_agent_endpoint_url(
        &base_url,
        &format!(
            "{}/{}",
            HOSTED_AGENT_BUNDLE_ARTIFACT_PATH_PREFIX, bundle.bundle_name
        ),
        query.access_token.as_deref(),
    )?;
    let sha256_url = hosted_agent_endpoint_url(
        &base_url,
        &format!(
            "{}/{}",
            HOSTED_AGENT_BUNDLE_ARTIFACT_PATH_PREFIX, bundle.sha256_name
        ),
        query.access_token.as_deref(),
    )?;
    let bundle_manifest_url = hosted_agent_endpoint_url(
        &base_url,
        &format!(
            "{}/{}/manifest",
            HOSTED_AGENT_BUNDLE_ARTIFACT_PATH_PREFIX, bundle.bundle_name
        ),
        query.access_token.as_deref(),
    )?;
    let bundle_manifest_url = append_optional_query_parameter(
        bundle_manifest_url,
        "base_url",
        query.base_url.as_deref(),
    )?;
    let force_chunked_download = query
        .base_url
        .as_deref()
        .is_some_and(should_force_chunked_download);
    let script = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

if [ "${{EUID:-$(id -u)}}" -ne 0 ]; then
    printf '[!] Please run as root. Example: curl -fsSL {install_url} | sudo bash\n' >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    printf '[!] curl is required to fetch the hosted agent bundle.\n' >&2
    exit 1
fi

WORKDIR="$(mktemp -d)"
cleanup() {{
    rm -rf "$WORKDIR"
}}
trap cleanup EXIT
{runtime_env_exports}

fetch() {{
    local url="$1"
    local dest="$2"
    curl -fsSL \
        --retry 8 \
        --retry-delay 2 \
        --retry-all-errors \
        --connect-timeout 20 \
        --max-time 180 \
        "$url" -o "$dest"
}}

fetch_bundle_chunked() {{
    local manifest_url="$1"
    local dest="$2"
    local manifest_file="$WORKDIR/bundle.manifest"
    local chunk_dir="$WORKDIR/bundle-chunks"
    mkdir -p "$chunk_dir"
    fetch "$manifest_url" "$manifest_file"
    set -a
    . "$manifest_file"
    set +a

    : "${{BUNDLE_CHUNK_COUNT:?missing BUNDLE_CHUNK_COUNT}}"
    : "${{BUNDLE_CHUNK_BASE_URL:?missing BUNDLE_CHUNK_BASE_URL}}"

    : > "$dest.b64"
    local chunk_index
    for ((chunk_index = 0; chunk_index < BUNDLE_CHUNK_COUNT; chunk_index++)); do
        printf '[*] Downloading bundle chunk %s/%s...\n' "$((chunk_index + 1))" "$BUNDLE_CHUNK_COUNT"
        fetch "${{BUNDLE_CHUNK_BASE_URL}}/${{chunk_index}}" "$chunk_dir/${{chunk_index}}.b64"
        cat "$chunk_dir/${{chunk_index}}.b64" >> "$dest.b64"
    done

    if command -v base64 >/dev/null 2>&1; then
        base64 -d "$dest.b64" > "$dest"
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$dest.b64" "$dest" <<'PY'
import base64
import pathlib
import sys
source = pathlib.Path(sys.argv[1]).read_bytes()
pathlib.Path(sys.argv[2]).write_bytes(base64.b64decode(source))
PY
    else
        printf '[!] bundle fallback requires base64 or python3 on this host.\n' >&2
        exit 1
    fi

    rm -rf "$chunk_dir" "$manifest_file" "$dest.b64"
}}

BUNDLE_NAME={bundle_name}
BUNDLE_SHA256_NAME={sha_name}
BUNDLE_URL={bundle_url}
BUNDLE_SHA256_URL={sha_url}
BUNDLE_MANIFEST_URL={manifest_url}
BUNDLE_FORCE_CHUNKED={force_chunked}
printf '[*] Downloading hosted agent bootstrap helper...\n'
fetch {bootstrap_url} "$WORKDIR/bootstrap-agent-host.sh"
chmod 0755 "$WORKDIR/bootstrap-agent-host.sh"

printf "[*] Downloading $BUNDLE_NAME...\n"
if [ "$BUNDLE_FORCE_CHUNKED" = "true" ]; then
    fetch_bundle_chunked "$BUNDLE_MANIFEST_URL" "$WORKDIR/$BUNDLE_NAME"
elif ! fetch "$BUNDLE_URL" "$WORKDIR/$BUNDLE_NAME"; then
    printf '[!] direct bundle download failed; falling back to chunked transfer.\n' >&2
    fetch_bundle_chunked "$BUNDLE_MANIFEST_URL" "$WORKDIR/$BUNDLE_NAME"
fi
printf "[*] Downloading $BUNDLE_SHA256_NAME...\n"
fetch "$BUNDLE_SHA256_URL" "$WORKDIR/$BUNDLE_SHA256_NAME"

exec bash "$WORKDIR/bootstrap-agent-host.sh" \
    "$WORKDIR/$BUNDLE_NAME" \
    "$WORKDIR/$BUNDLE_SHA256_NAME"
"#,
        install_url = shell_single_quote(&install_url),
        bundle_name = shell_single_quote(&bundle.bundle_name),
        sha_name = shell_single_quote(&bundle.sha256_name),
        bundle_url = shell_single_quote(&bundle_url),
        sha_url = shell_single_quote(&sha256_url),
        manifest_url = shell_single_quote(&bundle_manifest_url),
        force_chunked = if force_chunked_download {
            shell_single_quote("true")
        } else {
            shell_single_quote("false")
        },
        bootstrap_url = shell_single_quote(&bootstrap_url),
        runtime_env_exports =
            render_install_runtime_overrides_script(runtime_management_url.as_deref()),
    );
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "text/x-shellscript; charset=utf-8".to_string(),
            ),
            (
                header::CACHE_CONTROL,
                "no-store, no-cache, private".to_string(),
            ),
        ],
        script,
    ))
}

async fn hosted_agent_bootstrap_script(
    Query(query): Query<HostedAgentBundleAccessQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    require_hosted_agent_bundle_access(query.access_token.as_deref())?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "text/x-shellscript; charset=utf-8".to_string(),
            ),
            (
                header::CACHE_CONTROL,
                "no-store, no-cache, private".to_string(),
            ),
        ],
        include_str!("../../bootstrap-agent-host.sh"),
    ))
}

async fn hosted_openwrt_opal_install_script(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HostedAgentBundleAccessQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_hosted_agent_bundle_access(query.access_token.as_deref())?;
    let base_url = hosted_agent_effective_base_url(&state, &headers, query.base_url.as_deref())?;
    let package_base_url = hosted_agent_endpoint_url(
        &base_url,
        HOSTED_OPENWRT_OPAL_FILE_PATH_PREFIX,
        query.access_token.as_deref(),
    )?;
    let package_base_url =
        append_optional_query_parameter(package_base_url, "base_url", query.base_url.as_deref())?;
    let installer_body = include_str!("../../openwrt/install-opal-agent.sh")
        .strip_prefix("#!/bin/sh\n")
        .unwrap_or(include_str!("../../openwrt/install-opal-agent.sh"));
    let script = format!(
        "#!/bin/sh\nset -eu\nexport ANYSCAN_OPAL_BASE_URL={base_url}\n{body}",
        base_url = shell_single_quote(&package_base_url),
        body = installer_body,
    );
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "text/x-shellscript; charset=utf-8".to_string(),
            ),
            (
                header::CACHE_CONTROL,
                "no-store, no-cache, private".to_string(),
            ),
        ],
        script,
    ))
}

async fn download_hosted_openwrt_opal_file(
    Query(query): Query<HostedAgentBundleAccessQuery>,
    Path(filename): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    require_hosted_agent_bundle_access(query.access_token.as_deref())?;
    if !HOSTED_OPENWRT_OPAL_ALLOWED_FILES
        .iter()
        .any(|allowed| *allowed == filename)
    {
        return Err(StatusCode::NOT_FOUND);
    }
    let artifact_path = PathBuf::from(HOSTED_OPENWRT_OPAL_OUTPUT_DIR).join(&filename);
    let body = tokio::fs::read(&artifact_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let content_type = if filename.ends_with(".ipk") {
        "application/octet-stream"
    } else if filename.ends_with(".sh") {
        "text/x-shellscript; charset=utf-8"
    } else {
        "text/plain; charset=utf-8"
    };
    Ok((
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CACHE_CONTROL,
                "no-store, no-cache, private".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        Bytes::from(body),
    ))
}

async fn refresh_hosted_agent_bundle(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HostedAgentBundleAccessQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_hosted_agent_bundle_access(query.access_token.as_deref())?;
    let base_url = hosted_agent_effective_base_url(&state, &headers, query.base_url.as_deref())?;
    let platform_key = query
        .platform
        .as_deref()
        .map(normalize_platform_key)
        .transpose()?
        .unwrap_or_else(|| native_hosted_agent_platform_key().to_string());
    let bundle = ensure_hosted_agent_bundle(&state, &platform_key, true).await?;
    let bundle_url = hosted_agent_endpoint_url(
        &base_url,
        &format!(
            "{}/{}",
            HOSTED_AGENT_BUNDLE_ARTIFACT_PATH_PREFIX, bundle.bundle_name
        ),
        query.access_token.as_deref(),
    )?;
    let sha256_url = hosted_agent_endpoint_url(
        &base_url,
        &format!(
            "{}/{}",
            HOSTED_AGENT_BUNDLE_ARTIFACT_PATH_PREFIX, bundle.sha256_name
        ),
        query.access_token.as_deref(),
    )?;
    let response = format!(
        "PLATFORM={}\nBUNDLE_NAME={}\nBUNDLE_SHA256_NAME={}\nBUNDLE_URL={}\nBUNDLE_SHA256_URL={}\n",
        shell_single_quote(&bundle.platform_key),
        shell_single_quote(&bundle.bundle_name),
        shell_single_quote(&bundle.sha256_name),
        shell_single_quote(&bundle_url),
        shell_single_quote(&sha256_url),
    );
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                header::CACHE_CONTROL,
                "no-store, no-cache, private".to_string(),
            ),
        ],
        response,
    ))
}

async fn download_hosted_agent_bundle_artifact(
    State(_state): State<Arc<AppState>>,
    Path(filename): Path<String>,
    Query(query): Query<HostedAgentBundleAccessQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    require_hosted_agent_bundle_access(query.access_token.as_deref())?;
    let bundle =
        resolve_hosted_agent_bundle_by_name(&filename).map_err(|_| StatusCode::NOT_FOUND)?;
    let artifact_path = if filename == bundle.bundle_name {
        bundle.bundle_path
    } else if filename == bundle.sha256_name {
        bundle.sha256_path
    } else {
        return Err(StatusCode::NOT_FOUND);
    };
    let body = tokio::fs::read(&artifact_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let content_type = if filename.ends_with(".tar.gz") {
        "application/gzip"
    } else {
        "text/plain; charset=utf-8"
    };
    Ok((
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CACHE_CONTROL,
                "no-store, no-cache, private".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        Bytes::from(body),
    ))
}

async fn get_hosted_agent_bundle_manifest(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
    Query(query): Query<HostedAgentBundleAccessQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_hosted_agent_bundle_access(query.access_token.as_deref())?;
    let bundle =
        resolve_hosted_agent_bundle_by_name(&filename).map_err(|_| StatusCode::NOT_FOUND)?;
    let base_url = hosted_agent_effective_base_url(&state, &headers, query.base_url.as_deref())?;
    let chunk_base_url = hosted_agent_endpoint_url(
        &base_url,
        &format!(
            "{}/{}/chunks",
            HOSTED_AGENT_BUNDLE_ARTIFACT_PATH_PREFIX, bundle.bundle_name
        ),
        query.access_token.as_deref(),
    )?;
    let metadata = fs::metadata(&bundle.bundle_path).map_err(|_| StatusCode::NOT_FOUND)?;
    let bundle_size_bytes = metadata.len() as usize;
    let chunk_count =
        (bundle_size_bytes + HOSTED_AGENT_BUNDLE_CHUNK_SIZE - 1) / HOSTED_AGENT_BUNDLE_CHUNK_SIZE;
    let manifest = format!(
        "BUNDLE_NAME={}\nBUNDLE_CHUNK_SIZE={}\nBUNDLE_CHUNK_COUNT={}\nBUNDLE_SIZE_BYTES={}\nBUNDLE_CHUNK_BASE_URL={}\n",
        shell_single_quote(&bundle.bundle_name),
        HOSTED_AGENT_BUNDLE_CHUNK_SIZE,
        chunk_count,
        bundle_size_bytes,
        shell_single_quote(&chunk_base_url),
    );
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                header::CACHE_CONTROL,
                "no-store, no-cache, private".to_string(),
            ),
        ],
        manifest,
    ))
}

async fn get_hosted_agent_bundle_chunk(
    State(_state): State<Arc<AppState>>,
    Path((filename, chunk_index)): Path<(String, usize)>,
    Query(query): Query<HostedAgentBundleAccessQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    require_hosted_agent_bundle_access(query.access_token.as_deref())?;
    let bundle =
        resolve_hosted_agent_bundle_by_name(&filename).map_err(|_| StatusCode::NOT_FOUND)?;
    let chunk = read_bundle_chunk_base64(&bundle.bundle_path, chunk_index)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                header::CACHE_CONTROL,
                "no-store, no-cache, private".to_string(),
            ),
        ],
        chunk,
    ))
}

async fn security_txt(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        build_security_txt(&state.config),
    )
}

async fn public_profile(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PublicProfileResponse>, StatusCode> {
    let scan_defaults = load_effective_scan_defaults(&state)?;
    Ok(Json(build_public_profile_response(
        &state.config,
        &scan_defaults,
    )))
}

async fn list_public_findings(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PublicFindingSearchQuery>,
) -> Result<Json<Vec<PublicFindingRecord>>, StatusCode> {
    let findings = state
        .store
        .search_public_findings(&query)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(findings))
}

async fn list_plugins(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<PluginCatalogQuery>,
) -> Result<Json<PluginCatalogResponse>, StatusCode> {
    require_auth(&state, &jar)?;
    Ok(Json(search_plugin_catalog(&query)))
}

async fn create_ownership_claim(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<OwnershipClaimRequest>,
) -> Result<(StatusCode, Json<OwnershipClaimRecord>), StatusCode> {
    let mut record = state
        .store
        .create_ownership_claim(&payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let verification = verify_public_resource_control(
        record.resource_kind,
        &record.resource,
        record.verification_method,
        &record.verification_value,
        &record.requester_email,
    )
    .await;
    match state.store.apply_ownership_claim_verification(
        record.id,
        verification.status,
        Some(&verification.summary),
        verification.verification_attempted_at,
        verification.verification_completed_at,
    ) {
        Ok(updated) => record = updated,
        Err(error) => warn!(
            claim_id = record.id,
            ?error,
            "failed to persist ownership claim verification result"
        ),
    }
    let _ = state.store.append_event(
        None,
        &ApiEvent::PublicWorkflowRecorded {
            workflow: PublicWorkflowKind::OwnershipClaim,
            record_id: record.id,
            resource: record.resource.clone(),
            status: record.status,
        },
    );
    Ok((StatusCode::CREATED, Json(record)))
}

async fn list_ownership_claims(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<OwnershipClaimRecord>>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let records = state
        .store
        .list_ownership_claims()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(records))
}

async fn update_ownership_claim_status(
    Path(claim_id): Path<i64>,
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<PublicWorkflowStatusUpdate>,
) -> Result<Json<OwnershipClaimRecord>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let record = state
        .store
        .update_ownership_claim_status(claim_id, &payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let _ = state.store.append_event(
        None,
        &ApiEvent::PublicWorkflowRecorded {
            workflow: PublicWorkflowKind::OwnershipClaim,
            record_id: record.id,
            resource: record.resource.clone(),
            status: record.status,
        },
    );
    Ok(Json(record))
}

async fn create_opt_out_request(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<OptOutRequest>,
) -> Result<(StatusCode, Json<OptOutRecord>), StatusCode> {
    let mut record = state
        .store
        .create_opt_out_request(&payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let verification = verify_public_resource_control(
        record.resource_kind,
        &record.resource,
        record.verification_method,
        &record.verification_value,
        &record.requester_email,
    )
    .await;
    match state.store.apply_opt_out_verification(
        record.id,
        verification.status,
        Some(&verification.summary),
        verification.verification_attempted_at,
        verification.verification_completed_at,
    ) {
        Ok(updated) => record = updated,
        Err(error) => warn!(
            opt_out_id = record.id,
            ?error,
            "failed to persist opt-out verification result"
        ),
    }
    let _ = state.store.append_event(
        None,
        &ApiEvent::PublicWorkflowRecorded {
            workflow: PublicWorkflowKind::OptOut,
            record_id: record.id,
            resource: record.resource.clone(),
            status: record.status,
        },
    );
    Ok((StatusCode::CREATED, Json(record)))
}

async fn list_opt_out_requests(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<OptOutRecord>>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let records = state
        .store
        .list_opt_out_requests()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(records))
}

async fn update_opt_out_status(
    Path(opt_out_id): Path<i64>,
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<PublicWorkflowStatusUpdate>,
) -> Result<Json<OptOutRecord>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let record = state
        .store
        .update_opt_out_status(opt_out_id, &payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let _ = state.store.append_event(
        None,
        &ApiEvent::PublicWorkflowRecorded {
            workflow: PublicWorkflowKind::OptOut,
            record_id: record.id,
            resource: record.resource.clone(),
            status: record.status,
        },
    );
    Ok(Json(record))
}

async fn create_abuse_report(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AbuseReportRequest>,
) -> Result<(StatusCode, Json<AbuseReportRecord>), StatusCode> {
    let record = state
        .store
        .create_abuse_report(&payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let _ = state.store.append_event(
        None,
        &ApiEvent::PublicWorkflowRecorded {
            workflow: PublicWorkflowKind::AbuseReport,
            record_id: record.id,
            resource: record.affected_resource.clone(),
            status: record.status,
        },
    );
    Ok((StatusCode::CREATED, Json(record)))
}

async fn list_abuse_reports(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<AbuseReportRecord>>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let records = state
        .store
        .list_abuse_reports()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(records))
}

async fn update_abuse_report_status(
    Path(report_id): Path<i64>,
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<PublicWorkflowStatusUpdate>,
) -> Result<Json<AbuseReportRecord>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let record = state
        .store
        .update_abuse_report_status(report_id, &payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let _ = state.store.append_event(
        None,
        &ApiEvent::PublicWorkflowRecorded {
            workflow: PublicWorkflowKind::AbuseReport,
            record_id: record.id,
            resource: record.affected_resource.clone(),
            status: record.status,
        },
    );
    Ok(Json(record))
}

async fn login(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<SessionRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let Some(operator) = state
        .config
        .authenticate_operator(&payload.username, &payload.password)
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let session = SessionContext {
        username: operator.username,
        role: operator.role,
    };

    let token = build_session_token(&state.config, &session)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cookie = Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(
            state.config.auth.session_ttl_seconds as i64,
        ))
        .build();

    Ok((jar.add(cookie), Json(session_response(&session))))
}

async fn logout(jar: CookieJar) -> impl IntoResponse {
    let cookie = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(0))
        .build();
    (jar.remove(cookie), StatusCode::NO_CONTENT)
}

async fn me(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<SessionResponse>, StatusCode> {
    let session = require_auth(&state, &jar)?;
    Ok(Json(session_response(&session)))
}

async fn worker_control(
    State(state): State<Arc<AppState>>,
    Json(mut envelope): Json<WorkerControlEnvelope>,
) -> Result<Json<WorkerControlResponse>, StatusCode> {
    envelope.worker_id = envelope.worker_id.trim().to_string();
    envelope.worker_token = envelope.worker_token.trim().to_string();
    if envelope.worker_id.is_empty() || envelope.worker_token.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match &envelope.request {
        WorkerControlRequest::RegisterWorker { registration, .. } => {
            let requested_worker_id = registration.worker_id.trim();
            if !requested_worker_id.is_empty() && requested_worker_id != envelope.worker_id {
                return Err(StatusCode::BAD_REQUEST);
            }
            if let Err(registration_error) = state
                .store
                .authenticate_worker_registration_token(&envelope.worker_id, &envelope.worker_token)
            {
                state
                    .store
                    .authenticate_registered_worker_token(
                        &envelope.worker_id,
                        &envelope.worker_token,
                    )
                    .map_err(|_| worker_auth_error_status(registration_error))?;
            }
        }
        _ => {
            state
                .store
                .authenticate_registered_worker_token(&envelope.worker_id, &envelope.worker_token)
                .map_err(worker_auth_error_status)?;
        }
    }

    let response = match envelope.request {
        WorkerControlRequest::RegisterWorker {
            mut registration,
            ttl_seconds,
        } => {
            registration.worker_id = envelope.worker_id.clone();
            registration.enrollment_token = Some(envelope.worker_token.clone());
            WorkerControlResponse::WorkerRecord {
                worker: state
                    .store
                    .register_worker(&registration, ttl_seconds)
                    .map_err(|_| StatusCode::BAD_REQUEST)?,
            }
        }
        WorkerControlRequest::QueueDueScheduleRunsWithEvents { limit } => {
            let mut queued = Vec::new();
            for (schedule, run) in state
                .store
                .queue_due_schedule_runs(limit)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            {
                let summary = state
                    .store
                    .summary(run.id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                state
                    .store
                    .append_event(
                        Some(run.id),
                        &ApiEvent::RunQueued {
                            run: run.clone(),
                            summary,
                        },
                    )
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                queued.push(QueuedScheduleRunRecord { schedule, run });
            }
            WorkerControlResponse::QueuedScheduleRuns { queued }
        }
        WorkerControlRequest::QueueRunWithEvent {
            requested_by,
            scope,
        } => {
            let run = state
                .store
                .queue_run(Some(&requested_by), scope.as_ref())
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            let summary = state
                .store
                .summary(run.id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            state
                .store
                .append_event(
                    Some(run.id),
                    &ApiEvent::RunQueued {
                        run: run.clone(),
                        summary: summary.clone(),
                    },
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            WorkerControlResponse::QueuedRunWithSummary {
                queued: QueuedRunWithSummary { run, summary },
            }
        }
        WorkerControlRequest::MaybeRunArchivePass => WorkerControlResponse::OptionalArchiveJob {
            job: run_archive_pass(&state.config, &state.store, &envelope.worker_id)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::ClaimNextRunnableRun { lease_seconds } => {
            WorkerControlResponse::OptionalRun {
                run: state
                    .store
                    .claim_next_runnable_run(&envelope.worker_id, lease_seconds)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::ClaimNextPendingBootstrapJob { lease_seconds } => {
            WorkerControlResponse::OptionalBootstrapJobClaim {
                claim: state
                    .store
                    .claim_next_pending_bootstrap_job(&envelope.worker_id, lease_seconds)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::ClaimNextPendingPortScan { lease_seconds } => {
            WorkerControlResponse::OptionalPortScan {
                port_scan: state
                    .store
                    .claim_next_pending_port_scan(&envelope.worker_id, lease_seconds)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::NextAssistableRun => WorkerControlResponse::OptionalRun {
            run: state
                .store
                .next_assistable_run(&envelope.worker_id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::RequeueInProgressJobs { run_id } => {
            state
                .store
                .requeue_in_progress_jobs(run_id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            WorkerControlResponse::Ack
        }
        WorkerControlRequest::MarkRunStartedIfQueued { run_id } => {
            WorkerControlResponse::OptionalRun {
                run: state
                    .store
                    .mark_run_started_if_queued(run_id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::Summary { run_id } => WorkerControlResponse::RunSummary {
            summary: state
                .store
                .summary(run_id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::AppendEvent { run_id, event } => WorkerControlResponse::EventId {
            event_id: state
                .store
                .append_event(run_id, &event)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::HasIncompleteJobs { run_id } => WorkerControlResponse::Bool {
            value: state
                .store
                .has_incomplete_jobs(run_id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::MarkRunFinishedIfOwned { run_id, notes } => {
            WorkerControlResponse::OptionalFinishedRun {
                run: state
                    .store
                    .mark_run_finished_if_owned(run_id, &envelope.worker_id, notes.as_deref())
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::AcknowledgeStoppingRun { run_id, notes } => {
            WorkerControlResponse::OptionalFinishedRun {
                run: state
                    .store
                    .acknowledge_stopping_run(run_id, notes.as_deref())
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::GetRun { run_id } => WorkerControlResponse::OptionalRun {
            run: state
                .store
                .get_run(run_id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::GetPortScan { port_scan_id } => {
            WorkerControlResponse::OptionalPortScan {
                port_scan: state
                    .store
                    .get_port_scan(port_scan_id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::LoadPortScanResumeState { port_scan_id } => {
            WorkerControlResponse::OptionalPortScanResumeState {
                resume_state: state
                    .store
                    .load_port_scan_resume_state(port_scan_id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::ClaimNextPendingJob {
            run_id,
            lease_seconds,
        } => WorkerControlResponse::OptionalJob {
            job: state
                .store
                .claim_next_pending_job(run_id, &envelope.worker_id, lease_seconds)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::RecordFindingIfNew { finding } => {
            WorkerControlResponse::OptionalFinding {
                finding: state
                    .store
                    .record_finding_if_new(&finding)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::MergeTargetDiscoveryProvenance {
            target_id,
            discovery_provenance,
        } => {
            state
                .store
                .merge_target_discovery_provenance(target_id, &discovery_provenance)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            WorkerControlResponse::Ack
        }
        WorkerControlRequest::MarkJobFinishedIfOwned {
            job_id,
            findings_count,
            telemetry,
            error,
        } => WorkerControlResponse::Bool {
            value: state
                .store
                .mark_job_finished_if_owned(
                    job_id,
                    &envelope.worker_id,
                    findings_count,
                    &telemetry,
                    error.as_deref(),
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::MarkPortScanStartedIfQueued { port_scan_id } => {
            WorkerControlResponse::OptionalStartedPortScan {
                port_scan: state
                    .store
                    .mark_port_scan_started_if_queued(port_scan_id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::UpdatePortScanProgressIfOwned {
            port_scan_id,
            discovered_endpoints_total,
            probe_rate_millis,
            receive_rate_millis,
            progress_percent,
        } => WorkerControlResponse::OptionalPortScan {
            port_scan: state
                .store
                .update_port_scan_progress_if_owned(
                    port_scan_id,
                    &envelope.worker_id,
                    discovered_endpoints_total,
                    probe_rate_millis,
                    receive_rate_millis,
                    progress_percent,
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::UpdatePortScanResumeStateIfOwned {
            port_scan_id,
            checkpoint_data,
            output_snapshot,
        } => WorkerControlResponse::OptionalPortScan {
            port_scan: state
                .store
                .update_port_scan_resume_state_if_owned(
                    port_scan_id,
                    &envelope.worker_id,
                    checkpoint_data.as_deref(),
                    output_snapshot.as_deref(),
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::AnnotatePortScanIfOwned { port_scan_id, note } => {
            WorkerControlResponse::OptionalPortScan {
                port_scan: state
                    .store
                    .annotate_port_scan_if_owned(
                        port_scan_id,
                        &envelope.worker_id,
                        &note,
                    )
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::CompletePortScanIfOwned {
            port_scan_id,
            discovered_endpoints_total,
            imported_targets_total,
            protocol_findings,
            queued_run_id,
            notes,
        } => WorkerControlResponse::OptionalPortScan {
            port_scan: state
                .store
                .complete_port_scan_if_owned(
                    port_scan_id,
                    &envelope.worker_id,
                    discovered_endpoints_total,
                    imported_targets_total,
                    &protocol_findings,
                    queued_run_id,
                    notes.as_deref(),
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::AppendPortScanFollowOnRunId {
            port_scan_id,
            run_id,
        } => WorkerControlResponse::OptionalPortScan {
            port_scan: state
                .store
                .append_port_scan_follow_on_run_id_if_owned(
                    port_scan_id,
                    &envelope.worker_id,
                    run_id,
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::CountActiveJobsForRuns { run_ids } => {
            WorkerControlResponse::ActiveJobCount {
                active_jobs: state
                    .store
                    .count_active_jobs_for_runs(&run_ids)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::FailPortScanIfOwned {
            port_scan_id,
            notes,
        } => WorkerControlResponse::OptionalPortScan {
            port_scan: state
                .store
                .fail_port_scan_if_owned(port_scan_id, &envelope.worker_id, notes.as_deref())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::AcknowledgeStoppingPortScan {
            port_scan_id,
            notes,
        } => WorkerControlResponse::OptionalPortScan {
            port_scan: state
                .store
                .acknowledge_stopping_port_scan(port_scan_id, notes.as_deref())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::CreateBootstrapCandidates {
            port_scan,
            candidates,
        } => WorkerControlResponse::BootstrapCandidates {
            candidates: state
                .store
                .create_bootstrap_candidates(&port_scan, &candidates)
                .map_err(|_| StatusCode::BAD_REQUEST)?,
        },
        WorkerControlRequest::MarkBootstrapJobStartedIfOwned { job_id } => {
            WorkerControlResponse::OptionalBootstrapJob {
                job: state
                    .store
                    .mark_bootstrap_job_started_if_owned(job_id, &envelope.worker_id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::CompleteBootstrapJobIfOwned { job_id, notes } => {
            WorkerControlResponse::OptionalBootstrapJob {
                job: state
                    .store
                    .complete_bootstrap_job_if_owned(job_id, &envelope.worker_id, notes.as_deref())
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::FailBootstrapJobIfOwned { job_id, notes } => {
            WorkerControlResponse::OptionalBootstrapJob {
                job: state
                    .store
                    .fail_bootstrap_job_if_owned(job_id, &envelope.worker_id, notes.as_deref())
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::RenewPortScanClaim {
            port_scan_id,
            lease_seconds,
        } => {
            state
                .store
                .renew_port_scan_claim(port_scan_id, &envelope.worker_id, lease_seconds)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            WorkerControlResponse::Ack
        }
        WorkerControlRequest::RenewBootstrapJobClaim {
            job_id,
            lease_seconds,
        } => {
            state
                .store
                .renew_bootstrap_job_claim(job_id, &envelope.worker_id, lease_seconds)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            WorkerControlResponse::Ack
        }
        WorkerControlRequest::RenewJobClaim {
            job_id,
            lease_seconds,
        } => {
            state
                .store
                .renew_job_claim(job_id, &envelope.worker_id, lease_seconds)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            WorkerControlResponse::Ack
        }
        WorkerControlRequest::RenewRunClaim {
            run_id,
            lease_seconds,
        } => {
            state
                .store
                .renew_run_claim(run_id, &envelope.worker_id, lease_seconds)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            WorkerControlResponse::Ack
        }
        WorkerControlRequest::ClaimNextPendingRemoteCommand => {
            WorkerControlResponse::OptionalRemoteCommand {
                command: state
                    .store
                    .claim_next_pending_worker_remote_command(&envelope.worker_id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            }
        }
        WorkerControlRequest::CompleteRemoteCommand {
            command_id,
            exit_code,
            timed_out,
            stdout,
            stderr,
            error,
        } => WorkerControlResponse::OptionalRemoteCommand {
            command: state
                .store
                .complete_worker_remote_command_if_owned(
                    command_id,
                    &envelope.worker_id,
                    exit_code,
                    timed_out,
                    stdout.as_deref(),
                    stderr.as_deref(),
                    error.as_deref(),
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
        WorkerControlRequest::AcknowledgeRemoteUpdate { requested_at } => {
            WorkerControlResponse::WorkerRecord {
                worker: state
                    .store
                    .acknowledge_worker_remote_update(&envelope.worker_id, requested_at)
                    .map_err(|_| StatusCode::BAD_REQUEST)?,
            }
        }
        WorkerControlRequest::UpsertTarget { target } => WorkerControlResponse::TargetRecord {
            target: state
                .store
                .upsert_target(&target)
                .map_err(|_| StatusCode::BAD_REQUEST)?,
        },
        WorkerControlRequest::UpsertRepository { repository } => {
            WorkerControlResponse::RepositoryRecord {
                repository: state
                    .store
                    .upsert_repository(&repository)
                    .map_err(|_| StatusCode::BAD_REQUEST)?,
            }
        }
        WorkerControlRequest::LoadScanSettings => WorkerControlResponse::OptionalScanSettings {
            settings: state
                .store
                .load_scan_settings()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        },
    };

    Ok(Json(response))
}

async fn dashboard(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<DashboardSnapshot>, StatusCode> {
    require_auth(&state, &jar)?;
    let mut snapshot = state
        .store
        .dashboard_snapshot()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    snapshot.scan_defaults = load_effective_scan_defaults(&state)?;
    snapshot.active_authorized_execution_policy =
        active_authorized_execution_policy_snapshot(&state.config);
    snapshot.operators = state.config.operator_records();
    snapshot.workers = state
        .store
        .list_workers()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .map(enrich_worker_with_bundle_state)
        .collect();
    snapshot.extensions = state
        .config
        .load_extension_manifests()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    snapshot.bin_dataset_status = state
        .store
        .load_bin_dataset_status()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    snapshot.archive_status = Some(
        state
            .store
            .archive_status(&state.config)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    Ok(Json(snapshot))
}

async fn get_archive_status(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<ArchiveStatusSnapshot>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let status = state
        .store
        .archive_status(&state.config)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(status))
}

async fn list_archive_jobs(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<ArchiveJobRecord>>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let jobs = state
        .store
        .list_archive_jobs(25)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(jobs))
}

async fn list_archive_pointers(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<ArchivePointersQuery>,
) -> Result<Json<Vec<ArchivePointerRecord>>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 250);
    let pointers = state
        .store
        .list_archive_pointers(limit, query.kind)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(pointers))
}

async fn get_archive_manifest(
    Path(pointer_id): Path<i64>,
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<ArchiveManifest>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let pointer = state
        .store
        .get_archive_pointer(pointer_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let manifest = download_archive_pointer_manifest(&state.config, &pointer)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(manifest))
}

async fn get_archive_records(
    Path(pointer_id): Path<i64>,
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let pointer = state
        .store
        .get_archive_pointer(pointer_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let records = download_archive_pointer_records(&state.config, &pointer)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(records))
}

async fn hydrate_archive_segment(
    Path(pointer_id): Path<i64>,
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<ArchiveHydrateResponse>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let pointer = state
        .store
        .get_archive_pointer(pointer_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let restored_count = hydrate_archive_pointer(&state.config, &state.store, &pointer)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ArchiveHydrateResponse {
        pointer_id,
        restored_count,
    }))
}

async fn trigger_archive_run(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<ArchiveJobRecord>, StatusCode> {
    let session = require_settings_access(&state, &jar)?;
    let job = run_archive_pass(&state.config, &state.store, &session.username)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::CONFLICT)?;
    Ok(Json(job))
}

async fn get_scan_settings(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<ScanDefaultsSummary>, StatusCode> {
    require_auth(&state, &jar)?;
    Ok(Json(load_effective_scan_defaults(&state)?))
}

async fn update_scan_settings(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<ScanDefaultsSummary>,
) -> Result<Json<ScanDefaultsSummary>, StatusCode> {
    require_settings_access(&state, &jar)?;
    let normalized = state
        .config
        .with_scan_defaults_summary(&payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .scan_defaults_summary();
    let persisted = state
        .store
        .upsert_scan_settings(&normalized)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(persisted))
}

async fn get_bin_dataset_status(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Option<BinDatasetStatus>>, StatusCode> {
    require_auth(&state, &jar)?;
    let status = state
        .store
        .load_bin_dataset_status()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(status))
}

async fn import_bin_dataset(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<BinDatasetImportRequest>,
) -> Result<Json<BinDatasetStatus>, StatusCode> {
    require_write_access(&state, &jar)?;
    let status = state
        .store
        .import_bin_dataset(&payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(status))
}

async fn bin_lookup(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<BinLookupRequest>,
) -> Result<Json<BinLookupResponse>, StatusCode> {
    require_auth(&state, &jar)?;

    let candidates = parse_bin_lookup_candidates(&payload.text);
    let processed_lines = payload.text.lines().count();
    let matched_lines = candidates.len();
    let limit = normalized_bin_lookup_limit(payload.limit);

    let line_previews_by_number = payload
        .text
        .lines()
        .enumerate()
        .map(|(index, raw_line)| (index + 1, bin_lookup_line_preview(raw_line)))
        .collect::<std::collections::HashMap<_, _>>();

    let mut aggregated = std::collections::BTreeMap::<String, (usize, Vec<usize>)>::new();
    for candidate in candidates {
        let entry = aggregated
            .entry(candidate.bin)
            .or_insert_with(|| (0usize, Vec::new()));
        entry.0 += 1;
        if !entry.1.contains(&candidate.line_number) {
            entry.1.push(candidate.line_number);
        }
    }

    let bins = aggregated.keys().cloned().collect::<Vec<_>>();
    let metadata = state
        .store
        .lookup_bin_metadata(&bins)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let metadata_by_bin = metadata
        .into_iter()
        .map(|record| (record.bin.clone(), record))
        .collect::<std::collections::HashMap<_, _>>();

    let matches = aggregated
        .into_iter()
        .take(limit)
        .map(|(bin, (occurrences, line_numbers))| {
            let line_previews = line_numbers
                .iter()
                .filter_map(|line_number| {
                    line_previews_by_number
                        .get(line_number)
                        .map(|text| BinLookupLinePreview {
                            line_number: *line_number,
                            text: text.clone(),
                        })
                })
                .collect::<Vec<_>>();

            BinLookupMatch {
                metadata: metadata_by_bin.get(&bin).cloned(),
                bin,
                occurrences,
                line_numbers,
                line_previews,
            }
        })
        .collect::<Vec<_>>();

    let response = BinLookupResponse {
        dataset: state
            .store
            .load_bin_dataset_status()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        processed_lines,
        matched_lines,
        unique_bins: bins.len(),
        matches,
    };

    Ok(Json(response))
}

async fn list_targets(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<TargetRecord>>, StatusCode> {
    require_auth(&state, &jar)?;
    let targets = state
        .store
        .list_targets()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(targets))
}

async fn create_target(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<TargetDefinition>,
) -> Result<Json<TargetRecord>, StatusCode> {
    require_write_access(&state, &jar)?;
    let normalized = state
        .config
        .normalize_target_definition(payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let target = state
        .store
        .upsert_target(&normalized)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(target))
}

async fn list_repositories(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<RepositoryRecord>>, StatusCode> {
    require_auth(&state, &jar)?;
    let repositories = state
        .store
        .list_repositories()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(repositories))
}

async fn create_repository(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<RepositoryDefinition>,
) -> Result<Json<RepositoryRecord>, StatusCode> {
    require_write_access(&state, &jar)?;
    let normalized = state
        .config
        .normalize_repository_definition(payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let repository = state
        .store
        .upsert_repository(&normalized)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(repository))
}

async fn list_port_scans(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<PortScanRecord>>, StatusCode> {
    require_auth(&state, &jar)?;
    let port_scans = state
        .store
        .list_port_scans(50)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(port_scans))
}

async fn queue_port_scan(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<PortScanQueueRequest>,
) -> Result<Json<PortScanRecord>, (StatusCode, String)> {
    let session =
        require_write_access(&state, &jar).map_err(|status| (status, status.to_string()))?;
    let normalized = state
        .config
        .normalize_port_scan_request(payload.request)
        .map_err(|error| {
            warn!(?error, "failed to normalize port scan request");
            (StatusCode::BAD_REQUEST, error.to_string())
        })?;
    let active_policy =
        resolve_active_authorized_execution(&state.config, payload.active_authorized_plugins);
    let port_scan = state
        .store
        .queue_port_scan_with_active_authorized_plugins(
            Some(&session.username),
            &normalized,
            &active_policy,
        )
        .map_err(|error| {
            warn!(?error, "failed to queue port scan");
            (StatusCode::BAD_REQUEST, error.to_string())
        })?;
    state
        .store
        .append_event(
            None,
            &ApiEvent::PortScanQueued {
                port_scan: port_scan.clone(),
            },
        )
        .map_err(|error| {
            warn!(?error, "failed to append port scan queued event");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to append port scan event".to_string(),
            )
        })?;
    Ok(Json(port_scan))
}

async fn stop_port_scan(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(port_scan_id): Path<i64>,
) -> Result<Json<PortScanRecord>, (StatusCode, String)> {
    let session =
        require_write_access(&state, &jar).map_err(|status| (status, status.to_string()))?;
    let notes = format!("stopped by operator {}", session.username);
    let port_scan = state
        .store
        .stop_port_scan(port_scan_id, Some(&notes))
        .map_err(|error| {
            warn!(?error, port_scan_id, "failed to stop port scan");
            (StatusCode::BAD_REQUEST, error.to_string())
        })?;
    state
        .store
        .append_event(
            None,
            &ApiEvent::PortScanStopped {
                port_scan: port_scan.clone(),
            },
        )
        .map_err(|error| {
            warn!(
                ?error,
                port_scan_id, "failed to append stopped port scan event"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to append port scan stop event".to_string(),
            )
        })?;
    Ok(Json(port_scan))
}

async fn list_workers(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<WorkerRecord>>, StatusCode> {
    require_auth(&state, &jar)?;
    let workers = state
        .store
        .list_workers()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .map(enrich_worker_with_bundle_state)
        .collect();
    Ok(Json(workers))
}

async fn list_worker_pools(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<WorkerPoolRecord>>, StatusCode> {
    require_auth(&state, &jar)?;
    let pools = state
        .store
        .list_worker_pools()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(pools))
}

async fn get_worker(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(worker_id): Path<String>,
) -> Result<Json<WorkerRecord>, StatusCode> {
    require_auth(&state, &jar)?;
    let worker = state
        .store
        .get_worker(&worker_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .map(enrich_worker_with_bundle_state)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(worker))
}

async fn update_worker_lifecycle(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(worker_id): Path<String>,
    Json(payload): Json<WorkerLifecycleUpdateRequest>,
) -> Result<Json<WorkerRecord>, StatusCode> {
    require_worker_management_access(&state, &jar)?;
    let worker = state
        .store
        .update_worker_lifecycle_state(&worker_id, payload.lifecycle_state)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let worker = enrich_worker_with_bundle_state(worker);
    state
        .store
        .append_event(
            None,
            &ApiEvent::WorkerStateChanged {
                worker: worker.clone(),
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(worker))
}

async fn request_worker_remote_update(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(worker_id): Path<String>,
) -> Result<Json<WorkerRecord>, StatusCode> {
    require_worker_management_access(&state, &jar)?;
    let worker = state
        .store
        .request_worker_remote_update(&worker_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let worker = enrich_worker_with_bundle_state(worker);
    state
        .store
        .append_event(
            None,
            &ApiEvent::WorkerRemoteUpdateRequested {
                worker: worker.clone(),
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(worker))
}

async fn request_all_worker_remote_updates(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<WorkerRecord>>, StatusCode> {
    require_worker_management_access(&state, &jar)?;
    let workers = state
        .store
        .request_all_worker_remote_updates()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .map(enrich_worker_with_bundle_state)
        .collect::<Vec<_>>();
    for worker in &workers {
        state
            .store
            .append_event(
                None,
                &ApiEvent::WorkerRemoteUpdateRequested {
                    worker: worker.clone(),
                },
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(Json(workers))
}

async fn list_worker_remote_commands(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<WorkerRemoteCommandsQuery>,
) -> Result<Json<Vec<WorkerRemoteCommandRecord>>, StatusCode> {
    require_worker_management_access(&state, &jar)?;
    let commands = state
        .store
        .list_worker_remote_commands(query.limit.unwrap_or(25).max(1), query.worker_id.as_deref())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(commands))
}

async fn queue_worker_remote_command(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(worker_id): Path<String>,
    Json(payload): Json<WorkerRemoteCommandRequest>,
) -> Result<Json<WorkerRemoteCommandRecord>, StatusCode> {
    let session = require_worker_management_access(&state, &jar)?;
    let command = state
        .store
        .queue_worker_remote_command(&worker_id, Some(&session.username), &payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .store
        .append_event(
            None,
            &ApiEvent::WorkerRemoteCommandQueued {
                command: command.clone(),
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(command))
}

async fn list_worker_enrollment_tokens(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<WorkerEnrollmentTokenRecord>>, StatusCode> {
    require_worker_management_access(&state, &jar)?;
    let tokens = state
        .store
        .list_worker_enrollment_tokens()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(tokens))
}

async fn issue_worker_bootstrap_code(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<WorkerBootstrapCodeIssueRequest>,
) -> Result<Json<WorkerBootstrapCodeIssued>, StatusCode> {
    let session = require_worker_management_access(&state, &jar)?;
    let issued = state
        .store
        .issue_worker_bootstrap_code(Some(&session.username), &payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(issued))
}

async fn exchange_worker_bootstrap_code(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WorkerBootstrapCodeExchangeRequest>,
) -> Result<Json<WorkerBootstrapCodeExchange>, StatusCode> {
    let exchanged = state
        .store
        .exchange_worker_bootstrap_code(&payload.code, &payload.worker_id)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(exchanged))
}

async fn issue_worker_enrollment_token(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<WorkerEnrollmentTokenIssueRequest>,
) -> Result<Json<WorkerEnrollmentTokenIssued>, StatusCode> {
    let session = require_worker_management_access(&state, &jar)?;
    let issued = state
        .store
        .issue_worker_enrollment_token(Some(&session.username), &payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .store
        .append_event(
            None,
            &ApiEvent::WorkerEnrollmentTokenIssued {
                token: issued.record.clone(),
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(issued))
}

async fn revoke_worker_enrollment_token(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(token_id): Path<i64>,
) -> Result<Json<WorkerEnrollmentTokenRecord>, StatusCode> {
    require_worker_management_access(&state, &jar)?;
    let token = state
        .store
        .revoke_worker_enrollment_token(token_id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .store
        .append_event(
            None,
            &ApiEvent::WorkerEnrollmentTokenRevoked {
                token: token.clone(),
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(token))
}

async fn list_bootstrap_candidates(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<WorkerBootstrapCandidateRecord>>, StatusCode> {
    require_worker_management_access(&state, &jar)?;
    let candidates = state
        .store
        .list_bootstrap_candidates()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(candidates))
}

async fn list_bootstrap_jobs(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<WorkerBootstrapJobRecord>>, StatusCode> {
    require_auth(&state, &jar)?;
    let jobs = state
        .store
        .list_bootstrap_jobs()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(jobs))
}

async fn approve_bootstrap_candidate(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(candidate_id): Path<i64>,
    Json(payload): Json<WorkerBootstrapCandidateApprovalRequest>,
) -> Result<Json<WorkerBootstrapCandidateApproval>, StatusCode> {
    let session = require_bootstrap_approval_access(&state, &jar)?;
    let approval = state
        .store
        .approve_bootstrap_candidate(candidate_id, Some(&session.username), &payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .store
        .append_event(
            None,
            &ApiEvent::WorkerBootstrapCandidateApproved {
                candidate: approval.candidate.clone(),
                token: approval.token.record.clone(),
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .store
        .append_event(
            None,
            &ApiEvent::WorkerEnrollmentTokenIssued {
                token: approval.token.record.clone(),
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(bootstrap_job) = &approval.bootstrap_job {
        state
            .store
            .append_event(
                None,
                &ApiEvent::WorkerBootstrapJobQueued {
                    job: bootstrap_job.clone(),
                },
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(Json(approval))
}

async fn reject_bootstrap_candidate(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(candidate_id): Path<i64>,
    Json(payload): Json<WorkerBootstrapCandidateRejectionRequest>,
) -> Result<Json<WorkerBootstrapCandidateRecord>, StatusCode> {
    require_bootstrap_approval_access(&state, &jar)?;
    let candidate = state
        .store
        .reject_bootstrap_candidate(candidate_id, &payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .store
        .append_event(
            None,
            &ApiEvent::WorkerBootstrapCandidateRejected {
                candidate: candidate.clone(),
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(candidate))
}

async fn list_runs(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<RunsQuery>,
) -> Result<Json<Vec<ScanRunRecord>>, StatusCode> {
    require_auth(&state, &jar)?;
    let runs = load_runs_with_archive(&state, &query)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(runs))
}

async fn queue_run(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    body: Bytes,
) -> Result<Json<RunSummary>, StatusCode> {
    let session = require_write_access(&state, &jar)?;
    let request = if body.iter().all(|byte| byte.is_ascii_whitespace()) {
        RunRequest::default()
    } else {
        serde_json::from_slice::<RunRequest>(&body).map_err(|_| StatusCode::BAD_REQUEST)?
    };
    let active_policy =
        resolve_active_authorized_execution(&state.config, request.active_authorized_plugins);
    let run = state
        .store
        .queue_run_with_active_authorized_plugins(
            Some(&session.username),
            request.scope.as_ref(),
            &active_policy,
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let summary = state
        .store
        .summary(run.id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .store
        .append_event(
            Some(run.id),
            &ApiEvent::RunQueued {
                run,
                summary: summary.clone(),
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(summary))
}

async fn stop_run(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(run_id): Path<i64>,
) -> Result<Json<ScanRunRecord>, (StatusCode, String)> {
    let session =
        require_write_access(&state, &jar).map_err(|status| (status, status.to_string()))?;
    let notes = format!("stopped by operator {}", session.username);
    let run = state
        .store
        .stop_run(run_id, Some(&notes))
        .map_err(|error| {
            warn!(?error, run_id, "failed to stop run");
            (StatusCode::BAD_REQUEST, error.to_string())
        })?;
    let summary = state.store.summary(run_id).map_err(|error| {
        warn!(?error, run_id, "failed to summarize stopped run");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to summarize stopped run".to_string(),
        )
    })?;
    state
        .store
        .append_event(
            Some(run_id),
            &ApiEvent::RunFailed {
                run: run.clone(),
                summary,
                error: notes.clone(),
            },
        )
        .map_err(|error| {
            warn!(?error, run_id, "failed to append stopped run event");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to append run stop event".to_string(),
            )
        })?;
    Ok(Json(run))
}

async fn list_schedules(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<RecurringScheduleRecord>>, StatusCode> {
    require_auth(&state, &jar)?;
    let schedules = state
        .store
        .list_schedules()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(schedules))
}

async fn create_schedule(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<ScheduleRequest>,
) -> Result<Json<RecurringScheduleRecord>, StatusCode> {
    let session = require_write_access(&state, &jar)?;
    let active_policy =
        resolve_active_authorized_execution(&state.config, payload.active_authorized_plugins);
    let schedule = state
        .store
        .upsert_schedule_with_active_authorized_plugins(
            &payload.label,
            payload.interval_seconds,
            payload.enabled.unwrap_or(true),
            Some(&session.username),
            payload.scope.as_ref(),
            &active_policy,
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(schedule))
}

async fn list_findings(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<FindingsQuery>,
) -> Result<Json<Vec<FindingRecord>>, StatusCode> {
    require_auth(&state, &jar)?;
    let findings = load_findings_with_archive(&state, &query)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(findings))
}

async fn list_finding_publications(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Vec<PublicFindingModerationRecord>>, StatusCode> {
    let session = require_auth(&state, &jar)?;
    let publications = state
        .store
        .list_public_finding_moderation_records()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(sanitize_public_finding_moderation_records(
        publications,
        session.role.can_moderate_public_findings(),
    )))
}

async fn moderate_public_finding(
    Path(finding_id): Path<i64>,
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Json(payload): Json<PublicFindingModerationRequest>,
) -> Result<Json<PublicFindingModerationRecord>, StatusCode> {
    let session = require_public_finding_moderation_access(&state, &jar)?;
    let record = state
        .store
        .moderate_public_finding(finding_id, Some(&session.username), &payload)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .store
        .append_event(
            None,
            &ApiEvent::PublicFindingModerated {
                finding: record.clone(),
            },
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(record))
}

async fn event_stream(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<EventQuery>,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let session = require_auth(&state, &jar)?;
    let store = state.store.clone();
    let requested_run = query.run_id;
    let initial_cursor = query.cursor.unwrap_or(0);
    let can_view_private_publication_notes = session.role.can_moderate_public_findings();

    let event_stream = stream! {
        let mut cursor = initial_cursor;
        loop {
            let events = store.list_events_since(cursor, 100).unwrap_or_default();
            if events.is_empty() {
                yield Ok(Event::default().event("keepalive").data("{\"type\":\"keepalive\"}"));
            } else {
                for stored_event in events {
                    cursor = stored_event.id;
                    if requested_run.map(|run_id| Some(run_id) == stored_event.run_id).unwrap_or(true) {
                        let payload = sanitize_api_event_for_session(
                            stored_event.payload.clone(),
                            can_view_private_publication_notes,
                        );
                        if let Ok(payload) = serde_json::to_string(&payload) {
                            yield Ok(Event::default()
                                .id(stored_event.id.to_string())
                                .event("api_event")
                                .data(payload));
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };

    Ok(Sse::new(event_stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    ))
}

fn seed_bootstrap_inventory(store: &AnyScanStore, config: &AppConfig) -> Result<()> {
    for target in config.normalized_bootstrap_targets()? {
        store.upsert_target(&target)?;
    }
    for repository in config.normalized_bootstrap_repositories()? {
        store.upsert_repository(&repository)?;
    }
    Ok(())
}

fn load_effective_scan_defaults(state: &AppState) -> Result<ScanDefaultsSummary, StatusCode> {
    match state
        .store
        .load_scan_settings()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        Some(settings) => Ok(settings),
        None => Ok(state.config.scan_defaults_summary()),
    }
}

async fn load_runs_with_archive(state: &AppState, query: &RunsQuery) -> Result<Vec<ScanRunRecord>> {
    let limit = query.limit.unwrap_or(25).clamp(1, 250);
    let mut runs = state.store.list_runs(limit)?;
    if !query.include_archive || !state.config.archive.enabled {
        return Ok(runs);
    }

    let pointers = state
        .store
        .list_archive_pointers(250, Some(ArchiveRecordKind::Runs))?;
    let mut archived = list_archived_runs(&state.config, &pointers).await?;
    runs.append(&mut archived);
    runs.sort_by(|left, right| right.id.cmp(&left.id));

    let mut seen = HashSet::new();
    runs.retain(|run| seen.insert(run.id));
    runs.truncate(limit);
    Ok(runs)
}

async fn load_findings_with_archive(
    state: &AppState,
    query: &FindingsQuery,
) -> Result<Vec<FindingRecord>> {
    let mut hot_query = query.clone();
    hot_query.include_archive = false;
    let hot_findings = state.store.search_findings(&hot_query)?;
    if !query.include_archive || !state.config.archive.enabled {
        return Ok(hot_findings);
    }

    let pointers = state
        .store
        .list_archive_pointers(250, Some(ArchiveRecordKind::Findings))?;
    let mut combined = hot_findings;
    combined.extend(search_archived_findings(&state.config, &pointers).await?);
    combined.sort_by(|left, right| {
        right
            .discovered_at
            .cmp(&left.discovered_at)
            .then(right.id.cmp(&left.id))
    });

    let mut seen = HashSet::new();
    combined.retain(|finding| seen.insert(finding.id));

    let target_tags_by_id = state
        .store
        .list_targets()?
        .into_iter()
        .map(|target| (target.id, target.tags))
        .collect::<HashMap<_, _>>();
    Ok(run_findings_query(
        &HybridFindingsRanker,
        combined,
        &target_tags_by_id,
        &hot_query,
    ))
}

fn active_authorized_execution_policy_snapshot(
    config: &AppConfig,
) -> anyscan::core::ActiveAuthorizedExecutionPolicySnapshot {
    anyscan::core::ActiveAuthorizedExecutionPolicySnapshot {
        active_authorized_supported: true,
        active_authorized_gate_enabled: config.scan.allow_active_authorized_execution
            || config.scan.enable_all_plugins_for_testing,
    }
}

fn resolve_active_authorized_execution(
    config: &AppConfig,
    requested: ActiveAuthorizedPluginExecution,
) -> ActiveAuthorizedPluginExecution {
    let testing_override = config.scan.enable_all_plugins_for_testing;
    ActiveAuthorizedPluginExecution {
        global_gate_enabled: config.scan.allow_active_authorized_execution || testing_override,
        request_opt_in_enabled: requested.request_opt_in_enabled || testing_override,
    }
}

fn session_response(session: &SessionContext) -> SessionResponse {
    SessionResponse {
        username: session.username.clone(),
        role: session.role,
        permissions: SessionPermissions {
            write: session.role.can_write(),
            manage_settings: session.role.can_manage_settings(),
            manage_operators: session.role.can_manage_operators(),
            manage_workers: session.role.can_manage_workers(),
            approve_bootstrap_candidates: session.role.can_approve_bootstrap_candidates(),
            moderate_public_findings: session.role.can_moderate_public_findings(),
        },
    }
}

fn sanitize_public_finding_moderation_record(
    mut record: PublicFindingModerationRecord,
    can_view_private_notes: bool,
) -> PublicFindingModerationRecord {
    if !can_view_private_notes {
        record.reviewer_notes = None;
    }
    record
}

fn sanitize_public_finding_moderation_records(
    records: Vec<PublicFindingModerationRecord>,
    can_view_private_notes: bool,
) -> Vec<PublicFindingModerationRecord> {
    records
        .into_iter()
        .map(|record| sanitize_public_finding_moderation_record(record, can_view_private_notes))
        .collect()
}

fn sanitize_api_event_for_session(
    event: ApiEvent,
    can_view_private_publication_notes: bool,
) -> ApiEvent {
    match event {
        ApiEvent::PublicFindingModerated { finding } => ApiEvent::PublicFindingModerated {
            finding: sanitize_public_finding_moderation_record(
                finding,
                can_view_private_publication_notes,
            ),
        },
        other => other,
    }
}

fn require_hosted_agent_bundle_access(access_token: Option<&str>) -> Result<(), StatusCode> {
    let expected = std::env::var("ANYSCAN_AGENT_BUNDLE_ACCESS_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    match expected {
        Some(expected) => {
            if access_token
                .map(str::trim)
                .is_some_and(|candidate| candidate == expected)
            {
                Ok(())
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        None => Ok(()),
    }
}

fn hosted_agent_base_url(state: &AppState, headers: &HeaderMap) -> Result<String, StatusCode> {
    let forwarded_proto = forwarded_header_value(headers, "x-forwarded-proto");
    let forwarded_host = forwarded_header_value(headers, "x-forwarded-host");
    let host = forwarded_host.or_else(|| forwarded_header_value(headers, "host"));
    if let (Some(proto), Some(host)) = (forwarded_proto, host.clone()) {
        return Ok(normalize_base_url(&format!("{proto}://{host}")));
    }
    if let Some(host) = host {
        return Ok(normalize_base_url(&format!("http://{host}")));
    }
    if let Some(base_url) = state.config.public.base_url.as_deref() {
        return Ok(normalize_base_url(base_url));
    }
    Err(StatusCode::INTERNAL_SERVER_ERROR)
}

fn hosted_agent_effective_base_url(
    state: &AppState,
    headers: &HeaderMap,
    explicit_base_url: Option<&str>,
) -> Result<String, StatusCode> {
    if let Some(explicit_base_url) = explicit_base_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let parsed = url::Url::parse(explicit_base_url).map_err(|_| StatusCode::BAD_REQUEST)?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(StatusCode::BAD_REQUEST);
        }
        return Ok(normalize_base_url(explicit_base_url));
    }
    hosted_agent_base_url(state, headers)
}

fn forwarded_header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').next().unwrap_or("").trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_base_url(value: &str) -> String {
    url::Url::parse(value)
        .map(|mut url| {
            url.set_path("");
            url.set_query(None);
            url.set_fragment(None);
            url.to_string().trim_end_matches('/').to_string()
        })
        .unwrap_or_else(|_| value.trim_end_matches('/').to_string())
}

fn should_force_chunked_download(base_url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(base_url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let lowered = host.to_ascii_lowercase();
    lowered.contains(".onion.") && !lowered.ends_with(".onion")
}

fn hosted_agent_endpoint_url(
    base_url: &str,
    path: &str,
    access_token: Option<&str>,
) -> Result<String, StatusCode> {
    let mut url = url::Url::parse(base_url).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    url.set_path(path);
    if let Some(access_token) = access_token
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        url.query_pairs_mut()
            .append_pair("access_token", access_token);
    }
    Ok(url.to_string())
}

fn append_query_parameter(url_value: String, key: &str, value: &str) -> Result<String, StatusCode> {
    let mut url = url::Url::parse(&url_value).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    url.query_pairs_mut().append_pair(key, value);
    Ok(url.to_string())
}

fn append_optional_query_parameter(
    url_value: String,
    key: &str,
    value: Option<&str>,
) -> Result<String, StatusCode> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(url_value);
    };
    append_query_parameter(url_value, key, value)
}

fn render_install_runtime_overrides_script(runtime_management_url: Option<&str>) -> String {
    let Some(runtime_management_url) = runtime_management_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return String::new();
    };
    format!(
        "export INSTALL_CONTROL_URL_OVERRIDE={control_url}\nexport INSTALL_MANAGEMENT_URL_OVERRIDE={management_url}\nexport INSTALL_CONTROL_PROXY_URL_OVERRIDE=''\n",
        control_url = shell_single_quote(runtime_management_url),
        management_url = shell_single_quote(runtime_management_url),
    )
}

fn normalize_platform_key(value: &str) -> Result<String, StatusCode> {
    let mut normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    normalized = normalized.replace('/', "-").replace(' ', "-");
    normalized = normalized.replace("macos", "darwin");
    while normalized.contains("--") {
        normalized = normalized.replace("--", "-");
    }
    let normalized = normalized.trim_matches('-').to_string();
    if normalized.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(normalized)
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

fn trigger_hosted_agent_bundle_rebuild(state: Arc<AppState>, platform_key: String) {
    tokio::spawn(async move {
        if let Err(error) = ensure_hosted_agent_bundle(&state, &platform_key, true).await {
            warn!(?error, "background hosted agent bundle rebuild failed");
        }
    });
}

async fn lease_cached_hosted_agent_bundle(
    state: &AppState,
    platform_key: &str,
) -> Result<HostedAgentBundleInfo, StatusCode> {
    let current_fingerprint = compute_hosted_agent_bundle_source_fingerprint(platform_key);
    if let Some(bundle) = find_latest_available_hosted_agent_bundle_for_platform(
        platform_key,
        current_fingerprint.as_deref(),
    )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        mark_hosted_agent_bundle_leased(&bundle).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Ok(resolve_hosted_agent_bundle_by_name(&bundle.bundle_name)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?);
    }

    rebuild_hosted_agent_bundle_blocking(
        state,
        platform_key,
        HostedAgentBundleBuildOptions {
            skip_recheck: false,
            mark_leased: true,
            fingerprint: current_fingerprint,
        },
    )
    .await
}

async fn allocate_fresh_hosted_agent_bundle(
    state: &AppState,
    platform_key: &str,
) -> Result<HostedAgentBundleInfo, StatusCode> {
    rebuild_hosted_agent_bundle_blocking(
        state,
        platform_key,
        HostedAgentBundleBuildOptions {
            skip_recheck: true,
            mark_leased: true,
            fingerprint: None,
        },
    )
    .await
}

async fn ensure_hosted_agent_bundle(
    state: &AppState,
    platform_key: &str,
    force_rebuild: bool,
) -> Result<HostedAgentBundleInfo, StatusCode> {
    let current_fingerprint = compute_hosted_agent_bundle_source_fingerprint(platform_key);
    if !force_rebuild {
        if let Some(bundle) = find_latest_available_hosted_agent_bundle_for_platform(
            platform_key,
            current_fingerprint.as_deref(),
        )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            return Ok(bundle);
        }
    }
    rebuild_hosted_agent_bundle_blocking(
        state,
        platform_key,
        HostedAgentBundleBuildOptions {
            skip_recheck: force_rebuild,
            mark_leased: false,
            fingerprint: current_fingerprint,
        },
    )
    .await
}

fn compute_hosted_agent_bundle_source_fingerprint(platform_key: &str) -> Option<String> {
    match current_hosted_agent_bundle_source_fingerprint() {
        Ok(fingerprint) => Some(fingerprint),
        Err(error) => {
            warn!(
                ?error,
                platform_key = %platform_key,
                "failed to compute hosted agent bundle source fingerprint; falling back to latest cached bundle"
            );
            None
        }
    }
}

struct HostedAgentBundleBuildOptions {
    skip_recheck: bool,
    mark_leased: bool,
    fingerprint: Option<String>,
}

// Drop-guard that flips an atomic flag when the awaiting future is dropped.
// Used by `rebuild_hosted_agent_bundle_blocking` to propagate caller-side
// cancellation into the spawn_blocking task so abandoned work doesn't queue
// up behind the build lock.
struct RequestCancelledGuard {
    cancelled: Arc<AtomicBool>,
}

impl Drop for RequestCancelledGuard {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

// Acquires `hosted_agent_bundle_build_lock` and runs the synchronous bundle
// rebuild on the blocking pool. The lock is acquired *inside* the
// spawn_blocking task so that caller-side cancellation (client disconnect,
// timeout) cannot drop the guard while the rebuild is still in flight — that
// would let a concurrent request start a second rebuild, defeating the
// serialization the lock is there to provide.
//
// A `RequestCancelledGuard` flips an atomic flag when the awaiting future is
// dropped, so canceled callers don't leave queued spawn_blocking tasks that
// still queue on the build lock and run a real rebuild for nobody. The
// blocking task checks the flag at two slow points — before queueing on
// `blocking_lock()`, and immediately after acquiring it — and bails with no
// state mutation if the caller is already gone. Past those checks the
// rebuild is "committed" and runs to completion: interrupting it mid-flight
// would leave inconsistent on-disk artifacts and a half-applied lease
// marker.
async fn rebuild_hosted_agent_bundle_blocking(
    state: &AppState,
    platform_key: &str,
    options: HostedAgentBundleBuildOptions,
) -> Result<HostedAgentBundleInfo, StatusCode> {
    let lock = state.hosted_agent_bundle_build_lock.clone();
    let config = state.config.clone();
    let platform_key_owned = platform_key.to_string();
    let platform_key_for_log = platform_key.to_string();
    let cancelled = Arc::new(AtomicBool::new(false));
    let task_cancelled = cancelled.clone();
    // Held for the lifetime of this future. When the future is dropped at
    // `.await` (caller cancellation), drop sets `cancelled = true`. The
    // spawned task holds its own clone of the Arc and observes the flip.
    let _cancel_guard = RequestCancelledGuard { cancelled };
    tokio::task::spawn_blocking(move || -> Result<HostedAgentBundleInfo, StatusCode> {
        if task_cancelled.load(Ordering::Acquire) {
            warn!(
                platform_key = %platform_key_owned,
                "skipping hosted agent bundle build: caller dropped before lock acquisition"
            );
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let _guard = lock.blocking_lock();
        if task_cancelled.load(Ordering::Acquire) {
            warn!(
                platform_key = %platform_key_owned,
                "skipping hosted agent bundle build: caller dropped while waiting for build lock"
            );
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        if !options.skip_recheck {
            if let Some(bundle) = find_latest_available_hosted_agent_bundle_for_platform(
                &platform_key_owned,
                options.fingerprint.as_deref(),
            )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            {
                if options.mark_leased && task_cancelled.load(Ordering::Acquire) {
                    warn!(
                        platform_key = %platform_key_owned,
                        "skipping hosted agent bundle lease: caller dropped after cache hit"
                    );
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                return finalize_hosted_agent_bundle(bundle, options.mark_leased);
            }
        }
        if task_cancelled.load(Ordering::Acquire) {
            warn!(
                platform_key = %platform_key_owned,
                "skipping hosted agent bundle build: caller dropped after cache miss"
            );
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let bundle = rebuild_hosted_agent_bundle(&config, &platform_key_owned).map_err(|error| {
            warn!(
                ?error,
                platform_key = %platform_key_owned,
                "failed to rebuild hosted agent bundle"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        finalize_hosted_agent_bundle(bundle, options.mark_leased)
    })
    .await
    .map_err(|error| {
        if error.is_panic() {
            warn!(
                ?error,
                platform_key = %platform_key_for_log,
                "hosted agent bundle build task panicked"
            );
        } else if error.is_cancelled() {
            warn!(
                ?error,
                platform_key = %platform_key_for_log,
                "hosted agent bundle build task was cancelled"
            );
        } else {
            warn!(
                ?error,
                platform_key = %platform_key_for_log,
                "hosted agent bundle build task failed"
            );
        }
        StatusCode::INTERNAL_SERVER_ERROR
    })?
}

fn finalize_hosted_agent_bundle(
    bundle: HostedAgentBundleInfo,
    mark_leased: bool,
) -> Result<HostedAgentBundleInfo, StatusCode> {
    if !mark_leased {
        return Ok(bundle);
    }
    mark_hosted_agent_bundle_leased(&bundle).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    resolve_hosted_agent_bundle_by_name(&bundle.bundle_name)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn rebuild_hosted_agent_bundle(
    config: &AppConfig,
    platform_key: &str,
) -> Result<HostedAgentBundleInfo> {
    let bundle_output_dir = PathBuf::from(HOSTED_AGENT_BUNDLE_OUTPUT_DIR);
    let build_root = PathBuf::from(HOSTED_AGENT_BUNDLE_BUILD_ROOT);
    fs::create_dir_all(&bundle_output_dir)
        .with_context(|| format!("failed to create {}", bundle_output_dir.display()))?;
    fs::create_dir_all(&build_root)
        .with_context(|| format!("failed to create {}", build_root.display()))?;
    let native_platform_key = native_hosted_agent_platform_key();
    if platform_key != native_platform_key {
        return Err(anyhow!(
            "no local hosted bundle build pipeline is configured for platform {platform_key}; publish a prebuilt bundle for that platform first"
        ));
    }
    let source_fingerprint = current_hosted_agent_bundle_source_fingerprint()?;
    let fingerprint_short = &source_fingerprint[..source_fingerprint
        .len()
        .min(HOSTED_AGENT_BUNDLE_FINGERPRINT_LEN)];
    let stage_root = build_root.join(format!(
        "{}-{}-{}",
        platform_key,
        Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id()
    ));
    if stage_root.exists() {
        fs::remove_dir_all(&stage_root)
            .with_context(|| format!("failed to clear {}", stage_root.display()))?;
    }
    fs::create_dir_all(&stage_root)
        .with_context(|| format!("failed to create {}", stage_root.display()))?;
    write_hosted_agent_bundle_assets(&stage_root)?;
    let packager_script = stage_root.join("package-worker-bundle.sh");
    let bundle_name = format!(
        "agent-bundle-{}__{}-{}-{}",
        platform_key,
        Utc::now().format("%Y%m%d%H%M%S"),
        std::process::id(),
        fingerprint_short,
    );
    let mut command = ProcessCommand::new("/usr/bin/bash");
    command.arg(&packager_script).current_dir(&stage_root);
    command.env("DIST_DIR", &bundle_output_dir);
    command.env("ANYSCAN_PACKAGE_BUNDLE_NAME", &bundle_name);
    command.env("ANYSCAN_PACKAGE_BUNDLE_PLATFORM", platform_key);
    command.env("ANYSCAN_PACKAGE_RUNTIME_ENV", INSTALLED_RUNTIME_ENV_PATH);
    command.env("ANYSCAN_PACKAGE_AGENT_BIN", INSTALLED_AGENT_BINARY_PATH);
    command.env(
        "ANYSCAN_PACKAGE_ADMIN_USERNAME",
        &config.auth.admin_username,
    );
    command.env(
        "ANYSCAN_PACKAGE_ADMIN_PASSWORD",
        &config.auth.admin_password,
    );
    command.env(
        "ANYSCAN_PACKAGE_API_BASE_URL",
        local_api_base_url(config).unwrap_or_else(|| "http://127.0.0.1:8088".to_string()),
    );
    command.env("ANYSCAN_PACKAGE_WORKER_SUPPORTS_BOOTSTRAP", "true");
    if FsPath::new(INSTALLED_SCANNER_BINARY_PATH).is_file() {
        command.env(
            "ANYSCAN_PACKAGE_VULNSCANNER_BIN",
            INSTALLED_SCANNER_BINARY_PATH,
        );
    }

    let output = command
        .output()
        .with_context(|| format!("failed to execute {}", packager_script.display()))?;
    let _ = fs::remove_dir_all(&stage_root);
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "hosted agent bundle build failed (status {}): stdout:\n{}\nstderr:\n{}",
            output.status,
            stdout.trim(),
            stderr.trim()
        ));
    }
    write_hosted_agent_bundle_metadata(
        &bundle_output_dir,
        &bundle_name,
        platform_key,
        &source_fingerprint,
    )?;
    let bundle = resolve_hosted_agent_bundle_by_name(&format!("{bundle_name}.tar.gz"))?;
    if let Err(error) = prune_hosted_agent_bundles(HOSTED_AGENT_BUNDLE_KEEP_COUNT) {
        warn!(?error, "failed to prune old hosted agent bundles");
    }
    Ok(bundle)
}

fn local_api_base_url(config: &AppConfig) -> Option<String> {
    let bind_addr = config.server.bind_addr.trim();
    let (host, port) = bind_addr.rsplit_once(':')?;
    let host = match host {
        "" | "0.0.0.0" | "::" | "[::]" => "127.0.0.1",
        other => other.trim_matches(['[', ']']),
    };
    Some(format!("http://{host}:{port}"))
}

fn current_hosted_agent_bundle_source_fingerprint() -> Result<String> {
    let mut hasher = Sha256::new();
    for asset in HOSTED_AGENT_BUNDLE_ASSETS {
        hasher.update(asset.relative_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(asset.contents);
        hasher.update(b"\0");
        hasher.update(if asset.executable { b"1" } else { b"0" });
        hasher.update(b"\0");
    }
    hash_file_with_label(
        &PathBuf::from(INSTALLED_AGENT_BINARY_PATH),
        "installed-agent-binary",
        &mut hasher,
    )?;
    if FsPath::new(INSTALLED_SCANNER_BINARY_PATH).is_file() {
        hash_file_with_label(
            &PathBuf::from(INSTALLED_SCANNER_BINARY_PATH),
            "installed-scanner-binary",
            &mut hasher,
        )?;
    }
    let digest = format!("{:x}", hasher.finalize());
    Ok(digest)
}

fn native_hosted_agent_platform_key() -> &'static str {
    "linux-x86_64"
}

fn find_latest_hosted_agent_bundle_for_platform(
    platform_key: &str,
    current_source_fingerprint: Option<&str>,
) -> Result<Option<HostedAgentBundleInfo>> {
    Ok(list_hosted_agent_bundles()?
        .into_iter()
        .find_map(|(_, info)| {
            (info.platform_key == platform_key
                && current_source_fingerprint.is_none_or(|fingerprint| {
                    info.source_fingerprint.as_deref() == Some(fingerprint)
                }))
            .then_some(info)
        }))
}

fn find_latest_available_hosted_agent_bundle_for_platform(
    platform_key: &str,
    current_source_fingerprint: Option<&str>,
) -> Result<Option<HostedAgentBundleInfo>> {
    Ok(list_hosted_agent_bundles()?
        .into_iter()
        .find_map(|(_, info)| {
            (info.platform_key == platform_key
                && !info.leased
                && current_source_fingerprint.is_none_or(|fingerprint| {
                    info.source_fingerprint.as_deref() == Some(fingerprint)
                }))
            .then_some(info)
        }))
}

fn enrich_worker_with_bundle_state(mut worker: WorkerRecord) -> WorkerRecord {
    let Some(platform_key) = worker.platform.as_deref() else {
        return worker;
    };
    let current_source_fingerprint = current_hosted_agent_bundle_source_fingerprint().ok();
    let Ok(latest_bundle) = find_latest_hosted_agent_bundle_for_platform(
        platform_key,
        current_source_fingerprint.as_deref(),
    ) else {
        return worker;
    };
    let Some(latest_bundle) = latest_bundle else {
        return worker;
    };
    worker.latest_available_bundle_name = Some(latest_bundle.bundle_name.clone());
    worker.latest_bundle_matches_installed = worker.installed_bundle_name.as_deref().map(
        |installed| {
            installed == latest_bundle.bundle_name
                || format!("{installed}.tar.gz") == latest_bundle.bundle_name
        },
    );
    worker
}

fn resolve_hosted_agent_bundle_by_name(filename: &str) -> Result<HostedAgentBundleInfo> {
    let bundle_output_dir = PathBuf::from(HOSTED_AGENT_BUNDLE_OUTPUT_DIR);
    let bundle_name = if filename.ends_with(".tar.gz") {
        filename.to_string()
    } else if filename.ends_with(".sha256") {
        format!("{}.tar.gz", filename.trim_end_matches(".sha256"))
    } else {
        return Err(anyhow!("unsupported hosted bundle artifact {filename}"));
    };
    let sha256_name = hosted_bundle_sha256_name(&bundle_name)
        .ok_or_else(|| anyhow!("invalid hosted bundle name {bundle_name}"))?;
    let platform_key = hosted_bundle_platform_key(&bundle_name)
        .ok_or_else(|| anyhow!("invalid hosted bundle platform {bundle_name}"))?;
    let bundle_path = bundle_output_dir.join(&bundle_name);
    let sha256_path = bundle_output_dir.join(&sha256_name);
    let metadata_path = bundle_output_dir.join(hosted_bundle_metadata_name(&bundle_name));
    let lease_marker_path = bundle_output_dir.join(hosted_bundle_lease_marker_name(&bundle_name));
    if !bundle_path.is_file() || !sha256_path.is_file() {
        return Err(anyhow!(
            "hosted bundle artifact pair is incomplete for {bundle_name}"
        ));
    }
    let source_fingerprint = load_hosted_agent_bundle_metadata(&metadata_path)
        .ok()
        .flatten()
        .map(|metadata| metadata.source_fingerprint);
    Ok(HostedAgentBundleInfo {
        platform_key,
        bundle_name,
        sha256_name,
        bundle_path,
        sha256_path,
        metadata_path,
        leased: lease_marker_path.is_file(),
        lease_marker_path,
        source_fingerprint,
    })
}

fn hosted_bundle_metadata_name(bundle_name: &str) -> String {
    format!("{bundle_name}.meta.json")
}

fn load_hosted_agent_bundle_metadata(
    metadata_path: &PathBuf,
) -> Result<Option<HostedAgentBundleMetadata>> {
    if !metadata_path.is_file() {
        return Ok(None);
    }
    let payload = fs::read_to_string(metadata_path)
        .with_context(|| format!("failed to read {}", metadata_path.display()))?;
    let metadata = serde_json::from_str::<HostedAgentBundleMetadata>(&payload)
        .with_context(|| format!("failed to parse {}", metadata_path.display()))?;
    Ok(Some(metadata))
}

fn write_hosted_agent_bundle_metadata(
    bundle_output_dir: &PathBuf,
    bundle_name: &str,
    platform_key: &str,
    source_fingerprint: &str,
) -> Result<()> {
    let metadata_path = bundle_output_dir.join(hosted_bundle_metadata_name(bundle_name));
    let metadata = HostedAgentBundleMetadata {
        platform_key: platform_key.to_string(),
        bundle_name: bundle_name.to_string(),
        source_fingerprint: source_fingerprint.to_string(),
        built_at: Utc::now().to_rfc3339(),
    };
    fs::write(&metadata_path, serde_json::to_vec_pretty(&metadata)?)
        .with_context(|| format!("failed to write {}", metadata_path.display()))?;
    Ok(())
}

fn hash_file_with_label(path: &PathBuf, label: &str, hasher: &mut Sha256) -> Result<()> {
    hasher.update(label.as_bytes());
    hasher.update(b"\0");
    let contents = fs::read(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    hasher.update(&contents);
    hasher.update(b"\0");
    Ok(())
}

fn hash_path_recursively(path: &PathBuf, label: &str, hasher: &mut Sha256) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.is_file() {
        return hash_file_with_label(path, label, hasher);
    }
    if metadata.is_dir() {
        let mut entries = fs::read_dir(path)
            .with_context(|| format!("failed to read {}", path.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("failed to list {}", path.display()))?;
        entries.sort_by_key(|entry| entry.file_name());
        hasher.update(label.as_bytes());
        hasher.update(b"/\0");
        for entry in entries {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            let child_label = format!("{label}/{}", file_name);
            hash_path_recursively(&entry.path(), &child_label, hasher)?;
        }
    }
    Ok(())
}

fn write_hosted_agent_bundle_assets(root: &FsPath) -> Result<()> {
    for asset in HOSTED_AGENT_BUNDLE_ASSETS {
        let path = root.join(asset.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(&path, asset.contents)
            .with_context(|| format!("failed to write {}", path.display()))?;
        let mode = if asset.executable { 0o755 } else { 0o644 };
        let mut permissions = fs::metadata(&path)?.permissions();
        permissions.set_mode(mode);
        fs::set_permissions(&path, permissions)
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    Ok(())
}

fn read_bundle_chunk_base64(bundle_path: &FsPath, chunk_index: usize) -> Result<String> {
    let mut file = fs::File::open(bundle_path)
        .with_context(|| format!("failed to open {}", bundle_path.display()))?;
    let metadata = file.metadata()?;
    let bundle_size = metadata.len() as usize;
    let offset = chunk_index
        .checked_mul(HOSTED_AGENT_BUNDLE_CHUNK_SIZE)
        .ok_or_else(|| anyhow!("bundle chunk offset overflow"))?;
    if offset >= bundle_size {
        return Err(anyhow!(
            "bundle chunk index {} is out of range",
            chunk_index
        ));
    }
    file.seek(SeekFrom::Start(offset as u64))?;
    let remaining = bundle_size - offset;
    let read_len = remaining.min(HOSTED_AGENT_BUNDLE_CHUNK_SIZE);
    let mut buffer = vec![0u8; read_len];
    file.read_exact(&mut buffer)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(buffer))
}

fn list_hosted_agent_bundles() -> Result<Vec<(SystemTime, HostedAgentBundleInfo)>> {
    let bundle_output_dir = PathBuf::from(HOSTED_AGENT_BUNDLE_OUTPUT_DIR);
    if !bundle_output_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut bundles = Vec::new();
    for entry in fs::read_dir(&bundle_output_dir)
        .with_context(|| format!("failed to read {}", bundle_output_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(sha256_name) = hosted_bundle_sha256_name(file_name) else {
            continue;
        };
        let Some(platform_key) = hosted_bundle_platform_key(file_name) else {
            continue;
        };
        let sha256_path = bundle_output_dir.join(&sha256_name);
        let metadata_path = bundle_output_dir.join(hosted_bundle_metadata_name(file_name));
        let lease_marker_path = bundle_output_dir.join(hosted_bundle_lease_marker_name(file_name));
        if !sha256_path.is_file() {
            continue;
        }
        let source_fingerprint = load_hosted_agent_bundle_metadata(&metadata_path)
            .ok()
            .flatten()
            .map(|metadata| metadata.source_fingerprint);
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        bundles.push((
            modified,
            HostedAgentBundleInfo {
                platform_key,
                bundle_name: file_name.to_string(),
                sha256_name,
                bundle_path: path.clone(),
                sha256_path,
                metadata_path,
                leased: lease_marker_path.is_file(),
                lease_marker_path,
                source_fingerprint,
            },
        ));
    }

    bundles.sort_by(|left, right| right.0.cmp(&left.0));
    Ok(bundles)
}

fn hosted_bundle_sha256_name(bundle_name: &str) -> Option<String> {
    if !bundle_name.starts_with("agent-bundle-") || !bundle_name.ends_with(".tar.gz") {
        return None;
    }
    Some(format!(
        "{}.sha256",
        bundle_name.trim_end_matches(".tar.gz")
    ))
}

fn hosted_bundle_platform_key(bundle_name: &str) -> Option<String> {
    if !bundle_name.starts_with("agent-bundle-") || !bundle_name.ends_with(".tar.gz") {
        return None;
    }
    let stem = bundle_name
        .trim_end_matches(".tar.gz")
        .strip_prefix("agent-bundle-")?;
    if let Some((platform, _suffix)) = stem.split_once("__") {
        return normalize_platform_key(platform).ok();
    }
    if let Some(legacy_suffix) = stem.strip_prefix("linux-x86_64-") {
        if !legacy_suffix.is_empty() {
            return Some("linux-x86_64".to_string());
        }
    }
    None
}

fn hosted_bundle_lease_marker_name(bundle_name: &str) -> String {
    format!("{bundle_name}.leased")
}

fn mark_hosted_agent_bundle_leased(bundle: &HostedAgentBundleInfo) -> Result<()> {
    if bundle.leased {
        return Ok(());
    }
    fs::write(
        &bundle.lease_marker_path,
        format!("{}\n", Utc::now().to_rfc3339()),
    )
    .with_context(|| format!("failed to write {}", bundle.lease_marker_path.display()))
}

fn prune_hosted_agent_bundles(keep_count: usize) -> Result<()> {
    let bundle_output_dir = PathBuf::from(HOSTED_AGENT_BUNDLE_OUTPUT_DIR);
    if !bundle_output_dir.is_dir() {
        return Ok(());
    }

    let bundles = list_hosted_agent_bundles()?;
    for (_, stale_bundle) in bundles.into_iter().skip(keep_count) {
        remove_file_if_exists(&stale_bundle.bundle_path)?;
        remove_file_if_exists(&stale_bundle.sha256_path)?;
        remove_file_if_exists(&stale_bundle.metadata_path)?;
        remove_file_if_exists(&stale_bundle.lease_marker_path)?;
    }

    prune_orphaned_hosted_agent_bundle_files(&bundle_output_dir)?;
    Ok(())
}

fn prune_orphaned_hosted_agent_bundle_files(bundle_output_dir: &FsPath) -> Result<()> {
    for entry in fs::read_dir(bundle_output_dir)
        .with_context(|| format!("failed to read {}", bundle_output_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if let Some(sha256_name) = hosted_bundle_sha256_name(file_name) {
            let sha256_path = bundle_output_dir.join(sha256_name);
            if !sha256_path.is_file() {
                remove_file_if_exists(&path)?;
            }
            continue;
        }
        if file_name.starts_with("agent-bundle-") && file_name.ends_with(".tar.gz.leased") {
            let bundle_name = file_name.trim_end_matches(".leased");
            let bundle_path = bundle_output_dir.join(bundle_name);
            if !bundle_path.is_file() {
                remove_file_if_exists(&path)?;
            }
            continue;
        }
        if file_name.starts_with("agent-bundle-") && file_name.ends_with(".sha256") {
            let bundle_name = format!("{}.tar.gz", file_name.trim_end_matches(".sha256"));
            let bundle_path = bundle_output_dir.join(bundle_name);
            if !bundle_path.is_file() {
                remove_file_if_exists(&path)?;
            }
            continue;
        }
        if file_name.starts_with("agent-bundle-") && file_name.ends_with(".tar.gz.meta.json") {
            let bundle_name = file_name.trim_end_matches(".meta.json");
            let bundle_path = bundle_output_dir.join(bundle_name);
            if !bundle_path.is_file() {
                remove_file_if_exists(&path)?;
            }
        }
    }
    Ok(())
}

fn remove_file_if_exists(path: &FsPath) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn worker_auth_error_status(error: anyhow::Error) -> StatusCode {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("revoked")
        || message.contains("invalid")
        || message.contains("expired")
        || message.contains("not registered")
        || message.contains("missing an enrollment token")
    {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_REQUEST
    }
}

fn require_auth(state: &AppState, jar: &CookieJar) -> Result<SessionContext, StatusCode> {
    let cookie = jar.get(SESSION_COOKIE).ok_or(StatusCode::UNAUTHORIZED)?;
    let token = cookie.value();
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.required_spec_claims = ["exp", "iat", "sub"]
        .into_iter()
        .map(String::from)
        .collect();
    let claims = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(state.config.auth.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let operator = state
        .config
        .operator(&claims.claims.sub)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !operator.enabled {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(SessionContext {
        username: operator.username,
        role: operator.role,
    })
}

fn require_write_access(state: &AppState, jar: &CookieJar) -> Result<SessionContext, StatusCode> {
    let session = require_auth(state, jar)?;
    if !session.role.can_write() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(session)
}

fn require_settings_access(
    state: &AppState,
    jar: &CookieJar,
) -> Result<SessionContext, StatusCode> {
    let session = require_auth(state, jar)?;
    if !session.role.can_manage_settings() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(session)
}

fn require_worker_management_access(
    state: &AppState,
    jar: &CookieJar,
) -> Result<SessionContext, StatusCode> {
    let session = require_auth(state, jar)?;
    if !session.role.can_manage_workers() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(session)
}

fn require_bootstrap_approval_access(
    state: &AppState,
    jar: &CookieJar,
) -> Result<SessionContext, StatusCode> {
    let session = require_auth(state, jar)?;
    if !session.role.can_approve_bootstrap_candidates() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(session)
}

fn require_public_finding_moderation_access(
    state: &AppState,
    jar: &CookieJar,
) -> Result<SessionContext, StatusCode> {
    let session = require_auth(state, jar)?;
    if !session.role.can_moderate_public_findings() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(session)
}

fn build_session_token(config: &AppConfig, session: &SessionContext) -> Result<String> {
    let issued_at = Utc::now().timestamp() as usize;
    let claims = SessionClaims {
        sub: session.username.clone(),
        role: session.role,
        iat: issued_at,
        exp: issued_at + config.auth.session_ttl_seconds as usize,
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.auth.jwt_secret.as_bytes()),
    )?)
}

fn build_public_profile_response(
    config: &AppConfig,
    scan_defaults: &ScanDefaultsSummary,
) -> PublicProfileResponse {
    let user_agent_examples = if config.public.user_agent_examples.is_empty() {
        vec![config.scan.user_agent.clone()]
    } else {
        config.public.user_agent_examples.clone()
    };
    PublicProfileResponse {
        service_name: config.public.service_name.clone(),
        base_url: config.public.base_url.clone(),
        security_email: config.public.security_email.clone(),
        abuse_email: config.public.abuse_email.clone(),
        opt_out_email: config.public.opt_out_email.clone(),
        scanner_ip_ranges: config.public.scanner_ip_ranges.clone(),
        scanner_asns: config.public.scanner_asns.clone(),
        reverse_dns_patterns: config.public.reverse_dns_patterns.clone(),
        user_agent_examples,
        published_search_scope: config.public.published_search_scope.clone(),
        data_retention_days: config.public.data_retention_days,
        opt_out_response_sla_hours: config.public.opt_out_response_sla_hours,
        max_concurrent_requests_per_host: scan_defaults.max_concurrent_requests_per_host,
        allow_authenticated_request_profiles: config.scan.allow_authenticated_request_profiles,
        rate_limit_policy: format!(
            "At most {} concurrent request(s) per host with {}ms-{}ms host backoff.",
            scan_defaults.max_concurrent_requests_per_host,
            scan_defaults.host_backoff_initial_ms,
            scan_defaults.host_backoff_max_ms
        ),
        scanning_policy_url: public_url(config, "/scanning-policy"),
        scanner_identity_url: public_url(config, "/scanner-identity"),
        data_policy_url: public_url(config, "/data-policy"),
        claim_url: public_url(config, "/claim"),
        opt_out_url: public_url(config, "/opt-out"),
        abuse_url: public_url(config, "/abuse"),
        security_txt_url: public_url(config, "/.well-known/security.txt"),
    }
}

fn public_url(config: &AppConfig, path: &str) -> String {
    match config.public.base_url.as_deref() {
        Some(base_url) => format!("{}{}", base_url.trim_end_matches('/'), path),
        None => path.to_string(),
    }
}

fn build_security_txt(config: &AppConfig) -> String {
    let scan_defaults = config.scan_defaults_summary();
    let profile = build_public_profile_response(config, &scan_defaults);
    let canonical_line = profile
        .base_url
        .as_ref()
        .map(|_| format!("Canonical: {}", profile.security_txt_url))
        .unwrap_or_default();
    let expiration = Utc::now() + chrono::Duration::days(365);
    let mut lines = vec![
        format!("Contact: mailto:{}", profile.security_email),
        format!("Contact: mailto:{}", profile.abuse_email),
        format!("Policy: {}", profile.scanning_policy_url),
        format!("Expires: {}", expiration.to_rfc3339()),
    ];
    if !canonical_line.is_empty() {
        lines.push(canonical_line);
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyscan::core::{PublicFindingStatus, Severity};

    fn sample_public_finding_moderation_record() -> PublicFindingModerationRecord {
        let now = Utc::now();
        PublicFindingModerationRecord {
            finding_id: 7,
            detector: "http".to_string(),
            severity: Severity::High,
            target_base_url: "https://example.test".to_string(),
            path: "/admin".to_string(),
            public_summary: "Admin panel requires authentication.".to_string(),
            plugin_metadata: None,
            reviewer_notes: Some("Contains reproduction details for operators only.".to_string()),
            status: PublicFindingStatus::Published,
            reviewed_by: Some("reviewer".to_string()),
            observed_at: now,
            reviewed_at: now,
            published_at: Some(now),
            updated_at: now,
        }
    }

    #[test]
    fn sanitize_public_finding_moderation_record_hides_private_notes() {
        let record = sample_public_finding_moderation_record();
        let sanitized = sanitize_public_finding_moderation_record(record, false);

        assert_eq!(sanitized.reviewer_notes, None);
    }

    #[test]
    fn sanitize_public_finding_moderation_record_preserves_notes_for_moderators() {
        let record = sample_public_finding_moderation_record();
        let sanitized = sanitize_public_finding_moderation_record(record.clone(), true);

        assert_eq!(sanitized.reviewer_notes, record.reviewer_notes);
    }

    #[test]
    fn direct_onion_urls_do_not_force_chunked_downloads() {
        assert!(!should_force_chunked_download(
            "http://nbhhzmw5m2fwpss44aktrgxjzwxnw5fssfzl76fg6edfzf4c6sy4ihad.onion"
        ));
        assert!(should_force_chunked_download(
            "http://nbhhzmw5m2fwpss44aktrgxjzwxnw5fssfzl76fg6edfzf4c6sy4ihad.onion.run"
        ));
        assert!(!should_force_chunked_download("https://scan.anyvm.tech"));
    }

    #[test]
    fn sanitize_public_finding_moderation_records_hides_private_notes_in_lists() {
        let records = vec![sample_public_finding_moderation_record()];
        let sanitized = sanitize_public_finding_moderation_records(records, false);

        assert_eq!(sanitized.len(), 1);
        assert_eq!(sanitized[0].reviewer_notes, None);
    }

    #[test]
    fn sanitize_api_event_for_session_hides_public_finding_notes_from_read_only_sessions() {
        let event = ApiEvent::PublicFindingModerated {
            finding: sample_public_finding_moderation_record(),
        };

        let sanitized = sanitize_api_event_for_session(event, false);

        match sanitized {
            ApiEvent::PublicFindingModerated { finding } => {
                assert_eq!(finding.reviewer_notes, None);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn sanitize_api_event_for_session_preserves_public_finding_notes_for_moderators() {
        let event = ApiEvent::PublicFindingModerated {
            finding: sample_public_finding_moderation_record(),
        };

        let sanitized = sanitize_api_event_for_session(event.clone(), true);

        match sanitized {
            ApiEvent::PublicFindingModerated { finding } => {
                let ApiEvent::PublicFindingModerated { finding: original } = event else {
                    unreachable!();
                };
                assert_eq!(finding.reviewer_notes, original.reviewer_notes);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn normalize_request_host_strips_ports_and_brackets() {
        assert_eq!(
            normalize_request_host(
                "nbhhzmw5m2fwpss44aktrgxjzwxnw5fssfzl76fg6edfzf4c6sy4ihad.onion:8088"
            ),
            Some("nbhhzmw5m2fwpss44aktrgxjzwxnw5fssfzl76fg6edfzf4c6sy4ihad.onion".to_string())
        );
        assert_eq!(
            normalize_request_host("[2001:db8::1]:8088"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn worker_only_host_allows_expected_routes() {
        assert!(worker_only_host_allows_request(
            &Method::POST,
            "/api/worker/control"
        ));
        assert!(worker_only_host_allows_request(
            &Method::POST,
            "/api/worker/bootstrap/exchange"
        ));
        assert!(worker_only_host_allows_request(
            &Method::GET,
            "/api/agent/install.sh"
        ));
        assert!(worker_only_host_allows_request(
            &Method::GET,
            "/api/agent/bundles/agent-bundle-linux-x86_64.tar.gz"
        ));
        assert!(!worker_only_host_allows_request(&Method::GET, "/"));
        assert!(!worker_only_host_allows_request(&Method::GET, "/app"));
        assert!(!worker_only_host_allows_request(
            &Method::POST,
            "/api/session"
        ));
        assert!(!worker_only_host_allows_request(
            &Method::GET,
            "/api/dashboard"
        ));
    }

    #[test]
    fn request_targets_worker_only_host_matches_configured_onion_host() {
        let mut config = AppConfig::default();
        config.server.worker_only_hosts =
            vec!["nbhhzmw5m2fwpss44aktrgxjzwxnw5fssfzl76fg6edfzf4c6sy4ihad.onion".to_string()];

        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            "nbhhzmw5m2fwpss44aktrgxjzwxnw5fssfzl76fg6edfzf4c6sy4ihad.onion"
                .parse()
                .expect("host header should parse"),
        );

        assert!(request_targets_worker_only_host(&headers, &config));
    }

    #[test]
    fn hosted_bundle_sha256_name_matches_bundle_name() {
        assert_eq!(
            hosted_bundle_sha256_name("agent-bundle-linux-x86_64-20260417173926-814835.tar.gz"),
            Some("agent-bundle-linux-x86_64-20260417173926-814835.sha256".to_string())
        );
        assert_eq!(hosted_bundle_sha256_name("notes.txt"), None);
    }

    #[test]
    fn hosted_bundle_platform_key_supports_new_and_legacy_names() {
        assert_eq!(
            hosted_bundle_platform_key("agent-bundle-linux-aarch64__20260419040000-1234.tar.gz"),
            Some("linux-aarch64".to_string())
        );
        assert_eq!(
            hosted_bundle_platform_key("agent-bundle-linux-x86_64-20260417173926-814835.tar.gz"),
            Some("linux-x86_64".to_string())
        );
        assert_eq!(hosted_bundle_platform_key("notes.txt"), None);
    }

    #[test]
    fn run_request_defaults_active_authorized_plugins_to_disabled() {
        let request = serde_json::from_str::<RunRequest>("{}").expect("request should deserialize");

        assert!(!request.active_authorized_plugins.global_gate_enabled);
        assert!(!request.active_authorized_plugins.request_opt_in_enabled);
    }

    #[test]
    fn schedule_request_deserializes_active_authorized_plugins() {
        let request = serde_json::from_str::<ScheduleRequest>(
            r#"{
                "label": "nightly",
                "interval_seconds": 3600,
                "active_authorized_plugins": {
                    "global_gate_enabled": true,
                    "request_opt_in_enabled": true
                }
            }"#,
        )
        .expect("request should deserialize");

        assert_eq!(request.label, "nightly");
        assert!(request.active_authorized_plugins.global_gate_enabled);
        assert!(request.active_authorized_plugins.request_opt_in_enabled);
        assert!(request.active_authorized_plugins.is_enabled());
    }

    #[test]
    fn port_scan_queue_request_defaults_active_authorized_plugins_to_disabled() {
        let request = serde_json::from_str::<PortScanQueueRequest>(
            r#"{
                "target_range": "10.0.0.0/24",
                "ports": "80,443"
            }"#,
        )
        .expect("request should deserialize");

        assert_eq!(request.request.target_range, "10.0.0.0/24");
        assert_eq!(request.request.ports, "80,443");
        assert!(request.request.follow_on_run_policy.enabled);
        assert_eq!(request.request.follow_on_run_policy.worker_pool, None);
        assert_eq!(
            request.request.follow_on_run_policy.selection_mode,
            anyscan::core::PortScanFollowOnSelectionMode::Validated
        );
        assert!(!request.active_authorized_plugins.global_gate_enabled);
        assert!(!request.active_authorized_plugins.request_opt_in_enabled);
    }

    #[test]
    fn port_scan_queue_request_deserializes_follow_on_run_policy() {
        let request = serde_json::from_str::<PortScanQueueRequest>(
            r#"{
                "target_range": "10.0.0.0/24",
                "ports": "80,443",
                "follow_on_run_policy": {
                    "enabled": false,
                    "worker_pool": "edge-scanners",
                    "selection_mode": "both"
                }
            }"#,
        )
        .expect("request should deserialize");

        assert!(!request.request.follow_on_run_policy.enabled);
        assert_eq!(
            request.request.follow_on_run_policy.worker_pool.as_deref(),
            Some("edge-scanners")
        );
        assert_eq!(
            request.request.follow_on_run_policy.selection_mode,
            anyscan::core::PortScanFollowOnSelectionMode::Both
        );
    }

    #[test]
    fn resolve_active_authorized_execution_forces_enablement_when_testing_override_is_on() {
        let mut config = AppConfig::default();
        config.scan.allow_active_authorized_execution = false;
        config.scan.enable_all_plugins_for_testing = true;

        let resolved = resolve_active_authorized_execution(
            &config,
            ActiveAuthorizedPluginExecution::default(),
        );

        assert!(resolved.global_gate_enabled);
        assert!(resolved.request_opt_in_enabled);
        assert!(resolved.is_enabled());
    }
}
