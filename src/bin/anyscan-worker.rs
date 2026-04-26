use std::{
    collections::HashSet,
    env, fs,
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use anyscan::{
    config::{AppConfig, ProxyMode, parse_port_scan_ports, resolve_scan_proxy_url},
    core::{
        ApiEvent, DiscoveryProvenanceRecord, ExtensionManifest, FetchTelemetry, NewFinding,
        PortScanFollowOnSelectionMode, PortScanProtocolFindingRecord, PortScanRecord,
        PortScanResumeStateRecord, PortScanSchemePolicy, RunScope, RunStatus, RunSummary,
        ScanJobRecord, ScanRunRecord, Severity, TargetDefinition,
        WorkerBootstrapCandidateInput, WorkerBootstrapCandidateRecord, WorkerBootstrapJobClaim,
        WorkerBootstrapJobRecord, WorkerRegistration, WorkerRemoteCommandRecord,
        WorkerRemoteUpdateStatus, merge_coverage_source_stat, normalize_run_scope,
    },
    detectors::DetectorEngine,
    fetcher::{Fetcher, TargetFetchReport, build_http_client},
    ops::init_tracing,
    plugins::{PluginExecutionMode, build_plugin_metadata, lookup_plugin},
    worker_api::AnyScanWorkerApiClient as AnyScanStore,
};
use chrono::Utc;
use clap::{Parser, Subcommand};
use futures::stream::{self, StreamExt};
use reqwest::blocking::Client as BlockingHttpClient;
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;
use tracing::{error, info, warn};

#[cfg(feature = "worker-bundle-stealth")]
const WORKER_NAME_ENV_NAMES: &[&str] = &["AGENT_NAME"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const WORKER_NAME_ENV_NAMES: &[&str] = &["AGENT_NAME", "ANYSCAN_WORKER_NAME"];
#[cfg(feature = "worker-bundle-stealth")]
const WORKER_POOL_ENV_NAMES: &[&str] = &["AGENT_POOL"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const WORKER_POOL_ENV_NAMES: &[&str] = &["AGENT_POOL", "ANYSCAN_WORKER_POOL"];
#[cfg(feature = "worker-bundle-stealth")]
const WORKER_TOKEN_ENV_NAMES: &[&str] = &["AGENT_TOKEN", "AGENT_ENROLLMENT_TOKEN"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const WORKER_TOKEN_ENV_NAMES: &[&str] = &[
    "AGENT_TOKEN",
    "AGENT_ENROLLMENT_TOKEN",
    "ANYSCAN_WORKER_TOKEN",
    "ANYSCAN_WORKER_ENROLLMENT_TOKEN",
];
#[cfg(feature = "worker-bundle-stealth")]
const WORKER_TAGS_ENV_NAMES: &[&str] = &["AGENT_TAGS"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const WORKER_TAGS_ENV_NAMES: &[&str] = &["AGENT_TAGS", "ANYSCAN_WORKER_TAGS"];
#[cfg(feature = "worker-bundle-stealth")]
const WORKER_BOOTSTRAP_SUPPORT_ENV_NAMES: &[&str] = &["AGENT_ENABLE_BOOTSTRAP"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const WORKER_BOOTSTRAP_SUPPORT_ENV_NAMES: &[&str] = &[
    "AGENT_ENABLE_BOOTSTRAP",
    "ANYSCAN_WORKER_SUPPORTS_BOOTSTRAP",
    "ANYSCAN_WORKER_ENABLE_BOOTSTRAP",
];
#[cfg(feature = "worker-bundle-stealth")]
const WORKER_ID_ENV_NAMES: &[&str] = &["AGENT_ID"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const WORKER_ID_ENV_NAMES: &[&str] = &["AGENT_ID", "ANYSCAN_WORKER_ID"];
#[cfg(feature = "worker-bundle-stealth")]
const CONTROL_URL_ENV_NAMES: &[&str] = &["AGENT_MANAGEMENT_URL", "CONTROL_URL"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const CONTROL_URL_ENV_NAMES: &[&str] = &[
    "AGENT_MANAGEMENT_URL",
    "ANYSCAN_WORKER_MANAGEMENT_URL",
    "CONTROL_URL",
    "ANYSCAN_API_BASE_URL",
];
#[cfg(feature = "worker-bundle-stealth")]
const REMOTE_UPDATE_ENABLED_ENV_NAMES: &[&str] = &["AGENT_REMOTE_UPDATE_ENABLED"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const REMOTE_UPDATE_ENABLED_ENV_NAMES: &[&str] = &[
    "AGENT_REMOTE_UPDATE_ENABLED",
    "ANYSCAN_WORKER_REMOTE_UPDATE_ENABLED",
];
#[cfg(feature = "worker-bundle-stealth")]
const REMOTE_UPDATE_REQUEST_FILE_ENV_NAMES: &[&str] = &["AGENT_REMOTE_UPDATE_REQUEST_FILE"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const REMOTE_UPDATE_REQUEST_FILE_ENV_NAMES: &[&str] = &[
    "AGENT_REMOTE_UPDATE_REQUEST_FILE",
    "ANYSCAN_WORKER_REMOTE_UPDATE_REQUEST_FILE",
];
#[cfg(feature = "worker-bundle-stealth")]
const REMOTE_UPDATE_INSTALLER_URL_ENV_NAMES: &[&str] = &["AGENT_REMOTE_UPDATE_INSTALLER_URL"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const REMOTE_UPDATE_INSTALLER_URL_ENV_NAMES: &[&str] = &[
    "AGENT_REMOTE_UPDATE_INSTALLER_URL",
    "ANYSCAN_WORKER_REMOTE_UPDATE_INSTALLER_URL",
];
#[cfg(feature = "worker-bundle-stealth")]
const REMOTE_DEBUG_ENABLED_ENV_NAMES: &[&str] = &["AGENT_REMOTE_DEBUG_ENABLED"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const REMOTE_DEBUG_ENABLED_ENV_NAMES: &[&str] = &[
    "AGENT_REMOTE_DEBUG_ENABLED",
    "ANYSCAN_WORKER_REMOTE_DEBUG_ENABLED",
];
#[cfg(feature = "worker-bundle-stealth")]
const REMOTE_UPDATE_STATUS_FILE_ENV_NAMES: &[&str] = &["AGENT_REMOTE_UPDATE_STATUS_FILE"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const REMOTE_UPDATE_STATUS_FILE_ENV_NAMES: &[&str] = &[
    "AGENT_REMOTE_UPDATE_STATUS_FILE",
    "ANYSCAN_WORKER_REMOTE_UPDATE_STATUS_FILE",
];
#[cfg(feature = "worker-bundle-stealth")]
const MAX_ACTIVE_TASKS_ENV_NAMES: &[&str] = &["AGENT_MAX_ACTIVE_TASKS"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const MAX_ACTIVE_TASKS_ENV_NAMES: &[&str] =
    &["AGENT_MAX_ACTIVE_TASKS", "ANYSCAN_WORKER_MAX_ACTIVE_TASKS"];
#[cfg(feature = "worker-bundle-stealth")]
const INSTALLED_BUNDLE_NAME_ENV_NAMES: &[&str] = &["AGENT_BUNDLE_NAME"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const INSTALLED_BUNDLE_NAME_ENV_NAMES: &[&str] =
    &["AGENT_BUNDLE_NAME", "ANYSCAN_WORKER_BUNDLE_NAME"];
#[cfg(feature = "worker-bundle-stealth")]
const AGENT_CONCURRENCY_ENV_NAMES: &[&str] = &["AGENT_CONCURRENCY"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const AGENT_CONCURRENCY_ENV_NAMES: &[&str] = &["AGENT_CONCURRENCY", "ANYSCAN_SCAN_CONCURRENCY"];
#[cfg(feature = "worker-bundle-stealth")]
const SCANNER_DEFAULT_RATE_ENV_NAMES: &[&str] = &["SCANNER_DEFAULT_RATE"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const SCANNER_DEFAULT_RATE_ENV_NAMES: &[&str] = &["SCANNER_DEFAULT_RATE"];
#[cfg(feature = "worker-bundle-stealth")]
const SCANNER_SENDER_THREADS_ENV_NAMES: &[&str] = &["SCANNER_SENDER_THREADS"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const SCANNER_SENDER_THREADS_ENV_NAMES: &[&str] = &["SCANNER_SENDER_THREADS"];
#[cfg(feature = "worker-bundle-stealth")]
const SCANNER_RECEIVER_THREADS_ENV_NAMES: &[&str] = &["SCANNER_RECEIVER_THREADS"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const SCANNER_RECEIVER_THREADS_ENV_NAMES: &[&str] = &["SCANNER_RECEIVER_THREADS"];
#[cfg(feature = "worker-bundle-stealth")]
const DEFAULT_RUNTIME_ENV_FILE_PATH: &str = "/etc/agentd/runtime.env";
#[cfg(not(feature = "worker-bundle-stealth"))]
const DEFAULT_RUNTIME_ENV_FILE_PATH: &str = "/etc/anyscan/runtime.env";

#[derive(Debug, Parser)]
struct Cli {
    #[cfg_attr(feature = "worker-bundle-stealth", arg(long, env = "AGENT_CONFIG"))]
    #[cfg_attr(
        not(feature = "worker-bundle-stealth"),
        arg(long, env = "ANYSCAN_CONFIG")
    )]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Seed,
    Queue {
        #[arg(long, default_value = "worker")]
        requested_by: String,
        #[arg(long = "target-id")]
        target_ids: Vec<i64>,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long)]
        failed_only: bool,
    },
    Once,
    Daemon,
}

#[derive(Debug, Clone)]
struct WorkerRuntime {
    registration: WorkerRegistration,
    scanner_adapters: Vec<ExtensionManifest>,
    importers: Vec<ExtensionManifest>,
    provisioners: Vec<ExtensionManifest>,
    remote_update_plan: Option<RemoteUpdatePlan>,
    max_active_tasks: usize,
}

#[derive(Debug, Clone, Copy)]
enum TopLevelTaskKind {
    BootstrapJob,
    PortScan,
    Run,
}

#[derive(Debug)]
struct ActiveTaskCompletion {
    kind: TopLevelTaskKind,
    label: String,
    result: Result<()>,
}

#[derive(Debug, Clone)]
struct RemoteUpdatePlan {
    request_file: PathBuf,
    installer_url: String,
}

#[derive(Debug, Clone, Default)]
struct WorkerRemoteUpdateState {
    status: Option<WorkerRemoteUpdateStatus>,
    message: Option<String>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug)]
struct RemoteCommandExecution {
    exit_code: Option<i32>,
    timed_out: bool,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
struct DiscoveredEndpoint {
    host: String,
    port: u16,
    service_name: Option<String>,
    transport: Option<String>,
    tags: Vec<String>,
    version: Option<String>,
    reported_plugins: Vec<ReportedProtocolPluginFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct ReportedProtocolPluginFinding {
    plugin_id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    severity: Option<String>,
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
}

#[derive(Debug)]
struct ScannerExecutionResult {
    discovered_endpoints: Vec<DiscoveredEndpoint>,
    notes: Vec<String>,
}

#[derive(Debug)]
struct ImportedTargetsResult {
    target_ids: Vec<i64>,
    notes: Vec<String>,
}

#[derive(Debug)]
struct SelectedFollowOnTargets {
    targets: Vec<TargetDefinition>,
    notes: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum ValidationTransport {
    Direct,
    Proxy,
}

#[derive(Debug)]
struct QueuedFollowOnRun {
    run: ScanRunRecord,
    summary: RunSummary,
}

#[derive(Debug, Serialize)]
struct ScannerAdapterInvocation<'a> {
    port_scan_id: i64,
    target_range: &'a str,
    ports: &'a str,
    schemes: &'a str,
    rate_limit: u64,
    sender_threads: Option<u64>,
    receiver_threads: Option<u64>,
    output_path: &'a str,
    checkpoint_path: Option<&'a str>,
    resume: bool,
    requested_by: Option<&'a str>,
    tags: &'a [String],
    adapter_name: &'a str,
}

fn scanner_target_range_for_adapter(target_range: &str) -> String {
    let trimmed = target_range.trim();
    if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains('-') {
        return trimmed.to_string();
    }
    if trimmed.parse::<std::net::Ipv4Addr>().is_ok() {
        return format!("{trimmed}/32");
    }
    trimmed.to_string()
}

#[derive(Debug, Serialize)]
struct ImporterInvocation<'a> {
    importer_name: &'a str,
    port_scan: &'a PortScanRecord,
    discovered_endpoints: &'a [DiscoveredEndpoint],
}

#[derive(Debug, Serialize)]
struct ProvisionerInvocation<'a> {
    provisioner_name: &'a str,
    executor_worker_id: &'a str,
    job: &'a WorkerBootstrapJobRecord,
    candidate: &'a WorkerBootstrapCandidateRecord,
    enrollment_token: &'a str,
}

#[derive(Debug, Clone, Default)]
struct WorkerNetworkIdentity {
    local_ip_addresses: Vec<String>,
    public_ip_address: Option<String>,
    public_ip_checked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Default)]
struct WorkerPlatformIdentity {
    operating_system: Option<String>,
    architecture: Option<String>,
    platform: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ScannerProgressSnapshot {
    #[serde(default)]
    progress_percent: Option<u64>,
    #[serde(default)]
    probe_rate_millis: u64,
    #[serde(default)]
    receive_rate_millis: u64,
}

const PUBLIC_IP_CHECK_URLS: &[&str] = &[
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://checkip.amazonaws.com",
];
const PUBLIC_IP_CHECK_TIMEOUT_SECONDS: u64 = 5;
const REMOTE_COMMAND_MAX_OUTPUT_BYTES: usize = 64 * 1024;
const CLAIM_CANCELLATION_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::load(cli.config.as_deref())?;
    init_tracing("agentd");

    let detectors = DetectorEngine::from_config(&config)?;
    let worker_id = build_worker_id();

    match cli.command.unwrap_or(Command::Daemon) {
        Command::Seed => {
            let store = AnyScanStore::from_config_and_worker(&config, &worker_id)?;
            store.initialize()?;
            seed_bootstrap_inventory(&store, &config)?;
            info!("seeded bootstrap inventory");
        }
        Command::Queue {
            requested_by,
            target_ids,
            tags,
            failed_only,
        } => {
            let store = AnyScanStore::from_config_and_worker(&config, &worker_id)?;
            store.initialize()?;
            let scope = normalize_run_scope(Some(RunScope {
                target_ids,
                tags,
                worker_pool: None,
                failed_only,
            }));
            queue_run_with_event(&store, &requested_by, scope.as_ref())?;
            info!(requested_by = %requested_by, has_scope = scope.is_some(), "queued run");
        }
        Command::Once => {
            let store = AnyScanStore::from_config_and_worker(&config, &worker_id)?;
            store.initialize()?;
            let worker_runtime = build_worker_runtime(&config, &worker_id)?;
            seed_bootstrap_inventory(&store, &config)?;
            run_once(&config, &worker_id, store, detectors, &worker_runtime).await?;
        }
        Command::Daemon => {
            run_daemon_with_retry(config, worker_id, detectors).await?;
        }
    }

    Ok(())
}

async fn run_daemon_with_retry(
    config: AppConfig,
    worker_id: String,
    detectors: DetectorEngine,
) -> Result<()> {
    const DAEMON_STARTUP_RETRY_SECONDS: u64 = 5;

    loop {
        let attempt = (|| -> Result<(AnyScanStore, WorkerRuntime)> {
            let store = AnyScanStore::from_config_and_worker(&config, &worker_id)?;
            store.initialize()?;
            let worker_runtime = build_worker_runtime(&config, &worker_id)?;
            seed_bootstrap_inventory(&store, &config)?;
            Ok((store, worker_runtime))
        })();

        match attempt {
            Ok((store, worker_runtime)) => match run_daemon(
                config.clone(),
                worker_id.clone(),
                store,
                detectors.clone(),
                worker_runtime,
            )
            .await
            {
                Ok(()) => return Ok(()),
                Err(error) => {
                    let error_chain = format!("{error:#}");
                    error!(
                        worker_id = %worker_id,
                        %error,
                        error_chain = %error_chain,
                        retry_seconds = DAEMON_STARTUP_RETRY_SECONDS,
                        "agent daemon exited; retrying"
                    );
                }
            },
            Err(error) => {
                let error_chain = format!("{error:#}");
                error!(
                    worker_id = %worker_id,
                    %error,
                    error_chain = %error_chain,
                    retry_seconds = DAEMON_STARTUP_RETRY_SECONDS,
                    "agent startup failed; retrying"
                );
            }
        }

        tokio::time::sleep(Duration::from_secs(DAEMON_STARTUP_RETRY_SECONDS)).await;
    }
}

async fn run_daemon(
    config: AppConfig,
    worker_id: String,
    store: AnyScanStore,
    detectors: DetectorEngine,
    worker_runtime: WorkerRuntime,
) -> Result<()> {
    let worker_registration_ttl = worker_registration_ttl_seconds(&config);
    let worker_registration_interval =
        worker_registration_refresh_interval(&config, worker_registration_ttl);
    let registered_worker = register_worker_or_bail(
        &store,
        &worker_runtime.registration,
        worker_registration_ttl,
    )?;
    let (remote_update_tx, remote_update_rx) =
        watch::channel(registered_worker.remote_update_requested_at);
    let (registration_shutdown_tx, registration_shutdown_rx) = oneshot::channel();
    let registration_handle = tokio::spawn(worker_registration_heartbeat(
        store.clone(),
        worker_runtime.registration.clone(),
        worker_registration_ttl,
        worker_registration_interval,
        remote_update_tx,
        registration_shutdown_rx,
    ));
    let mut last_handled_remote_update_at = None;
    let mut active_tasks = JoinSet::<ActiveTaskCompletion>::new();
    let max_active_tasks = worker_runtime.max_active_tasks.max(1);

    let daemon_result = async {
        loop {
            while let Some(joined) = active_tasks.try_join_next() {
                match joined {
                    Ok(completion) => match completion.result {
                        Ok(()) => {
                            info!(
                                task_kind = %top_level_task_kind_label(completion.kind),
                                task = %completion.label,
                                worker_id = %worker_id,
                                "completed worker task"
                            );
                        }
                        Err(error) => {
                            error!(
                                task_kind = %top_level_task_kind_label(completion.kind),
                                task = %completion.label,
                                worker_id = %worker_id,
                                %error,
                                "worker task failed"
                            );
                        }
                    },
                    Err(error) => {
                        error!(worker_id = %worker_id, %error, "worker task join failed");
                    }
                }
            }

            if worker_runtime.registration.supports_remote_debug_commands {
                if let Some(command) = store.claim_next_pending_remote_command()? {
                    info!(
                        remote_command_id = command.id,
                        worker_id = %worker_id,
                        "claimed remote debug command"
                    );
                    process_remote_command(&store, &worker_id, command).await?;
                    continue;
                }
            }

            if let Some(requested_at) = remote_update_rx.borrow().clone() {
                if last_handled_remote_update_at != Some(requested_at)
                    && active_tasks.is_empty()
                    && maybe_schedule_remote_update(&store, &worker_runtime, requested_at)?
                {
                    last_handled_remote_update_at = Some(requested_at);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            }

            if let Err(error) = seed_bootstrap_inventory(&store, &config) {
                error!(%error, "failed to seed bootstrap inventory");
            }
            if let Err(error) = queue_due_schedules_with_events(&store, 10) {
                error!(%error, "failed to queue due schedules");
            }

            if active_tasks.len() < max_active_tasks
                && worker_runtime.registration.supports_bootstrap
            {
                if let Some(bootstrap_job) = store
                    .claim_next_pending_bootstrap_job(config.storage.redis_run_lease_seconds)?
                {
                    info!(
                        bootstrap_job_id = bootstrap_job.job.id,
                        worker_id = %worker_id,
                        provisioner = %bootstrap_job.job.provisioner,
                        provisioner_count = worker_runtime.provisioners.len(),
                        "claimed bootstrap job"
                    );
                    let config = config.clone();
                    let worker_runtime = worker_runtime.clone();
                    let worker_id = worker_id.clone();
                    let store = store.clone();
                    let job_id = bootstrap_job.job.id;
                    active_tasks.spawn(async move {
                        ActiveTaskCompletion {
                            kind: TopLevelTaskKind::BootstrapJob,
                            label: format!("#{}", job_id),
                            result: process_bootstrap_job(
                                &config,
                                &worker_runtime,
                                &worker_id,
                                &store,
                                bootstrap_job,
                            )
                            .await,
                        }
                    });
                    continue;
                }
            }

            if active_tasks.len() < max_active_tasks
                && worker_runtime.registration.supports_port_scans
            {
                if let Some(port_scan) =
                    store.claim_next_pending_port_scan(config.storage.redis_run_lease_seconds)?
                {
                    info!(
                        port_scan_id = port_scan.id,
                        worker_id = %worker_id,
                        adapter_count = worker_runtime.scanner_adapters.len(),
                        "claimed port scan"
                    );
                    let config = config.clone();
                    let worker_runtime = worker_runtime.clone();
                    let worker_id = worker_id.clone();
                    let store = store.clone();
                    let port_scan_id = port_scan.id;
                    active_tasks.spawn(async move {
                        ActiveTaskCompletion {
                            kind: TopLevelTaskKind::PortScan,
                            label: format!("#{}", port_scan_id),
                            result: process_port_scan(
                                &config,
                                &worker_runtime,
                                &worker_id,
                                &store,
                                port_scan,
                            )
                            .await,
                        }
                    });
                    continue;
                }
            }

            if active_tasks.len() < max_active_tasks {
                if let Some(run) = store.next_assistable_run()? {
                    info!(run_id = run.id, worker_id = %worker_id, "assisting active run");
                    let config = config.clone();
                    let worker_id = worker_id.clone();
                    let store = store.clone();
                    let detectors = detectors.clone();
                    let run_id = run.id;
                    active_tasks.spawn(async move {
                        ActiveTaskCompletion {
                            kind: TopLevelTaskKind::Run,
                            label: format!("assist #{}", run_id),
                            result: assist_run(&config, &worker_id, &store, detectors, run_id)
                                .await,
                        }
                    });
                    continue;
                }
            }

            if active_tasks.len() < max_active_tasks {
                if let Some(run) =
                    store.claim_next_runnable_run(config.storage.redis_run_lease_seconds)?
                {
                    info!(run_id = run.id, worker_id = %worker_id, "claimed runnable run");
                    let config = config.clone();
                    let worker_id = worker_id.clone();
                    let store = store.clone();
                    let detectors = detectors.clone();
                    let run_id = run.id;
                    active_tasks.spawn(async move {
                        ActiveTaskCompletion {
                            kind: TopLevelTaskKind::Run,
                            label: format!("#{}", run_id),
                            result: process_run(&config, &worker_id, &store, detectors, run_id)
                                .await,
                        }
                    });
                    continue;
                }
            }

            if active_tasks.is_empty() {
                match store.maybe_run_archive_pass() {
                    Ok(Some(job)) => {
                        info!(
                            archive_job_id = job.id,
                            pressure_mode = ?job.pressure_mode,
                            hot_retention_days = job.hot_retention_days,
                            archived_record_count = job.archived_record_count,
                            archived_object_count = job.archived_object_count,
                            "completed archive pass"
                        );
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        error!(%error, "failed to run archive pass");
                    }
                }
            }

            let effective_config = load_effective_runtime_config(&config, &store)?;
            let idle_sleep_seconds = if active_tasks.is_empty() {
                effective_config.scan.poll_interval_seconds
            } else {
                1
            };
            tokio::time::sleep(Duration::from_secs(idle_sleep_seconds.max(1))).await;
        }
    }
    .await;

    let _ = registration_shutdown_tx.send(());
    let _ = registration_handle.await;
    daemon_result
}

async fn run_once(
    config: &AppConfig,
    worker_id: &str,
    store: AnyScanStore,
    detectors: DetectorEngine,
    worker_runtime: &WorkerRuntime,
) -> Result<()> {
    let worker_registration_ttl = worker_registration_ttl_seconds(config);
    let worker_registration_interval =
        worker_registration_refresh_interval(config, worker_registration_ttl);
    let registered_worker = register_worker_or_bail(
        &store,
        &worker_runtime.registration,
        worker_registration_ttl,
    )?;
    let (remote_update_tx, remote_update_rx) =
        watch::channel(registered_worker.remote_update_requested_at);
    let (registration_shutdown_tx, registration_shutdown_rx) = oneshot::channel();
    let registration_handle = tokio::spawn(worker_registration_heartbeat(
        store.clone(),
        worker_runtime.registration.clone(),
        worker_registration_ttl,
        worker_registration_interval,
        remote_update_tx,
        registration_shutdown_rx,
    ));

    let once_result = async {
        if worker_runtime.registration.supports_remote_debug_commands {
            if let Some(command) = store.claim_next_pending_remote_command()? {
                process_remote_command(&store, worker_id, command).await?;
                return Ok(());
            }
        }

        if let Some(requested_at) = remote_update_rx.borrow().clone() {
            if maybe_schedule_remote_update(&store, worker_runtime, requested_at)? {
                return Ok(());
            }
        }

        queue_due_schedules_with_events(&store, 10)?;
        let run_id = {
            if worker_runtime.registration.supports_bootstrap {
                if let Some(bootstrap_job) = store
                    .claim_next_pending_bootstrap_job(config.storage.redis_run_lease_seconds)?
                {
                    process_bootstrap_job(config, worker_runtime, worker_id, &store, bootstrap_job)
                        .await?;
                    return Ok(());
                }
            }
            if worker_runtime.registration.supports_port_scans {
                if let Some(port_scan) =
                    store.claim_next_pending_port_scan(config.storage.redis_run_lease_seconds)?
                {
                    process_port_scan(config, worker_runtime, worker_id, &store, port_scan).await?;
                    return Ok(());
                }
            }
            if let Some(run) = store.next_assistable_run()? {
                assist_run(config, worker_id, &store, detectors, run.id).await?;
                return Ok(());
            }
            if let Some(run) =
                store.claim_next_runnable_run(config.storage.redis_run_lease_seconds)?
            {
                run.id
            } else {
                if let Some(job) = store.maybe_run_archive_pass()? {
                    info!(
                        archive_job_id = job.id,
                        pressure_mode = ?job.pressure_mode,
                        hot_retention_days = job.hot_retention_days,
                        archived_record_count = job.archived_record_count,
                        archived_object_count = job.archived_object_count,
                        "completed archive pass"
                    );
                    return Ok(());
                }
                queue_run_with_event(&store, "worker-once", None)?;
                store
                    .claim_next_runnable_run(config.storage.redis_run_lease_seconds)?
                    .map(|run| run.id)
                    .ok_or_else(|| anyhow!("queued run could not be claimed by {worker_id}"))?
            }
        };

        process_run(config, worker_id, &store, detectors, run_id).await
    }
    .await;

    let _ = registration_shutdown_tx.send(());
    let _ = registration_handle.await;
    once_result
}

async fn process_run(
    config: &AppConfig,
    worker_id: &str,
    store: &AnyScanStore,
    detectors: DetectorEngine,
    run_id: i64,
) -> Result<()> {
    let (claim_shutdown_tx, claim_shutdown_rx) = oneshot::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let heartbeat_store = store.clone();
    let heartbeat_worker_id = worker_id.to_string();
    let lease_seconds = config.storage.redis_run_lease_seconds;
    let heartbeat_cancelled = cancelled.clone();
    let heartbeat_handle = tokio::spawn(async move {
        run_claim_heartbeat(
            heartbeat_store,
            heartbeat_worker_id,
            run_id,
            lease_seconds,
            heartbeat_cancelled,
            claim_shutdown_rx,
        )
        .await
    });

    let run_result = async {
        store.requeue_in_progress_jobs(run_id)?;
        if let Some(run) = store.mark_run_started_if_queued(run_id)? {
            let summary = store.summary(run_id)?;
            store.append_event(
                Some(run_id),
                &ApiEvent::RunStarted {
                    run,
                    summary: summary.clone(),
                },
            )?;
        }

        let mut notes =
            process_claimed_jobs(config, worker_id, store, detectors.clone(), run_id).await?;
        while !cancelled.load(Ordering::SeqCst) && store.has_incomplete_jobs(run_id)? {
            let mut recovery_notes =
                process_claimed_jobs(config, worker_id, store, detectors.clone(), run_id).await?;
            notes.append(&mut recovery_notes);
            if cancelled.load(Ordering::SeqCst) {
                break;
            }
            if store.has_incomplete_jobs(run_id)? {
                tokio::select! {
                    _ = tokio::time::sleep(run_completion_poll_interval(
                        config.storage.redis_run_lease_seconds,
                    )) => {}
                    _ = wait_for_cancellation(cancelled.clone()) => {
                        break;
                    }
                }
            }
        }

        if cancelled.load(Ordering::SeqCst) {
            if let Some(stopped_run) = store
                .acknowledge_stopping_run(run_id, Some("stop request acknowledged by worker"))?
            {
                let stopped_summary = store.summary(run_id)?;
                store.append_event(
                    Some(run_id),
                    &ApiEvent::RunFailed {
                        run: stopped_run,
                        summary: stopped_summary,
                        error: "stop request acknowledged by worker".to_string(),
                    },
                )?;
            }
            return Ok(());
        }

        let notes_text = if notes.is_empty() {
            None
        } else {
            Some(notes.join(" | "))
        };
        let Some(completed_run) =
            store.mark_run_finished_if_owned(run_id, notes_text.as_deref())?
        else {
            if let Some(existing_run) = store.get_run(run_id)? {
                if matches!(
                    existing_run.status,
                    RunStatus::Completed | RunStatus::Failed
                ) {
                    return Ok(());
                }
            }
            return Err(anyhow!(
                "run {run_id} is no longer owned by worker {worker_id} for finalization"
            ));
        };
        let completed_summary = store.summary(run_id)?;

        match completed_run.status {
            RunStatus::Completed => {
                store.append_event(
                    Some(run_id),
                    &ApiEvent::RunCompleted {
                        run: completed_run,
                        summary: completed_summary,
                    },
                )?;
            }
            RunStatus::Failed => {
                store.append_event(
                    Some(run_id),
                    &ApiEvent::RunFailed {
                        run: completed_run,
                        summary: completed_summary,
                        error: notes_text.unwrap_or_else(|| "one or more jobs failed".to_string()),
                    },
                )?;
            }
            RunStatus::Queued | RunStatus::InProgress | RunStatus::Stopping => {}
        }

        Ok(())
    }
    .await;

    let _ = claim_shutdown_tx.send(());
    let heartbeat_result = match heartbeat_handle.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("run claim heartbeat task failed: {error}")),
    };

    match (run_result, heartbeat_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(heartbeat_error)) => Err(error).context(format!(
            "run claim heartbeat also failed: {heartbeat_error}"
        )),
    }
}

async fn assist_run(
    config: &AppConfig,
    worker_id: &str,
    store: &AnyScanStore,
    detectors: DetectorEngine,
    run_id: i64,
) -> Result<()> {
    let notes = process_claimed_jobs(config, worker_id, store, detectors, run_id).await?;
    for note in notes {
        error!(run_id, worker_id = %worker_id, error = %note, "job processing failed while assisting run");
    }
    Ok(())
}

async fn process_claimed_jobs(
    config: &AppConfig,
    worker_id: &str,
    store: &AnyScanStore,
    detectors: DetectorEngine,
    run_id: i64,
) -> Result<Vec<String>> {
    let effective_config = load_effective_runtime_config(config, store)?;
    let allow_active_authorized = store
        .get_run(run_id)?
        .map(|run| run.active_authorized_plugins.is_enabled())
        .unwrap_or(false)
        || effective_config.scan.enable_all_plugins_for_testing;
    let fetcher = Arc::new(Fetcher::new(&effective_config)?);
    let worker_concurrency = effective_config.scan.concurrency.max(1);
    let job_claim_lease_seconds = config.storage.redis_run_lease_seconds;
    let shared_store = Arc::new(store.clone());

    let task_results = stream::iter(0..worker_concurrency)
        .map(|_| {
            let store = shared_store.clone();
            let fetcher = fetcher.clone();
            let detectors = detectors.clone();
            let worker_id = worker_id.to_string();
            async move {
                claim_jobs_for_run(
                    store,
                    fetcher,
                    detectors,
                    run_id,
                    worker_id,
                    job_claim_lease_seconds,
                    allow_active_authorized,
                )
                .await
            }
        })
        .buffer_unordered(worker_concurrency)
        .collect::<Vec<_>>()
        .await;

    let mut notes = Vec::new();
    for result in task_results {
        match result {
            Ok(mut task_notes) => notes.append(&mut task_notes),
            Err(error) => notes.push(error.to_string()),
        }
    }
    Ok(notes)
}

async fn claim_jobs_for_run(
    store: Arc<AnyScanStore>,
    fetcher: Arc<Fetcher>,
    detectors: DetectorEngine,
    run_id: i64,
    worker_id: String,
    lease_seconds: u64,
    allow_active_authorized: bool,
) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    loop {
        let Some(job) = store.claim_next_pending_job(run_id, lease_seconds)? else {
            break;
        };
        info!(run_id, job_id = job.id, worker_id = %worker_id, "claimed pending job");
        if let Err(error) = process_job(
            store.clone(),
            fetcher.clone(),
            detectors.clone(),
            worker_id.clone(),
            lease_seconds,
            job,
            allow_active_authorized,
        )
        .await
        {
            notes.push(error.to_string());
        }
    }
    Ok(notes)
}

async fn process_job(
    store: Arc<AnyScanStore>,
    fetcher: Arc<Fetcher>,
    detectors: DetectorEngine,
    worker_id: String,
    lease_seconds: u64,
    job: ScanJobRecord,
    allow_active_authorized: bool,
) -> Result<()> {
    let (claim_shutdown_tx, claim_shutdown_rx) = oneshot::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let heartbeat_store = store.as_ref().clone();
    let heartbeat_worker_id = worker_id.clone();
    let job_id = job.id;
    let heartbeat_cancelled = cancelled.clone();
    let heartbeat_handle = tokio::spawn(async move {
        job_claim_heartbeat(
            heartbeat_store,
            heartbeat_worker_id,
            job_id,
            job.run_id,
            lease_seconds,
            heartbeat_cancelled,
            claim_shutdown_rx,
        )
        .await
    });

    let outcome = async {
        let fetch_result = tokio::select! {
            result = fetcher.fetch_target(&job.target) => Some(result),
            _ = wait_for_cancellation(cancelled.clone()) => None,
        };
        let (findings_count, telemetry, terminal_error, fetch_error) = match fetch_result {
            Some(Ok(report)) => {
                let TargetFetchReport {
                    documents,
                    discovered_paths,
                    mut telemetry,
                    errors,
                } = report;
                let mut findings_count = 0u64;
                let discovery_provenance = discovered_paths
                    .iter()
                    .map(|discovered_path| DiscoveryProvenanceRecord {
                        path: discovered_path.path.clone(),
                        source: discovered_path.source.clone(),
                        score: discovered_path.score,
                        depth: discovered_path.depth,
                        first_seen_at: None,
                        last_seen_at: None,
                    })
                    .collect::<Vec<_>>();
                if !discovery_provenance.is_empty() {
                    store
                        .merge_target_discovery_provenance(job.target.id, &discovery_provenance)?;
                }

                for document in &documents {
                    let matches = if detectors.has_external_packs() {
                        let detectors = detectors.clone();
                        let document = document.clone();
                        tokio::task::spawn_blocking(move || detectors.scan_document(&document))
                            .await
                            .map_err(|error| anyhow!("detector task failed: {error}"))?
                    } else {
                        detectors.scan_document(document)
                    };
                    for finding in matches {
                        if finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                            metadata.execution_mode == PluginExecutionMode::ActiveAuthorized
                        }) && !allow_active_authorized
                        {
                            continue;
                        }
                        if let Some(record) = store.record_finding_if_new(&NewFinding {
                            run_id: job.run_id,
                            target_id: job.target.id,
                            detector: finding.detector,
                            severity: finding.severity,
                            path: finding.path,
                            redacted_value: finding.redacted_value,
                            evidence: finding.evidence,
                            fingerprint: finding.fingerprint,
                            confidence: finding.confidence,
                            matched_signals: finding.matched_signals,
                            review_labels: finding.review_labels,
                            plugin_metadata: finding.plugin_metadata,
                        })? {
                            findings_count += 1;
                            merge_coverage_source_stat(
                                &mut telemetry.coverage_sources,
                                &document.coverage_source,
                                0,
                                0,
                                0,
                                0,
                                1,
                            );
                            store.append_event(
                                Some(job.run_id),
                                &ApiEvent::FindingRecorded { finding: record },
                            )?;
                        }
                    }
                }

                let terminal_error = if documents.is_empty() && !errors.is_empty() {
                    Some(errors.join(" | "))
                } else {
                    None
                };
                (findings_count, telemetry, terminal_error, None)
            }
            Some(Err(error)) => {
                let error_message = error.to_string();
                (
                    0,
                    FetchTelemetry::default(),
                    Some(error_message.clone()),
                    Some(error_message),
                )
            }
            None => {
                if store
                    .get_run(job.run_id)?
                    .is_some_and(|run| matches!(run.status, RunStatus::Stopping | RunStatus::Failed))
                {
                    return Ok(());
                }
                return Err(anyhow!("job {} claim was lost before fetch completed", job.id));
            }
        };

        let completion_applied = store.mark_job_finished_if_owned(
            job.id,
            findings_count,
            &telemetry,
            terminal_error.as_deref(),
        )?;
        if !completion_applied {
            return Err(anyhow!(
                "job {} is no longer claimed by worker {} during completion",
                job.id,
                worker_id
            ));
        }

        let summary = store.summary(job.run_id)?;
        store.append_event(
            Some(job.run_id),
            &ApiEvent::StatsUpdated {
                run_id: job.run_id,
                summary,
            },
        )?;

        match fetch_error {
            Some(error) => Err(anyhow!(error)),
            None => Ok(()),
        }
    }
    .await;

    let _ = claim_shutdown_tx.send(());
    let heartbeat_result = match heartbeat_handle.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("job claim heartbeat task failed: {error}")),
    };

    match (outcome, heartbeat_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(heartbeat_error)) => Err(error).context(format!(
            "job claim heartbeat also failed: {heartbeat_error}"
        )),
    }
}

async fn process_port_scan(
    config: &AppConfig,
    worker_runtime: &WorkerRuntime,
    worker_id: &str,
    store: &AnyScanStore,
    port_scan: PortScanRecord,
) -> Result<()> {
    let (claim_shutdown_tx, claim_shutdown_rx) = oneshot::channel();
    let (progress_shutdown_tx, progress_shutdown_rx) = oneshot::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let heartbeat_store = store.clone();
    let heartbeat_worker_id = worker_id.to_string();
    let lease_seconds = config.storage.redis_run_lease_seconds;
    let port_scan_id = port_scan.id;
    let heartbeat_cancelled = cancelled.clone();
    let heartbeat_handle = tokio::spawn(async move {
        port_scan_claim_heartbeat(
            heartbeat_store,
            heartbeat_worker_id,
            port_scan_id,
            lease_seconds,
            heartbeat_cancelled,
            claim_shutdown_rx,
        )
        .await
    });
    let adapter = select_scanner_adapter(&worker_runtime.scanner_adapters, &port_scan)?;
    let output_path = build_scanner_output_path(&adapter.name, port_scan.id);
    let checkpoint_path = build_scanner_checkpoint_path(&output_path);
    let resume_state = store.load_port_scan_resume_state(port_scan.id)?;
    let should_resume =
        restore_port_scan_resume_state(&output_path, &checkpoint_path, resume_state.as_ref())?;
    if should_resume {
        let _ = store.annotate_port_scan_if_owned(
            port_scan.id,
            "resumed port scan from persisted checkpoint",
        )?;
    }
    let progress_store = store.clone();
    let progress_target_range = port_scan.target_range.clone();
    let progress_ports = port_scan.ports.clone();
    let progress_output_format = adapter.output_format().to_string();
    let progress_output_path = output_path.clone();
    let progress_checkpoint_path = checkpoint_path.clone();
    let progress_cancelled = cancelled.clone();
    let progress_handle = tokio::spawn(async move {
        port_scan_progress_reporter(
            progress_store,
            port_scan_id,
            progress_target_range,
            progress_ports,
            progress_output_format,
            progress_output_path,
            progress_checkpoint_path,
            progress_cancelled,
            progress_shutdown_rx,
        )
        .await
    });

    let (streaming_shutdown_tx, streaming_shutdown_rx) = oneshot::channel();
    let streaming_handle = if port_scan.follow_on_run_policy.is_enabled() {
        let streaming_ctx = StreamingFollowOnContext {
            config: config.clone(),
            store: store.clone(),
            worker_runtime: worker_runtime.clone(),
            port_scan: port_scan.clone(),
            output_path: output_path.clone(),
            output_format: adapter.output_format().to_string(),
            cancelled: cancelled.clone(),
            should_resume,
        };
        Some(tokio::spawn(async move {
            streaming_followon_flusher(streaming_ctx, streaming_shutdown_rx).await
        }))
    } else {
        // No flusher needed; the shutdown sender will be dropped naturally.
        None
    };

    let outcome: Result<()> = async {
        if let Some(started) = store.mark_port_scan_started_if_queued(port_scan.id)? {
            store.append_event(None, &ApiEvent::PortScanStarted { port_scan: started })?;
        }

        let execution = execute_scanner_adapter(
            &port_scan,
            adapter,
            &output_path,
            &checkpoint_path,
            should_resume,
            cancelled.clone(),
        )
        .await?;

        // Signal the streaming flusher to drain any remaining endpoints and
        // exit, then collect what it queued during the scan so the final
        // import can avoid double-queueing those targets.
        let _ = streaming_shutdown_tx.send(());
        let streaming_summary = match streaming_handle {
            Some(handle) => match handle.await {
                Ok(Ok(summary)) => summary,
                Ok(Err(error)) => {
                    warn!(
                        port_scan_id = port_scan.id,
                        %error,
                        "streaming follow-on flusher returned error"
                    );
                    StreamingFollowOnSummary::default()
                }
                Err(error) => {
                    warn!(
                        port_scan_id = port_scan.id,
                        %error,
                        "streaming follow-on flusher join failed"
                    );
                    StreamingFollowOnSummary::default()
                }
            },
            None => StreamingFollowOnSummary::default(),
        };

        let protocol_findings = derive_protocol_plugin_findings_with_active_mode(
            &execution.discovered_endpoints,
            port_scan.active_authorized_plugins.is_enabled()
                || config.scan.enable_all_plugins_for_testing,
        );
        let mut bootstrap_notes = create_bootstrap_candidates_for_port_scan(
            config,
            store,
            &port_scan,
            &execution.discovered_endpoints,
        )?;
        let final_endpoints = filter_endpoints_excluding_streamed(
            &execution.discovered_endpoints,
            &streaming_summary.flushed_endpoint_keys,
        );
        let imported = import_port_scan_targets(
            config,
            store,
            &port_scan,
            &final_endpoints,
            &worker_runtime.importers,
        )
        .await?;
        let follow_on = queue_follow_on_run_for_targets(
            store,
            &port_scan,
            port_scan
                .requested_by
                .as_deref()
                .unwrap_or("port-scan-worker"),
            &imported.target_ids,
        )?;

        let mut notes = execution.notes;
        if should_resume {
            notes.push("resumed port scan from persisted checkpoint".to_string());
        }
        if !protocol_findings.is_empty() {
            notes.push(format!(
                "identified {} authless protocol plugin match(es)",
                protocol_findings.len()
            ));
        }
        notes.append(&mut bootstrap_notes);
        notes.extend(imported.notes);
        if !port_scan.follow_on_run_policy.is_enabled() && !imported.target_ids.is_empty() {
            notes.push("follow-on scanning of imported targets is disabled".to_string());
        }
        if !streaming_summary.queued_run_ids.is_empty() {
            notes.push(format!(
                "streamed {} follow-on run(s) during scan covering {} endpoint(s)",
                streaming_summary.queued_run_ids.len(),
                streaming_summary.flushed_endpoint_keys.len()
            ));
        }
        if streaming_summary.backpressure_events > 0 {
            notes.push(format!(
                "streaming follow-on backpressure events: {}",
                streaming_summary.backpressure_events
            ));
        }
        notes.extend(streaming_summary.notes.iter().cloned());
        if let Some(queued_run) = &follow_on {
            let pool_note = queued_run
                .run
                .scope
                .as_ref()
                .and_then(|scope| scope.worker_pool.as_deref())
                .map(|pool| format!(" in pool {pool}"))
                .unwrap_or_default();
            notes.push(format!(
                "queued follow-on run {} for {} target(s){}",
                queued_run.run.id,
                imported.target_ids.len(),
                pool_note
            ));
        }
        let notes = notes
            .into_iter()
            .filter(|note| !note.trim().is_empty())
            .collect::<Vec<_>>();
        let notes_text = join_notes(&notes);

        let total_imported_targets = (imported.target_ids.len() as u64)
            .saturating_add(streaming_summary.imported_targets_total);
        let completed = store
            .complete_port_scan_if_owned(
                port_scan.id,
                execution.discovered_endpoints.len() as u64,
                total_imported_targets,
                &protocol_findings,
                follow_on.as_ref().map(|item| item.run.id),
                notes_text.as_deref(),
            )?
            .ok_or_else(|| {
                anyhow!(
                    "port scan {} is no longer claimed by worker {} during completion",
                    port_scan.id,
                    worker_id
                )
            })?;

        store.append_event(
            None,
            &ApiEvent::PortScanCompleted {
                port_scan: completed,
                queued_run: follow_on.as_ref().map(|item| item.run.clone()),
                summary: follow_on.as_ref().map(|item| item.summary.clone()),
            },
        )?;

        Ok(())
    }
    .await;

    if let Err(error) = &outcome {
        let error_message = error.to_string();
        if !cancelled.load(Ordering::SeqCst) {
            if let Some(failed) =
                store.fail_port_scan_if_owned(port_scan.id, Some(&error_message))?
            {
                store.append_event(
                    None,
                    &ApiEvent::PortScanFailed {
                        port_scan: failed,
                        error: error_message,
                    },
                )?;
            }
        } else if let Some(failed) = store.acknowledge_stopping_port_scan(
            port_scan.id,
            Some("stop request acknowledged by worker"),
        )? {
            store.append_event(
                None,
                &ApiEvent::PortScanFailed {
                    port_scan: failed,
                    error: "stop request acknowledged by worker".to_string(),
                },
            )?;
        }
    }

    let _ = progress_shutdown_tx.send(());
    let _ = claim_shutdown_tx.send(());
    if let Err(error) = progress_handle.await {
        warn!(port_scan_id = port_scan.id, %error, "port scan progress reporter task failed");
    }
    let heartbeat_result = match heartbeat_handle.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("port scan claim heartbeat task failed: {error}")),
    };

    match (outcome, heartbeat_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(heartbeat_error)) => Err(error).context(format!(
            "port scan claim heartbeat also failed: {heartbeat_error}"
        )),
    }
}

async fn process_bootstrap_job(
    config: &AppConfig,
    worker_runtime: &WorkerRuntime,
    worker_id: &str,
    store: &AnyScanStore,
    bootstrap_job: WorkerBootstrapJobClaim,
) -> Result<()> {
    let (claim_shutdown_tx, claim_shutdown_rx) = oneshot::channel();
    let heartbeat_store = store.clone();
    let heartbeat_worker_id = worker_id.to_string();
    let lease_seconds = config.storage.redis_run_lease_seconds;
    let bootstrap_job_id = bootstrap_job.job.id;
    let heartbeat_handle = tokio::spawn(async move {
        bootstrap_job_claim_heartbeat(
            heartbeat_store,
            heartbeat_worker_id,
            bootstrap_job_id,
            lease_seconds,
            claim_shutdown_rx,
        )
        .await
    });

    let outcome: Result<()> = async {
        let started = store
            .mark_bootstrap_job_started_if_owned(bootstrap_job.job.id)?
            .ok_or_else(|| {
                anyhow!(
                    "bootstrap job {} is no longer claimed by worker {} during start",
                    bootstrap_job.job.id,
                    worker_id
                )
            })?;
        store.append_event(None, &ApiEvent::WorkerBootstrapJobStarted { job: started })?;

        let mut notes = bootstrap_job
            .job
            .notes
            .clone()
            .into_iter()
            .filter(|note| !note.trim().is_empty())
            .collect::<Vec<_>>();
        let mut execution_notes =
            execute_bootstrap_provisioner(&bootstrap_job, worker_id, &worker_runtime.provisioners)
                .await?;
        notes.append(&mut execution_notes);
        let notes_text = join_notes(&notes);

        let completed = store
            .complete_bootstrap_job_if_owned(bootstrap_job.job.id, notes_text.as_deref())?
            .ok_or_else(|| {
                anyhow!(
                    "bootstrap job {} is no longer claimed by worker {} during completion",
                    bootstrap_job.job.id,
                    worker_id
                )
            })?;
        store.append_event(
            None,
            &ApiEvent::WorkerBootstrapJobCompleted { job: completed },
        )?;

        Ok(())
    }
    .await;

    if let Err(error) = &outcome {
        let error_message = error.to_string();
        let mut notes = bootstrap_job
            .job
            .notes
            .clone()
            .into_iter()
            .filter(|note| !note.trim().is_empty())
            .collect::<Vec<_>>();
        notes.push(error_message.clone());
        let notes_text = join_notes(&notes);
        if let Some(failed) =
            store.fail_bootstrap_job_if_owned(bootstrap_job.job.id, notes_text.as_deref())?
        {
            store.append_event(
                None,
                &ApiEvent::WorkerBootstrapJobFailed {
                    job: failed,
                    error: error_message,
                },
            )?;
        }
    }

    let _ = claim_shutdown_tx.send(());
    let heartbeat_result = match heartbeat_handle.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!(
            "bootstrap job claim heartbeat task failed: {error}"
        )),
    };

    match (outcome, heartbeat_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(heartbeat_error)) => Err(error).context(format!(
            "bootstrap job claim heartbeat also failed: {heartbeat_error}"
        )),
    }
}

async fn process_remote_command(
    store: &AnyScanStore,
    worker_id: &str,
    command: WorkerRemoteCommandRecord,
) -> Result<()> {
    store.append_event(
        None,
        &ApiEvent::WorkerRemoteCommandStarted {
            command: command.clone(),
        },
    )?;

    let command_id = command.id;
    let shell_command = command.command.clone();
    let timeout_seconds = command.timeout_seconds;
    let execution = tokio::task::spawn_blocking(move || {
        run_remote_debug_command(shell_command, timeout_seconds)
    })
    .await
    .map_err(|error| anyhow!("remote command task failed: {error}"))?;

    let completed = match execution {
        Ok(execution) => store.complete_remote_command(
            command_id,
            execution.exit_code,
            execution.timed_out,
            Some(&execution.stdout),
            Some(&execution.stderr),
            if execution.timed_out {
                Some("remote command timed out")
            } else {
                None
            },
        )?,
        Err(error) => store.complete_remote_command(
            command_id,
            None,
            false,
            None,
            None,
            Some(&error.to_string()),
        )?,
    };

    if let Some(completed) = completed {
        match completed.status {
            anyscan::core::WorkerRemoteCommandStatus::Completed => {
                store.append_event(
                    None,
                    &ApiEvent::WorkerRemoteCommandCompleted { command: completed },
                )?;
            }
            anyscan::core::WorkerRemoteCommandStatus::Failed => {
                store.append_event(
                    None,
                    &ApiEvent::WorkerRemoteCommandFailed {
                        error: completed
                            .error
                            .clone()
                            .unwrap_or_else(|| "remote command failed".to_string()),
                        command: completed,
                    },
                )?;
            }
            anyscan::core::WorkerRemoteCommandStatus::Queued
            | anyscan::core::WorkerRemoteCommandStatus::Running => {}
        }
    } else {
        return Err(anyhow!(
            "remote command {} is no longer owned by worker {}",
            command_id,
            worker_id
        ));
    }

    Ok(())
}

fn run_remote_debug_command(
    command: String,
    timeout_seconds: u64,
) -> Result<RemoteCommandExecution> {
    let mut child = ProcessCommand::new("/bin/sh")
        .arg("-lc")
        .arg(&command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn remote command `{command}`"))?;

    let started_at = Instant::now();
    let timed_out = loop {
        if child
            .try_wait()
            .context("failed while waiting for remote command")?
            .is_some()
        {
            break false;
        }
        if started_at.elapsed() >= Duration::from_secs(timeout_seconds.max(1)) {
            let _ = child.kill();
            break true;
        }
        thread::sleep(Duration::from_millis(200));
    };

    let output = child
        .wait_with_output()
        .context("failed to collect remote command output")?;

    Ok(RemoteCommandExecution {
        exit_code: output.status.code(),
        timed_out,
        stdout: truncate_output(String::from_utf8_lossy(&output.stdout).as_ref()),
        stderr: truncate_output(String::from_utf8_lossy(&output.stderr).as_ref()),
    })
}

fn truncate_output(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() <= REMOTE_COMMAND_MAX_OUTPUT_BYTES {
        return value.to_string();
    }
    let truncated = &bytes[..REMOTE_COMMAND_MAX_OUTPUT_BYTES];
    format!(
        "{}\n[truncated at {} bytes]",
        String::from_utf8_lossy(truncated),
        REMOTE_COMMAND_MAX_OUTPUT_BYTES
    )
}

async fn execute_bootstrap_provisioner(
    bootstrap_job: &WorkerBootstrapJobClaim,
    worker_id: &str,
    provisioners: &[ExtensionManifest],
) -> Result<Vec<String>> {
    let provisioner = select_bootstrap_provisioner(provisioners, bootstrap_job)?;
    let command = provisioner
        .resolved_command()
        .ok_or_else(|| anyhow!("provisioner {} is missing a command", provisioner.name))?;
    let rendered_command = render_bootstrap_template(&command, bootstrap_job, provisioner);
    let rendered_args = provisioner
        .args
        .iter()
        .map(|arg| render_bootstrap_template(arg, bootstrap_job, provisioner))
        .collect::<Vec<_>>();
    let invocation = serde_json::to_vec(&ProvisionerInvocation {
        provisioner_name: &provisioner.name,
        executor_worker_id: worker_id,
        job: &bootstrap_job.job,
        candidate: &bootstrap_job.candidate,
        enrollment_token: &bootstrap_job.enrollment_token,
    })
    .context("failed to serialize bootstrap provisioner invocation")?;
    let provisioner_name = provisioner.name.clone();

    let output = tokio::task::spawn_blocking(move || {
        run_bootstrap_provisioner_process(rendered_command, rendered_args, invocation)
    })
    .await
    .map_err(|error| anyhow!("bootstrap provisioner task failed: {error}"))??;

    let status = output.status;
    if !status.success() {
        let status_label = status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".to_string());
        return Err(anyhow!(
            "bootstrap provisioner {} exited with status {}",
            provisioner_name,
            status_label
        ));
    }

    Ok(vec![format!(
        "provisioner {} completed on worker {}",
        provisioner_name, worker_id
    )])
}

fn run_bootstrap_provisioner_process(
    command: String,
    args: Vec<String>,
    invocation: Vec<u8>,
) -> Result<std::process::Output> {
    let mut child = ProcessCommand::new(&command)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn bootstrap provisioner command {command}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&invocation)
            .context("failed to write bootstrap provisioner invocation")?;
    }

    child
        .wait_with_output()
        .context("failed to wait for bootstrap provisioner command")
}

fn select_bootstrap_provisioner<'a>(
    provisioners: &'a [ExtensionManifest],
    bootstrap_job: &WorkerBootstrapJobClaim,
) -> Result<&'a ExtensionManifest> {
    provisioners
        .iter()
        .find(|provisioner| {
            provisioner
                .name
                .eq_ignore_ascii_case(&bootstrap_job.job.provisioner)
        })
        .ok_or_else(|| {
            anyhow!(
                "bootstrap provisioner {} is not registered on this worker",
                bootstrap_job.job.provisioner
            )
        })
}

async fn execute_scanner_adapter(
    port_scan: &PortScanRecord,
    adapter: &ExtensionManifest,
    output_path: &Path,
    checkpoint_path: &Path,
    should_resume: bool,
    cancelled: Arc<AtomicBool>,
) -> Result<ScannerExecutionResult> {
    let command = adapter
        .resolved_command()
        .ok_or_else(|| anyhow!("scanner adapter {} is missing a command", adapter.name))?;
    let rendered_command =
        render_scanner_template(&command, port_scan, Some(output_path), adapter);
    let rendered_args = adapter
        .args
        .iter()
        .map(|value| render_scanner_template(value, port_scan, Some(output_path), adapter))
        .collect::<Vec<_>>();
    let output_path_value = output_path.to_string_lossy().into_owned();
    let checkpoint_path_value = checkpoint_path.to_string_lossy().into_owned();
    let scanner_target_range = scanner_target_range_for_adapter(&port_scan.target_range);
    let invocation = serde_json::to_vec(&ScannerAdapterInvocation {
        port_scan_id: port_scan.id,
        target_range: &scanner_target_range,
        ports: &port_scan.ports,
        schemes: port_scan.schemes.as_str(),
        rate_limit: port_scan.rate_limit,
        sender_threads: port_scan.scanner_sender_threads,
        receiver_threads: port_scan.scanner_receiver_threads,
        output_path: &output_path_value,
        checkpoint_path: Some(&checkpoint_path_value),
        resume: should_resume,
        requested_by: port_scan.requested_by.as_deref(),
        tags: &port_scan.tags,
        adapter_name: &adapter.name,
    })
    .context("failed to serialize scanner adapter invocation")?;
    let adapter_name = adapter.name.clone();
    let output_format = adapter.output_format().to_string();
    let output_path_for_process = output_path.to_path_buf();

    let output = tokio::task::spawn_blocking(move || {
        run_scanner_process(
            rendered_command,
            rendered_args,
            invocation,
            output_path_for_process,
            cancelled,
        )
    })
    .await
    .map_err(|error| anyhow!("scanner adapter task failed: {error}"))??;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let status = output.status;
    if !status.success() {
        let status_label = status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".to_string());
        let stderr = stderr.trim();
        let detail = if stderr.is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.to_string()
        };
        return Err(anyhow!(
            "scanner adapter {} exited with status {}{}",
            adapter_name,
            status_label,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        ));
    }

    let raw_output = if output_path.exists() {
        let contents = fs::read_to_string(output_path).with_context(|| {
            format!(
                "failed to read scanner adapter output file {}",
                output_path.display()
            )
        })?;
        let _ = fs::remove_file(output_path);
        if contents.trim().is_empty() {
            stdout
        } else {
            contents
        }
    } else {
        stdout
    };
    let discovered_endpoints = parse_scanner_output(&raw_output, &port_scan.ports, &output_format)?;
    let mut notes = vec![format!(
        "adapter {} reported {} discovered endpoint(s)",
        adapter_name,
        discovered_endpoints.len()
    )];
    if !stderr.trim().is_empty() {
        notes.push(format!(
            "adapter stderr: {}",
            truncate_note(stderr.trim(), 240)
        ));
    }

    Ok(ScannerExecutionResult {
        discovered_endpoints,
        notes,
    })
}

fn run_scanner_process(
    command: String,
    args: Vec<String>,
    invocation: Vec<u8>,
    output_path: PathBuf,
    cancelled: Arc<AtomicBool>,
) -> Result<std::process::Output> {
    let mut child = ProcessCommand::new(&command)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn scanner adapter command {command}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&invocation)
            .context("failed to write scanner adapter invocation")?;
    }

    let was_cancelled = loop {
        if child
            .try_wait()
            .context("failed while waiting for scanner adapter command")?
            .is_some()
        {
            break false;
        }
        if cancelled.load(Ordering::SeqCst) {
            terminate_child_process_tree(child.id());
            let _ = child.kill();
            break true;
        }
        thread::sleep(Duration::from_millis(200));
    };

    let output = child
        .wait_with_output()
        .context("failed to wait for scanner adapter command")?;

    if was_cancelled {
        return Err(anyhow!("scanner adapter command {command} cancelled"));
    }

    if output_path.exists() && output.stdout.is_empty() {
        return Ok(output);
    }

    Ok(output)
}

fn terminate_child_process_tree(parent_pid: u32) {
    let child_pids = read_child_process_ids(parent_pid);
    if child_pids.is_empty() {
        return;
    }
    for pid in &child_pids {
        let _ = ProcessCommand::new("/bin/kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status();
    }
    thread::sleep(Duration::from_millis(250));
    for pid in &child_pids {
        let _ = ProcessCommand::new("/bin/kill")
            .arg("-KILL")
            .arg(pid.to_string())
            .status();
    }
}

fn read_child_process_ids(parent_pid: u32) -> Vec<u32> {
    let path = format!("/proc/{}/task/{}/children", parent_pid, parent_pid);
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };
    contents
        .split_whitespace()
        .filter_map(|value| value.parse::<u32>().ok())
        .collect()
}

fn select_scanner_adapter<'a>(
    scanner_adapters: &'a [ExtensionManifest],
    port_scan: &PortScanRecord,
) -> Result<&'a ExtensionManifest> {
    if scanner_adapters.is_empty() {
        return Err(anyhow!(
            "no enabled scanner_adapter extensions are configured for port scan {}",
            port_scan.id
        ));
    }

    if let Some(requested_adapter) = port_scan.tags.iter().find_map(|tag| {
        tag.strip_prefix("adapter:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }) {
        return scanner_adapters
            .iter()
            .find(|adapter| adapter.name.eq_ignore_ascii_case(requested_adapter))
            .ok_or_else(|| {
                anyhow!(
                    "requested scanner adapter {} is not registered on this worker",
                    requested_adapter
                )
            });
    }

    let mut tag_matches = scanner_adapters
        .iter()
        .filter(|adapter| {
            !adapter.tags.is_empty()
                && adapter.tags.iter().any(|tag| {
                    port_scan
                        .tags
                        .iter()
                        .any(|scan_tag| scan_tag.eq_ignore_ascii_case(tag))
                })
        })
        .collect::<Vec<_>>();
    if tag_matches.len() == 1 {
        return Ok(tag_matches.remove(0));
    }
    if tag_matches.len() > 1 {
        let candidates = tag_matches
            .into_iter()
            .map(|adapter| adapter.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(anyhow!(
            "multiple scanner adapters matched port scan tags: {candidates}"
        ));
    }

    scanner_adapters
        .first()
        .ok_or_else(|| anyhow!("scanner adapter list unexpectedly empty"))
}

fn render_bootstrap_template(
    template: &str,
    bootstrap_job: &WorkerBootstrapJobClaim,
    provisioner: &ExtensionManifest,
) -> String {
    let mut rendered = template.to_string();
    let job_id = bootstrap_job.job.id.to_string();
    let candidate_id = bootstrap_job.job.candidate_id.to_string();
    let discovered_port = bootstrap_job
        .job
        .discovered_port
        .map(|value| value.to_string())
        .unwrap_or_default();
    let worker_pool = bootstrap_job.job.worker_pool.clone().unwrap_or_default();
    let tag_csv = bootstrap_job.job.tags.join(",");
    let executor_worker_pool = bootstrap_job
        .job
        .executor_worker_pool
        .clone()
        .unwrap_or_default();
    let executor_tag_csv = bootstrap_job.job.executor_tags.join(",");
    let enrollment_token_id = bootstrap_job
        .job
        .enrollment_token_id
        .map(|value| value.to_string())
        .unwrap_or_default();

    for (needle, value) in [
        ("{{job_id}}", job_id.as_str()),
        ("{{candidate_id}}", candidate_id.as_str()),
        (
            "{{discovered_host}}",
            bootstrap_job.job.discovered_host.as_str(),
        ),
        ("{{discovered_port}}", discovered_port.as_str()),
        ("{{worker_pool}}", worker_pool.as_str()),
        ("{{tag_csv}}", tag_csv.as_str()),
        ("{{provisioner_name}}", provisioner.name.as_str()),
        ("{{executor_worker_pool}}", executor_worker_pool.as_str()),
        ("{{executor_tag_csv}}", executor_tag_csv.as_str()),
        ("{{enrollment_token_id}}", enrollment_token_id.as_str()),
    ] {
        rendered = rendered.replace(needle, value);
    }

    rendered
}

fn render_scanner_template(
    template: &str,
    port_scan: &PortScanRecord,
    output_path: Option<&Path>,
    adapter: &ExtensionManifest,
) -> String {
    let mut rendered = template.to_string();
    let tags_csv = port_scan.tags.join(",");
    let rate_limit = port_scan.rate_limit.to_string();
    let port_scan_id = port_scan.id.to_string();
    let output_path = output_path
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();

    for (needle, value) in [
        ("{{target_range}}", port_scan.target_range.as_str()),
        ("{{ports}}", port_scan.ports.as_str()),
        ("{{schemes}}", port_scan.schemes.as_str()),
        (
            "{{requested_by}}",
            port_scan.requested_by.as_deref().unwrap_or(""),
        ),
        ("{{tag_csv}}", tags_csv.as_str()),
        ("{{adapter_name}}", adapter.name.as_str()),
        ("{{rate_limit}}", rate_limit.as_str()),
        ("{{port_scan_id}}", port_scan_id.as_str()),
        ("{{output_path}}", output_path.as_str()),
    ] {
        rendered = rendered.replace(needle, value);
    }
    rendered
}

fn build_scanner_output_path(adapter_name: &str, port_scan_id: i64) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let safe_name = adapter_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    env::temp_dir().join(format!(
        "agent-{}-{}-{}.out",
        safe_name, port_scan_id, timestamp
    ))
}

fn build_scanner_checkpoint_path(output_path: &Path) -> PathBuf {
    output_path.with_file_name(
        output_path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|value| format!("{value}.checkpoint"))
            .unwrap_or_else(|| "scanner.checkpoint".to_string()),
    )
}

fn restore_port_scan_resume_state(
    output_path: &Path,
    checkpoint_path: &Path,
    resume_state: Option<&PortScanResumeStateRecord>,
) -> Result<bool> {
    let Some(resume_state) = resume_state else {
        return Ok(false);
    };
    let mut restored = false;
    if let Some(output_snapshot) = resume_state
        .output_snapshot
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        fs::write(output_path, output_snapshot).with_context(|| {
            format!(
                "failed to restore port scan output snapshot {}",
                output_path.display()
            )
        })?;
        restored = true;
    }
    if let Some(checkpoint_data) = resume_state
        .checkpoint_data
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        fs::write(checkpoint_path, checkpoint_data).with_context(|| {
            format!(
                "failed to restore port scan checkpoint {}",
                checkpoint_path.display()
            )
        })?;
        restored = true;
    }
    Ok(restored)
}

fn parse_scanner_output(
    output: &str,
    requested_ports: &str,
    output_format: &str,
) -> Result<Vec<DiscoveredEndpoint>> {
    match output_format {
        "endpoint_lines" => parse_endpoint_lines(output, requested_ports),
        "json_lines" => parse_json_endpoint_lines(output, requested_ports),
        other => Err(anyhow!(
            "unsupported scanner adapter output format {}",
            other
        )),
    }
}

fn parse_endpoint_lines(output: &str, requested_ports: &str) -> Result<Vec<DiscoveredEndpoint>> {
    let fallback_port = single_requested_port(requested_ports)?;
    let mut discovered = Vec::new();
    let mut seen = HashSet::new();

    for line in output.lines() {
        let token = line.trim();
        if token.is_empty() || token.starts_with('#') {
            continue;
        }
        let Some(endpoint) = parse_endpoint_token(token, fallback_port)? else {
            continue;
        };
        if seen.insert((endpoint.host.clone(), endpoint.port)) {
            discovered.push(endpoint);
        }
    }

    Ok(discovered)
}

fn parse_json_endpoint_lines(
    output: &str,
    requested_ports: &str,
) -> Result<Vec<DiscoveredEndpoint>> {
    let fallback_port = single_requested_port(requested_ports)?;
    let mut discovered = Vec::new();
    let mut seen = HashSet::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .with_context(|| format!("invalid scanner adapter json line: {line}"))?;
        let host = value
            .get("host")
            .and_then(|value| value.as_str())
            .or_else(|| value.get("ip").and_then(|value| value.as_str()))
            .or_else(|| value.get("address").and_then(|value| value.as_str()))
            .ok_or_else(|| anyhow!("scanner adapter json line is missing host/ip/address"))?;
        let port = value
            .get("port")
            .and_then(|value| value.as_u64())
            .map(|value| value as u16)
            .or(fallback_port)
            .ok_or_else(|| anyhow!("scanner adapter json line is missing port"))?;
        let endpoint = DiscoveredEndpoint {
            host: host.to_string(),
            port,
            service_name: value
                .get("service")
                .and_then(|value| value.as_str())
                .or_else(|| value.get("service_name").and_then(|value| value.as_str()))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            transport: value
                .get("protocol")
                .and_then(|value| value.as_str())
                .or_else(|| value.get("transport").and_then(|value| value.as_str()))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            tags: value
                .get("tags")
                .and_then(|value| value.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str())
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            version: value
                .get("version")
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            reported_plugins: parse_reported_protocol_plugins(&value)?,
        };
        if seen.insert((endpoint.host.clone(), endpoint.port)) {
            discovered.push(endpoint);
        }
    }

    Ok(discovered)
}

fn parse_endpoint_token(
    token: &str,
    fallback_port: Option<u16>,
) -> Result<Option<DiscoveredEndpoint>> {
    let token = token
        .split_whitespace()
        .next()
        .map(str::trim)
        .unwrap_or_default();
    if token.is_empty() {
        return Ok(None);
    }

    if let Ok(address) = token.parse::<SocketAddr>() {
        return Ok(Some(DiscoveredEndpoint {
            host: address.ip().to_string(),
            port: address.port(),
            service_name: None,
            transport: None,
            tags: Vec::new(),
            version: None,
            reported_plugins: Vec::new(),
        }));
    }

    if let Ok(ip) = token.parse::<IpAddr>() {
        let port = fallback_port.ok_or_else(|| {
            anyhow!(
                "scanner adapter output line {} is missing a port and multiple ports were requested",
                token
            )
        })?;
        return Ok(Some(DiscoveredEndpoint {
            host: ip.to_string(),
            port,
            service_name: None,
            transport: None,
            tags: Vec::new(),
            version: None,
            reported_plugins: Vec::new(),
        }));
    }

    if token.matches(':').count() == 1 {
        let (host, port) = token
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("invalid scanner adapter endpoint {}", token))?;
        let port = port
            .parse::<u16>()
            .with_context(|| format!("invalid scanner adapter port in {}", token))?;
        return Ok(Some(DiscoveredEndpoint {
            host: host.trim().to_string(),
            port,
            service_name: None,
            transport: None,
            tags: Vec::new(),
            version: None,
            reported_plugins: Vec::new(),
        }));
    }

    let port = fallback_port.ok_or_else(|| {
        anyhow!(
            "scanner adapter output line {} is missing a port and multiple ports were requested",
            token
        )
    })?;
    Ok(Some(DiscoveredEndpoint {
        host: token.to_string(),
        port,
        service_name: None,
        transport: None,
        tags: Vec::new(),
        version: None,
        reported_plugins: Vec::new(),
    }))
}

fn parse_reported_protocol_plugins(
    value: &serde_json::Value,
) -> Result<Vec<ReportedProtocolPluginFinding>> {
    let mut reported = Vec::new();

    if let Some(plugin_id) = value.get("plugin_id").and_then(|value| value.as_str()) {
        let trimmed = plugin_id.trim();
        if !trimmed.is_empty() {
            reported.push(ReportedProtocolPluginFinding {
                plugin_id: trimmed.to_string(),
                summary: None,
                severity: None,
                product_name: None,
                product_version: None,
                cpe: None,
                cve_ids: Vec::new(),
                kev_matched: None,
            });
        }
    }

    if let Some(plugin_ids) = value.get("plugin_ids").and_then(|value| value.as_array()) {
        for plugin_id in plugin_ids.iter().filter_map(|item| item.as_str()) {
            let trimmed = plugin_id.trim();
            if trimmed.is_empty() {
                continue;
            }
            reported.push(ReportedProtocolPluginFinding {
                plugin_id: trimmed.to_string(),
                summary: None,
                severity: None,
                product_name: None,
                product_version: None,
                cpe: None,
                cve_ids: Vec::new(),
                kev_matched: None,
            });
        }
    }

    if let Some(plugin_findings) = value
        .get("plugin_findings")
        .and_then(|value| value.as_array())
    {
        for finding in plugin_findings {
            let record: ReportedProtocolPluginFinding = serde_json::from_value(finding.clone())
                .with_context(|| format!("invalid scanner adapter plugin_finding: {finding}"))?;
            if !record.plugin_id.trim().is_empty() {
                reported.push(record);
            }
        }
    }

    let mut deduped = Vec::new();
    let mut seen = HashSet::new();
    for item in reported {
        let key = format!(
            "{}:{}:{}",
            item.plugin_id.to_ascii_lowercase(),
            item.summary.as_deref().unwrap_or_default(),
            item.product_version.as_deref().unwrap_or_default()
        );
        if seen.insert(key) {
            deduped.push(item);
        }
    }
    Ok(deduped)
}

fn derive_protocol_plugin_findings_with_active_mode(
    discovered_endpoints: &[DiscoveredEndpoint],
    allow_active_authorized: bool,
) -> Vec<PortScanProtocolFindingRecord> {
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for endpoint in discovered_endpoints {
        for reported in &endpoint.reported_plugins {
            let plugin_id = reported.plugin_id.trim();
            let Some(entry) = lookup_plugin(plugin_id) else {
                continue;
            };
            if entry.execution_mode == PluginExecutionMode::ActiveAuthorized
                && !allow_active_authorized
            {
                continue;
            }
            let cve_ids = reported
                .cve_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let Some(plugin_metadata) = build_plugin_metadata(
                plugin_id,
                reported
                    .product_name
                    .as_deref()
                    .or(endpoint.service_name.as_deref()),
                reported
                    .product_version
                    .as_deref()
                    .or(endpoint.version.as_deref()),
                reported.cpe.as_deref(),
                &cve_ids,
                reported.kev_matched,
                endpoint.transport.as_deref(),
                Some(endpoint.port),
            ) else {
                continue;
            };
            let severity = reported
                .severity
                .as_deref()
                .and_then(|value| value.trim().to_ascii_lowercase().parse::<Severity>().ok())
                .or_else(|| entry.default_severity.parse::<Severity>().ok())
                .unwrap_or(Severity::Medium);
            let summary = reported.summary.clone().unwrap_or_else(|| {
                format!(
                    "{} was reported by scanner adapter metadata.",
                    entry.display_name
                )
            });
            let dedupe_key = format!("{}:{}:{}", endpoint.host, endpoint.port, plugin_id);
            if seen.insert(dedupe_key) {
                findings.push(PortScanProtocolFindingRecord {
                    host: endpoint.host.clone(),
                    port: endpoint.port,
                    service_name: endpoint.service_name.clone(),
                    transport: endpoint.transport.clone(),
                    severity,
                    summary,
                    plugin_metadata,
                });
            }
        }

        let Some((plugin_id, product_name, summary)) =
            protocol_plugin_mapping_for_endpoint(endpoint)
        else {
            continue;
        };
        let Some(plugin_metadata) = build_plugin_metadata(
            plugin_id,
            Some(product_name),
            endpoint.version.as_deref(),
            None,
            &[],
            None,
            endpoint.transport.as_deref(),
            Some(endpoint.port),
        ) else {
            continue;
        };
        let severity = lookup_plugin(plugin_id)
            .and_then(|entry| entry.default_severity.parse::<Severity>().ok())
            .unwrap_or(Severity::Medium);
        let dedupe_key = format!("{}:{}:{}", endpoint.host, endpoint.port, plugin_id);
        if !seen.insert(dedupe_key) {
            continue;
        }
        findings.push(PortScanProtocolFindingRecord {
            host: endpoint.host.clone(),
            port: endpoint.port,
            service_name: endpoint.service_name.clone(),
            transport: endpoint.transport.clone(),
            severity,
            summary: summary.to_string(),
            plugin_metadata,
        });
    }

    findings.sort_by(|left, right| {
        left.host
            .cmp(&right.host)
            .then(left.port.cmp(&right.port))
            .then(
                left.plugin_metadata
                    .plugin_id
                    .cmp(&right.plugin_metadata.plugin_id),
            )
    });
    findings
}

fn protocol_plugin_mapping_for_endpoint(
    endpoint: &DiscoveredEndpoint,
) -> Option<(&'static str, &'static str, &'static str)> {
    let service = endpoint
        .service_name
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let transport = endpoint
        .transport
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let tags = endpoint
        .tags
        .iter()
        .map(|tag| tag.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();

    if endpoint_matches_service(endpoint, &service, &transport, &tags, &["ssh"], &[22])
        && endpoint_version_matches_openssh_regresshion(endpoint.version.as_deref())
    {
        return Some((
            "SshRegresshionPlugin",
            "OpenSSH",
            "OpenSSH version markers matched a regreSSHion-style vulnerable release during a port scan.",
        ));
    }

    if endpoint_matches_service(endpoint, &service, &transport, &tags, &["redis"], &[6379]) {
        return Some((
            "RedisOpenPlugin",
            "Redis",
            "Redis service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["arangodb", "arango"],
        &[8529],
    ) {
        return Some((
            "ArangoDBOpenPlugin",
            "ArangoDB",
            "ArangoDB service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["ajp", "apache jserv protocol"],
        &[8009],
    ) {
        return Some((
            "AjpPlugin",
            "Apache JServ Protocol",
            "AJP service was identified during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["mongo", "mongodb"],
        &[27017],
    ) && endpoint_has_tag(
        &tags,
        &["mongo-bleed", "mongobleed", "memory-leak", "memory_leak"],
    ) {
        return Some((
            "MongoBleedPlugin",
            "MongoDB",
            "MongoDB service appears vulnerable to MongoBleed-style unauthenticated memory leakage during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["mongo", "mongodb"],
        &[27017],
    ) {
        return Some((
            "MongoOpenPlugin",
            "MongoDB",
            "MongoDB service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["typesense"],
        &[8108],
    ) && endpoint_has_tag(
        &tags,
        &[
            "default-api-key",
            "default_api_key",
            "default-credentials",
            "default_credentials",
            "unauthenticated",
            "no-auth",
            "no_auth",
        ],
    ) {
        return Some((
            "TypesensePlugin",
            "Typesense",
            "Typesense API was identified with default API key or unauthenticated access during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["openedge", "progress openedge"],
        &[20931, 30931, 2092],
    ) {
        return Some((
            "OpenEdgePlugin",
            "OpenEdge",
            "OpenEdge service markers were identified during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["firebird", "firebirdsql"],
        &[3050],
    ) {
        return Some((
            "FirebirdPlugin",
            "Firebird",
            "Firebird service markers were identified during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["freeswitch"],
        &[8021, 5060, 5080],
    ) && (endpoint.port == 8021
        || endpoint_has_tag(
            &tags,
            &[
                "default-password",
                "default_password",
                "event-socket",
                "event_socket",
            ],
        ))
    {
        return Some((
            "FreeSWITCHOpenPlugin",
            "FreeSWITCH",
            "FreeSWITCH event socket markers were identified during a port scan.",
        ));
    }
    if endpoint_matches_alias(
        &service,
        &transport,
        &tags,
        &[
            "jdwp",
            "java-debug-wire-protocol",
            "java debug wire protocol",
        ],
    ) || ([5005u16, 8000, 8001, 8787].contains(&endpoint.port)
        && endpoint_has_tag(&tags, &["jdwp", "java-debug-wire-protocol", "java_debug"]))
    {
        return Some((
            "JdwpPlugin",
            "JDWP",
            "Java Debug Wire Protocol markers were identified during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["mysql", "mariadb"],
        &[3306],
    ) {
        return Some((
            "MysqlOpenPlugin",
            "MySQL",
            "MySQL-compatible service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["postgres", "postgresql"],
        &[5432],
    ) {
        return Some((
            "PostgreSQLOpenPlugin",
            "PostgreSQL",
            "PostgreSQL service was identified during a port scan; active/default-credential checks remain disabled.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["clickhouse"],
        &[8123],
    ) {
        return Some((
            "ClickHousePlugin",
            "ClickHouse",
            "ClickHouse service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["crate", "cratedb"],
        &[4200],
    ) {
        return Some((
            "CrateDBPlugin",
            "CrateDB",
            "CrateDB service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["memcached"],
        &[11211],
    ) {
        return Some((
            "MemcachedOpenPlugin",
            "Memcached",
            "Memcached service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["docker", "docker-api", "docker daemon"],
        &[2375],
    ) {
        return Some((
            "DockerAPIPlugin",
            "Docker API",
            "Docker API service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["epmd", "erlang port mapper"],
        &[4369],
    ) {
        return Some((
            "EpmdPlugin",
            "Erlang Port Mapper Daemon",
            "EPMD service was identified during a port scan.",
        ));
    }
    if endpoint_matches_alias(&service, &transport, &tags, &["dns"])
        && endpoint_has_tag(
            &tags,
            &[
                "axfr-allowed",
                "axfr_allowed",
                "zone-transfer",
                "zone_transfer",
            ],
        )
    {
        return Some((
            "DNSPlugin",
            "DNS",
            "DNS server was identified with zone transfer allowed during a port scan.",
        ));
    }
    if endpoint_matches_alias(
        &service,
        &transport,
        &tags,
        &["dotnet-remoting", ".net-remoting", "dotnet remoting"],
    ) {
        return Some((
            "DotnetRemotingPlugin",
            ".NET Remoting",
            ".NET Remoting TCP service was identified during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["mqtt", "mosquitto"],
        &[1883, 8883],
    ) {
        return Some((
            "MqttPlugin",
            "MQTT",
            "MQTT broker service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["influxdb", "influx"],
        &[8086],
    ) {
        return Some((
            "InfluxDBPlugin",
            "InfluxDB",
            "InfluxDB service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["php-fpm", "phpfpm", "fastcgi"],
        &[9000],
    ) {
        return Some((
            "PhpFpmPlugin",
            "PHP-FPM",
            "PHP-FPM / FastCGI service was identified during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["ldap", "ldaps"],
        &[389, 636],
    ) && endpoint_has_tag(
        &tags,
        &["anonymous-bind", "anonymous_bind", "ldap-anonymous-bind"],
    ) {
        return Some((
            "LDAPPlugin",
            "LDAP",
            "LDAP service was identified during a port scan; anonymous-bind enumeration remains disabled in phase 1.",
        ));
    }
    if endpoint_matches_alias(&service, &transport, &tags, &["h2", "h2tcp", "h2-tcp"]) {
        return Some((
            "H2TcpPlugin",
            "H2 TCP Server",
            "H2 TCP server was identified during a port scan.",
        ));
    }
    if endpoint_matches_service(endpoint, &service, &transport, &tags, &["kafka"], &[9092]) {
        return Some((
            "KafkaOpenPlugin",
            "Apache Kafka",
            "Kafka service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["zookeeper", "zk"],
        &[2181],
    ) {
        return Some((
            "ZookeeperOpenPlugin",
            "Apache ZooKeeper",
            "ZooKeeper service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(endpoint, &service, &transport, &tags, &["nfs"], &[2049])
        && endpoint_has_tag(&tags, &["export-enum", "export_enum", "nfs-export-enum"])
    {
        return Some((
            "NFSOpenPlugin",
            "NFS",
            "NFS service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["etcd"],
        &[2379, 2380],
    ) {
        return Some((
            "EtcdOpenPlugin",
            "etcd",
            "etcd service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(endpoint, &service, &transport, &tags, &["modbus"], &[502]) {
        return Some((
            "ModbusPlugin",
            "Modbus",
            "Modbus service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_alias(&service, &transport, &tags, &["generic-dvr", "genericdvr"])
        && endpoint_has_tag(&tags, &["vulnerable-family", "vulnerable_family"])
    {
        return Some((
            "GenericDvrPlugin",
            "Generic DVR",
            "Generic DVR vulnerable-family markers were identified during a port scan.",
        ));
    }
    if endpoint_matches_alias(&service, &transport, &tags, &["hisilicon-dvr", "hisilicon"])
        && endpoint_has_tag(&tags, &["vulnerable-family", "vulnerable_family"])
    {
        return Some((
            "HiSiliconDVR",
            "HiSilicon DVR",
            "HiSilicon DVR vulnerable-family markers were identified during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["rdp", "ms-wbt-server"],
        &[3389],
    ) && endpoint_has_tag(&tags, &["no-nla", "nla-disabled", "nla_disabled"])
    {
        return Some((
            "RdpPlugin",
            "RDP",
            "RDP service was identified during a port scan.",
        ));
    }
    if endpoint_matches_alias(
        &service,
        &transport,
        &tags,
        &["proxy", "http-proxy", "socks"],
    ) && endpoint_has_tag(&tags, &["proxy-open", "open-proxy", "open_proxy"])
    {
        return Some((
            "ProxyOpenPlugin",
            "Open Proxy",
            "Proxy service accepted open proxy behavior during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["opcua", "opc ua"],
        &[4840],
    ) {
        return Some((
            "OPCUAPlugin",
            "OPC UA",
            "OPC UA service was identified without authentication during a port scan.",
        ));
    }
    if endpoint.port >= 5900
        && endpoint.port <= 5905
        && (service.is_empty()
            || service.contains("vnc")
            || service.contains("rfb")
            || tags
                .iter()
                .any(|tag| tag.contains("vnc") || tag.contains("rfb")))
        && endpoint_has_tag(&tags, &["no-auth", "no_auth", "unauthenticated"])
    {
        return Some((
            "VNCPlugin",
            "VNC",
            "VNC service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["rethinkdb"],
        &[28015],
    ) && endpoint_has_tag(
        &tags,
        &[
            "admin-console-open",
            "admin_console_open",
            "unauthenticated",
        ],
    ) {
        return Some((
            "RethinkDBPlugin",
            "RethinkDB",
            "RethinkDB service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["riak"],
        &[8087, 8098],
    ) {
        return Some((
            "RiakPlugin",
            "Riak",
            "Riak service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["rmi", "java-rmi"],
        &[1099],
    ) {
        return Some((
            "RmiPlugin",
            "Java RMI",
            "Java RMI registry was identified during a port scan.",
        ));
    }
    if endpoint_matches_service(endpoint, &service, &transport, &tags, &["rsync"], &[873]) {
        return Some((
            "RsyncOpenPlugin",
            "rsync",
            "rsync daemon service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["s7comm", "siemens-s7"],
        &[102],
    ) {
        return Some((
            "S7commPlugin",
            "Siemens S7",
            "Siemens S7 service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["smb", "microsoft-ds", "netbios-ssn"],
        &[445, 139],
    ) {
        return Some((
            "SmbPlugin",
            "SMB",
            "SMB file sharing service was identified during a port scan.",
        ));
    }
    if endpoint_matches_service(endpoint, &service, &transport, &tags, &["ssh"], &[22]) {
        return Some((
            "SSHOpenPlugin",
            "SSH",
            "SSH service was identified during a port scan.",
        ));
    }
    if endpoint_matches_service(endpoint, &service, &transport, &tags, &["telnet"], &[23])
        && endpoint_has_tag(
            &tags,
            &[
                "auth-bypass",
                "auth_bypass",
                "gnu-inetutils",
                "gnu_inetutils",
            ],
        )
    {
        return Some((
            "TelnetAuthBypassPlugin",
            "Telnet",
            "Telnet service markers suggested a GNU Inetutils-style authentication bypass during a port scan.",
        ));
    }
    if endpoint_matches_alias(&service, &transport, &tags, &["presto", "trino"]) {
        return Some((
            "PrestoPlugin",
            "Presto/Trino",
            "Presto/Trino service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_alias(&service, &transport, &tags, &["neo4j-bolt", "bolt"]) {
        return Some((
            "Neo4jBoltPlugin",
            "Neo4j Bolt",
            "Neo4j Bolt service was identified during a port scan.",
        ));
    }
    if endpoint_matches_alias(&service, &transport, &tags, &["t3", "weblogic"]) {
        return Some((
            "T3Plugin",
            "Oracle WebLogic T3",
            "WebLogic T3 service was identified during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["cassandra", "cassandra-thrift"],
        &[9160],
    ) {
        return Some((
            "CassandraOpenPlugin",
            "Apache Cassandra",
            "Apache Cassandra Thrift service was identified without authentication during a port scan.",
        ));
    }
    if endpoint_matches_service(
        endpoint,
        &service,
        &transport,
        &tags,
        &["adb", "android-debug-bridge"],
        &[5555],
    ) {
        return Some((
            "AdbPlugin",
            "Android Debug Bridge",
            "Android Debug Bridge service was identified without authentication during a port scan.",
        ));
    }
    None
}

fn endpoint_matches_service(
    endpoint: &DiscoveredEndpoint,
    service: &str,
    transport: &str,
    tags: &[String],
    aliases: &[&str],
    ports: &[u16],
) -> bool {
    ports.contains(&endpoint.port)
        || aliases.iter().any(|alias| {
            service.contains(alias)
                || transport.contains(alias)
                || tags.iter().any(|tag| tag.contains(alias))
        })
}

fn endpoint_matches_alias(
    service: &str,
    transport: &str,
    tags: &[String],
    aliases: &[&str],
) -> bool {
    aliases.iter().any(|alias| {
        service.contains(alias)
            || transport.contains(alias)
            || tags.iter().any(|tag| tag.contains(alias))
    })
}

fn endpoint_has_tag(tags: &[String], aliases: &[&str]) -> bool {
    aliases
        .iter()
        .any(|alias| tags.iter().any(|tag| tag.contains(alias)))
}

fn endpoint_version_matches_openssh_regresshion(version: Option<&str>) -> bool {
    let Some(version) = version else {
        return false;
    };
    let lowered = version.to_ascii_lowercase();
    if !lowered.contains("openssh") {
        return false;
    }
    let Some(parsed) = parse_openssh_version(version) else {
        return false;
    };
    parsed >= (8, 5) && parsed < (9, 8)
}

fn parse_openssh_version(version: &str) -> Option<(u16, u16)> {
    let marker = version.to_ascii_lowercase().find("openssh")?;
    let tail = &version[marker..];
    let digits = tail
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
        .collect::<String>();
    let mut parts = digits.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn single_requested_port(requested_ports: &str) -> Result<Option<u16>> {
    let ports = parse_port_scan_ports(requested_ports)?;
    Ok((ports.len() == 1).then_some(ports[0]))
}

async fn import_port_scan_targets(
    config: &AppConfig,
    store: &AnyScanStore,
    port_scan: &PortScanRecord,
    discovered_endpoints: &[DiscoveredEndpoint],
    importers: &[ExtensionManifest],
) -> Result<ImportedTargetsResult> {
    let generated_targets = if importers.is_empty() {
        build_builtin_import_targets(port_scan, discovered_endpoints)
    } else {
        run_importers(port_scan, discovered_endpoints, importers)?
    };
    let selected_targets =
        select_follow_on_targets_for_port_scan(config, port_scan, generated_targets).await?;

    let mut target_ids = Vec::new();
    let mut notes = selected_targets.notes;
    let mut normalized_targets = HashSet::new();
    let target_tags = normalized_port_scan_tags(&port_scan.tags);

    for generated_target in selected_targets.targets {
        let generated_target = merge_imported_target_definition(generated_target, &target_tags);
        let target = config.normalize_target_definition(generated_target)?;
        if !normalized_targets.insert(target.base_url.clone()) {
            continue;
        }
        let record = store.upsert_target(&target)?;
        target_ids.push(record.id);
    }

    target_ids.sort_unstable();
    target_ids.dedup();
    notes.push(format!(
        "normalized {} target(s) from {} discovered endpoint(s)",
        target_ids.len(),
        discovered_endpoints.len()
    ));
    if !importers.is_empty() {
        notes.push(format!("applied {} importer extension(s)", importers.len()));
    }

    Ok(ImportedTargetsResult { target_ids, notes })
}

fn build_builtin_import_targets(
    port_scan: &PortScanRecord,
    discovered_endpoints: &[DiscoveredEndpoint],
) -> Vec<TargetDefinition> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();

    for endpoint in discovered_endpoints {
        for scheme in schemes_for_port_scan(port_scan.schemes, endpoint.port) {
            let base_url = format_target_base_url(&endpoint.host, endpoint.port, scheme);
            if !seen.insert(base_url.clone()) {
                continue;
            }
            targets.push(TargetDefinition {
                label: base_url.clone(),
                base_url,
                ..TargetDefinition::default()
            });
        }
    }

    targets
}

async fn select_follow_on_targets_for_port_scan(
    config: &AppConfig,
    port_scan: &PortScanRecord,
    generated_targets: Vec<TargetDefinition>,
) -> Result<SelectedFollowOnTargets> {
    let selection_mode = port_scan.follow_on_run_policy.selection_mode;

    if matches!(selection_mode, PortScanFollowOnSelectionMode::Raw) {
        return Ok(apply_follow_on_selection_mode_to_targets(
            generated_targets,
            selection_mode,
            &HashSet::new(),
        ));
    }

    let validated_urls = validate_follow_on_target_urls(config, &generated_targets).await?;
    Ok(apply_follow_on_selection_mode_to_targets(
        generated_targets,
        selection_mode,
        &validated_urls,
    ))
}

fn follow_on_selection_mode_label(mode: PortScanFollowOnSelectionMode) -> &'static str {
    match mode {
        PortScanFollowOnSelectionMode::Raw => "raw",
        PortScanFollowOnSelectionMode::Validated => "validated",
        PortScanFollowOnSelectionMode::Both => "both",
    }
}

fn validated_target_tag(base_url: &str) -> Option<&'static str> {
    if base_url.starts_with("https://") {
        Some("validated-https")
    } else if base_url.starts_with("http://") {
        Some("validated-http")
    } else {
        None
    }
}

fn apply_follow_on_selection_mode_to_targets(
    generated_targets: Vec<TargetDefinition>,
    selection_mode: PortScanFollowOnSelectionMode,
    validated_urls: &HashSet<String>,
) -> SelectedFollowOnTargets {
    let raw_candidate_total = generated_targets.len();
    if matches!(selection_mode, PortScanFollowOnSelectionMode::Raw) {
        return SelectedFollowOnTargets {
            targets: generated_targets,
            notes: vec![format!(
                "follow-on target mode raw kept {} candidate target(s)",
                raw_candidate_total
            )],
        };
    }

    let mut validated_count = 0usize;
    let mut selected = Vec::new();
    for mut target in generated_targets {
        if !validated_urls.contains(&target.base_url) {
            continue;
        }
        validated_count += 1;
        if let Some(tag) = validated_target_tag(&target.base_url) {
            if !target
                .tags
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(tag))
            {
                target.tags.push(tag.to_string());
            }
        }
        selected.push(target);
    }

    let mut notes = vec![format!(
        "follow-on target mode {} validated {} of {} candidate target(s)",
        follow_on_selection_mode_label(selection_mode),
        validated_count,
        raw_candidate_total
    )];
    if matches!(selection_mode, PortScanFollowOnSelectionMode::Both) {
        notes.push("raw discovered endpoint metadata remains available for benchmarking".to_string());
    }

    SelectedFollowOnTargets {
        targets: selected,
        notes,
    }
}

fn validation_transport_attempts(
    proxy_mode: ProxyMode,
    has_proxy: bool,
) -> Vec<ValidationTransport> {
    match proxy_mode {
        ProxyMode::DirectOnly => vec![ValidationTransport::Direct],
        ProxyMode::PreferProxy => {
            if has_proxy {
                vec![ValidationTransport::Proxy]
            } else {
                vec![ValidationTransport::Direct]
            }
        }
        ProxyMode::ProxyOnly => {
            if has_proxy {
                vec![ValidationTransport::Proxy]
            } else {
                Vec::new()
            }
        }
        ProxyMode::ProxyThenDirect => {
            if has_proxy {
                vec![ValidationTransport::Proxy, ValidationTransport::Direct]
            } else {
                vec![ValidationTransport::Direct]
            }
        }
        ProxyMode::DirectThenProxy => {
            if has_proxy {
                vec![ValidationTransport::Direct, ValidationTransport::Proxy]
            } else {
                vec![ValidationTransport::Direct]
            }
        }
    }
}

async fn validate_follow_on_target_urls(
    config: &AppConfig,
    generated_targets: &[TargetDefinition],
) -> Result<HashSet<String>> {
    let mut unique_urls = Vec::new();
    let mut seen_urls = HashSet::new();
    for target in generated_targets {
        if seen_urls.insert(target.base_url.clone()) {
            unique_urls.push(target.base_url.clone());
        }
    }
    if unique_urls.is_empty() {
        return Ok(HashSet::new());
    }

    let direct_client = build_http_client(&config.scan, None)?;
    let proxy_url = resolve_scan_proxy_url(&config.scan);
    let proxy_client = match proxy_url.as_deref() {
        Some(url) => Some(build_http_client(&config.scan, Some(url))?),
        None => None,
    };
    let transports = validation_transport_attempts(config.scan.proxy_mode, proxy_client.is_some());
    let validation_concurrency = config.scan.probe_concurrency.max(1);

    let validated_urls = stream::iter(unique_urls.into_iter().map(|base_url| {
        let direct_client = direct_client.clone();
        let proxy_client = proxy_client.clone();
        let transports = transports.clone();
        async move {
            let is_valid =
                validate_follow_on_target_url(&base_url, &direct_client, proxy_client.as_ref(), &transports).await;
            (base_url, is_valid)
        }
    }))
    .buffer_unordered(validation_concurrency)
    .collect::<Vec<_>>()
    .await;

    Ok(validated_urls
        .into_iter()
        .filter_map(|(base_url, is_valid)| is_valid.then_some(base_url))
        .collect())
}

async fn validate_follow_on_target_url(
    base_url: &str,
    direct_client: &reqwest::Client,
    proxy_client: Option<&reqwest::Client>,
    transports: &[ValidationTransport],
) -> bool {
    for transport in transports {
        let client = match transport {
            ValidationTransport::Direct => direct_client,
            ValidationTransport::Proxy => match proxy_client {
                Some(client) => client,
                None => continue,
            },
        };
        match client.get(base_url).send().await {
            Ok(_response) => return true,
            Err(_error) => continue,
        }
    }
    false
}

fn run_importers(
    port_scan: &PortScanRecord,
    discovered_endpoints: &[DiscoveredEndpoint],
    importers: &[ExtensionManifest],
) -> Result<Vec<TargetDefinition>> {
    let mut targets = Vec::new();
    for importer in importers {
        let mut importer_targets = run_importer(port_scan, discovered_endpoints, importer)?;
        targets.append(&mut importer_targets);
    }
    Ok(targets)
}

fn run_importer(
    port_scan: &PortScanRecord,
    discovered_endpoints: &[DiscoveredEndpoint],
    importer: &ExtensionManifest,
) -> Result<Vec<TargetDefinition>> {
    let command = importer
        .resolved_command()
        .ok_or_else(|| anyhow!("importer {} is missing a command", importer.name))?;
    let invocation = serde_json::to_vec(&ImporterInvocation {
        importer_name: &importer.name,
        port_scan,
        discovered_endpoints,
    })
    .context("failed to serialize importer invocation")?;

    let mut child = ProcessCommand::new(&command)
        .args(&importer.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn importer {}", importer.name))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&invocation)
            .with_context(|| format!("failed to write importer input for {}", importer.name))?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("failed to wait for importer {}", importer.name))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(anyhow!(
            "importer {} exited unsuccessfully{}",
            importer.name,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    parse_importer_output(&stdout, importer)
}

fn parse_importer_output(
    output: &str,
    importer: &ExtensionManifest,
) -> Result<Vec<TargetDefinition>> {
    match importer.output_format() {
        "target_json_lines" => parse_target_json_lines(output),
        "target_url_lines" => parse_target_url_lines(output),
        other => Err(anyhow!(
            "importer {} uses unsupported output format {}",
            importer.name,
            other
        )),
    }
}

fn parse_target_json_lines(output: &str) -> Result<Vec<TargetDefinition>> {
    let mut targets = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let target: TargetDefinition = serde_json::from_str(line)
            .with_context(|| format!("invalid importer target JSON line: {line}"))?;
        targets.push(target);
    }
    Ok(targets)
}

fn parse_target_url_lines(output: &str) -> Result<Vec<TargetDefinition>> {
    let mut targets = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        targets.push(TargetDefinition {
            label: line.to_string(),
            base_url: line.to_string(),
            ..TargetDefinition::default()
        });
    }
    Ok(targets)
}

fn merge_imported_target_definition(
    mut target: TargetDefinition,
    inherited_tags: &[String],
) -> TargetDefinition {
    if target.label.trim().is_empty() {
        target.label = target.base_url.trim().to_string();
    }
    if !inherited_tags.is_empty() {
        for tag in inherited_tags {
            if !target
                .tags
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(tag))
            {
                target.tags.push(tag.clone());
            }
        }
    }
    target
}

fn normalized_port_scan_tags(tags: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = Vec::new();
    for tag in tags {
        let trimmed = tag.trim();
        if trimmed.is_empty() || trimmed.starts_with("adapter:") {
            continue;
        }
        if !normalized
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(trimmed))
        {
            normalized.push(trimmed.to_string());
        }
    }
    normalized
}

fn schemes_for_port_scan(policy: PortScanSchemePolicy, port: u16) -> Vec<&'static str> {
    match policy {
        PortScanSchemePolicy::Http => vec!["http"],
        PortScanSchemePolicy::Https => vec!["https"],
        PortScanSchemePolicy::Both => vec!["http", "https"],
        PortScanSchemePolicy::Auto => {
            if matches!(port, 443 | 8443 | 9443 | 10443) {
                vec!["https"]
            } else {
                vec!["http"]
            }
        }
    }
}

fn format_target_base_url(host: &str, port: u16, scheme: &str) -> String {
    let host = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) if !host.starts_with('[') => format!("[{host}]"),
        _ => host.to_string(),
    };
    format!("{scheme}://{host}:{port}")
}

fn queue_follow_on_run_for_targets(
    store: &AnyScanStore,
    port_scan: &PortScanRecord,
    requested_by: &str,
    target_ids: &[i64],
) -> Result<Option<QueuedFollowOnRun>> {
    if target_ids.is_empty() || !port_scan.follow_on_run_policy.is_enabled() {
        return Ok(None);
    }

    let scope = normalize_run_scope(Some(RunScope {
        target_ids: target_ids.to_vec(),
        tags: Vec::new(),
        worker_pool: port_scan.follow_on_run_policy.worker_pool.clone(),
        failed_only: false,
    }));
    let run = queue_run_with_event(store, requested_by, scope.as_ref())?;
    let summary = store.summary(run.id)?;
    Ok(Some(QueuedFollowOnRun { run, summary }))
}

fn join_notes(notes: &[String]) -> Option<String> {
    if notes.is_empty() {
        None
    } else {
        Some(notes.join(" | "))
    }
}

fn truncate_note(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        value.to_string()
    } else {
        let prefix = value
            .chars()
            .take(max_len.saturating_sub(3))
            .collect::<String>();
        format!("{}...", prefix)
    }
}

async fn port_scan_claim_heartbeat(
    store: AnyScanStore,
    _worker_id: String,
    port_scan_id: i64,
    lease_seconds: u64,
    cancelled: Arc<AtomicBool>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let renew_interval = run_claim_heartbeat_interval(lease_seconds);
    let mut next_renewal = tokio::time::Instant::now() + renew_interval;
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = tokio::time::sleep(CLAIM_CANCELLATION_POLL_INTERVAL) => {
                match store.get_port_scan(port_scan_id)? {
                    Some(port_scan) if matches!(port_scan.status, RunStatus::Stopping | RunStatus::Completed | RunStatus::Failed) => {
                        cancelled.store(true, Ordering::SeqCst);
                        return Ok(());
                    }
                    None => {
                        cancelled.store(true, Ordering::SeqCst);
                        return Ok(());
                    }
                    _ => {}
                }
                if tokio::time::Instant::now() >= next_renewal {
                    if let Err(error) = store.renew_port_scan_claim(port_scan_id, lease_seconds) {
                        cancelled.store(true, Ordering::SeqCst);
                        return Err(error);
                    }
                    next_renewal = tokio::time::Instant::now() + renew_interval;
                }
            }
        }
    }
}

async fn bootstrap_job_claim_heartbeat(
    store: AnyScanStore,
    _worker_id: String,
    bootstrap_job_id: i64,
    lease_seconds: u64,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let renew_interval = run_claim_heartbeat_interval(lease_seconds);
    let mut next_renewal = tokio::time::Instant::now() + renew_interval;
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = tokio::time::sleep(CLAIM_CANCELLATION_POLL_INTERVAL) => {
                if tokio::time::Instant::now() >= next_renewal {
                    store.renew_bootstrap_job_claim(bootstrap_job_id, lease_seconds)?;
                    next_renewal = tokio::time::Instant::now() + renew_interval;
                }
            }
        }
    }
}

async fn job_claim_heartbeat(
    store: AnyScanStore,
    _worker_id: String,
    job_id: i64,
    run_id: i64,
    lease_seconds: u64,
    cancelled: Arc<AtomicBool>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let renew_interval = run_claim_heartbeat_interval(lease_seconds);
    let mut next_renewal = tokio::time::Instant::now() + renew_interval;
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = tokio::time::sleep(CLAIM_CANCELLATION_POLL_INTERVAL) => {
                match store.get_run(run_id)? {
                    Some(run) if matches!(run.status, RunStatus::Stopping | RunStatus::Completed | RunStatus::Failed) => {
                        cancelled.store(true, Ordering::SeqCst);
                        return Ok(());
                    }
                    None => {
                        cancelled.store(true, Ordering::SeqCst);
                        return Ok(());
                    }
                    _ => {}
                }
                if tokio::time::Instant::now() >= next_renewal {
                    if let Err(error) = store.renew_job_claim(job_id, lease_seconds) {
                        cancelled.store(true, Ordering::SeqCst);
                        return Err(error);
                    }
                    next_renewal = tokio::time::Instant::now() + renew_interval;
                }
            }
        }
    }
}

async fn run_claim_heartbeat(
    store: AnyScanStore,
    _worker_id: String,
    run_id: i64,
    lease_seconds: u64,
    cancelled: Arc<AtomicBool>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let renew_interval = run_claim_heartbeat_interval(lease_seconds);
    let mut next_renewal = tokio::time::Instant::now() + renew_interval;
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = tokio::time::sleep(CLAIM_CANCELLATION_POLL_INTERVAL) => {
                match store.get_run(run_id)? {
                    Some(run) if matches!(run.status, RunStatus::Stopping | RunStatus::Completed | RunStatus::Failed) => {
                        cancelled.store(true, Ordering::SeqCst);
                        return Ok(());
                    }
                    None => {
                        cancelled.store(true, Ordering::SeqCst);
                        return Ok(());
                    }
                    _ => {}
                }
                if tokio::time::Instant::now() >= next_renewal {
                    store.renew_run_claim(run_id, lease_seconds)?;
                    next_renewal = tokio::time::Instant::now() + renew_interval;
                }
            }
        }
    }
}

fn run_claim_heartbeat_interval(lease_seconds: u64) -> Duration {
    Duration::from_secs(lease_seconds.saturating_div(3).max(1))
}

fn run_completion_poll_interval(lease_seconds: u64) -> Duration {
    Duration::from_secs(lease_seconds.saturating_div(6).max(1))
}

async fn wait_for_cancellation(cancelled: Arc<AtomicBool>) {
    while !cancelled.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn port_scan_progress_reporter(
    store: AnyScanStore,
    port_scan_id: i64,
    target_range: String,
    requested_ports: String,
    output_format: String,
    output_path: PathBuf,
    checkpoint_path: PathBuf,
    cancelled: Arc<AtomicBool>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let mut last_count = 0u64;
    let mut last_probe_rate = 0u64;
    let mut last_receive_rate = 0u64;
    let mut last_progress_percent = None;
    let mut last_checkpoint_data = None::<String>;
    let mut last_output_snapshot_len: Option<u64> = None;
    let scanner_interface = resolve_scanner_interface_name();
    let mut last_interface_counters = scanner_interface
        .as_deref()
        .and_then(read_interface_packet_counters);
    let mut last_interface_sample_at = Instant::now();
    let mut estimated_sent_total = 0u64;
    let total_targets_estimate = estimate_target_packet_total(&target_range, &requested_ports);
    let mut counter = ScannerOutputCounter::new(&requested_ports);
    let resume_min_interval = port_scan_resume_state_min_interval();
    let resume_min_bytes_delta = port_scan_resume_state_min_bytes_delta();
    let mut last_resume_push_at: Option<Instant> = None;
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                if cancelled.load(Ordering::SeqCst) {
                    return Ok(());
                }
                counter.refresh(&output_path, &output_format)?;
                let mut progress = read_scanner_progress_snapshot(&output_path, &counter)?;
                if progress.probe_rate_millis == 0
                    && progress.receive_rate_millis == 0
                    && progress.progress_percent.is_none()
                {
                    if let Some(interface_name) = scanner_interface.as_deref() {
                        if let Some(current_counters) = read_interface_packet_counters(interface_name) {
                            let now = Instant::now();
                            let elapsed = now.saturating_duration_since(last_interface_sample_at);
                            if let Some(previous) = last_interface_counters {
                                let tx_delta = current_counters.tx_packets.saturating_sub(previous.tx_packets);
                                let rx_delta = current_counters.rx_packets.saturating_sub(previous.rx_packets);
                                if elapsed.as_secs_f64() > 0.0 {
                                    progress.probe_rate_millis =
                                        ((tx_delta as f64 / elapsed.as_secs_f64()) * 1000.0) as u64;
                                    progress.receive_rate_millis =
                                        ((rx_delta as f64 / elapsed.as_secs_f64()) * 1000.0) as u64;
                                }
                                estimated_sent_total = estimated_sent_total.saturating_add(tx_delta);
                                if let Some(total_targets) = total_targets_estimate.filter(|value| *value > 0) {
                                    let percent = ((estimated_sent_total as f64 / total_targets as f64) * 100.0)
                                        .clamp(0.0, 100.0);
                                    progress.progress_percent = Some(percent as u64);
                                }
                            }
                            last_interface_counters = Some(current_counters);
                            last_interface_sample_at = now;
                        }
                    }
                }
                if progress.discovered_endpoints_total > last_count
                    || progress.probe_rate_millis != last_probe_rate
                    || progress.receive_rate_millis != last_receive_rate
                    || progress.progress_percent != last_progress_percent
                {
                    last_count = progress.discovered_endpoints_total;
                    last_probe_rate = progress.probe_rate_millis;
                    last_receive_rate = progress.receive_rate_millis;
                    last_progress_percent = progress.progress_percent;
                    let _ = store.update_port_scan_progress_if_owned(
                        port_scan_id,
                        progress.discovered_endpoints_total,
                        progress.probe_rate_millis,
                        progress.receive_rate_millis,
                        progress.progress_percent,
                    )?;
                }
                let checkpoint_data = fs::read_to_string(&checkpoint_path)
                    .ok()
                    .filter(|value| !value.trim().is_empty());
                let output_size = fs::metadata(&output_path).ok().map(|meta| meta.len());
                let checkpoint_changed = checkpoint_data != last_checkpoint_data;
                let now = Instant::now();
                let interval_elapsed = last_resume_push_at
                    .map(|prev| now.saturating_duration_since(prev) >= resume_min_interval)
                    .unwrap_or(true);
                let should_push_resume = should_push_resume_state(
                    checkpoint_changed,
                    interval_elapsed,
                    last_output_snapshot_len,
                    output_size,
                    resume_min_bytes_delta,
                );
                if should_push_resume {
                    let output_snapshot = if output_size.is_some() {
                        fs::read_to_string(&output_path)
                            .ok()
                            .filter(|value| !value.trim().is_empty())
                    } else {
                        None
                    };
                    let _ = store.update_port_scan_resume_state_if_owned(
                        port_scan_id,
                        checkpoint_data.as_deref(),
                        output_snapshot.as_deref(),
                    )?;
                    last_checkpoint_data = checkpoint_data;
                    last_output_snapshot_len = output_size;
                    last_resume_push_at = Some(now);
                }
            }
        }
    }
}

const PORT_SCAN_RESUME_STATE_INTERVAL_SECONDS_ENV: &str =
    "ANYSCAN_PORT_SCAN_RESUME_STATE_INTERVAL_SECONDS";
const PORT_SCAN_RESUME_STATE_MIN_BYTES_DELTA_ENV: &str =
    "ANYSCAN_PORT_SCAN_RESUME_STATE_MIN_BYTES_DELTA";
const DEFAULT_PORT_SCAN_RESUME_STATE_INTERVAL_SECONDS: u64 = 30;
const DEFAULT_PORT_SCAN_RESUME_STATE_MIN_BYTES_DELTA: u64 = 256 * 1024;

fn port_scan_resume_state_min_interval() -> Duration {
    let secs = resolve_optional_env(PORT_SCAN_RESUME_STATE_INTERVAL_SECONDS_ENV)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PORT_SCAN_RESUME_STATE_INTERVAL_SECONDS)
        .max(2);
    Duration::from_secs(secs)
}

fn port_scan_resume_state_min_bytes_delta() -> u64 {
    resolve_optional_env(PORT_SCAN_RESUME_STATE_MIN_BYTES_DELTA_ENV)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PORT_SCAN_RESUME_STATE_MIN_BYTES_DELTA)
}

fn should_push_resume_state(
    checkpoint_changed: bool,
    interval_elapsed: bool,
    last_output_snapshot_len: Option<u64>,
    output_size: Option<u64>,
    resume_min_bytes_delta: u64,
) -> bool {
    if checkpoint_changed {
        return true;
    }
    // Output rotated/truncated: push immediately so persisted resume state
    // doesn't lag behind a smaller-but-different file.
    if let (Some(prev), Some(current)) = (last_output_snapshot_len, output_size) {
        if current < prev {
            return true;
        }
    }
    let bytes_grew_enough = match (last_output_snapshot_len, output_size) {
        (Some(prev), Some(current)) => current.saturating_sub(prev) >= resume_min_bytes_delta,
        (None, Some(current)) => current > 0,
        _ => false,
    };
    output_size.is_some() && (interval_elapsed || bytes_grew_enough)
}

const FOLLOWON_FLUSH_MIN_RESULTS_ENV: &str = "ANYSCAN_FOLLOWON_FLUSH_MIN_RESULTS";
const FOLLOWON_FLUSH_INTERVAL_SECONDS_ENV: &str = "ANYSCAN_FOLLOWON_FLUSH_INTERVAL_SECONDS";
const FOLLOWON_BACKPRESSURE_THRESHOLD_ENV: &str =
    "ANYSCAN_FOLLOWON_BACKPRESSURE_PENDING_THRESHOLD";
const FOLLOWON_POLL_INTERVAL_SECONDS_ENV: &str = "ANYSCAN_FOLLOWON_POLL_INTERVAL_SECONDS";

const DEFAULT_FOLLOWON_FLUSH_MIN_RESULTS: usize = 64;
const DEFAULT_FOLLOWON_FLUSH_INTERVAL_SECONDS: u64 = 30;
const DEFAULT_FOLLOWON_BACKPRESSURE_THRESHOLD: u64 = 1024;
const DEFAULT_FOLLOWON_POLL_INTERVAL_SECONDS: u64 = 3;

fn followon_flush_min_results() -> usize {
    resolve_optional_env(FOLLOWON_FLUSH_MIN_RESULTS_ENV)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_FOLLOWON_FLUSH_MIN_RESULTS)
        .max(1)
}

fn followon_flush_interval() -> Duration {
    let secs = resolve_optional_env(FOLLOWON_FLUSH_INTERVAL_SECONDS_ENV)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_FOLLOWON_FLUSH_INTERVAL_SECONDS)
        .max(1);
    Duration::from_secs(secs)
}

fn followon_backpressure_threshold() -> u64 {
    resolve_optional_env(FOLLOWON_BACKPRESSURE_THRESHOLD_ENV)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_FOLLOWON_BACKPRESSURE_THRESHOLD)
}

fn followon_poll_interval() -> Duration {
    let secs = resolve_optional_env(FOLLOWON_POLL_INTERVAL_SECONDS_ENV)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_FOLLOWON_POLL_INTERVAL_SECONDS)
        .max(1);
    Duration::from_secs(secs)
}

#[derive(Debug, Default)]
struct StreamingFollowOnSummary {
    flushed_endpoint_keys: HashSet<String>,
    queued_run_ids: Vec<i64>,
    notes: Vec<String>,
    backpressure_events: u64,
    imported_targets_total: u64,
}

#[derive(Debug, Clone, Copy)]
struct StreamingFollowOnTunables {
    flush_min_results: usize,
    flush_interval: Duration,
    poll_interval: Duration,
    backpressure_threshold: u64,
}

impl StreamingFollowOnTunables {
    fn from_env() -> Self {
        Self {
            flush_min_results: followon_flush_min_results(),
            flush_interval: followon_flush_interval(),
            poll_interval: followon_poll_interval(),
            backpressure_threshold: followon_backpressure_threshold(),
        }
    }
}

fn streaming_followon_should_flush(
    pending_count: usize,
    flush_min_results: usize,
    elapsed_since_flush: Duration,
    flush_interval: Duration,
    final_drain: bool,
) -> bool {
    if pending_count == 0 {
        return false;
    }
    if final_drain {
        return true;
    }
    if pending_count >= flush_min_results {
        return true;
    }
    elapsed_since_flush >= flush_interval
}

struct StreamingFollowOnContext {
    config: AppConfig,
    store: AnyScanStore,
    worker_runtime: WorkerRuntime,
    port_scan: PortScanRecord,
    output_path: PathBuf,
    output_format: String,
    cancelled: Arc<AtomicBool>,
    /// True when `restore_port_scan_resume_state` repopulated the scanner
    /// output file from a checkpoint. The flusher must skip-ahead through
    /// the pre-existing content so it does not re-emit endpoints that were
    /// already streamed (and possibly already host-scanned) in the prior
    /// life of this port scan.
    should_resume: bool,
}

async fn streaming_followon_flusher(
    ctx: StreamingFollowOnContext,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<StreamingFollowOnSummary> {
    let mut summary = StreamingFollowOnSummary::default();
    if !ctx.port_scan.follow_on_run_policy.is_enabled() {
        return Ok(summary);
    }
    let tunables = StreamingFollowOnTunables::from_env();
    let mut counter = ScannerOutputCounter::new(&ctx.port_scan.ports);

    if ctx.should_resume {
        // Prime the counter from the restored output so prior endpoints
        // populate `seen` (preventing re-emission) and add them to the
        // flushed set so the end-of-scan filter does not re-queue host-scan
        // jobs for them either.
        if let Err(error) = counter.refresh(&ctx.output_path, &ctx.output_format) {
            warn!(
                port_scan_id = ctx.port_scan.id,
                %error,
                "streaming follow-on resume seed read failed"
            );
        }
        let resumed_keys = counter.drain_new_keys();
        if !resumed_keys.is_empty() {
            summary.notes.push(format!(
                "streaming follow-on skipped re-emitting {} pre-resume endpoint(s)",
                resumed_keys.len()
            ));
            summary.flushed_endpoint_keys.extend(resumed_keys);
        }
    }

    let mut last_flush_at = Instant::now();
    let requested_by = ctx
        .port_scan
        .requested_by
        .clone()
        .unwrap_or_else(|| "port-scan-worker".to_string());

    loop {
        let final_drain = tokio::select! {
            _ = &mut shutdown => true,
            _ = tokio::time::sleep(tunables.poll_interval) => false,
        };

        if ctx.cancelled.load(Ordering::SeqCst) {
            return Ok(summary);
        }

        if let Err(error) = counter.refresh(&ctx.output_path, &ctx.output_format) {
            warn!(
                port_scan_id = ctx.port_scan.id,
                %error,
                "streaming follow-on counter refresh failed"
            );
            if final_drain {
                return Ok(summary);
            }
            continue;
        }

        let pending_count = counter.pending.len();
        let elapsed = last_flush_at.elapsed();
        if !streaming_followon_should_flush(
            pending_count,
            tunables.flush_min_results,
            elapsed,
            tunables.flush_interval,
            final_drain,
        ) {
            if final_drain {
                return Ok(summary);
            }
            continue;
        }

        let active_jobs = match ctx.store.count_active_jobs_for_runs(&summary.queued_run_ids) {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    port_scan_id = ctx.port_scan.id,
                    %error,
                    "streaming follow-on backpressure probe failed"
                );
                0
            }
        };
        if !final_drain && active_jobs > tunables.backpressure_threshold {
            summary.backpressure_events = summary.backpressure_events.saturating_add(1);
            info!(
                port_scan_id = ctx.port_scan.id,
                active_jobs,
                threshold = tunables.backpressure_threshold,
                pending = pending_count,
                "streaming follow-on backpressure: deferring flush"
            );
            // Leave keys in counter.pending so they roll forward into the
            // next iteration once workers drain the queue.
            continue;
        }

        let keys = counter.drain_new_keys();
        if keys.is_empty() {
            continue;
        }

        match flush_streaming_followon_batch(
            &ctx.config,
            &ctx.store,
            &ctx.worker_runtime,
            &ctx.port_scan,
            &requested_by,
            &keys,
        )
        .await
        {
            Ok(outcome) => {
                summary.imported_targets_total = summary
                    .imported_targets_total
                    .saturating_add(outcome.imported_targets);
                summary.flushed_endpoint_keys.extend(keys.into_iter());
                last_flush_at = Instant::now();
                if let Some(queued_run_id) = outcome.queued_run_id {
                    summary.queued_run_ids.push(queued_run_id);
                    if let Err(error) = ctx
                        .store
                        .append_port_scan_follow_on_run_id_if_owned(
                            ctx.port_scan.id,
                            queued_run_id,
                        )
                    {
                        warn!(
                            port_scan_id = ctx.port_scan.id,
                            run_id = queued_run_id,
                            %error,
                            "failed to persist streamed follow-on run id"
                        );
                    }
                    info!(
                        port_scan_id = ctx.port_scan.id,
                        run_id = queued_run_id,
                        batch_size = pending_count,
                        imported_targets = outcome.imported_targets,
                        "streaming follow-on flushed batch"
                    );
                }
            }
            Err(error) => {
                warn!(
                    port_scan_id = ctx.port_scan.id,
                    batch_size = keys.len(),
                    %error,
                    "streaming follow-on batch flush failed"
                );
                summary
                    .notes
                    .push(format!("streaming follow-on batch flush failed: {error}"));
                // Do NOT mark these keys as flushed. The counter has them in
                // `seen` (so they will not re-emit in subsequent streaming
                // batches this life), but leaving them out of
                // `flushed_endpoint_keys` lets the end-of-scan
                // `filter_endpoints_excluding_streamed` keep them in the
                // final import pass — that is the recovery path for any
                // transient importer/queue/store failure here.
                last_flush_at = Instant::now();
            }
        }

        if final_drain {
            return Ok(summary);
        }
    }
}

struct StreamingBatchOutcome {
    queued_run_id: Option<i64>,
    imported_targets: u64,
}

async fn flush_streaming_followon_batch(
    config: &AppConfig,
    store: &AnyScanStore,
    worker_runtime: &WorkerRuntime,
    port_scan: &PortScanRecord,
    requested_by: &str,
    keys: &[String],
) -> Result<StreamingBatchOutcome> {
    let endpoints = parse_endpoint_keys_for_streaming(keys, port_scan);
    if endpoints.is_empty() {
        return Ok(StreamingBatchOutcome {
            queued_run_id: None,
            imported_targets: 0,
        });
    }
    let imported = import_port_scan_targets(
        config,
        store,
        port_scan,
        &endpoints,
        &worker_runtime.importers,
    )
    .await?;
    let imported_count = imported.target_ids.len() as u64;
    if imported.target_ids.is_empty() {
        return Ok(StreamingBatchOutcome {
            queued_run_id: None,
            imported_targets: imported_count,
        });
    }
    let queued = queue_follow_on_run_for_targets(
        store,
        port_scan,
        requested_by,
        &imported.target_ids,
    )?;
    Ok(StreamingBatchOutcome {
        queued_run_id: queued.map(|item| item.run.id),
        imported_targets: imported_count,
    })
}

fn parse_endpoint_keys_for_streaming(
    keys: &[String],
    port_scan: &PortScanRecord,
) -> Vec<DiscoveredEndpoint> {
    let fallback_port = single_requested_port(&port_scan.ports).ok().flatten();
    let mut endpoints = Vec::with_capacity(keys.len());
    for key in keys {
        if let Ok(Some(endpoint)) = parse_endpoint_token(key, fallback_port) {
            endpoints.push(endpoint);
        }
    }
    endpoints
}

/// Drop endpoints whose host:port was already imported during streaming so
/// the final import pass does not double-queue host-scan jobs for them.
fn filter_endpoints_excluding_streamed(
    endpoints: &[DiscoveredEndpoint],
    flushed_keys: &HashSet<String>,
) -> Vec<DiscoveredEndpoint> {
    if flushed_keys.is_empty() {
        return endpoints.to_vec();
    }
    endpoints
        .iter()
        .filter(|endpoint| {
            !flushed_keys.contains(&endpoint_cache_key(&endpoint.host, endpoint.port))
        })
        .cloned()
        .collect()
}

#[derive(Debug, Clone, Default)]
struct ScannerProgressCounts {
    discovered_endpoints_total: u64,
    probe_rate_millis: u64,
    receive_rate_millis: u64,
    progress_percent: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct NetworkPacketCounters {
    tx_packets: u64,
    rx_packets: u64,
}

/// Incremental endpoint counter: re-parsing the full output file each tick is
/// O(N²) over the scan, so we track byte offset plus the dedup set instead.
struct ScannerOutputCounter {
    offset: u64,
    seen: HashSet<String>,
    // Endpoint keys observed since the last drain_new_keys() call. Streaming
    // follow-on uses this to flush incremental batches into host-scan tasks
    // without re-parsing the whole output file.
    pending: Vec<String>,
    fallback_port: Option<u16>,
    leftover: String,
    // (device, inode) of the file we last consumed. A change here means the
    // file was unlinked-and-recreated; the saved offset is meaningless against
    // the new inode even if the new size happens to be >= the old offset.
    file_id: Option<(u64, u64)>,
}

impl ScannerOutputCounter {
    fn new(requested_ports: &str) -> Self {
        let fallback_port = single_requested_port(requested_ports).ok().flatten();
        Self {
            offset: 0,
            seen: HashSet::new(),
            pending: Vec::new(),
            fallback_port,
            leftover: String::new(),
            file_id: None,
        }
    }

    fn count(&self) -> u64 {
        self.seen.len() as u64
    }

    fn rewind(&mut self) {
        self.offset = 0;
        self.seen.clear();
        self.pending.clear();
        self.leftover.clear();
    }

    /// Take and clear keys observed since the last drain. Already-flushed keys
    /// remain in `seen` so duplicates are not re-emitted.
    fn drain_new_keys(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending)
    }

    fn record_key(&mut self, key: String) {
        if self.seen.insert(key.clone()) {
            self.pending.push(key);
        }
    }

    fn refresh(&mut self, output_path: &Path, output_format: &str) -> Result<()> {
        let metadata = match fs::metadata(output_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(error) => {
                return Err(anyhow!(error)).with_context(|| {
                    format!(
                        "failed to stat scanner progress file {}",
                        output_path.display()
                    )
                });
            }
        };
        let size = metadata.len();
        let current_id = file_identity(&metadata);
        let inode_changed = matches!(
            (self.file_id, current_id),
            (Some(prev), Some(now)) if prev != now
        );
        if size < self.offset || inode_changed {
            // Output truncated or rotated (size shrank, or unlink+recreate
            // produced a new inode even at >= the old size); rewind and reparse.
            self.rewind();
        }
        self.file_id = current_id.or(self.file_id);
        if size == self.offset {
            return Ok(());
        }
        let mut file = fs::File::open(output_path).with_context(|| {
            format!(
                "failed to open scanner progress file {}",
                output_path.display()
            )
        })?;
        if self.offset > 0 {
            file.seek(SeekFrom::Start(self.offset))
                .with_context(|| {
                    format!(
                        "failed to seek scanner progress file {} to {}",
                        output_path.display(),
                        self.offset
                    )
                })?;
        }
        let mut buffer = Vec::with_capacity((size - self.offset) as usize);
        file.read_to_end(&mut buffer).with_context(|| {
            format!(
                "failed to read scanner progress file {}",
                output_path.display()
            )
        })?;
        self.offset = size;
        let chunk = String::from_utf8_lossy(&buffer);
        let mut combined = std::mem::take(&mut self.leftover);
        combined.push_str(chunk.as_ref());
        let ends_with_newline = combined.ends_with('\n') || combined.ends_with('\r');
        let mut iter = combined.split(['\n', '\r']).peekable();
        while let Some(piece) = iter.next() {
            if iter.peek().is_none() && !ends_with_newline {
                self.leftover = piece.to_string();
                break;
            }
            let token = piece.trim();
            if token.is_empty() || token.starts_with('#') {
                continue;
            }
            match output_format {
                "endpoint_lines" => {
                    if let Ok(Some(endpoint)) = parse_endpoint_token(token, self.fallback_port) {
                        self.record_key(endpoint_cache_key(&endpoint.host, endpoint.port));
                    }
                }
                "json_lines" => {
                    if let Some(key) = parse_json_endpoint_key(token, self.fallback_port) {
                        self.record_key(key);
                    }
                }
                _ => {
                    self.record_key(token.to_string());
                }
            }
        }
        if ends_with_newline {
            self.leftover.clear();
        }
        Ok(())
    }
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(_metadata: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

fn parse_json_endpoint_key(line: &str, fallback_port: Option<u16>) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let host = value
        .get("host")
        .and_then(|value| value.as_str())
        .or_else(|| value.get("ip").and_then(|value| value.as_str()))
        .or_else(|| value.get("address").and_then(|value| value.as_str()))?;
    let port = value
        .get("port")
        .and_then(|value| value.as_u64())
        .map(|value| value as u16)
        .or(fallback_port)?;
    Some(endpoint_cache_key(host, port))
}

/// Canonical "host:port" cache key shared between the streaming counter,
/// `parse_endpoint_token`, and the final-import filter. IPv6 hosts contain
/// ':' literally, so a naïve `{host}:{port}` would collide and round-trip
/// incorrectly (e.g. "2001:db8::1:80" cannot be re-parsed unambiguously).
/// The bracketed form `[host]:port` parses through `SocketAddr::from_str`
/// and is unique across all endpoints.
fn endpoint_cache_key(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn read_scanner_progress_snapshot(
    output_path: &Path,
    counter: &ScannerOutputCounter,
) -> Result<ScannerProgressCounts> {
    let mut progress = ScannerProgressCounts {
        discovered_endpoints_total: counter.count(),
        ..ScannerProgressCounts::default()
    };
    let progress_path = output_path.with_file_name(
        output_path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|value| format!("{value}.progress"))
            .unwrap_or_else(|| "scanner.progress".to_string()),
    );
    if progress_path.exists() {
        if let Ok(contents) = fs::read_to_string(&progress_path) {
            if let Ok(snapshot) = serde_json::from_str::<ScannerProgressSnapshot>(&contents) {
                progress.probe_rate_millis = snapshot.probe_rate_millis;
                progress.receive_rate_millis = snapshot.receive_rate_millis;
                progress.progress_percent = snapshot.progress_percent;
            }
        }
    }
    Ok(progress)
}

fn resolve_scanner_interface_name() -> Option<String> {
    if let Some(value) = resolve_optional_env("SCANNER_INTERFACE") {
        return Some(value);
    }
    let contents = fs::read_to_string("/proc/net/route").ok()?;
    for line in contents.lines().skip(1) {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.len() > 2 && columns[1] == "00000000" {
            let iface = columns[0].trim();
            if !iface.is_empty() {
                return Some(iface.to_string());
            }
        }
    }
    None
}

fn read_interface_packet_counters(interface_name: &str) -> Option<NetworkPacketCounters> {
    let base = PathBuf::from("/sys/class/net")
        .join(interface_name)
        .join("statistics");
    let tx_packets = fs::read_to_string(base.join("tx_packets"))
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    let rx_packets = fs::read_to_string(base.join("rx_packets"))
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(NetworkPacketCounters {
        tx_packets,
        rx_packets,
    })
}

fn estimate_target_packet_total(target_range: &str, requested_ports: &str) -> Option<u64> {
    let (start, end) = parse_ipv4_target_range_bounds(target_range)?;
    let host_count = end.saturating_sub(start).saturating_add(1);
    let port_count = parse_port_scan_ports(requested_ports).ok()?.len() as u64;
    if port_count == 0 {
        return None;
    }
    Some(host_count.saturating_mul(port_count))
}

fn parse_ipv4_target_range_bounds(target_range: &str) -> Option<(u64, u64)> {
    let trimmed = target_range.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((ip_text, prefix_text)) = trimmed.split_once('/') {
        let ip = ip_text.trim().parse::<Ipv4Addr>().ok()?;
        let prefix = prefix_text.trim().parse::<u8>().ok()?;
        if prefix > 32 {
            return None;
        }
        let ip_u32 = u32::from(ip);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = ip_u32 & mask;
        let broadcast = network | !mask;
        return Some((network as u64, broadcast as u64));
    }
    if let Some((start_text, end_text)) = trimmed.split_once('-') {
        let start = start_text.trim().parse::<Ipv4Addr>().ok()?;
        let end = end_text.trim().parse::<Ipv4Addr>().ok()?;
        let start = u32::from(start) as u64;
        let end = u32::from(end) as u64;
        if start > end {
            return None;
        }
        return Some((start, end));
    }
    let ip = trimmed.parse::<Ipv4Addr>().ok()?;
    let value = u32::from(ip) as u64;
    Some((value, value))
}

fn create_bootstrap_candidates_for_port_scan(
    config: &AppConfig,
    store: &AnyScanStore,
    port_scan: &PortScanRecord,
    discovered_endpoints: &[DiscoveredEndpoint],
) -> Result<Vec<String>> {
    if !port_scan.bootstrap_policy.is_enabled() || discovered_endpoints.is_empty() {
        return Ok(Vec::new());
    }

    let mut candidate_inputs = Vec::new();
    let mut skipped_outside_inventory = 0usize;
    for endpoint in discovered_endpoints {
        if !config.host_is_allowed(&endpoint.host) {
            skipped_outside_inventory += 1;
            continue;
        }
        candidate_inputs.push(WorkerBootstrapCandidateInput {
            discovered_host: endpoint.host.clone(),
            discovered_port: Some(endpoint.port),
        });
    }

    let created = store.create_bootstrap_candidates(port_scan, &candidate_inputs)?;
    for candidate in &created {
        store.append_event(
            None,
            &ApiEvent::WorkerBootstrapCandidateCreated {
                candidate: candidate.clone(),
            },
        )?;
    }

    let mut notes = Vec::new();
    if !created.is_empty() {
        notes.push(format!("queued {} bootstrap candidate(s)", created.len()));
    }
    if skipped_outside_inventory > 0 {
        notes.push(format!(
            "skipped {} discovered endpoint(s) outside approved inventory for bootstrap candidates",
            skipped_outside_inventory
        ));
    }
    Ok(notes)
}

fn register_worker_or_bail(
    store: &AnyScanStore,
    registration: &WorkerRegistration,
    ttl_seconds: u64,
) -> Result<anyscan::core::WorkerRecord> {
    let registration = refresh_dynamic_worker_registration(registration);
    let worker = store
        .register_worker(&registration, ttl_seconds)
        .with_context(|| format!("failed to register worker {}", registration.worker_id))?;
    Ok(worker)
}

fn build_worker_runtime(config: &AppConfig, worker_id: &str) -> Result<WorkerRuntime> {
    let manifests = config.enabled_extension_manifests()?;
    let scanner_adapters = manifests
        .iter()
        .filter(|manifest| manifest.is_scanner_adapter())
        .cloned()
        .collect::<Vec<_>>();
    let importers = manifests
        .iter()
        .filter(|manifest| manifest.is_importer())
        .cloned()
        .collect::<Vec<_>>();
    let provisioners = manifests
        .iter()
        .filter(|manifest| manifest.is_provisioner())
        .cloned()
        .collect::<Vec<_>>();
    let display_name = resolve_optional_env_aliases(WORKER_NAME_ENV_NAMES).or_else(|| {
        env::var("HOSTNAME")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    });
    let worker_pool = resolve_optional_env_aliases(WORKER_POOL_ENV_NAMES);
    let enrollment_token = resolve_optional_env_aliases(WORKER_TOKEN_ENV_NAMES);
    let tags = resolve_worker_tags();
    let supports_bootstrap = resolve_worker_bootstrap_support() && !provisioners.is_empty();
    let supports_remote_debug_commands =
        resolve_bool_env_aliases(REMOTE_DEBUG_ENABLED_ENV_NAMES).unwrap_or(false);
    let remote_update_plan = resolve_remote_update_plan();
    let max_active_tasks = resolve_usize_env_aliases_or_runtime_file(MAX_ACTIVE_TASKS_ENV_NAMES)
        .filter(|value| *value > 0)
        .unwrap_or(2);
    let network_identity = detect_worker_network_identity();
    let platform_identity = detect_worker_platform_identity();
    let remote_update_state = read_remote_update_state();
    let installed_bundle_name =
        resolve_optional_env_aliases_or_runtime_file(INSTALLED_BUNDLE_NAME_ENV_NAMES);
    let agent_concurrency = resolve_u64_env_aliases_or_runtime_file(AGENT_CONCURRENCY_ENV_NAMES);
    let scanner_default_rate =
        resolve_u64_env_aliases_or_runtime_file(SCANNER_DEFAULT_RATE_ENV_NAMES);
    let scanner_sender_threads =
        resolve_u64_env_aliases_or_runtime_file(SCANNER_SENDER_THREADS_ENV_NAMES);
    let scanner_receiver_threads =
        resolve_u64_env_aliases_or_runtime_file(SCANNER_RECEIVER_THREADS_ENV_NAMES);
    let registration = WorkerRegistration {
        worker_id: worker_id.to_string(),
        display_name,
        worker_pool,
        tags,
        operating_system: platform_identity.operating_system,
        architecture: platform_identity.architecture,
        platform: platform_identity.platform,
        supports_runs: true,
        supports_port_scans: !scanner_adapters.is_empty(),
        supports_bootstrap,
        supports_remote_updates: remote_update_plan.is_some(),
        supports_remote_debug_commands,
        scanner_adapters: scanner_adapters
            .iter()
            .map(|adapter| adapter.name.clone())
            .collect(),
        provisioners: provisioners
            .iter()
            .map(|provisioner| provisioner.name.clone())
            .collect(),
        local_ip_addresses: network_identity.local_ip_addresses,
        public_ip_address: network_identity.public_ip_address,
        public_ip_checked_at: network_identity.public_ip_checked_at,
        remote_update_status: remote_update_state.status,
        remote_update_status_message: remote_update_state.message,
        remote_update_status_updated_at: remote_update_state.updated_at,
        installed_bundle_name,
        max_active_tasks: Some(max_active_tasks as u64),
        agent_concurrency,
        scanner_default_rate,
        scanner_sender_threads,
        scanner_receiver_threads,
        enrollment_token,
    };

    Ok(WorkerRuntime {
        registration,
        scanner_adapters,
        importers,
        provisioners,
        remote_update_plan,
        max_active_tasks,
    })
}

fn detect_worker_network_identity() -> WorkerNetworkIdentity {
    let local_ip_addresses = match detect_local_ip_addresses() {
        Ok(ip_addresses) => ip_addresses,
        Err(error) => {
            warn!(%error, "failed to collect worker local IP addresses");
            Vec::new()
        }
    };

    let (public_ip_address, public_ip_checked_at) = match detect_public_ip_address() {
        Ok(Some(public_ip)) => (Some(public_ip), Some(chrono::Utc::now())),
        Ok(None) => (None, None),
        Err(error) => {
            warn!(%error, "failed to collect worker public IP address");
            (None, None)
        }
    };

    WorkerNetworkIdentity {
        local_ip_addresses,
        public_ip_address,
        public_ip_checked_at,
    }
}

fn detect_worker_platform_identity() -> WorkerPlatformIdentity {
    let operating_system = normalize_platform_operating_system(std::env::consts::OS);
    let architecture = normalize_platform_architecture(std::env::consts::ARCH);
    let platform = match (&operating_system, &architecture) {
        (Some(os), Some(arch)) => Some(format!("{os}-{arch}")),
        _ => None,
    };
    WorkerPlatformIdentity {
        operating_system,
        architecture,
        platform,
    }
}

fn normalize_platform_operating_system(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    Some(
        match normalized.as_str() {
            "macos" => "darwin",
            other => other,
        }
        .to_string(),
    )
}

fn normalize_platform_architecture(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    Some(
        match normalized.as_str() {
            "amd64" => "x86_64",
            "x64" => "x86_64",
            "arm64" => "aarch64",
            "armv7l" | "armv7" => "armv7",
            "armv6l" | "armv6" => "armv6",
            other => other,
        }
        .to_string(),
    )
}

fn detect_local_ip_addresses() -> Result<Vec<String>> {
    let output = ProcessCommand::new("ip")
        .args(["-o", "addr", "show", "up", "scope", "global"])
        .output()
        .context("failed to execute `ip -o addr show up scope global`")?;
    if !output.status.success() {
        return Err(anyhow!(
            "`ip -o addr show up scope global` exited with status {}",
            output.status
        ));
    }
    let stdout = String::from_utf8(output.stdout).context("`ip` output was not valid UTF-8")?;
    Ok(parse_ip_addr_show_output(&stdout))
}

fn parse_ip_addr_show_output(output: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    for line in output.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(token) = tokens.next() {
            if token != "inet" && token != "inet6" {
                continue;
            }
            let Some(value) = tokens.next() else {
                continue;
            };
            let ip_text = value.split('/').next().unwrap_or("").trim();
            let Ok(ip_addr) = ip_text.parse::<IpAddr>() else {
                continue;
            };
            if ip_addr.is_loopback() {
                continue;
            }
            let normalized = ip_addr.to_string();
            if !addresses.contains(&normalized) {
                addresses.push(normalized);
            }
        }
    }
    addresses
}

fn detect_public_ip_address() -> Result<Option<String>> {
    let client = BlockingHttpClient::builder()
        .no_proxy()
        .timeout(Duration::from_secs(PUBLIC_IP_CHECK_TIMEOUT_SECONDS))
        .build()
        .context("failed to build worker public IP client")?;

    for url in PUBLIC_IP_CHECK_URLS {
        let response = match client.get(*url).send() {
            Ok(response) => response,
            Err(error) => {
                warn!(url = %url, %error, "failed to query public IP endpoint");
                continue;
            }
        };
        if !response.status().is_success() {
            warn!(
                url = %url,
                status = response.status().as_u16(),
                "public IP endpoint returned non-success status"
            );
            continue;
        }
        let body = response.text().unwrap_or_default();
        let trimmed = body.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(ip_addr) = trimmed.parse::<IpAddr>() {
            return Ok(Some(ip_addr.to_string()));
        }
    }

    Ok(None)
}

fn resolve_worker_tags() -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    if let Some(raw_tags) = resolve_optional_env_aliases(WORKER_TAGS_ENV_NAMES) {
        for tag in raw_tags.split(',') {
            let trimmed = tag.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !tags
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(trimmed))
            {
                tags.push(trimmed.to_string());
            }
        }
    }
    tags
}

fn resolve_remote_update_plan() -> Option<RemoteUpdatePlan> {
    if !resolve_bool_env_aliases(REMOTE_UPDATE_ENABLED_ENV_NAMES).unwrap_or(false) {
        return None;
    }

    let installer_url = resolve_optional_env_aliases(REMOTE_UPDATE_INSTALLER_URL_ENV_NAMES)
        .or_else(resolve_management_installer_url)?;
    let request_file = resolve_optional_env_aliases(REMOTE_UPDATE_REQUEST_FILE_ENV_NAMES)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/agentd/remote-update.request"));
    Some(RemoteUpdatePlan {
        request_file,
        installer_url,
    })
}

fn resolve_management_installer_url() -> Option<String> {
    let management_url = resolve_optional_env_aliases(CONTROL_URL_ENV_NAMES)?;
    let trimmed = management_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let encoded = url::form_urlencoded::byte_serialize(trimmed.as_bytes()).collect::<String>();
    Some(format!(
        "{trimmed}/api/agent/install.sh?rebuild=false&base_url={encoded}"
    ))
}

fn read_remote_update_state() -> WorkerRemoteUpdateState {
    let status_file = resolve_optional_env_aliases(REMOTE_UPDATE_STATUS_FILE_ENV_NAMES)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/agentd/remote-update.status"));
    let Ok(contents) = fs::read_to_string(&status_file) else {
        return WorkerRemoteUpdateState::default();
    };

    let mut status = None;
    let mut message = None;
    let mut updated_at = None;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("STATUS=") {
            status = match value.trim() {
                "queued" => Some(WorkerRemoteUpdateStatus::Queued),
                "running" => Some(WorkerRemoteUpdateStatus::Running),
                "success" => Some(WorkerRemoteUpdateStatus::Success),
                "failed" => Some(WorkerRemoteUpdateStatus::Failed),
                "rolled_back" => Some(WorkerRemoteUpdateStatus::RolledBack),
                "rollback_failed" => Some(WorkerRemoteUpdateStatus::RollbackFailed),
                _ => None,
            };
        } else if let Some(value) = line.strip_prefix("MESSAGE=") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                message = Some(trimmed.to_string());
            }
        } else if let Some(value) = line.strip_prefix("UPDATED_AT=") {
            updated_at = chrono::DateTime::parse_from_rfc3339(value.trim())
                .ok()
                .map(|value| value.with_timezone(&chrono::Utc));
        }
    }

    WorkerRemoteUpdateState {
        status,
        message,
        updated_at,
    }
}

fn write_remote_update_state(status: WorkerRemoteUpdateStatus, message: &str) -> Result<()> {
    let status_file = resolve_optional_env_aliases(REMOTE_UPDATE_STATUS_FILE_ENV_NAMES)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/agentd/remote-update.status"));
    let parent = status_file
        .parent()
        .ok_or_else(|| anyhow!("remote update status file has no parent directory"))?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create remote update status directory {}",
            parent.display()
        )
    })?;
    let temp_path = status_file.with_extension("status.tmp");
    fs::write(
        &temp_path,
        format!(
            "STATUS={}\nUPDATED_AT={}\nMESSAGE={}\n",
            status.as_str(),
            Utc::now().to_rfc3339(),
            message.trim()
        ),
    )
    .with_context(|| format!("failed to write {}", temp_path.display()))?;
    fs::rename(&temp_path, &status_file)
        .with_context(|| format!("failed to move status into {}", status_file.display()))?;
    Ok(())
}

fn resolve_optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resolve_optional_env_aliases(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| resolve_optional_env(name))
}

fn resolve_optional_env_aliases_or_runtime_file(names: &[&str]) -> Option<String> {
    resolve_optional_env_aliases(names).or_else(|| {
        names
            .iter()
            .find_map(|name| load_env_value_from_runtime_file(DEFAULT_RUNTIME_ENV_FILE_PATH, name))
    })
}

fn resolve_u64_env_aliases_or_runtime_file(names: &[&str]) -> Option<u64> {
    resolve_optional_env_aliases_or_runtime_file(names)
        .and_then(|value| value.parse::<u64>().ok())
}

fn resolve_usize_env_aliases_or_runtime_file(names: &[&str]) -> Option<usize> {
    resolve_optional_env_aliases_or_runtime_file(names)
        .and_then(|value| value.parse::<usize>().ok())
}

fn load_env_value_from_runtime_file(path: &str, key: &str) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let needle = format!("{key}=");
    content.lines().find_map(|line| {
        line.strip_prefix(&needle)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn resolve_worker_bootstrap_support() -> bool {
    resolve_bool_env_aliases(WORKER_BOOTSTRAP_SUPPORT_ENV_NAMES).unwrap_or(false)
}

fn resolve_bool_env(name: &str) -> Option<bool> {
    let value = resolve_optional_env(name)?;
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn resolve_bool_env_aliases(names: &[&str]) -> Option<bool> {
    names.iter().find_map(|name| resolve_bool_env(name))
}

fn resolve_usize_env_aliases(names: &[&str]) -> Option<usize> {
    names.iter()
        .find_map(|name| resolve_optional_env(name).and_then(|value| value.parse::<usize>().ok()))
}

fn top_level_task_kind_label(kind: TopLevelTaskKind) -> &'static str {
    match kind {
        TopLevelTaskKind::BootstrapJob => "bootstrap_job",
        TopLevelTaskKind::PortScan => "port_scan",
        TopLevelTaskKind::Run => "run",
    }
}

fn worker_registration_ttl_seconds(config: &AppConfig) -> u64 {
    config
        .storage
        .redis_run_lease_seconds
        .saturating_mul(4)
        .max(config.scan.poll_interval_seconds.saturating_mul(2))
        .max(30)
}

fn worker_registration_refresh_interval(config: &AppConfig, ttl_seconds: u64) -> Duration {
    let ttl_interval = ttl_seconds.saturating_div(3).max(5);
    let poll_interval = config.scan.poll_interval_seconds.max(5);
    Duration::from_secs(ttl_interval.min(poll_interval))
}

async fn worker_registration_heartbeat(
    store: AnyScanStore,
    registration: WorkerRegistration,
    ttl_seconds: u64,
    interval: Duration,
    remote_update_tx: watch::Sender<Option<chrono::DateTime<chrono::Utc>>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        let refreshed_registration = refresh_dynamic_worker_registration(&registration);
        match store.register_worker(&refreshed_registration, ttl_seconds) {
            Ok(worker) => {
                let _ = remote_update_tx.send(worker.remote_update_requested_at);
            }
            Err(error) => {
                error!(worker_id = %registration.worker_id, %error, "failed to register worker");
            }
        }

        tokio::select! {
            _ = &mut shutdown => return,
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

fn refresh_dynamic_worker_registration(registration: &WorkerRegistration) -> WorkerRegistration {
    let mut refreshed = registration.clone();
    let remote_update_state = read_remote_update_state();
    refreshed.remote_update_status = remote_update_state.status;
    refreshed.remote_update_status_message = remote_update_state.message;
    refreshed.remote_update_status_updated_at = remote_update_state.updated_at;
    refreshed.installed_bundle_name =
        resolve_optional_env_aliases_or_runtime_file(INSTALLED_BUNDLE_NAME_ENV_NAMES);
    refreshed.max_active_tasks = Some(resolve_usize_env_aliases(MAX_ACTIVE_TASKS_ENV_NAMES)
        .filter(|value| *value > 0)
        .unwrap_or(2) as u64);
    refreshed.agent_concurrency =
        resolve_u64_env_aliases_or_runtime_file(AGENT_CONCURRENCY_ENV_NAMES);
    refreshed.scanner_default_rate =
        resolve_u64_env_aliases_or_runtime_file(SCANNER_DEFAULT_RATE_ENV_NAMES);
    refreshed.scanner_sender_threads =
        resolve_u64_env_aliases_or_runtime_file(SCANNER_SENDER_THREADS_ENV_NAMES);
    refreshed.scanner_receiver_threads =
        resolve_u64_env_aliases_or_runtime_file(SCANNER_RECEIVER_THREADS_ENV_NAMES);
    refreshed
}

fn maybe_schedule_remote_update(
    store: &AnyScanStore,
    worker_runtime: &WorkerRuntime,
    requested_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool> {
    let Some(plan) = worker_runtime.remote_update_plan.as_ref() else {
        let message = format!(
            "remote update requested at {} but this worker has no local update plan",
            requested_at
        );
        warn!(
            worker_id = %worker_runtime.registration.worker_id,
            requested_at = %requested_at,
            "remote update was requested but this worker has no local update plan"
        );
        let _ = write_remote_update_state(WorkerRemoteUpdateStatus::Failed, &message);
        if let Err(error) = store.acknowledge_remote_update(requested_at) {
            warn!(
                worker_id = %worker_runtime.registration.worker_id,
                requested_at = %requested_at,
                %error,
                "failed to acknowledge remote update request without local plan"
            );
            return Ok(false);
        }
        return Ok(true);
    };

    if let Err(error) =
        write_remote_update_request(plan, &worker_runtime.registration.worker_id, requested_at)
    {
        let message = format!("remote update scheduling failed: {error}");
        warn!(
            worker_id = %worker_runtime.registration.worker_id,
            requested_at = %requested_at,
            %error,
            "failed to write remote update request file"
        );
        let _ = write_remote_update_state(WorkerRemoteUpdateStatus::Failed, &message);
        if let Err(ack_error) = store.acknowledge_remote_update(requested_at) {
            warn!(
                worker_id = %worker_runtime.registration.worker_id,
                requested_at = %requested_at,
                %ack_error,
                "failed to acknowledge remote update request after scheduling failure"
            );
            return Ok(false);
        }
        return Ok(true);
    }

    if let Err(error) = store.acknowledge_remote_update(requested_at) {
        warn!(
            worker_id = %worker_runtime.registration.worker_id,
            requested_at = %requested_at,
            %error,
            "failed to acknowledge remote update request after scheduling"
        );
        return Ok(true);
    }
    info!(
        worker_id = %worker_runtime.registration.worker_id,
        requested_at = %requested_at,
        request_file = %plan.request_file.display(),
        installer_url = %plan.installer_url,
        "scheduled remote update request"
    );
    Ok(true)
}

fn write_remote_update_request(
    plan: &RemoteUpdatePlan,
    worker_id: &str,
    requested_at: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let parent = plan
        .request_file
        .parent()
        .ok_or_else(|| anyhow!("remote update request file has no parent directory"))?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create remote update request directory {}",
            parent.display()
        )
    })?;
    let temp_path = plan.request_file.with_extension("request.tmp");
    fs::write(
        &temp_path,
        format!(
            "REQUESTED_AT={}\nWORKER_ID={}\n",
            requested_at.to_rfc3339(),
            worker_id
        ),
    )
    .with_context(|| format!("failed to write {}", temp_path.display()))?;
    fs::rename(&temp_path, &plan.request_file).with_context(|| {
        format!(
            "failed to move remote update request into place at {}",
            plan.request_file.display()
        )
    })?;
    Ok(())
}

fn build_worker_id() -> String {
    if let Some(worker_id) = resolve_optional_env_aliases(WORKER_ID_ENV_NAMES) {
        return worker_id;
    }
    env::var("HOSTNAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("agent-{}", std::process::id()))
}

fn seed_bootstrap_inventory(store: &AnyScanStore, config: &AppConfig) -> Result<()> {
    if resolve_optional_env_aliases(CONTROL_URL_ENV_NAMES).is_some() {
        return Ok(());
    }
    for target in config.normalized_bootstrap_targets()? {
        store.upsert_target(&target)?;
    }
    for repository in config.normalized_bootstrap_repositories()? {
        store.upsert_repository(&repository)?;
    }
    Ok(())
}

fn queue_due_schedules_with_events(store: &AnyScanStore, limit: usize) -> Result<()> {
    for queued in store.queue_due_schedule_runs_with_events(limit)? {
        info!(
            schedule = %queued.schedule.label,
            run_id = queued.run.id,
            "queued recurring schedule run"
        );
    }
    Ok(())
}

fn queue_run_with_event(
    store: &AnyScanStore,
    requested_by: &str,
    scope: Option<&RunScope>,
) -> Result<ScanRunRecord> {
    Ok(store.queue_run_with_event(requested_by, scope)?.run)
}

fn load_effective_runtime_config(
    base_config: &AppConfig,
    store: &AnyScanStore,
) -> Result<AppConfig> {
    let Some(scan_settings) = store.load_scan_settings()? else {
        return Ok(base_config.clone());
    };
    base_config.with_scan_defaults_summary(&scan_settings)
}

#[cfg(test)]
mod tests {
    use super::{
        DiscoveredEndpoint, PortScanFollowOnSelectionMode, ReportedProtocolPluginFinding,
        ScannerOutputCounter, apply_follow_on_selection_mode_to_targets,
        derive_protocol_plugin_findings_with_active_mode, endpoint_cache_key,
        filter_endpoints_excluding_streamed, normalize_platform_architecture,
        normalize_platform_operating_system, parse_endpoint_token, parse_ip_addr_show_output,
        parse_json_endpoint_lines, scanner_target_range_for_adapter, should_push_resume_state,
        streaming_followon_should_flush, validated_target_tag,
    };
    use anyscan::core::TargetDefinition;
    use std::collections::HashSet;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    fn endpoint(
        host: &str,
        port: u16,
        service_name: &str,
        transport: &str,
        tags: &[&str],
    ) -> DiscoveredEndpoint {
        DiscoveredEndpoint {
            host: host.to_string(),
            port,
            service_name: Some(service_name.to_string()),
            transport: Some(transport.to_string()),
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            version: None,
            reported_plugins: Vec::new(),
        }
    }

    fn endpoint_with_version(
        host: &str,
        port: u16,
        service_name: &str,
        transport: &str,
        tags: &[&str],
        version: &str,
    ) -> DiscoveredEndpoint {
        DiscoveredEndpoint {
            host: host.to_string(),
            port,
            service_name: Some(service_name.to_string()),
            transport: Some(transport.to_string()),
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            version: Some(version.to_string()),
            reported_plugins: Vec::new(),
        }
    }

    #[test]
    fn parse_json_endpoint_lines_preserves_service_transport_and_tags() {
        let endpoints = parse_json_endpoint_lines(
            r#"{"host":"10.0.0.10","port":6379,"service":"redis","protocol":"tcp","tags":["datastore","edge"]}"#,
            "6379",
        )
        .expect("json endpoint lines should parse");

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].host, "10.0.0.10");
        assert_eq!(endpoints[0].port, 6379);
        assert_eq!(endpoints[0].service_name.as_deref(), Some("redis"));
        assert_eq!(endpoints[0].transport.as_deref(), Some("tcp"));
        assert_eq!(
            endpoints[0].tags,
            vec!["datastore".to_string(), "edge".to_string()]
        );
    }

    #[test]
    fn parse_ip_addr_show_output_collects_ipv4_and_ipv6_addresses() {
        let addresses = parse_ip_addr_show_output(
            "2: eth0    inet 10.10.0.5/24 brd 10.10.0.255 scope global eth0\n\
             2: eth0    inet6 2001:db8::10/64 scope global dynamic\n\
             1: lo      inet 127.0.0.1/8 scope host lo\n",
        );

        assert_eq!(
            addresses,
            vec!["10.10.0.5".to_string(), "2001:db8::10".to_string()]
        );
    }

    #[test]
    fn scanner_target_range_for_adapter_normalizes_single_ipv4_hosts_to_cidr32() {
        assert_eq!(scanner_target_range_for_adapter("0.0.0.0"), "0.0.0.0/32");
        assert_eq!(scanner_target_range_for_adapter("8.8.8.8"), "8.8.8.8/32");
        assert_eq!(
            scanner_target_range_for_adapter("10.0.0.0-10.0.0.255"),
            "10.0.0.0-10.0.0.255"
        );
        assert_eq!(
            scanner_target_range_for_adapter("10.0.0.0/24"),
            "10.0.0.0/24"
        );
    }

    #[test]
    fn apply_follow_on_selection_mode_to_targets_respects_validated_and_both_modes() {
        let targets = vec![
            TargetDefinition {
                label: "one".to_string(),
                base_url: "http://example.com:80".to_string(),
                ..TargetDefinition::default()
            },
            TargetDefinition {
                label: "two".to_string(),
                base_url: "https://example.com:443".to_string(),
                ..TargetDefinition::default()
            },
        ];
        let validated = HashSet::from(["https://example.com:443".to_string()]);

        let selected = apply_follow_on_selection_mode_to_targets(
            targets.clone(),
            PortScanFollowOnSelectionMode::Validated,
            &validated,
        );
        assert_eq!(selected.targets.len(), 1);
        assert_eq!(selected.targets[0].base_url, "https://example.com:443");
        assert!(selected.targets[0].tags.contains(&"validated-https".to_string()));

        let both = apply_follow_on_selection_mode_to_targets(
            targets,
            PortScanFollowOnSelectionMode::Both,
            &validated,
        );
        assert_eq!(both.targets.len(), 1);
        assert!(both
            .notes
            .iter()
            .any(|note| note.contains("raw discovered endpoint metadata remains available")));
    }

    #[test]
    fn validated_target_tag_matches_http_and_https() {
        assert_eq!(validated_target_tag("http://example.com:80"), Some("validated-http"));
        assert_eq!(
            validated_target_tag("https://example.com:443"),
            Some("validated-https")
        );
        assert_eq!(validated_target_tag("ftp://example.com"), None);
    }

    #[test]
    fn derive_protocol_plugin_findings_maps_known_authless_services() {
        let findings = derive_protocol_plugin_findings_with_active_mode(
            &[
                endpoint("10.0.0.10", 6379, "redis", "tcp", &["datastore"]),
                endpoint("10.0.0.11", 5432, "postgresql", "tcp", &["database"]),
                endpoint("10.0.0.12", 5901, "rfb", "tcp", &["vnc", "no-auth"]),
                endpoint("10.0.0.13", 27017, "mongodb", "tcp", &[]),
                endpoint("10.0.0.13", 27017, "mongodb", "tcp", &["mongo-bleed"]),
                endpoint("10.0.0.14", 3306, "mysql", "tcp", &[]),
                endpoint("10.0.0.15", 11211, "memcached", "tcp", &[]),
                endpoint("10.0.0.16", 1883, "mqtt", "tcp", &[]),
                endpoint("10.0.0.17", 389, "ldap", "tcp", &["anonymous-bind"]),
                endpoint("10.0.0.18", 9092, "kafka", "tcp", &[]),
                endpoint("10.0.0.19", 2181, "zookeeper", "tcp", &[]),
                endpoint("10.0.0.20", 2379, "etcd", "tcp", &[]),
                endpoint("10.0.0.22", 9160, "cassandra-thrift", "tcp", &[]),
                endpoint("10.0.0.23", 5555, "adb", "tcp", &[]),
                endpoint("10.0.0.24", 8529, "arangodb", "tcp", &[]),
                endpoint("10.0.0.25", 8009, "ajp", "tcp", &[]),
                endpoint("10.0.0.26", 8123, "clickhouse", "tcp", &[]),
                endpoint("10.0.0.26", 4200, "cratedb", "tcp", &[]),
                endpoint("10.0.0.27", 2375, "docker-api", "tcp", &[]),
                endpoint("10.0.0.28", 4369, "epmd", "tcp", &[]),
                endpoint("10.0.0.28", 53, "dns", "udp", &["axfr-allowed"]),
                endpoint("10.0.0.28", 9000, "php-fpm", "tcp", &[]),
                endpoint("10.0.0.28", 9090, "dotnet-remoting", "tcp", &[]),
                endpoint("10.0.0.29", 8086, "influxdb", "tcp", &[]),
                endpoint("10.0.0.30", 2049, "nfs", "tcp", &["export-enum"]),
                endpoint("10.0.0.31", 502, "modbus", "tcp", &[]),
                endpoint(
                    "10.0.0.31",
                    80,
                    "generic-dvr",
                    "tcp",
                    &["vulnerable-family"],
                ),
                endpoint(
                    "10.0.0.31",
                    8080,
                    "hisilicon-dvr",
                    "tcp",
                    &["vulnerable-family"],
                ),
                endpoint("10.0.0.32", 4840, "opcua", "tcp", &[]),
                endpoint(
                    "10.0.0.33",
                    28015,
                    "rethinkdb",
                    "tcp",
                    &["admin-console-open"],
                ),
                endpoint("10.0.0.34", 8087, "riak", "tcp", &[]),
                endpoint("10.0.0.35", 1099, "java-rmi", "tcp", &[]),
                endpoint("10.0.0.36", 873, "rsync", "tcp", &[]),
                endpoint("10.0.0.37", 102, "s7comm", "tcp", &[]),
                endpoint("10.0.0.38", 445, "microsoft-ds", "tcp", &[]),
                endpoint("10.0.0.39", 22, "ssh", "tcp", &[]),
                endpoint_with_version("10.0.0.39", 22, "ssh", "tcp", &[], "OpenSSH_9.7p1 Debian-5"),
                endpoint("10.0.0.39", 8080, "http-proxy", "tcp", &["proxy-open"]),
                endpoint("10.0.0.40", 8080, "trino", "tcp", &[]),
                endpoint("10.0.0.44", 3389, "rdp", "tcp", &["no-nla"]),
                endpoint("10.0.0.41", 9092, "h2tcp", "tcp", &[]),
                endpoint("10.0.0.42", 7687, "neo4j-bolt", "tcp", &[]),
                endpoint("10.0.0.43", 7001, "weblogic", "tcp", &[]),
                endpoint("10.0.0.43", 20931, "openedge", "tcp", &[]),
                endpoint("10.0.0.43", 3050, "firebird", "tcp", &[]),
                endpoint(
                    "10.0.0.43",
                    8021,
                    "freeswitch",
                    "tcp",
                    &["default-password"],
                ),
                endpoint("10.0.0.43", 5005, "jdwp", "tcp", &["java-debug"]),
                endpoint(
                    "10.0.0.43",
                    23,
                    "telnet",
                    "tcp",
                    &["auth-bypass", "gnu-inetutils"],
                ),
                endpoint("10.0.0.45", 8108, "typesense", "tcp", &["default-api-key"]),
            ],
            false,
        );

        let plugin_ids = findings
            .iter()
            .map(|finding| finding.plugin_metadata.plugin_id.as_str())
            .collect::<Vec<_>>();

        assert!(plugin_ids.contains(&"AdbPlugin"));
        assert!(plugin_ids.contains(&"AjpPlugin"));
        assert!(plugin_ids.contains(&"ArangoDBOpenPlugin"));
        assert!(plugin_ids.contains(&"CassandraOpenPlugin"));
        assert!(plugin_ids.contains(&"ClickHousePlugin"));
        assert!(plugin_ids.contains(&"CrateDBPlugin"));
        assert!(plugin_ids.contains(&"DockerAPIPlugin"));
        assert!(plugin_ids.contains(&"DNSPlugin"));
        assert!(plugin_ids.contains(&"DotnetRemotingPlugin"));
        assert!(plugin_ids.contains(&"EpmdPlugin"));
        assert!(plugin_ids.contains(&"EtcdOpenPlugin"));
        assert!(plugin_ids.contains(&"GenericDvrPlugin"));
        assert!(plugin_ids.contains(&"H2TcpPlugin"));
        assert!(plugin_ids.contains(&"HiSiliconDVR"));
        assert!(plugin_ids.contains(&"InfluxDBPlugin"));
        assert!(plugin_ids.contains(&"KafkaOpenPlugin"));
        assert!(plugin_ids.contains(&"LDAPPlugin"));
        assert!(plugin_ids.contains(&"MemcachedOpenPlugin"));
        assert!(plugin_ids.contains(&"ModbusPlugin"));
        assert!(plugin_ids.contains(&"MongoBleedPlugin"));
        assert!(plugin_ids.contains(&"MongoOpenPlugin"));
        assert!(plugin_ids.contains(&"MqttPlugin"));
        assert!(plugin_ids.contains(&"MysqlOpenPlugin"));
        assert!(plugin_ids.contains(&"Neo4jBoltPlugin"));
        assert!(plugin_ids.contains(&"NFSOpenPlugin"));
        assert!(plugin_ids.contains(&"OPCUAPlugin"));
        assert!(plugin_ids.contains(&"PrestoPlugin"));
        assert!(plugin_ids.contains(&"ProxyOpenPlugin"));
        assert!(plugin_ids.contains(&"RdpPlugin"));
        assert!(plugin_ids.contains(&"RedisOpenPlugin"));
        assert!(plugin_ids.contains(&"RethinkDBPlugin"));
        assert!(plugin_ids.contains(&"RiakPlugin"));
        assert!(plugin_ids.contains(&"RmiPlugin"));
        assert!(plugin_ids.contains(&"RsyncOpenPlugin"));
        assert!(plugin_ids.contains(&"S7commPlugin"));
        assert!(plugin_ids.contains(&"SmbPlugin"));
        assert!(plugin_ids.contains(&"SshRegresshionPlugin"));
        assert!(plugin_ids.contains(&"SSHOpenPlugin"));
        assert!(plugin_ids.contains(&"T3Plugin"));
        assert!(plugin_ids.contains(&"OpenEdgePlugin"));
        assert!(plugin_ids.contains(&"FirebirdPlugin"));
        assert!(plugin_ids.contains(&"FreeSWITCHOpenPlugin"));
        assert!(plugin_ids.contains(&"JdwpPlugin"));
        assert!(plugin_ids.contains(&"TelnetAuthBypassPlugin"));
        assert!(plugin_ids.contains(&"TypesensePlugin"));
        assert!(plugin_ids.contains(&"PostgreSQLOpenPlugin"));
        assert!(plugin_ids.contains(&"PhpFpmPlugin"));
        assert!(plugin_ids.contains(&"VNCPlugin"));
        assert!(plugin_ids.contains(&"ZookeeperOpenPlugin"));
        assert!(
            findings
                .iter()
                .all(|finding| !finding.summary.trim().is_empty())
        );
    }

    #[test]
    fn derive_protocol_plugin_findings_accepts_explicit_reported_plugins() {
        let findings = derive_protocol_plugin_findings_with_active_mode(
            &[DiscoveredEndpoint {
                host: "10.0.0.50".to_string(),
                port: 8443,
                service_name: Some("custom-scanner".to_string()),
                transport: Some("tcp".to_string()),
                tags: vec![],
                version: Some("1.2.3".to_string()),
                reported_plugins: vec![ReportedProtocolPluginFinding {
                    plugin_id: "CraftCMSPlugin".to_string(),
                    summary: Some(
                        "Craft CMS vulnerable version was reported by an external scanner."
                            .to_string(),
                    ),
                    severity: Some("high".to_string()),
                    product_name: Some("Craft CMS".to_string()),
                    product_version: Some("4.13.0".to_string()),
                    cpe: None,
                    cve_ids: vec!["CVE-2024-56145".to_string()],
                    kev_matched: Some(false),
                }],
            }],
            false,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin_metadata.plugin_id, "CraftCMSPlugin");
        assert_eq!(
            findings[0].plugin_metadata.product_name.as_deref(),
            Some("Craft CMS")
        );
        assert_eq!(
            findings[0].plugin_metadata.product_version.as_deref(),
            Some("4.13.0")
        );
        assert_eq!(findings[0].severity.as_str(), "high");
    }

    #[test]
    fn derive_protocol_plugin_findings_suppresses_active_authorized_reports_by_default() {
        let endpoint = DiscoveredEndpoint {
            host: "10.0.0.60".to_string(),
            port: 1880,
            service_name: Some("nodered".to_string()),
            transport: Some("tcp".to_string()),
            tags: vec![],
            version: None,
            reported_plugins: vec![ReportedProtocolPluginFinding {
                plugin_id: "NodeREDPlugin".to_string(),
                summary: Some("Node-RED exposed without authentication".to_string()),
                severity: Some("high".to_string()),
                product_name: Some("Node-RED".to_string()),
                product_version: Some("3.1.0".to_string()),
                cpe: None,
                cve_ids: Vec::new(),
                kev_matched: None,
            }],
        };

        let suppressed =
            derive_protocol_plugin_findings_with_active_mode(&[endpoint.clone()], false);
        assert!(suppressed.is_empty());

        let allowed = derive_protocol_plugin_findings_with_active_mode(&[endpoint], true);
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].plugin_metadata.plugin_id, "NodeREDPlugin");
    }

    #[test]
    fn platform_normalization_maps_common_aliases() {
        assert_eq!(
            normalize_platform_operating_system("macos"),
            Some("darwin".to_string())
        );
        assert_eq!(
            normalize_platform_architecture("amd64"),
            Some("x86_64".to_string())
        );
        assert_eq!(
            normalize_platform_architecture("arm64"),
            Some("aarch64".to_string())
        );
    }

    fn unique_scratch_path(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        path.push(format!(
            "anyscan-test-{label}-{}-{nanos}",
            std::process::id()
        ));
        path
    }

    #[test]
    fn scanner_output_counter_tracks_only_new_lines_across_refreshes() {
        let path = unique_scratch_path("counter-incremental");
        fs::write(&path, "10.0.0.1:80\n10.0.0.2:80\n").unwrap();
        let mut counter = ScannerOutputCounter::new("80");
        counter
            .refresh(&path, "endpoint_lines")
            .expect("first refresh should succeed");
        assert_eq!(counter.count(), 2);
        let offset_after_first = counter.offset;

        let mut handle = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append should open");
        writeln!(handle, "10.0.0.3:80").unwrap();
        writeln!(handle, "10.0.0.1:80").unwrap();
        drop(handle);

        counter
            .refresh(&path, "endpoint_lines")
            .expect("second refresh should succeed");
        assert_eq!(counter.count(), 3);
        assert!(counter.offset > offset_after_first);

        // Re-running with no new bytes should be a no-op.
        let offset_before_idle = counter.offset;
        counter
            .refresh(&path, "endpoint_lines")
            .expect("idle refresh should succeed");
        assert_eq!(counter.count(), 3);
        assert_eq!(counter.offset, offset_before_idle);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn scanner_output_counter_handles_partial_lines_at_buffer_boundary() {
        let path = unique_scratch_path("counter-partial");
        // Two complete entries plus a partial line at the end.
        fs::write(&path, "10.0.0.1:443\n10.0.0.2:443\n10.0.0").unwrap();
        let mut counter = ScannerOutputCounter::new("443");
        counter.refresh(&path, "endpoint_lines").unwrap();
        assert_eq!(counter.count(), 2);

        // Complete the partial entry on the next append.
        let mut handle = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(handle, ".3:443").unwrap();
        drop(handle);
        counter.refresh(&path, "endpoint_lines").unwrap();
        let mut endpoints: Vec<_> = counter.seen.iter().cloned().collect();
        endpoints.sort();
        assert_eq!(
            endpoints,
            vec![
                "10.0.0.1:443".to_string(),
                "10.0.0.2:443".to_string(),
                "10.0.0.3:443".to_string(),
            ]
        );

        let _ = fs::remove_file(&path);
    }

    // Run with:
    //   cargo test --release --bin anyscan-worker bench_progress_reporter_parsing \
    //       -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_progress_reporter_parsing() {
        let path = unique_scratch_path("counter-bench");
        let total_lines = 200_000usize;
        let chunk = total_lines / 100; // 100 reporter ticks
        // Pre-fill empty file.
        fs::write(&path, "").unwrap();

        // Legacy approach: read whole file + collect into HashSet on each tick.
        let legacy_start = std::time::Instant::now();
        let mut written = 0usize;
        for _ in 0..100 {
            let mut handle = fs::OpenOptions::new().append(true).open(&path).unwrap();
            for i in 0..chunk {
                writeln!(handle, "10.{}.{}.{}:80", (written + i) / 65536 % 256,
                    (written + i) / 256 % 256, (written + i) % 256).unwrap();
            }
            drop(handle);
            written += chunk;
            let contents = fs::read_to_string(&path).unwrap();
            let count = contents
                .lines()
                .filter_map(|line| {
                    let token = line.trim();
                    if token.is_empty() || token.starts_with('#') {
                        return None;
                    }
                    Some(token.to_string())
                })
                .collect::<HashSet<_>>()
                .len();
            assert_eq!(count, written);
        }
        let legacy = legacy_start.elapsed();

        // Reset for incremental approach.
        fs::write(&path, "").unwrap();
        let incremental_start = std::time::Instant::now();
        let mut counter = ScannerOutputCounter::new("80");
        let mut written = 0usize;
        for _ in 0..100 {
            let mut handle = fs::OpenOptions::new().append(true).open(&path).unwrap();
            for i in 0..chunk {
                writeln!(handle, "10.{}.{}.{}:80", (written + i) / 65536 % 256,
                    (written + i) / 256 % 256, (written + i) % 256).unwrap();
            }
            drop(handle);
            written += chunk;
            counter.refresh(&path, "endpoint_lines").unwrap();
            assert_eq!(counter.count() as usize, written);
        }
        let incremental = incremental_start.elapsed();

        println!(
            "progress reporter parsing benchmark ({total_lines} endpoints over 100 ticks):"
        );
        println!("  legacy (full reparse):      {legacy:?}");
        println!("  incremental (this PR):      {incremental:?}");
        let ratio = legacy.as_secs_f64() / incremental.as_secs_f64().max(1e-9);
        println!("  speedup:                    {ratio:.2}x");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn scanner_output_counter_resets_when_output_file_truncates() {
        let path = unique_scratch_path("counter-truncate");
        fs::write(&path, "10.0.0.1:22\n10.0.0.2:22\n").unwrap();
        let mut counter = ScannerOutputCounter::new("22");
        counter.refresh(&path, "endpoint_lines").unwrap();
        assert_eq!(counter.count(), 2);

        // Simulate file rotation / truncate (smaller size than previous read).
        fs::write(&path, "10.0.0.9:22\n").unwrap();
        counter.refresh(&path, "endpoint_lines").unwrap();
        assert_eq!(counter.count(), 1);
        assert!(counter.seen.contains("10.0.0.9:22"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn should_push_resume_state_forces_push_when_output_rotates() {
        // 8 KiB delta threshold, lots of headroom.
        let delta = 8 * 1024;
        // Output shrunk (rotation/truncation) and checkpoint hasn't changed.
        assert!(should_push_resume_state(
            false,
            false,
            Some(1_000_000),
            Some(2048),
            delta,
        ));
    }

    #[test]
    fn should_push_resume_state_holds_when_growth_below_threshold_and_interval_not_elapsed() {
        let delta = 256 * 1024;
        // 64 KiB grew, threshold 256 KiB, interval not yet elapsed → don't push.
        assert!(!should_push_resume_state(
            false,
            false,
            Some(1_000_000),
            Some(1_064_000),
            delta,
        ));
    }

    #[test]
    fn should_push_resume_state_pushes_on_first_observation_with_content() {
        let delta = 256 * 1024;
        // First push when there's any content and interval considered elapsed.
        assert!(should_push_resume_state(false, true, None, Some(1024), delta));
    }

    #[test]
    fn should_push_resume_state_pushes_on_checkpoint_change_even_when_quiet() {
        let delta = 256 * 1024;
        // Even with no growth and no interval, a checkpoint change forces a push.
        assert!(should_push_resume_state(
            true,
            false,
            Some(1_000_000),
            Some(1_000_000),
            delta,
        ));
    }

    #[test]
    fn scanner_output_counter_rewinds_when_inode_changes_at_same_or_larger_size() {
        let path = unique_scratch_path("counter-inode");
        // First file: two endpoints.
        fs::write(&path, "10.0.0.1:80\n10.0.0.2:80\n").unwrap();
        let mut counter = ScannerOutputCounter::new("80");
        counter.refresh(&path, "endpoint_lines").unwrap();
        assert_eq!(counter.count(), 2);
        let original_offset = counter.offset;

        // Replace the file with a brand-new inode whose size is >= the old
        // offset and whose content is entirely different. Without inode
        // tracking, the old offset would skip the new prefix and the old
        // dedup set would keep the stale endpoints in the count.
        let _ = fs::remove_file(&path);
        let new_contents = "10.0.0.9:80\n10.0.0.10:80\n10.0.0.11:80\n";
        fs::write(&path, new_contents).unwrap();
        // Sanity: new file is >= old offset.
        let new_size = fs::metadata(&path).unwrap().len();
        assert!(new_size >= original_offset);

        counter.refresh(&path, "endpoint_lines").unwrap();
        let mut endpoints: Vec<_> = counter.seen.iter().cloned().collect();
        endpoints.sort();
        assert_eq!(
            endpoints,
            vec![
                "10.0.0.10:80".to_string(),
                "10.0.0.11:80".to_string(),
                "10.0.0.9:80".to_string(),
            ]
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn scanner_output_counter_dedupes_json_lines_on_host_and_port() {
        let path = unique_scratch_path("counter-json");
        // Same host:port emitted twice with different field ordering and a
        // noise field; should count once. A second distinct host:port plus
        // an `ip` alias and a missing-port line that uses the fallback.
        let contents = concat!(
            r#"{"host":"10.0.0.5","port":443,"service":"https"}"#, "\n",
            r#"{"port":443,"host":"10.0.0.5","extra":"noise"}"#, "\n",
            r#"{"host":"10.0.0.6","port":443}"#, "\n",
            r#"{"ip":"10.0.0.7","port":443}"#, "\n",
            r#"{"address":"10.0.0.8"}"#, "\n",
            "not-json-line\n",
        );
        fs::write(&path, contents).unwrap();
        let mut counter = ScannerOutputCounter::new("443");
        counter.refresh(&path, "json_lines").unwrap();
        let mut endpoints: Vec<_> = counter.seen.iter().cloned().collect();
        endpoints.sort();
        assert_eq!(
            endpoints,
            vec![
                "10.0.0.5:443".to_string(),
                "10.0.0.6:443".to_string(),
                "10.0.0.7:443".to_string(),
                "10.0.0.8:443".to_string(),
            ]
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn scanner_output_counter_drains_only_new_keys_each_call() {
        let path = unique_scratch_path("counter-drain");
        // Append the file in three separate writes; each refresh+drain
        // should return only the keys added since the previous drain.
        fs::write(&path, "1.1.1.1:80\n2.2.2.2:80\n").unwrap();
        let mut counter = ScannerOutputCounter::new("80");
        counter.refresh(&path, "endpoint_lines").unwrap();
        let mut first = counter.drain_new_keys();
        first.sort();
        assert_eq!(
            first,
            vec!["1.1.1.1:80".to_string(), "2.2.2.2:80".to_string()]
        );

        // Second drain immediately after — no new lines, no keys.
        counter.refresh(&path, "endpoint_lines").unwrap();
        assert!(counter.drain_new_keys().is_empty());

        // Append, including a duplicate; only the new key should drain.
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"1.1.1.1:80\n3.3.3.3:80\n")
            .unwrap();
        counter.refresh(&path, "endpoint_lines").unwrap();
        let second = counter.drain_new_keys();
        assert_eq!(second, vec!["3.3.3.3:80".to_string()]);
        assert_eq!(counter.count(), 3);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn streaming_followon_should_flush_respects_thresholds_and_intervals() {
        let interval = std::time::Duration::from_secs(30);
        // No pending → never flush.
        assert!(!streaming_followon_should_flush(
            0,
            10,
            std::time::Duration::from_secs(60),
            interval,
            false
        ));
        // Final drain with any pending → flush.
        assert!(streaming_followon_should_flush(
            1,
            64,
            std::time::Duration::ZERO,
            interval,
            true
        ));
        // Hit min results threshold → flush.
        assert!(streaming_followon_should_flush(
            64,
            64,
            std::time::Duration::ZERO,
            interval,
            false
        ));
        // Below threshold but interval elapsed → flush.
        assert!(streaming_followon_should_flush(
            5,
            64,
            std::time::Duration::from_secs(45),
            interval,
            false
        ));
        // Below threshold and within interval → wait.
        assert!(!streaming_followon_should_flush(
            5,
            64,
            std::time::Duration::from_secs(5),
            interval,
            false
        ));
    }

    #[test]
    fn filter_endpoints_excluding_streamed_drops_overlap() {
        let endpoints = vec![
            DiscoveredEndpoint {
                host: "10.0.0.1".to_string(),
                port: 80,
                service_name: None,
                transport: None,
                tags: Vec::new(),
                version: None,
                reported_plugins: Vec::new(),
            },
            DiscoveredEndpoint {
                host: "10.0.0.2".to_string(),
                port: 443,
                service_name: None,
                transport: None,
                tags: Vec::new(),
                version: None,
                reported_plugins: Vec::new(),
            },
            DiscoveredEndpoint {
                host: "10.0.0.3".to_string(),
                port: 22,
                service_name: None,
                transport: None,
                tags: Vec::new(),
                version: None,
                reported_plugins: Vec::new(),
            },
        ];
        let mut flushed = HashSet::new();
        flushed.insert("10.0.0.1:80".to_string());
        flushed.insert("10.0.0.3:22".to_string());

        let remaining = filter_endpoints_excluding_streamed(&endpoints, &flushed);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].host, "10.0.0.2");
        assert_eq!(remaining[0].port, 443);

        // Empty flushed set → return all.
        let all = filter_endpoints_excluding_streamed(&endpoints, &HashSet::new());
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn streaming_drives_host_scan_jobs_before_scan_finishes() {
        // End-to-end test of the streaming pipeline driven by synthetic
        // PortScanResults written to the scanner output file. We exercise
        // the same primitives the live worker uses (ScannerOutputCounter
        // drain + flush decision), simulating a port scan that yields
        // batches of endpoints in three writes. The assertion is that
        // host-scan task batches become available before the synthetic
        // scan finishes — i.e. multiple flushes happen, each producing a
        // distinct batch of keys, while the file is still being written.
        let path = unique_scratch_path("streaming-drives");
        let mut counter = ScannerOutputCounter::new("80");
        let interval = std::time::Duration::from_secs(60);
        let min_results: usize = 3;
        let mut all_batches: Vec<Vec<String>> = Vec::new();

        // Phase 1 of the synthetic scan: 3 endpoints arrive — should
        // trigger a flush (>= min_results).
        fs::write(&path, "1.1.1.1:80\n2.2.2.2:80\n3.3.3.3:80\n").unwrap();
        counter.refresh(&path, "endpoint_lines").unwrap();
        let pending = counter.pending.len();
        assert!(streaming_followon_should_flush(
            pending,
            min_results,
            std::time::Duration::ZERO,
            interval,
            false
        ));
        let batch = counter.drain_new_keys();
        assert_eq!(batch.len(), 3);
        all_batches.push(batch);

        // Phase 2: only 1 new endpoint, within interval — should NOT flush
        // until either threshold or interval is met.
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"4.4.4.4:80\n")
            .unwrap();
        counter.refresh(&path, "endpoint_lines").unwrap();
        let pending = counter.pending.len();
        assert!(!streaming_followon_should_flush(
            pending,
            min_results,
            std::time::Duration::from_secs(1),
            interval,
            false
        ));

        // Phase 3: 2 more endpoints arrive — total pending hits the
        // threshold, flush again.
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"5.5.5.5:80\n6.6.6.6:80\n")
            .unwrap();
        counter.refresh(&path, "endpoint_lines").unwrap();
        let pending = counter.pending.len();
        assert!(streaming_followon_should_flush(
            pending,
            min_results,
            std::time::Duration::from_secs(1),
            interval,
            false
        ));
        let batch = counter.drain_new_keys();
        assert_eq!(batch.len(), 3);
        all_batches.push(batch);

        // Phase 4: scan ends — final-drain semantics flush whatever's
        // left, even if below threshold or within interval.
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"7.7.7.7:80\n")
            .unwrap();
        counter.refresh(&path, "endpoint_lines").unwrap();
        let pending = counter.pending.len();
        assert!(streaming_followon_should_flush(
            pending,
            min_results,
            std::time::Duration::ZERO,
            interval,
            true
        ));
        let batch = counter.drain_new_keys();
        assert_eq!(batch.len(), 1);
        all_batches.push(batch);

        // Three distinct batches were produced before the scan output
        // file was finalized — host-scan tasks would have been queued
        // incrementally rather than in a single end-of-scan burst.
        assert_eq!(all_batches.len(), 3);
        let total: usize = all_batches.iter().map(|b| b.len()).sum();
        assert_eq!(total, 7);
        // No key was emitted in more than one batch — the streaming
        // pipeline does not double-queue endpoints.
        let mut all_keys: Vec<String> =
            all_batches.iter().flatten().cloned().collect();
        all_keys.sort();
        let unique: std::collections::HashSet<_> = all_keys.iter().cloned().collect();
        assert_eq!(unique.len(), all_keys.len());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn endpoint_cache_key_round_trips_for_ipv4_and_ipv6() {
        // IPv4 keys keep the bare host:port form so the existing zmap output
        // continues to work unchanged.
        assert_eq!(endpoint_cache_key("10.0.0.1", 80), "10.0.0.1:80");

        // IPv6 hosts contain ':' literally; without bracketing the key would
        // collide with another endpoint and could not be unambiguously
        // re-parsed. The bracketed form is canonical and round-trips through
        // `parse_endpoint_token` (which delegates to `SocketAddr::parse`).
        let v6_key = endpoint_cache_key("2001:db8::1", 443);
        assert_eq!(v6_key, "[2001:db8::1]:443");
        let parsed = parse_endpoint_token(&v6_key, None)
            .expect("parse")
            .expect("non-empty");
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 443);
        // Round-tripping the parsed endpoint must produce the same key.
        assert_eq!(endpoint_cache_key(&parsed.host, parsed.port), v6_key);

        // Already-bracketed inputs are not re-bracketed.
        assert_eq!(endpoint_cache_key("[fe80::1]", 22), "[fe80::1]:22");
    }

    #[test]
    fn filter_endpoints_excluding_streamed_handles_ipv6_keys() {
        let endpoints = vec![
            DiscoveredEndpoint {
                host: "2001:db8::1".to_string(),
                port: 443,
                service_name: None,
                transport: None,
                tags: Vec::new(),
                version: None,
                reported_plugins: Vec::new(),
            },
            DiscoveredEndpoint {
                host: "10.0.0.5".to_string(),
                port: 443,
                service_name: None,
                transport: None,
                tags: Vec::new(),
                version: None,
                reported_plugins: Vec::new(),
            },
        ];
        let mut flushed = HashSet::new();
        flushed.insert(endpoint_cache_key("2001:db8::1", 443));

        let remaining = filter_endpoints_excluding_streamed(&endpoints, &flushed);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].host, "10.0.0.5");
    }

    #[test]
    fn scanner_output_counter_seen_set_dedupes_resumed_content() {
        // Simulates the resume seed path: the scanner output file already
        // contains pre-resume endpoints, the flusher refresh+drain prologue
        // moves them into `seen` (without re-emission), and a subsequent
        // refresh after the scanner appends new lines drains only the new
        // post-resume endpoints.
        let path = unique_scratch_path("counter-resume-seed");
        fs::write(&path, "1.1.1.1:80\n2.2.2.2:80\n").unwrap();
        let mut counter = ScannerOutputCounter::new("80");

        // Resume prologue: refresh, drain, discard (or stash as flushed).
        counter.refresh(&path, "endpoint_lines").unwrap();
        let resumed = counter.drain_new_keys();
        assert_eq!(resumed.len(), 2);
        // After draining, `seen` still contains them — a re-refresh of the
        // same file does NOT re-emit.
        counter.refresh(&path, "endpoint_lines").unwrap();
        assert!(counter.drain_new_keys().is_empty());

        // Scanner appends a new line; only the new key drains.
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"3.3.3.3:80\n")
            .unwrap();
        counter.refresh(&path, "endpoint_lines").unwrap();
        let post = counter.drain_new_keys();
        assert_eq!(post, vec!["3.3.3.3:80".to_string()]);

        let _ = fs::remove_file(&path);
    }
}
