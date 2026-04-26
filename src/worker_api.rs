use std::{
    env,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use reqwest::{blocking::Client, Proxy};
use serde::{Deserialize, Serialize};

use crate::{
    config::AppConfig,
    core::{
        ApiEvent, ArchiveJobRecord, FetchTelemetry, FindingRecord, NewFinding,
        PortScanProtocolFindingRecord, PortScanRecord, PortScanResumeStateRecord,
        RecurringScheduleRecord,
        RepositoryDefinition, RepositoryRecord, RunScope, RunSummary, ScanDefaultsSummary,
        ScanJobRecord, ScanRunRecord, TargetDefinition, TargetRecord,
        WorkerBootstrapCodeExchange, WorkerBootstrapCodeExchangeRequest,
        WorkerBootstrapCandidateInput, WorkerBootstrapCandidateRecord,
        WorkerBootstrapJobClaim, WorkerBootstrapJobRecord, WorkerRecord, WorkerRegistration,
        WorkerRemoteCommandRecord,
    },
};

pub const WORKER_CONTROL_ENDPOINT_PATH: &str = "/api/worker/control";
const DEFAULT_TOR_SOCKS_PROXY_URL: &str = "socks5h://127.0.0.1:9050";
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
const CONTROL_PROXY_URL_ENV_NAMES: &[&str] = &["CONTROL_PROXY_URL"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const CONTROL_PROXY_URL_ENV_NAMES: &[&str] = &["CONTROL_PROXY_URL", "ANYSCAN_API_PROXY_URL"];
#[cfg(feature = "worker-bundle-stealth")]
const AGENT_TOKEN_ENV_NAMES: &[&str] = &["AGENT_TOKEN", "AGENT_ENROLLMENT_TOKEN"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const AGENT_TOKEN_ENV_NAMES: &[&str] = &[
    "AGENT_TOKEN",
    "AGENT_ENROLLMENT_TOKEN",
    "ANYSCAN_WORKER_TOKEN",
    "ANYSCAN_WORKER_ENROLLMENT_TOKEN",
];
#[cfg(feature = "worker-bundle-stealth")]
const AGENT_BOOTSTRAP_CODE_ENV_NAMES: &[&str] = &["AGENT_BOOTSTRAP_CODE"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const AGENT_BOOTSTRAP_CODE_ENV_NAMES: &[&str] =
    &["AGENT_BOOTSTRAP_CODE", "ANYSCAN_WORKER_BOOTSTRAP_CODE"];
#[cfg(feature = "worker-bundle-stealth")]
const AGENT_BOOTSTRAP_CODE_OBFUSCATED_ENV_NAMES: &[&str] = &["AGENT_BOOTSTRAP_CODE_OBFUSCATED"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const AGENT_BOOTSTRAP_CODE_OBFUSCATED_ENV_NAMES: &[&str] = &[
    "AGENT_BOOTSTRAP_CODE_OBFUSCATED",
    "ANYSCAN_WORKER_BOOTSTRAP_CODE_OBFUSCATED",
];
#[cfg(feature = "worker-bundle-stealth")]
const AGENT_STATE_FILE_ENV_NAMES: &[&str] = &["AGENT_STATE_FILE"];
#[cfg(not(feature = "worker-bundle-stealth"))]
const AGENT_STATE_FILE_ENV_NAMES: &[&str] =
    &["AGENT_STATE_FILE", "ANYSCAN_WORKER_STATE_ENV_FILE"];
#[cfg(feature = "worker-bundle-stealth")]
const DEFAULT_AGENT_STATE_FILE_PATH: &str = "/var/lib/agentd/agent.env";
#[cfg(not(feature = "worker-bundle-stealth"))]
const DEFAULT_AGENT_STATE_FILE_PATH: &str = "/var/lib/anyscan/worker.env";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueuedScheduleRunRecord {
    pub schedule: RecurringScheduleRecord,
    pub run: ScanRunRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueuedRunWithSummary {
    pub run: ScanRunRecord,
    pub summary: RunSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerControlEnvelope {
    pub worker_id: String,
    pub worker_token: String,
    pub request: WorkerControlRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerControlRequest {
    RegisterWorker {
        registration: WorkerRegistration,
        ttl_seconds: u64,
    },
    QueueDueScheduleRunsWithEvents {
        limit: usize,
    },
    QueueRunWithEvent {
        requested_by: String,
        scope: Option<RunScope>,
    },
    MaybeRunArchivePass,
    ClaimNextRunnableRun {
        lease_seconds: u64,
    },
    ClaimNextPendingBootstrapJob {
        lease_seconds: u64,
    },
    ClaimNextPendingPortScan {
        lease_seconds: u64,
    },
    NextAssistableRun,
    RequeueInProgressJobs {
        run_id: i64,
    },
    MarkRunStartedIfQueued {
        run_id: i64,
    },
    Summary {
        run_id: i64,
    },
    AppendEvent {
        run_id: Option<i64>,
        event: ApiEvent,
    },
    HasIncompleteJobs {
        run_id: i64,
    },
    MarkRunFinishedIfOwned {
        run_id: i64,
        notes: Option<String>,
    },
    AcknowledgeStoppingRun {
        run_id: i64,
        notes: Option<String>,
    },
    GetRun {
        run_id: i64,
    },
    GetPortScan {
        port_scan_id: i64,
    },
    ClaimNextPendingJob {
        run_id: i64,
        lease_seconds: u64,
    },
    RecordFindingIfNew {
        finding: NewFinding,
    },
    MergeTargetDiscoveryProvenance {
        target_id: i64,
        discovery_provenance: Vec<crate::core::DiscoveryProvenanceRecord>,
    },
    MarkJobFinishedIfOwned {
        job_id: i64,
        findings_count: u64,
        telemetry: FetchTelemetry,
        error: Option<String>,
    },
    MarkPortScanStartedIfQueued {
        port_scan_id: i64,
    },
    UpdatePortScanProgressIfOwned {
        port_scan_id: i64,
        discovered_endpoints_total: u64,
        probe_rate_millis: u64,
        receive_rate_millis: u64,
        progress_percent: Option<u64>,
    },
    LoadPortScanResumeState {
        port_scan_id: i64,
    },
    UpdatePortScanResumeStateIfOwned {
        port_scan_id: i64,
        checkpoint_data: Option<String>,
        output_snapshot: Option<String>,
    },
    AnnotatePortScanIfOwned {
        port_scan_id: i64,
        note: String,
    },
    CompletePortScanIfOwned {
        port_scan_id: i64,
        discovered_endpoints_total: u64,
        imported_targets_total: u64,
        protocol_findings: Vec<PortScanProtocolFindingRecord>,
        queued_run_id: Option<i64>,
        notes: Option<String>,
    },
    FailPortScanIfOwned {
        port_scan_id: i64,
        notes: Option<String>,
    },
    AcknowledgeStoppingPortScan {
        port_scan_id: i64,
        notes: Option<String>,
    },
    CreateBootstrapCandidates {
        port_scan: PortScanRecord,
        candidates: Vec<WorkerBootstrapCandidateInput>,
    },
    MarkBootstrapJobStartedIfOwned {
        job_id: i64,
    },
    CompleteBootstrapJobIfOwned {
        job_id: i64,
        notes: Option<String>,
    },
    FailBootstrapJobIfOwned {
        job_id: i64,
        notes: Option<String>,
    },
    RenewPortScanClaim {
        port_scan_id: i64,
        lease_seconds: u64,
    },
    RenewBootstrapJobClaim {
        job_id: i64,
        lease_seconds: u64,
    },
    RenewJobClaim {
        job_id: i64,
        lease_seconds: u64,
    },
    RenewRunClaim {
        run_id: i64,
        lease_seconds: u64,
    },
    ClaimNextPendingRemoteCommand,
    CompleteRemoteCommand {
        command_id: i64,
        exit_code: Option<i32>,
        timed_out: bool,
        stdout: Option<String>,
        stderr: Option<String>,
        error: Option<String>,
    },
    AcknowledgeRemoteUpdate {
        requested_at: DateTime<Utc>,
    },
    UpsertTarget {
        target: TargetDefinition,
    },
    UpsertRepository {
        repository: RepositoryDefinition,
    },
    LoadScanSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerControlResponse {
    Ack,
    WorkerRecord {
        worker: WorkerRecord,
    },
    OptionalRun {
        run: Option<ScanRunRecord>,
    },
    OptionalBootstrapJobClaim {
        claim: Option<WorkerBootstrapJobClaim>,
    },
    OptionalPortScan {
        port_scan: Option<PortScanRecord>,
    },
    OptionalPortScanResumeState {
        resume_state: Option<PortScanResumeStateRecord>,
    },
    RunSummary {
        summary: RunSummary,
    },
    EventId {
        event_id: i64,
    },
    Bool {
        value: bool,
    },
    OptionalFinishedRun {
        run: Option<ScanRunRecord>,
    },
    OptionalJob {
        job: Option<ScanJobRecord>,
    },
    OptionalFinding {
        finding: Option<FindingRecord>,
    },
    OptionalStartedPortScan {
        port_scan: Option<PortScanRecord>,
    },
    BootstrapCandidates {
        candidates: Vec<WorkerBootstrapCandidateRecord>,
    },
    OptionalBootstrapJob {
        job: Option<WorkerBootstrapJobRecord>,
    },
    TargetRecord {
        target: TargetRecord,
    },
    RepositoryRecord {
        repository: RepositoryRecord,
    },
    QueuedScheduleRuns {
        queued: Vec<QueuedScheduleRunRecord>,
    },
    QueuedRunWithSummary {
        queued: QueuedRunWithSummary,
    },
    OptionalScanSettings {
        settings: Option<ScanDefaultsSummary>,
    },
    OptionalArchiveJob {
        job: Option<ArchiveJobRecord>,
    },
    OptionalRemoteCommand {
        command: Option<WorkerRemoteCommandRecord>,
    },
}

#[derive(Debug, Clone)]
pub struct AnyScanWorkerApiClient {
    http: Client,
    base_url: String,
    worker_id: String,
    worker_token: String,
}

impl AnyScanWorkerApiClient {
    pub fn from_config_and_worker(config: &AppConfig, worker_id: &str) -> Result<Self> {
        let worker_id = worker_id.trim().to_string();
        if worker_id.is_empty() {
            return Err(anyhow!("worker_id is required"));
        }
        let base_url = resolve_worker_api_base_url(config)?;
        let http = build_worker_api_client(config, &base_url)?;
        let worker_token = resolve_worker_api_token(&http, &base_url, &worker_id)?;
        Ok(Self {
            http,
            base_url,
            worker_id,
            worker_token,
        })
    }

    pub fn initialize(&self) -> Result<()> {
        Ok(())
    }

    fn request(&self, request: WorkerControlRequest) -> Result<WorkerControlResponse> {
        let envelope = WorkerControlEnvelope {
            worker_id: self.worker_id.clone(),
            worker_token: self.worker_token.clone(),
            request,
        };
        let url = format!("{}{}", self.base_url, WORKER_CONTROL_ENDPOINT_PATH);
        let response = self
            .http
            .post(&url)
            .json(&envelope)
            .send()
            .with_context(|| format!("failed to reach control API at {url}"))?;
        decode_worker_response(response)
    }

    pub fn register_worker(
        &self,
        registration: &WorkerRegistration,
        ttl_seconds: u64,
    ) -> Result<WorkerRecord> {
        let mut registration = registration.clone();
        registration.worker_id = self.worker_id.clone();
        registration.enrollment_token = Some(self.worker_token.clone());
        match self.request(WorkerControlRequest::RegisterWorker {
            registration,
            ttl_seconds,
        })? {
            WorkerControlResponse::WorkerRecord { worker } => Ok(worker),
            other => Err(unexpected_worker_response("worker record", &other)),
        }
    }

    pub fn queue_due_schedule_runs_with_events(
        &self,
        limit: usize,
    ) -> Result<Vec<QueuedScheduleRunRecord>> {
        match self.request(WorkerControlRequest::QueueDueScheduleRunsWithEvents { limit })? {
            WorkerControlResponse::QueuedScheduleRuns { queued } => Ok(queued),
            other => Err(unexpected_worker_response("queued schedule runs", &other)),
        }
    }

    pub fn queue_run_with_event(
        &self,
        requested_by: &str,
        scope: Option<&crate::core::RunScope>,
    ) -> Result<QueuedRunWithSummary> {
        match self.request(WorkerControlRequest::QueueRunWithEvent {
            requested_by: requested_by.to_string(),
            scope: scope.cloned(),
        })? {
            WorkerControlResponse::QueuedRunWithSummary { queued } => Ok(queued),
            other => Err(unexpected_worker_response("queued run with summary", &other)),
        }
    }

    pub fn maybe_run_archive_pass(&self) -> Result<Option<ArchiveJobRecord>> {
        match self.request(WorkerControlRequest::MaybeRunArchivePass)? {
            WorkerControlResponse::OptionalArchiveJob { job } => Ok(job),
            other => Err(unexpected_worker_response("optional archive job", &other)),
        }
    }

    pub fn claim_next_runnable_run(&self, lease_seconds: u64) -> Result<Option<ScanRunRecord>> {
        match self.request(WorkerControlRequest::ClaimNextRunnableRun { lease_seconds })? {
            WorkerControlResponse::OptionalRun { run } => Ok(run),
            other => Err(unexpected_worker_response("optional run", &other)),
        }
    }

    pub fn claim_next_pending_bootstrap_job(
        &self,
        lease_seconds: u64,
    ) -> Result<Option<WorkerBootstrapJobClaim>> {
        match self.request(WorkerControlRequest::ClaimNextPendingBootstrapJob { lease_seconds })? {
            WorkerControlResponse::OptionalBootstrapJobClaim { claim } => Ok(claim),
            other => Err(unexpected_worker_response("optional bootstrap job claim", &other)),
        }
    }

    pub fn claim_next_pending_port_scan(
        &self,
        lease_seconds: u64,
    ) -> Result<Option<PortScanRecord>> {
        match self.request(WorkerControlRequest::ClaimNextPendingPortScan { lease_seconds })? {
            WorkerControlResponse::OptionalPortScan { port_scan } => Ok(port_scan),
            other => Err(unexpected_worker_response("optional port scan", &other)),
        }
    }

    pub fn next_assistable_run(&self) -> Result<Option<ScanRunRecord>> {
        match self.request(WorkerControlRequest::NextAssistableRun)? {
            WorkerControlResponse::OptionalRun { run } => Ok(run),
            other => Err(unexpected_worker_response("optional run", &other)),
        }
    }

    pub fn requeue_in_progress_jobs(&self, run_id: i64) -> Result<()> {
        match self.request(WorkerControlRequest::RequeueInProgressJobs { run_id })? {
            WorkerControlResponse::Ack => Ok(()),
            other => Err(unexpected_worker_response("ack", &other)),
        }
    }

    pub fn mark_run_started_if_queued(&self, run_id: i64) -> Result<Option<ScanRunRecord>> {
        match self.request(WorkerControlRequest::MarkRunStartedIfQueued { run_id })? {
            WorkerControlResponse::OptionalRun { run } => Ok(run),
            other => Err(unexpected_worker_response("optional run", &other)),
        }
    }

    pub fn summary(&self, run_id: i64) -> Result<RunSummary> {
        match self.request(WorkerControlRequest::Summary { run_id })? {
            WorkerControlResponse::RunSummary { summary } => Ok(summary),
            other => Err(unexpected_worker_response("run summary", &other)),
        }
    }

    pub fn append_event(&self, run_id: Option<i64>, event: &ApiEvent) -> Result<i64> {
        match self.request(WorkerControlRequest::AppendEvent {
            run_id,
            event: event.clone(),
        })? {
            WorkerControlResponse::EventId { event_id } => Ok(event_id),
            other => Err(unexpected_worker_response("event id", &other)),
        }
    }

    pub fn has_incomplete_jobs(&self, run_id: i64) -> Result<bool> {
        match self.request(WorkerControlRequest::HasIncompleteJobs { run_id })? {
            WorkerControlResponse::Bool { value } => Ok(value),
            other => Err(unexpected_worker_response("bool", &other)),
        }
    }

    pub fn mark_run_finished_if_owned(
        &self,
        run_id: i64,
        notes: Option<&str>,
    ) -> Result<Option<ScanRunRecord>> {
        match self.request(WorkerControlRequest::MarkRunFinishedIfOwned {
            run_id,
            notes: notes.map(|value| value.to_string()),
        })? {
            WorkerControlResponse::OptionalFinishedRun { run } => Ok(run),
            other => Err(unexpected_worker_response("optional finished run", &other)),
        }
    }

    pub fn acknowledge_stopping_run(
        &self,
        run_id: i64,
        notes: Option<&str>,
    ) -> Result<Option<ScanRunRecord>> {
        match self.request(WorkerControlRequest::AcknowledgeStoppingRun {
            run_id,
            notes: notes.map(|value| value.to_string()),
        })? {
            WorkerControlResponse::OptionalFinishedRun { run } => Ok(run),
            other => Err(unexpected_worker_response("optional finished run", &other)),
        }
    }

    pub fn get_run(&self, run_id: i64) -> Result<Option<ScanRunRecord>> {
        match self.request(WorkerControlRequest::GetRun { run_id })? {
            WorkerControlResponse::OptionalRun { run } => Ok(run),
            other => Err(unexpected_worker_response("optional run", &other)),
        }
    }

    pub fn get_port_scan(&self, port_scan_id: i64) -> Result<Option<PortScanRecord>> {
        match self.request(WorkerControlRequest::GetPortScan { port_scan_id })? {
            WorkerControlResponse::OptionalPortScan { port_scan } => Ok(port_scan),
            other => Err(unexpected_worker_response("optional port scan", &other)),
        }
    }

    pub fn load_port_scan_resume_state(
        &self,
        port_scan_id: i64,
    ) -> Result<Option<PortScanResumeStateRecord>> {
        match self.request(WorkerControlRequest::LoadPortScanResumeState { port_scan_id })? {
            WorkerControlResponse::OptionalPortScanResumeState { resume_state } => Ok(resume_state),
            other => Err(unexpected_worker_response("optional port scan resume state", &other)),
        }
    }

    pub fn claim_next_pending_job(
        &self,
        run_id: i64,
        lease_seconds: u64,
    ) -> Result<Option<ScanJobRecord>> {
        match self.request(WorkerControlRequest::ClaimNextPendingJob {
            run_id,
            lease_seconds,
        })? {
            WorkerControlResponse::OptionalJob { job } => Ok(job),
            other => Err(unexpected_worker_response("optional job", &other)),
        }
    }

    pub fn record_finding_if_new(&self, finding: &NewFinding) -> Result<Option<FindingRecord>> {
        match self.request(WorkerControlRequest::RecordFindingIfNew {
            finding: finding.clone(),
        })? {
            WorkerControlResponse::OptionalFinding { finding } => Ok(finding),
            other => Err(unexpected_worker_response("optional finding", &other)),
        }
    }

    pub fn merge_target_discovery_provenance(
        &self,
        target_id: i64,
        discovery_provenance: &[crate::core::DiscoveryProvenanceRecord],
    ) -> Result<()> {
        match self.request(WorkerControlRequest::MergeTargetDiscoveryProvenance {
            target_id,
            discovery_provenance: discovery_provenance.to_vec(),
        })? {
            WorkerControlResponse::Ack => Ok(()),
            other => Err(unexpected_worker_response("ack", &other)),
        }
    }

    pub fn mark_job_finished_if_owned(
        &self,
        job_id: i64,
        findings_count: u64,
        telemetry: &FetchTelemetry,
        error: Option<&str>,
    ) -> Result<bool> {
        match self.request(WorkerControlRequest::MarkJobFinishedIfOwned {
            job_id,
            findings_count,
            telemetry: telemetry.clone(),
            error: error.map(|value| value.to_string()),
        })? {
            WorkerControlResponse::Bool { value } => Ok(value),
            other => Err(unexpected_worker_response("bool", &other)),
        }
    }

    pub fn mark_port_scan_started_if_queued(
        &self,
        port_scan_id: i64,
    ) -> Result<Option<PortScanRecord>> {
        match self.request(WorkerControlRequest::MarkPortScanStartedIfQueued { port_scan_id })? {
            WorkerControlResponse::OptionalStartedPortScan { port_scan } => Ok(port_scan),
            other => Err(unexpected_worker_response("optional started port scan", &other)),
        }
    }

    pub fn update_port_scan_progress_if_owned(
        &self,
        port_scan_id: i64,
        discovered_endpoints_total: u64,
        probe_rate_millis: u64,
        receive_rate_millis: u64,
        progress_percent: Option<u64>,
    ) -> Result<Option<PortScanRecord>> {
        match self.request(WorkerControlRequest::UpdatePortScanProgressIfOwned {
            port_scan_id,
            discovered_endpoints_total,
            probe_rate_millis,
            receive_rate_millis,
            progress_percent,
        })? {
            WorkerControlResponse::OptionalPortScan { port_scan } => Ok(port_scan),
            other => Err(unexpected_worker_response("optional port scan", &other)),
        }
    }

    pub fn update_port_scan_resume_state_if_owned(
        &self,
        port_scan_id: i64,
        checkpoint_data: Option<&str>,
        output_snapshot: Option<&str>,
    ) -> Result<Option<PortScanRecord>> {
        match self.request(WorkerControlRequest::UpdatePortScanResumeStateIfOwned {
            port_scan_id,
            checkpoint_data: checkpoint_data.map(|value| value.to_string()),
            output_snapshot: output_snapshot.map(|value| value.to_string()),
        })? {
            WorkerControlResponse::OptionalPortScan { port_scan } => Ok(port_scan),
            other => Err(unexpected_worker_response("optional port scan", &other)),
        }
    }

    pub fn annotate_port_scan_if_owned(
        &self,
        port_scan_id: i64,
        note: &str,
    ) -> Result<Option<PortScanRecord>> {
        match self.request(WorkerControlRequest::AnnotatePortScanIfOwned {
            port_scan_id,
            note: note.to_string(),
        })? {
            WorkerControlResponse::OptionalPortScan { port_scan } => Ok(port_scan),
            other => Err(unexpected_worker_response("optional port scan", &other)),
        }
    }

    pub fn complete_port_scan_if_owned(
        &self,
        port_scan_id: i64,
        discovered_endpoints_total: u64,
        imported_targets_total: u64,
        protocol_findings: &[PortScanProtocolFindingRecord],
        queued_run_id: Option<i64>,
        notes: Option<&str>,
    ) -> Result<Option<PortScanRecord>> {
        match self.request(WorkerControlRequest::CompletePortScanIfOwned {
            port_scan_id,
            discovered_endpoints_total,
            imported_targets_total,
            protocol_findings: protocol_findings.to_vec(),
            queued_run_id,
            notes: notes.map(|value| value.to_string()),
        })? {
            WorkerControlResponse::OptionalPortScan { port_scan } => Ok(port_scan),
            other => Err(unexpected_worker_response("optional port scan", &other)),
        }
    }

    pub fn fail_port_scan_if_owned(
        &self,
        port_scan_id: i64,
        notes: Option<&str>,
    ) -> Result<Option<PortScanRecord>> {
        match self.request(WorkerControlRequest::FailPortScanIfOwned {
            port_scan_id,
            notes: notes.map(|value| value.to_string()),
        })? {
            WorkerControlResponse::OptionalPortScan { port_scan } => Ok(port_scan),
            other => Err(unexpected_worker_response("optional port scan", &other)),
        }
    }

    pub fn acknowledge_stopping_port_scan(
        &self,
        port_scan_id: i64,
        notes: Option<&str>,
    ) -> Result<Option<PortScanRecord>> {
        match self.request(WorkerControlRequest::AcknowledgeStoppingPortScan {
            port_scan_id,
            notes: notes.map(|value| value.to_string()),
        })? {
            WorkerControlResponse::OptionalPortScan { port_scan } => Ok(port_scan),
            other => Err(unexpected_worker_response("optional port scan", &other)),
        }
    }

    pub fn create_bootstrap_candidates(
        &self,
        port_scan: &PortScanRecord,
        candidates: &[WorkerBootstrapCandidateInput],
    ) -> Result<Vec<WorkerBootstrapCandidateRecord>> {
        match self.request(WorkerControlRequest::CreateBootstrapCandidates {
            port_scan: port_scan.clone(),
            candidates: candidates.to_vec(),
        })? {
            WorkerControlResponse::BootstrapCandidates { candidates } => Ok(candidates),
            other => Err(unexpected_worker_response("bootstrap candidates", &other)),
        }
    }

    pub fn mark_bootstrap_job_started_if_owned(
        &self,
        job_id: i64,
    ) -> Result<Option<WorkerBootstrapJobRecord>> {
        match self.request(WorkerControlRequest::MarkBootstrapJobStartedIfOwned { job_id })? {
            WorkerControlResponse::OptionalBootstrapJob { job } => Ok(job),
            other => Err(unexpected_worker_response("optional bootstrap job", &other)),
        }
    }

    pub fn complete_bootstrap_job_if_owned(
        &self,
        job_id: i64,
        notes: Option<&str>,
    ) -> Result<Option<WorkerBootstrapJobRecord>> {
        match self.request(WorkerControlRequest::CompleteBootstrapJobIfOwned {
            job_id,
            notes: notes.map(|value| value.to_string()),
        })? {
            WorkerControlResponse::OptionalBootstrapJob { job } => Ok(job),
            other => Err(unexpected_worker_response("optional bootstrap job", &other)),
        }
    }

    pub fn fail_bootstrap_job_if_owned(
        &self,
        job_id: i64,
        notes: Option<&str>,
    ) -> Result<Option<WorkerBootstrapJobRecord>> {
        match self.request(WorkerControlRequest::FailBootstrapJobIfOwned {
            job_id,
            notes: notes.map(|value| value.to_string()),
        })? {
            WorkerControlResponse::OptionalBootstrapJob { job } => Ok(job),
            other => Err(unexpected_worker_response("optional bootstrap job", &other)),
        }
    }

    pub fn renew_port_scan_claim(&self, port_scan_id: i64, lease_seconds: u64) -> Result<()> {
        match self.request(WorkerControlRequest::RenewPortScanClaim {
            port_scan_id,
            lease_seconds,
        })? {
            WorkerControlResponse::Ack => Ok(()),
            other => Err(unexpected_worker_response("ack", &other)),
        }
    }

    pub fn renew_bootstrap_job_claim(&self, job_id: i64, lease_seconds: u64) -> Result<()> {
        match self.request(WorkerControlRequest::RenewBootstrapJobClaim {
            job_id,
            lease_seconds,
        })? {
            WorkerControlResponse::Ack => Ok(()),
            other => Err(unexpected_worker_response("ack", &other)),
        }
    }

    pub fn renew_job_claim(&self, job_id: i64, lease_seconds: u64) -> Result<()> {
        match self.request(WorkerControlRequest::RenewJobClaim {
            job_id,
            lease_seconds,
        })? {
            WorkerControlResponse::Ack => Ok(()),
            other => Err(unexpected_worker_response("ack", &other)),
        }
    }

    pub fn renew_run_claim(&self, run_id: i64, lease_seconds: u64) -> Result<()> {
        match self.request(WorkerControlRequest::RenewRunClaim {
            run_id,
            lease_seconds,
        })? {
            WorkerControlResponse::Ack => Ok(()),
            other => Err(unexpected_worker_response("ack", &other)),
        }
    }

    pub fn acknowledge_remote_update(&self, requested_at: DateTime<Utc>) -> Result<WorkerRecord> {
        match self.request(WorkerControlRequest::AcknowledgeRemoteUpdate { requested_at })? {
            WorkerControlResponse::WorkerRecord { worker } => Ok(worker),
            other => Err(unexpected_worker_response("worker record", &other)),
        }
    }

    pub fn claim_next_pending_remote_command(&self) -> Result<Option<WorkerRemoteCommandRecord>> {
        match self.request(WorkerControlRequest::ClaimNextPendingRemoteCommand)? {
            WorkerControlResponse::OptionalRemoteCommand { command } => Ok(command),
            other => Err(unexpected_worker_response("optional remote command", &other)),
        }
    }

    pub fn complete_remote_command(
        &self,
        command_id: i64,
        exit_code: Option<i32>,
        timed_out: bool,
        stdout: Option<&str>,
        stderr: Option<&str>,
        error: Option<&str>,
    ) -> Result<Option<WorkerRemoteCommandRecord>> {
        match self.request(WorkerControlRequest::CompleteRemoteCommand {
            command_id,
            exit_code,
            timed_out,
            stdout: stdout.map(|value| value.to_string()),
            stderr: stderr.map(|value| value.to_string()),
            error: error.map(|value| value.to_string()),
        })? {
            WorkerControlResponse::OptionalRemoteCommand { command } => Ok(command),
            other => Err(unexpected_worker_response("optional remote command", &other)),
        }
    }

    pub fn upsert_target(&self, target: &TargetDefinition) -> Result<TargetRecord> {
        match self.request(WorkerControlRequest::UpsertTarget {
            target: target.clone(),
        })? {
            WorkerControlResponse::TargetRecord { target } => Ok(target),
            other => Err(unexpected_worker_response("target record", &other)),
        }
    }

    pub fn upsert_repository(&self, repository: &RepositoryDefinition) -> Result<RepositoryRecord> {
        match self.request(WorkerControlRequest::UpsertRepository {
            repository: repository.clone(),
        })? {
            WorkerControlResponse::RepositoryRecord { repository } => Ok(repository),
            other => Err(unexpected_worker_response("repository record", &other)),
        }
    }

    pub fn load_scan_settings(&self) -> Result<Option<ScanDefaultsSummary>> {
        match self.request(WorkerControlRequest::LoadScanSettings)? {
            WorkerControlResponse::OptionalScanSettings { settings } => Ok(settings),
            other => Err(unexpected_worker_response("optional scan settings", &other)),
        }
    }
}

fn decode_worker_response(response: reqwest::blocking::Response) -> Result<WorkerControlResponse> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        return Err(anyhow!(
            "control API request failed with status {}{}",
            status.as_u16(),
            if body.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", body.trim())
            }
        ));
    }
    response
        .json::<WorkerControlResponse>()
        .context("failed to decode control API response")
}

fn unexpected_worker_response(expected: &str, response: &WorkerControlResponse) -> anyhow::Error {
    anyhow!(
        "unexpected control API response; expected {expected}, got {:?}",
        response
    )
}

fn resolve_worker_api_base_url(config: &AppConfig) -> Result<String> {
    if let Some(value) = first_nonempty_env(CONTROL_URL_ENV_NAMES) {
        return normalize_worker_api_base_url(&value);
    }

    if let Some(value) = config.public.base_url.as_deref() {
        return normalize_worker_api_base_url(value);
    }

    let bind_addr: SocketAddr = config
        .server
        .bind_addr
        .parse()
        .with_context(|| format!("invalid control bind addr {}", config.server.bind_addr))?;
    let host = match bind_addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    normalize_worker_api_base_url(&format!("http://{host}:{}", bind_addr.port()))
}

fn normalize_worker_api_base_url(value: &str) -> Result<String> {
    let mut url = url::Url::parse(value)
        .with_context(|| format!("invalid worker management URL {value}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(anyhow!("worker management URL must use http or https"));
    }
    url.set_path("");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn build_worker_api_client(config: &AppConfig, base_url: &str) -> Result<Client> {
    let mut builder =
        Client::builder().timeout(Duration::from_secs(config.scan.request_timeout_secs.max(5)));
    if let Some(proxy_url) = resolve_worker_api_proxy_url(base_url)? {
        let proxy = Proxy::all(&proxy_url)
            .with_context(|| format!("invalid CONTROL_PROXY_URL {proxy_url}"))?;
        builder = builder.proxy(proxy);
    }
    builder.build().context("failed to build worker API client")
}

fn resolve_worker_api_proxy_url(base_url: &str) -> Result<Option<String>> {
    if let Some(value) = first_nonempty_env(CONTROL_PROXY_URL_ENV_NAMES) {
        url::Url::parse(&value).with_context(|| format!("invalid CONTROL_PROXY_URL {value}"))?;
        return Ok(Some(value));
    }

    Ok(default_worker_api_proxy_url_for_base_url(base_url))
}

fn default_worker_api_proxy_url_for_base_url(base_url: &str) -> Option<String> {
    let url = url::Url::parse(base_url).ok()?;
    let host = url.host_str()?.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.ends_with(".onion") {
        Some(DEFAULT_TOR_SOCKS_PROXY_URL.to_string())
    } else {
        None
    }
}

fn resolve_worker_api_token(http: &Client, base_url: &str, worker_id: &str) -> Result<String> {
    let state_file = worker_state_env_file_path()?;

    if let Some(token) = first_nonempty_env(AGENT_TOKEN_ENV_NAMES) {
        persist_worker_state_env_token(state_file, &token)?;
        return Ok(token);
    }

    if let Some(token) = load_env_value_from_file(&state_file, "AGENT_TOKEN")? {
        return Ok(token);
    }

    let bootstrap_code = resolve_worker_bootstrap_code()?;
    let exchange = exchange_worker_bootstrap_code(http, base_url, &bootstrap_code, worker_id)?;
    persist_worker_state_env_token(state_file, &exchange.token.token)?;
    Ok(exchange.token.token)
}

fn resolve_worker_bootstrap_code() -> Result<String> {
    if let Some(code) = first_nonempty_env(AGENT_BOOTSTRAP_CODE_ENV_NAMES) {
        return Ok(code);
    }

    if let Some(obfuscated) = first_nonempty_env(AGENT_BOOTSTRAP_CODE_OBFUSCATED_ENV_NAMES) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(obfuscated)
            .context("failed to decode AGENT_BOOTSTRAP_CODE_OBFUSCATED")?;
        let decoded = String::from_utf8(bytes)
            .context("AGENT_BOOTSTRAP_CODE_OBFUSCATED is not valid UTF-8")?;
        let trimmed = decoded.trim().to_string();
        if trimmed.is_empty() {
            return Err(anyhow!("decoded worker bootstrap code is empty"));
        }
        return Ok(trimmed);
    }

    Err(anyhow!(
        "AGENT_TOKEN or AGENT_BOOTSTRAP_CODE is required"
    ))
}

fn exchange_worker_bootstrap_code(
    http: &Client,
    base_url: &str,
    code: &str,
    worker_id: &str,
) -> Result<WorkerBootstrapCodeExchange> {
    let url = format!("{base_url}/api/worker/bootstrap/exchange");
    let response = http
        .post(&url)
        .json(&WorkerBootstrapCodeExchangeRequest {
            code: code.to_string(),
            worker_id: worker_id.to_string(),
        })
        .send()
        .with_context(|| format!("failed to reach bootstrap exchange API at {url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        return Err(anyhow!(
            "bootstrap exchange failed with status {}{}",
            status.as_u16(),
            if body.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", body.trim())
            }
        ));
    }
    response
        .json::<WorkerBootstrapCodeExchange>()
        .context("failed to decode bootstrap exchange response")
}

fn worker_state_env_file_path() -> Result<PathBuf> {
    Ok(first_nonempty_env(AGENT_STATE_FILE_ENV_NAMES)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_AGENT_STATE_FILE_PATH)))
}

fn persist_worker_state_env_token(path: PathBuf, token: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create worker state directory {}", parent.display()))?;
    }
    write_env_value(&path, "AGENT_TOKEN", token)
}

fn load_env_value_from_file(path: &Path, key: &str) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }

    let needle = format!("{key}=");
    let value = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?
        .lines()
        .find_map(|line| {
            line.strip_prefix(&needle)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        });
    Ok(value)
}

fn write_env_value(path: &Path, key: &str, value: &str) -> Result<()> {
    let needle = format!("{key}=");
    let mut lines = if path.exists() {
        fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut updated = false;
    for line in &mut lines {
        if line.starts_with(&needle) {
            *line = format!("{needle}{value}");
            updated = true;
            break;
        }
    }
    if !updated {
        lines.push(format!("{needle}{value}"));
    }
    fs::write(path, format!("{}\n", lines.join("\n")))
        .with_context(|| format!("failed to write {}", path.display()))
}

fn first_nonempty_env(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        env::var(name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};

    use super::{default_worker_api_proxy_url_for_base_url, load_env_value_from_file};

    #[test]
    fn onion_worker_api_defaults_to_tor_socks_proxy() {
        assert_eq!(
            default_worker_api_proxy_url_for_base_url(
                "http://nbhhzmw5m2fwpss44aktrgxjzwxnw5fssfzl76fg6edfzf4c6sy4ihad.onion/"
            ),
            Some("socks5h://127.0.0.1:9050".to_string())
        );
    }

    #[test]
    fn clearnet_worker_api_does_not_force_proxy() {
        assert_eq!(
            default_worker_api_proxy_url_for_base_url("https://scan.anyvm.tech"),
            None
        );
    }

    #[test]
    fn load_env_value_from_file_reads_agent_token() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("anyscan-worker-api-{unique}.env"));
        fs::write(&path, "AGENT_TOKEN=test-token\n")
            .expect("temp env file should be written");

        let value =
            load_env_value_from_file(&path, "AGENT_TOKEN").expect("state file should load");
        assert_eq!(value, Some("test-token".to_string()));

        let _ = fs::remove_file(path);
    }
}
