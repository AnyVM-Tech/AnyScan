use crate::{
    archive::{ArchivePressureDecision, ArchivedObject, PreparedArchivePayload},
    config::AppConfig,
    core::{
        AbuseReportRecord, AbuseReportRequest, ActiveAuthorizedPluginExecution, ApiEvent,
        ArchiveJobRecord, ArchivePointerRecord, ArchiveRecordKind, ArchiveStatusSnapshot,
        BinDatasetImportRequest, BinDatasetStatus, BinMetadataRecord, DashboardSnapshot,
        DiscoveryProvenanceRecord, FetchTelemetry, FindingRecord, FindingsQuery, NewFinding,
        OptOutRecord, OptOutRequest, OwnershipClaimRecord, OwnershipClaimRequest,
        PortScanProtocolFindingRecord, PortScanRecord, PortScanRequest,
        PublicFindingModerationRecord, PublicFindingModerationRequest, PublicFindingRecord,
        PublicFindingSearchQuery, PublicWorkflowStatus, PublicWorkflowStatusUpdate,
        RecurringScheduleRecord, RepositoryDefinition, RepositoryRecord, RunScope, RunSummary,
        ScanDefaultsSummary, ScanJobRecord, ScanRunRecord, StoredEvent, TargetDefinition,
        TargetRecord, WorkerBootstrapCandidateApproval, WorkerBootstrapCandidateApprovalRequest,
        WorkerBootstrapCodeExchange, WorkerBootstrapCodeIssueRequest, WorkerBootstrapCodeIssued,
        WorkerBootstrapCandidateInput, WorkerBootstrapCandidateRecord,
        WorkerBootstrapCandidateRejectionRequest, WorkerBootstrapJobClaim,
        WorkerBootstrapJobRecord, WorkerEnrollmentTokenIssueRequest, WorkerEnrollmentTokenIssued,
        WorkerEnrollmentTokenRecord, WorkerLifecycleState, WorkerPoolRecord, WorkerRecord,
        WorkerRegistration, WorkerRemoteCommandRecord, WorkerRemoteCommandRequest,
    },
    dragonfly_store::DragonflyAnyScanStore,
};
use anyhow::Result;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct AnyScanStore {
    inner: DragonflyAnyScanStore,
}

impl AnyScanStore {
    pub fn from_config(config: &AppConfig) -> Result<Self> {
        Ok(Self {
            inner: DragonflyAnyScanStore::from_config(config)?,
        })
    }

    pub fn initialize(&self) -> Result<()> {
        self.inner.initialize()
    }

    pub fn upsert_target(&self, target: &TargetDefinition) -> Result<TargetRecord> {
        self.inner.upsert_target(target)
    }

    pub fn list_targets(&self) -> Result<Vec<TargetRecord>> {
        self.inner.list_targets()
    }

    pub fn list_enabled_targets(&self) -> Result<Vec<TargetRecord>> {
        self.inner.list_enabled_targets()
    }

    pub fn upsert_repository(&self, repository: &RepositoryDefinition) -> Result<RepositoryRecord> {
        self.inner.upsert_repository(repository)
    }

    pub fn list_repositories(&self) -> Result<Vec<RepositoryRecord>> {
        self.inner.list_repositories()
    }

    pub fn get_repository(&self, repository_id: i64) -> Result<Option<RepositoryRecord>> {
        self.inner.get_repository(repository_id)
    }

    pub fn import_bin_dataset(
        &self,
        request: &BinDatasetImportRequest,
    ) -> Result<BinDatasetStatus> {
        self.inner.import_bin_dataset(request)
    }

    pub fn load_bin_dataset_status(&self) -> Result<Option<BinDatasetStatus>> {
        self.inner.load_bin_dataset_status()
    }

    pub fn lookup_bin_metadata(&self, bins: &[String]) -> Result<Vec<BinMetadataRecord>> {
        self.inner.lookup_bin_metadata(bins)
    }

    pub fn queue_port_scan(
        &self,
        requested_by: Option<&str>,
        request: &PortScanRequest,
    ) -> Result<PortScanRecord> {
        self.inner.queue_port_scan(requested_by, request)
    }

    pub fn queue_port_scan_with_active_authorized_plugins(
        &self,
        requested_by: Option<&str>,
        request: &PortScanRequest,
        active_authorized_plugins: &ActiveAuthorizedPluginExecution,
    ) -> Result<PortScanRecord> {
        self.inner.queue_port_scan_with_active_authorized_plugins(
            requested_by,
            request,
            active_authorized_plugins,
        )
    }

    pub fn list_port_scans(&self, limit: usize) -> Result<Vec<PortScanRecord>> {
        self.inner.list_port_scans(limit)
    }

    pub fn register_worker(
        &self,
        registration: &WorkerRegistration,
        ttl_seconds: u64,
    ) -> Result<WorkerRecord> {
        self.inner.register_worker(registration, ttl_seconds)
    }

    pub fn authenticate_worker_registration_token(
        &self,
        worker_id: &str,
        token: &str,
    ) -> Result<()> {
        self.inner
            .authenticate_worker_registration_token(worker_id, token)
    }

    pub fn authenticate_registered_worker_token(
        &self,
        worker_id: &str,
        token: &str,
    ) -> Result<()> {
        self.inner
            .authenticate_registered_worker_token(worker_id, token)
    }

    pub fn list_workers(&self) -> Result<Vec<WorkerRecord>> {
        self.inner.list_workers()
    }

    pub fn get_worker(&self, worker_id: &str) -> Result<Option<WorkerRecord>> {
        self.inner.get_worker(worker_id)
    }

    pub fn list_worker_pools(&self) -> Result<Vec<WorkerPoolRecord>> {
        self.inner.list_worker_pools()
    }

    pub fn update_worker_lifecycle_state(
        &self,
        worker_id: &str,
        lifecycle_state: WorkerLifecycleState,
    ) -> Result<WorkerRecord> {
        self.inner
            .update_worker_lifecycle_state(worker_id, lifecycle_state)
    }

    pub fn request_worker_remote_update(&self, worker_id: &str) -> Result<WorkerRecord> {
        self.inner.request_worker_remote_update(worker_id)
    }

    pub fn request_all_worker_remote_updates(&self) -> Result<Vec<WorkerRecord>> {
        self.inner.request_all_worker_remote_updates()
    }

    pub fn acknowledge_worker_remote_update(
        &self,
        worker_id: &str,
        requested_at: DateTime<Utc>,
    ) -> Result<WorkerRecord> {
        self.inner
            .acknowledge_worker_remote_update(worker_id, requested_at)
    }

    pub fn list_worker_remote_commands(
        &self,
        limit: usize,
        worker_id: Option<&str>,
    ) -> Result<Vec<WorkerRemoteCommandRecord>> {
        self.inner.list_worker_remote_commands(limit, worker_id)
    }

    pub fn queue_worker_remote_command(
        &self,
        worker_id: &str,
        requested_by: Option<&str>,
        request: &WorkerRemoteCommandRequest,
    ) -> Result<WorkerRemoteCommandRecord> {
        self.inner
            .queue_worker_remote_command(worker_id, requested_by, request)
    }

    pub fn claim_next_pending_worker_remote_command(
        &self,
        worker_id: &str,
    ) -> Result<Option<WorkerRemoteCommandRecord>> {
        self.inner.claim_next_pending_worker_remote_command(worker_id)
    }

    pub fn complete_worker_remote_command_if_owned(
        &self,
        command_id: i64,
        worker_id: &str,
        exit_code: Option<i32>,
        timed_out: bool,
        stdout: Option<&str>,
        stderr: Option<&str>,
        error: Option<&str>,
    ) -> Result<Option<WorkerRemoteCommandRecord>> {
        self.inner.complete_worker_remote_command_if_owned(
            command_id,
            worker_id,
            exit_code,
            timed_out,
            stdout,
            stderr,
            error,
        )
    }

    pub fn list_worker_enrollment_tokens(&self) -> Result<Vec<WorkerEnrollmentTokenRecord>> {
        self.inner.list_worker_enrollment_tokens()
    }

    pub fn issue_worker_enrollment_token(
        &self,
        created_by: Option<&str>,
        request: &WorkerEnrollmentTokenIssueRequest,
    ) -> Result<WorkerEnrollmentTokenIssued> {
        self.inner
            .issue_worker_enrollment_token(created_by, request)
    }

    pub fn revoke_worker_enrollment_token(
        &self,
        token_id: i64,
    ) -> Result<WorkerEnrollmentTokenRecord> {
        self.inner.revoke_worker_enrollment_token(token_id)
    }

    pub fn issue_worker_bootstrap_code(
        &self,
        created_by: Option<&str>,
        request: &WorkerBootstrapCodeIssueRequest,
    ) -> Result<WorkerBootstrapCodeIssued> {
        self.inner.issue_worker_bootstrap_code(created_by, request)
    }

    pub fn exchange_worker_bootstrap_code(
        &self,
        code: &str,
        worker_id: &str,
    ) -> Result<WorkerBootstrapCodeExchange> {
        self.inner.exchange_worker_bootstrap_code(code, worker_id)
    }

    pub fn list_bootstrap_candidates(&self) -> Result<Vec<WorkerBootstrapCandidateRecord>> {
        self.inner.list_bootstrap_candidates()
    }

    pub fn list_bootstrap_jobs(&self) -> Result<Vec<WorkerBootstrapJobRecord>> {
        self.inner.list_bootstrap_jobs()
    }

    pub fn create_bootstrap_candidates(
        &self,
        port_scan: &PortScanRecord,
        candidates: &[WorkerBootstrapCandidateInput],
    ) -> Result<Vec<WorkerBootstrapCandidateRecord>> {
        self.inner
            .create_bootstrap_candidates(port_scan, candidates)
    }

    pub fn approve_bootstrap_candidate(
        &self,
        candidate_id: i64,
        approved_by: Option<&str>,
        request: &WorkerBootstrapCandidateApprovalRequest,
    ) -> Result<WorkerBootstrapCandidateApproval> {
        self.inner
            .approve_bootstrap_candidate(candidate_id, approved_by, request)
    }

    pub fn reject_bootstrap_candidate(
        &self,
        candidate_id: i64,
        request: &WorkerBootstrapCandidateRejectionRequest,
    ) -> Result<WorkerBootstrapCandidateRecord> {
        self.inner.reject_bootstrap_candidate(candidate_id, request)
    }

    pub fn claim_next_pending_bootstrap_job(
        &self,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<Option<WorkerBootstrapJobClaim>> {
        self.inner
            .claim_next_pending_bootstrap_job(worker_id, lease_seconds)
    }

    pub fn renew_bootstrap_job_claim(
        &self,
        job_id: i64,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<()> {
        self.inner
            .renew_bootstrap_job_claim(job_id, worker_id, lease_seconds)
    }

    pub fn mark_bootstrap_job_started_if_owned(
        &self,
        job_id: i64,
        worker_id: &str,
    ) -> Result<Option<WorkerBootstrapJobRecord>> {
        self.inner
            .mark_bootstrap_job_started_if_owned(job_id, worker_id)
    }

    pub fn complete_bootstrap_job_if_owned(
        &self,
        job_id: i64,
        worker_id: &str,
        notes: Option<&str>,
    ) -> Result<Option<WorkerBootstrapJobRecord>> {
        self.inner
            .complete_bootstrap_job_if_owned(job_id, worker_id, notes)
    }

    pub fn fail_bootstrap_job_if_owned(
        &self,
        job_id: i64,
        worker_id: &str,
        notes: Option<&str>,
    ) -> Result<Option<WorkerBootstrapJobRecord>> {
        self.inner
            .fail_bootstrap_job_if_owned(job_id, worker_id, notes)
    }

    pub fn claim_next_pending_port_scan(
        &self,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<Option<PortScanRecord>> {
        self.inner
            .claim_next_pending_port_scan(worker_id, lease_seconds)
    }

    pub fn renew_port_scan_claim(
        &self,
        port_scan_id: i64,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<()> {
        self.inner
            .renew_port_scan_claim(port_scan_id, worker_id, lease_seconds)
    }

    pub fn mark_port_scan_started_if_queued(
        &self,
        port_scan_id: i64,
    ) -> Result<Option<PortScanRecord>> {
        self.inner.mark_port_scan_started_if_queued(port_scan_id)
    }

    pub fn complete_port_scan_if_owned(
        &self,
        port_scan_id: i64,
        worker_id: &str,
        discovered_endpoints_total: u64,
        imported_targets_total: u64,
        protocol_findings: &[PortScanProtocolFindingRecord],
        queued_run_id: Option<i64>,
        notes: Option<&str>,
    ) -> Result<Option<PortScanRecord>> {
        self.inner.complete_port_scan_if_owned(
            port_scan_id,
            worker_id,
            discovered_endpoints_total,
            imported_targets_total,
            protocol_findings,
            queued_run_id,
            notes,
        )
    }

    pub fn fail_port_scan_if_owned(
        &self,
        port_scan_id: i64,
        worker_id: &str,
        notes: Option<&str>,
    ) -> Result<Option<PortScanRecord>> {
        self.inner
            .fail_port_scan_if_owned(port_scan_id, worker_id, notes)
    }

    pub fn upsert_schedule(
        &self,
        label: &str,
        interval_seconds: u64,
        enabled: bool,
        requested_by: Option<&str>,
        scope: Option<&RunScope>,
    ) -> Result<RecurringScheduleRecord> {
        self.inner
            .upsert_schedule(label, interval_seconds, enabled, requested_by, scope)
    }

    pub fn upsert_schedule_with_active_authorized_plugins(
        &self,
        label: &str,
        interval_seconds: u64,
        enabled: bool,
        requested_by: Option<&str>,
        scope: Option<&RunScope>,
        active_authorized_plugins: &ActiveAuthorizedPluginExecution,
    ) -> Result<RecurringScheduleRecord> {
        self.inner.upsert_schedule_with_active_authorized_plugins(
            label,
            interval_seconds,
            enabled,
            requested_by,
            scope,
            active_authorized_plugins,
        )
    }

    pub fn list_schedules(&self) -> Result<Vec<RecurringScheduleRecord>> {
        self.inner.list_schedules()
    }

    pub fn queue_due_schedule_runs(
        &self,
        limit: usize,
    ) -> Result<Vec<(RecurringScheduleRecord, ScanRunRecord)>> {
        self.inner.queue_due_schedule_runs(limit)
    }

    pub fn queue_run(
        &self,
        requested_by: Option<&str>,
        scope: Option<&RunScope>,
    ) -> Result<ScanRunRecord> {
        self.inner.queue_run(requested_by, scope)
    }

    pub fn queue_run_with_active_authorized_plugins(
        &self,
        requested_by: Option<&str>,
        scope: Option<&RunScope>,
        active_authorized_plugins: &ActiveAuthorizedPluginExecution,
    ) -> Result<ScanRunRecord> {
        self.inner.queue_run_with_active_authorized_plugins(
            requested_by,
            scope,
            active_authorized_plugins,
        )
    }

    pub fn claim_next_runnable_run(
        &self,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<Option<ScanRunRecord>> {
        self.inner.claim_next_runnable_run(worker_id, lease_seconds)
    }

    pub fn next_assistable_run(&self, worker_id: &str) -> Result<Option<ScanRunRecord>> {
        self.inner.next_assistable_run(worker_id)
    }

    pub fn next_runnable_run(&self) -> Result<Option<ScanRunRecord>> {
        self.inner.next_runnable_run()
    }

    pub fn renew_run_claim(&self, run_id: i64, worker_id: &str, lease_seconds: u64) -> Result<()> {
        self.inner.renew_run_claim(run_id, worker_id, lease_seconds)
    }

    pub fn requeue_in_progress_jobs(&self, run_id: i64) -> Result<()> {
        self.inner.requeue_in_progress_jobs(run_id)
    }

    pub fn has_incomplete_jobs(&self, run_id: i64) -> Result<bool> {
        self.inner.has_incomplete_jobs(run_id)
    }

    pub fn mark_run_started(&self, run_id: i64) -> Result<ScanRunRecord> {
        self.inner.mark_run_started(run_id)
    }

    pub fn mark_run_started_if_queued(&self, run_id: i64) -> Result<Option<ScanRunRecord>> {
        self.inner.mark_run_started_if_queued(run_id)
    }

    pub fn mark_job_started(&self, job_id: i64) -> Result<()> {
        self.inner.mark_job_started(job_id)
    }

    pub fn claim_next_pending_job(
        &self,
        run_id: i64,
        worker_id: &str,
        lease_seconds: u64,
    ) -> Result<Option<ScanJobRecord>> {
        self.inner
            .claim_next_pending_job(run_id, worker_id, lease_seconds)
    }

    pub fn renew_job_claim(&self, job_id: i64, worker_id: &str, lease_seconds: u64) -> Result<()> {
        self.inner.renew_job_claim(job_id, worker_id, lease_seconds)
    }

    pub fn mark_job_finished(
        &self,
        job_id: i64,
        findings_count: u64,
        telemetry: &FetchTelemetry,
        error: Option<&str>,
    ) -> Result<()> {
        self.inner
            .mark_job_finished(job_id, findings_count, telemetry, error)
    }

    pub fn mark_job_finished_if_owned(
        &self,
        job_id: i64,
        worker_id: &str,
        findings_count: u64,
        telemetry: &FetchTelemetry,
        error: Option<&str>,
    ) -> Result<bool> {
        self.inner
            .mark_job_finished_if_owned(job_id, worker_id, findings_count, telemetry, error)
    }

    pub fn merge_target_discovery_provenance(
        &self,
        target_id: i64,
        discovery_provenance: &[DiscoveryProvenanceRecord],
    ) -> Result<()> {
        self.inner
            .merge_target_discovery_provenance(target_id, discovery_provenance)
    }

    pub fn list_pending_jobs(&self, run_id: i64) -> Result<Vec<ScanJobRecord>> {
        self.inner.list_pending_jobs(run_id)
    }

    pub fn record_finding(&self, finding: &NewFinding) -> Result<FindingRecord> {
        self.inner.record_finding(finding)
    }

    pub fn record_finding_if_new(&self, finding: &NewFinding) -> Result<Option<FindingRecord>> {
        self.inner.record_finding_if_new(finding)
    }

    pub fn recent_findings(&self, limit: usize) -> Result<Vec<FindingRecord>> {
        self.inner.recent_findings(limit)
    }

    pub fn search_findings(&self, query: &FindingsQuery) -> Result<Vec<FindingRecord>> {
        self.inner.search_findings(query)
    }

    pub fn search_public_findings(
        &self,
        query: &PublicFindingSearchQuery,
    ) -> Result<Vec<PublicFindingRecord>> {
        self.inner.search_public_findings(query)
    }

    pub fn list_public_finding_moderation_records(
        &self,
    ) -> Result<Vec<PublicFindingModerationRecord>> {
        self.inner.list_public_finding_moderation_records()
    }

    pub fn moderate_public_finding(
        &self,
        finding_id: i64,
        reviewed_by: Option<&str>,
        request: &PublicFindingModerationRequest,
    ) -> Result<PublicFindingModerationRecord> {
        self.inner
            .moderate_public_finding(finding_id, reviewed_by, request)
    }

    pub fn list_runs(&self, limit: usize) -> Result<Vec<ScanRunRecord>> {
        self.inner.list_runs(limit)
    }

    pub fn latest_run(&self) -> Result<Option<ScanRunRecord>> {
        self.inner.latest_run()
    }

    pub fn get_run(&self, run_id: i64) -> Result<Option<ScanRunRecord>> {
        self.inner.get_run(run_id)
    }

    pub fn summary(&self, run_id: i64) -> Result<RunSummary> {
        self.inner.summary(run_id)
    }

    pub fn mark_run_finished(&self, run_id: i64, notes: Option<&str>) -> Result<ScanRunRecord> {
        self.inner.mark_run_finished(run_id, notes)
    }

    pub fn mark_run_finished_if_owned(
        &self,
        run_id: i64,
        worker_id: &str,
        notes: Option<&str>,
    ) -> Result<Option<ScanRunRecord>> {
        self.inner
            .mark_run_finished_if_owned(run_id, worker_id, notes)
    }

    pub fn append_event(&self, run_id: Option<i64>, event: &ApiEvent) -> Result<i64> {
        self.inner.append_event(run_id, event)
    }

    pub fn list_events_since(&self, cursor: i64, limit: usize) -> Result<Vec<StoredEvent>> {
        self.inner.list_events_since(cursor, limit)
    }

    pub fn dashboard_snapshot(&self) -> Result<DashboardSnapshot> {
        self.inner.dashboard_snapshot()
    }

    pub fn archive_due(&self, cadence_seconds: u64, now: DateTime<Utc>) -> Result<bool> {
        self.inner.archive_due(cadence_seconds, now)
    }

    pub fn used_memory_bytes(&self) -> Result<u64> {
        self.inner.used_memory_bytes()
    }

    pub fn namespace_storage_estimate_bytes(&self) -> Result<u64> {
        self.inner.namespace_storage_estimate_bytes()
    }

    pub fn archive_status(&self, config: &AppConfig) -> Result<ArchiveStatusSnapshot> {
        self.inner.archive_status(config)
    }

    pub fn list_archive_jobs(&self, limit: usize) -> Result<Vec<ArchiveJobRecord>> {
        self.inner.list_archive_jobs(limit)
    }

    pub fn list_archive_pointers(
        &self,
        limit: usize,
        kind: Option<ArchiveRecordKind>,
    ) -> Result<Vec<ArchivePointerRecord>> {
        self.inner.list_archive_pointers(limit, kind)
    }

    pub fn get_archive_pointer(&self, pointer_id: i64) -> Result<Option<ArchivePointerRecord>> {
        self.inner.get_archive_pointer(pointer_id)
    }

    pub fn begin_archive_job(
        &self,
        decision: &ArchivePressureDecision,
        now: DateTime<Utc>,
    ) -> Result<ArchiveJobRecord> {
        self.inner.begin_archive_job(decision, now)
    }

    pub fn complete_archive_job(
        &self,
        job_id: i64,
        archived_counts: &std::collections::BTreeMap<ArchiveRecordKind, usize>,
        archived_object_count: usize,
        now: DateTime<Utc>,
    ) -> Result<ArchiveJobRecord> {
        self.inner
            .complete_archive_job(job_id, archived_counts, archived_object_count, now)
    }

    pub fn fail_archive_job(
        &self,
        job_id: i64,
        archived_counts: &std::collections::BTreeMap<ArchiveRecordKind, usize>,
        archived_object_count: usize,
        error: &str,
        now: DateTime<Utc>,
    ) -> Result<ArchiveJobRecord> {
        self.inner
            .fail_archive_job(job_id, archived_counts, archived_object_count, error, now)
    }

    pub fn plan_archive_payloads(
        &self,
        hot_retention_days: u64,
        max_records_per_batch: usize,
        bootstrap_artifact_dir: Option<&std::path::Path>,
    ) -> Result<Vec<PreparedArchivePayload>> {
        self.inner.plan_archive_payloads(
            hot_retention_days,
            max_records_per_batch,
            bootstrap_artifact_dir,
        )
    }

    pub fn record_archived_payload(
        &self,
        payload: &PreparedArchivePayload,
        archived: &ArchivedObject,
    ) -> Result<ArchivePointerRecord> {
        self.inner.record_archived_payload(payload, archived)
    }

    pub fn hydrate_archive_records(
        &self,
        kind: ArchiveRecordKind,
        records: &[serde_json::Value],
    ) -> Result<usize> {
        self.inner.hydrate_archive_records(kind, records)
    }

    pub fn try_acquire_archive_lease(&self, token: &str, ttl_ms: u64) -> Result<bool> {
        self.inner.try_acquire_archive_lease(token, ttl_ms)
    }

    pub fn release_archive_lease(&self, token: &str) -> Result<()> {
        self.inner.release_archive_lease(token)
    }

    pub fn load_scan_settings(&self) -> Result<Option<ScanDefaultsSummary>> {
        self.inner.load_scan_settings()
    }

    pub fn upsert_scan_settings(
        &self,
        settings: &ScanDefaultsSummary,
    ) -> Result<ScanDefaultsSummary> {
        self.inner.upsert_scan_settings(settings)
    }

    pub fn create_ownership_claim(
        &self,
        request: &OwnershipClaimRequest,
    ) -> Result<OwnershipClaimRecord> {
        self.inner.create_ownership_claim(request)
    }

    pub fn list_ownership_claims(&self) -> Result<Vec<OwnershipClaimRecord>> {
        self.inner.list_ownership_claims()
    }

    pub fn update_ownership_claim_status(
        &self,
        claim_id: i64,
        update: &PublicWorkflowStatusUpdate,
    ) -> Result<OwnershipClaimRecord> {
        self.inner.update_ownership_claim_status(claim_id, update)
    }

    pub fn apply_ownership_claim_verification(
        &self,
        claim_id: i64,
        status: PublicWorkflowStatus,
        verification_summary: Option<&str>,
        verification_attempted_at: Option<DateTime<Utc>>,
        verification_completed_at: Option<DateTime<Utc>>,
    ) -> Result<OwnershipClaimRecord> {
        self.inner.apply_ownership_claim_verification(
            claim_id,
            status,
            verification_summary,
            verification_attempted_at,
            verification_completed_at,
        )
    }

    pub fn create_opt_out_request(&self, request: &OptOutRequest) -> Result<OptOutRecord> {
        self.inner.create_opt_out_request(request)
    }

    pub fn list_opt_out_requests(&self) -> Result<Vec<OptOutRecord>> {
        self.inner.list_opt_out_requests()
    }

    pub fn update_opt_out_status(
        &self,
        opt_out_id: i64,
        update: &PublicWorkflowStatusUpdate,
    ) -> Result<OptOutRecord> {
        self.inner.update_opt_out_status(opt_out_id, update)
    }

    pub fn apply_opt_out_verification(
        &self,
        opt_out_id: i64,
        status: PublicWorkflowStatus,
        verification_summary: Option<&str>,
        verification_attempted_at: Option<DateTime<Utc>>,
        verification_completed_at: Option<DateTime<Utc>>,
    ) -> Result<OptOutRecord> {
        self.inner.apply_opt_out_verification(
            opt_out_id,
            status,
            verification_summary,
            verification_attempted_at,
            verification_completed_at,
        )
    }

    pub fn create_abuse_report(&self, request: &AbuseReportRequest) -> Result<AbuseReportRecord> {
        self.inner.create_abuse_report(request)
    }

    pub fn list_abuse_reports(&self) -> Result<Vec<AbuseReportRecord>> {
        self.inner.list_abuse_reports()
    }

    pub fn update_abuse_report_status(
        &self,
        report_id: i64,
        update: &PublicWorkflowStatusUpdate,
    ) -> Result<AbuseReportRecord> {
        self.inner.update_abuse_report_status(report_id, update)
    }
}
