			// Skip a renderer when its target DOM is missing on the current
			// page. Each operator page renders only its own section's ids; the
			// shared dashboard refresh fans out to every renderer regardless,
			// so renderers that touch other sections' ids would otherwise
			// throw on null and abort the rest of the refresh.
			function safeRender(label, fn) {
				try {
					fn();
				} catch (error) {
					if (error instanceof TypeError) {
						return;
					}
					console.error('renderer failed', label, error);
				}
			}

			async function safeAsync(label, fn) {
				try {
					await fn();
				} catch (error) {
					if (error instanceof TypeError) {
						return;
					}
					console.error('async loader failed', label, error);
				}
			}

			const state = {
				eventSource: null,
				refreshTimer: null,
				liveDashboardTimer: null,
				reconnectTimer: null,
				dashboardLoading: false,
				dashboardSnapshot: null,
				findingsQuery: null,
				visibleFindings: [],
				pluginCatalog: null,
				pluginCatalogQuery: null,
				findingPublications: [],
				runWorkerPoolFilter: '',
				workerPoolFilter: '',
				workerHealthFilter: 'all',
				authenticated: false,
				session: null
			};

			const elements = {
				app: document.getElementById('app'),
				archiveMetrics: document.getElementById('archive-metrics'),
				archiveNote: document.getElementById('archive-note'),
				authCard: document.getElementById('auth-card'),
				authError: document.getElementById('auth-error'),
				bootstrapApprovalAccessNote: document.getElementById(
					'bootstrap-approval-access-note'
				),
				bootstrapApprovalError: document.getElementById(
					'bootstrap-approval-error'
				),
				bootstrapApprovalForm: document.getElementById(
					'bootstrap-approval-form'
				),
				bootstrapApprovalReadonlyNote: document.getElementById(
					'bootstrap-approval-readonly-note'
				),
				bootstrapApproveButton: document.getElementById(
					'bootstrap-approve-button'
				),
				bootstrapCandidateId: document.getElementById(
					'bootstrap-candidate-id'
				),
				bootstrapCandidatesEmpty: document.getElementById(
					'bootstrap-candidates-empty'
				),
				bootstrapCandidatesList: document.getElementById(
					'bootstrap-candidates-list'
				),
				bootstrapDispatchEnabled: document.getElementById(
					'bootstrap-dispatch-enabled'
				),
				bootstrapDispatchExecutorPool: document.getElementById(
					'bootstrap-dispatch-executor-pool'
				),
				bootstrapDispatchExecutorTags: document.getElementById(
					'bootstrap-dispatch-executor-tags'
				),
				bootstrapDispatchFields: document.getElementById(
					'bootstrap-dispatch-fields'
				),
				bootstrapDispatchNotes: document.getElementById(
					'bootstrap-dispatch-notes'
				),
				bootstrapDispatchProvisioner: document.getElementById(
					'bootstrap-dispatch-provisioner'
				),
				bootstrapJobsEmpty: document.getElementById(
					'bootstrap-jobs-empty'
				),
				bootstrapJobsList: document.getElementById(
					'bootstrap-jobs-list'
				),
				bootstrapProvisionerOptions: document.getElementById(
					'bootstrap-provisioner-options'
				),
				bootstrapRejectButton: document.getElementById(
					'bootstrap-reject-button'
				),
				bootstrapTokenSecretPanel: document.getElementById(
					'bootstrap-token-secret-panel'
				),
				bootstrapTokenSecretTitle: document.getElementById(
					'bootstrap-token-secret-title'
				),
				bootstrapTokenSecretValue: document.getElementById(
					'bootstrap-token-secret-value'
				),
				binDatasetImportError: document.getElementById(
					'bin-dataset-import-error'
				),
				binDatasetImportForm: document.getElementById(
					'bin-dataset-import-form'
				),
				binDatasetStatusEmpty: document.getElementById(
					'bin-dataset-status-empty'
				),
				binDatasetStatusList: document.getElementById(
					'bin-dataset-status-list'
				),
				binLookupError: document.getElementById('bin-lookup-error'),
				binLookupForm: document.getElementById('bin-lookup-form'),
				binLookupResults: document.getElementById('bin-lookup-results'),
				binLookupResultsEmpty: document.getElementById(
					'bin-lookup-results-empty'
				),
				connectionState: document.getElementById('connection-state'),
				coverageSourcesEmpty: document.getElementById(
					'coverage-sources-empty'
				),
				coverageSourcesList: document.getElementById(
					'coverage-sources-list'
				),
				detectorDistributionEmpty: document.getElementById(
					'detector-distribution-empty'
				),
				detectorDistributionList: document.getElementById(
					'detector-distribution-list'
				),
				eventsEmpty: document.getElementById('events-empty'),
				eventsList: document.getElementById('events-list'),
				failedTargetsEmpty: document.getElementById(
					'failed-targets-empty'
				),
				failedTargetsList: document.getElementById(
					'failed-targets-list'
				),
				findingsEmpty: document.getElementById('findings-empty'),
				findingsList: document.getElementById('findings-list'),
				findingsPublicationAccessNote: document.getElementById(
					'findings-publication-access-note'
				),
					publicationRecordsEmpty: document.getElementById(
						'publication-records-empty'
					),
					publicationRecordsList: document.getElementById(
						'publication-records-list'
					),
					publicationRecordsNote: document.getElementById(
						'publication-records-note'
					),

				gobusterDefaultsNote: document.getElementById(
					'gobuster-defaults-note'
				),
				gobusterDefaultsPills: document.getElementById(
					'gobuster-defaults-pills'
				),
				findingsQueryError: document.getElementById(
					'findings-search-error'
				),
				findingsQueryForm: document.getElementById(
					'findings-search-form'
				),
				findingsQueryResetButton: document.getElementById(
					'findings-reset-button'
				),
				findingsQueryStatus: document.getElementById(
					'findings-search-status'
				),
				pluginCatalogGateNote: document.getElementById(
					'plugin-catalog-gate-note'
				),
				pluginCatalogEmpty: document.getElementById(
					'plugin-catalog-empty'
				),
				pluginCatalogList: document.getElementById(
					'plugin-catalog-list'
				),
				pluginCatalogNote: document.getElementById(
					'plugin-catalog-note'
				),
				pluginQueryError: document.getElementById(
					'plugins-search-error'
				),
				pluginQueryForm: document.getElementById('plugins-search-form'),
				pluginQueryResetButton: document.getElementById(
					'plugins-reset-button'
				),
				pluginQueryStatus: document.getElementById(
					'plugins-search-status'
				),
				loginForm: document.getElementById('login-form'),
				logoutButton: document.getElementById('logout-button'),
				portScanBootstrapEnabled: document.getElementById(
					'port-scan-bootstrap-enabled'
				),
				portScanBootstrapFields: document.getElementById(
					'port-scan-bootstrap-fields'
				),
				portScanFollowOnEnabled: document.getElementById(
					'port-scan-follow-on-enabled'
				),
				portScanFollowOnFields: document.getElementById(
					'port-scan-follow-on-fields'
				),
				portScanError: document.getElementById('port-scan-error'),
				portScanForm: document.getElementById('port-scan-form'),
				portScanActiveAuthorizedGate: document.getElementById(
					'port-scan-active-authorized-gate'
				),
				portScanActiveAuthorizedNote: document.getElementById(
					'port-scan-active-authorized-note'
				),
				portScansEmpty: document.getElementById('port-scans-empty'),
				portScansList: document.getElementById('port-scans-list'),
				queueButton: document.getElementById('queue-button'),
				refreshButton: document.getElementById('refresh-button'),
				repositoriesEmpty:
					document.getElementById('repositories-empty'),
				repositoriesList: document.getElementById('repositories-list'),
				runError: document.getElementById('run-error'),
				runForm: document.getElementById('run-form'),
				runActiveAuthorizedGate: document.getElementById(
					'run-active-authorized-gate'
				),
				runActiveAuthorizedNote: document.getElementById(
					'run-active-authorized-note'
				),
				runsWorkerPoolFilter: document.getElementById(
					'runs-worker-pool-filter'
				),
				runsEmpty: document.getElementById('runs-empty'),
				runsList: document.getElementById('runs-list'),
				scanSettingsError: document.getElementById(
					'scan-settings-error'
				),
				scanSettingsForm: document.getElementById('scan-settings-form'),
				scheduleError: document.getElementById('schedule-error'),
				scheduleForm: document.getElementById('schedule-form'),
				scheduleActiveAuthorizedGate: document.getElementById(
					'schedule-active-authorized-gate'
				),
				scheduleActiveAuthorizedNote: document.getElementById(
					'schedule-active-authorized-note'
				),
				schedulesEmpty: document.getElementById('schedules-empty'),
				schedulesList: document.getElementById('schedules-list'),
				sessionUser: document.getElementById('session-user'),
				summaryMetrics: document.getElementById('summary-metrics'),
				targetError: document.getElementById('target-error'),
				targetForm: document.getElementById('target-form'),
				targetsBody: document.getElementById('targets-body'),
				targetsEmpty: document.getElementById('targets-empty'),
				timingMetrics: document.getElementById('timing-metrics'),
				workerFleetNote: document.getElementById('worker-fleet-note'),
				workerMetrics: document.getElementById('worker-metrics'),
				workerPoolsEmpty: document.getElementById('worker-pools-empty'),
				workerPoolsList: document.getElementById('worker-pools-list'),
				workerTokenAccessNote: document.getElementById(
					'worker-token-access-note'
				),
				workerTokenError: document.getElementById('worker-token-error'),
				workerTokenForm: document.getElementById('worker-token-form'),
				workerTokenReadonlyNote: document.getElementById(
					'worker-token-readonly-note'
				),
				workerTokensEmpty: document.getElementById(
					'worker-tokens-empty'
				),
				workerTokensList: document.getElementById('worker-tokens-list'),
				workerTokenSecretPanel: document.getElementById(
					'worker-token-secret-panel'
				),
				workerTokenSecretTitle: document.getElementById(
					'worker-token-secret-title'
				),
				workerTokenSecretValue: document.getElementById(
					'worker-token-secret-value'
				),
				workerRemoteCommandsEmpty: document.getElementById(
					'worker-remote-commands-empty'
				),
				workerRemoteCommandsList: document.getElementById(
					'worker-remote-commands-list'
				),
				workersRemoteUpdateAll: document.getElementById(
					'workers-remote-update-all'
				),
				workersHealthFilter: document.getElementById(
					'workers-health-filter'
				),
				workersWorkerPoolFilter: document.getElementById(
					'workers-worker-pool-filter'
				),
				workersEmpty: document.getElementById('workers-empty'),
				workersList: document.getElementById('workers-list')
			};

			async function request(path, options = {}) {
				const response = await fetch(path, {
					credentials: 'same-origin',
					headers: {
						'Content-Type': 'application/json',
						...(options.headers || {})
					},
					...options
				});

				if (response.status === 204) {
					return null;
				}

				const contentType = response.headers.get('content-type') || '';
				const payload = contentType.includes('application/json')
					? await response.json()
					: await response.text();

				if (!response.ok) {
					const message =
						typeof payload === 'string'
							? payload
							: payload.message || response.statusText;
					const error = new Error(message || 'Request failed');
					error.status = response.status;
					throw error;
				}

				return payload;
			}

			function setAuthenticated(session) {
				state.authenticated = true;
				state.session = session || null;
				if (elements.sessionUser) {
					elements.sessionUser.textContent = session
						? `Signed in as ${session.username} • ${formatHumanLabel(session.role, 'Unknown role')}`
						: 'Signed in';
				}
				if (elements.authCard) elements.authCard.classList.add('hidden');
				if (elements.app) elements.app.classList.remove('hidden');
				if (elements.authError) elements.authError.classList.add('hidden');
				applyWorkerManagementVisibility();
				syncActiveAuthorizedGateUi();
				startLiveDashboardRefresh();
			}

			function setUnauthenticated(message = '') {
				state.authenticated = false;
				state.dashboardSnapshot = null;
				state.findingsQuery = null;
				state.visibleFindings = [];
				state.pluginCatalog = null;
				state.pluginCatalogQuery = null;
				state.findingPublications = [];
				state.session = null;
				safeRender('findings (logout)', () => renderFindings([]));
				safeRender('pluginCatalog (logout)', () => renderPluginCatalog(null));
				safeRender('findingPublications (logout)', () => renderFindingPublications([]));
				safeRender('activeAuthorizedGateUi (logout)', syncActiveAuthorizedGateUi);
				closeEvents();
				stopLiveDashboardRefresh();
				if (elements.app) elements.app.classList.add('hidden');
				if (elements.authCard) elements.authCard.classList.remove('hidden');
				if (elements.authError) {
					if (message) {
						elements.authError.textContent = message;
						elements.authError.classList.remove('hidden');
					} else {
						elements.authError.classList.add('hidden');
					}
				}
				elements.findingsQueryForm?.reset();
				elements.findingsQueryError?.classList.add('hidden');
				if (elements.findingsQueryStatus) {
					elements.findingsQueryStatus.textContent =
						'Showing recent findings from the latest dashboard snapshot.';
				}
				elements.pluginQueryForm?.reset();
				elements.pluginQueryError?.classList.add('hidden');
				if (elements.pluginQueryStatus) {
					elements.pluginQueryStatus.textContent = 'Loading plugin catalog.';
				}
				if (elements.connectionState) {
					if (elements.connectionState) elements.connectionState.textContent =
						'Sign in to view dashboard data.';
				}
				elements.workerTokenForm?.reset();
				elements.bootstrapApprovalForm?.reset();
				elements.runForm?.reset();
				elements.scheduleForm?.reset();
				elements.portScanForm?.reset();
				resetWorkerTokenFormDefaults();
				resetBootstrapApprovalFormDefaults();
				resetPortScanFormDefaults();
				clearSecretPanel(
					elements.workerTokenSecretPanel,
					elements.workerTokenSecretTitle,
					'Enrollment token issued',
					elements.workerTokenSecretValue
				);
				clearSecretPanel(
					elements.bootstrapTokenSecretPanel,
					elements.bootstrapTokenSecretTitle,
					'Bootstrap enrollment token issued',
					elements.bootstrapTokenSecretValue
				);
				applyWorkerManagementVisibility();
			}

			function canManageWorkers() {
				return Boolean(state.session?.permissions?.manage_workers);
			}

			function canApproveBootstrapCandidates() {
				return Boolean(
					state.session?.permissions?.approve_bootstrap_candidates
				);
			}

			function canModeratePublicFindings() {
				return Boolean(
					state.session?.permissions?.moderate_public_findings
				);
			}

			function canViewPrivatePublicationNotes() {
				return canModeratePublicFindings();
			}

			function resetWorkerTokenFormDefaults() {
				document.getElementById('worker-token-allow-runs').checked =
					true;
				document.getElementById(
					'worker-token-allow-port-scans'
				).checked = true;
				document.getElementById(
					'worker-token-allow-bootstrap'
				).checked = false;
				document.getElementById('worker-token-single-use').checked =
					true;
			}

			function resetBootstrapApprovalFormDefaults() {
				document.getElementById('bootstrap-label').value = '';
				document.getElementById('bootstrap-pool').value = '';
				document.getElementById('bootstrap-tags').value = '';
				document.getElementById('bootstrap-expiry').value = '';
				document.getElementById('bootstrap-allow-runs').checked = true;
				document.getElementById('bootstrap-allow-port-scans').checked =
					true;
				document.getElementById('bootstrap-allow-bootstrap').checked =
					false;
				document.getElementById('bootstrap-single-use').checked = true;
				document.getElementById('bootstrap-notes').value = '';
				elements.bootstrapDispatchEnabled.checked = true;
				elements.bootstrapDispatchProvisioner.value =
					defaultBootstrapProvisionerName();
				elements.bootstrapDispatchExecutorPool.value = '';
				elements.bootstrapDispatchExecutorTags.value = '';
				elements.bootstrapDispatchNotes.value = '';
				syncBootstrapDispatchVisibility();
			}

			function syncPortScanBootstrapVisibility() {
				const enabled = Boolean(
					elements.portScanBootstrapEnabled?.checked
				);
				elements.portScanBootstrapFields?.classList.toggle(
					'hidden',
					!enabled
				);
				['port-scan-bootstrap-pool', 'port-scan-bootstrap-tags']
					.map(id => document.getElementById(id))
					.filter(Boolean)
					.forEach(element => {
						element.disabled = !enabled;
					});
			}

			function syncPortScanFollowOnVisibility() {
				const enabled = Boolean(
					elements.portScanFollowOnEnabled?.checked
				);
				elements.portScanFollowOnFields?.classList.toggle(
					'hidden',
					!enabled
				);
				['port-scan-follow-on-pool', 'port-scan-follow-on-selection-mode']
					.map(id => document.getElementById(id))
					.filter(Boolean)
					.forEach(element => {
						element.disabled = !enabled;
					});
			}

			function resetPortScanFormDefaults() {
				if (!elements.portScanForm) {
					return;
				}
				document.getElementById('port-scan-schemes').value = 'auto';
				document.getElementById('port-scan-rate-limit').value = '';
				document.getElementById('port-scan-sender-threads').value = '';
				document.getElementById('port-scan-receiver-threads').value = '';
				document.getElementById('port-scan-worker-pool').value = '';
				document.getElementById('port-scan-tags').value = '';
				document.getElementById('port-scan-follow-on-enabled').checked =
					true;
				document.getElementById('port-scan-follow-on-pool').value = '';
				document.getElementById(
					'port-scan-follow-on-selection-mode'
				).value = 'validated';
				document.getElementById('port-scan-bootstrap-enabled').checked =
					false;
				document.getElementById('port-scan-bootstrap-pool').value = '';
				document.getElementById('port-scan-bootstrap-tags').value = '';
				document.getElementById(
					'port-scan-active-authorized-enabled'
				).checked = false;
				syncPortScanFollowOnVisibility();
				syncPortScanBootstrapVisibility();
			}

			function clearSecretPanel(
				panel,
				titleElement,
				defaultTitle,
				valueElement
			) {
				panel.classList.add('hidden');
				titleElement.textContent = defaultTitle;
				valueElement.textContent = '';
			}

			function showSecretPanel(
				panel,
				titleElement,
				title,
				valueElement,
				secret
			) {
				titleElement.textContent = title;
				valueElement.textContent = secret || '';
				panel.classList.toggle('hidden', !secret);
			}

			function applyWorkerManagementVisibility() {
				const manageWorkers = canManageWorkers();
				const approveBootstrap = canApproveBootstrapCandidates();
				const moderatePublicFindings = canModeratePublicFindings();

				elements.workerTokenAccessNote.textContent = manageWorkers
					? 'Issue and revoke join tokens'
					: 'Read-only visibility';
				elements.workerTokenForm.classList.toggle(
					'hidden',
					!manageWorkers
				);
				elements.workerTokenReadonlyNote.classList.toggle(
					'hidden',
					manageWorkers
				);
				elements.workersRemoteUpdateAll.classList.toggle(
					'hidden',
					!manageWorkers
				);

				elements.bootstrapApprovalAccessNote.textContent =
					approveBootstrap
						? 'Approve or reject pending worker candidates'
						: 'Read-only visibility';
				elements.bootstrapApprovalForm.classList.toggle(
					'hidden',
					!approveBootstrap
				);
				elements.bootstrapApprovalReadonlyNote.classList.toggle(
					'hidden',
					approveBootstrap
				);

				elements.findingsPublicationAccessNote.textContent =
					moderatePublicFindings
						? 'Search redacted findings and publish or suppress public summaries.'
						: 'Search redacted findings with read-only visibility into public publication state.';
			}

			function closeEvents() {
				if (state.reconnectTimer) {
					clearTimeout(state.reconnectTimer);
					state.reconnectTimer = null;
				}
				if (state.eventSource) {
					state.eventSource.close();
					state.eventSource = null;
				}
			}

			function startLiveDashboardRefresh() {
				if (state.liveDashboardTimer) {
					return;
				}
				state.liveDashboardTimer = setInterval(async () => {
					if (!state.authenticated || state.refreshTimer) {
						return;
					}
					try {
						await loadDashboard();
					} catch (error) {
						handleRequestError(
							error,
							'Failed to refresh live worker metrics.'
						);
					}
				}, 5000);
			}

			function stopLiveDashboardRefresh() {
				if (state.liveDashboardTimer) {
					clearInterval(state.liveDashboardTimer);
					state.liveDashboardTimer = null;
				}
			}

			function scheduleRefresh() {
				if (state.refreshTimer) {
					return;
				}
				state.refreshTimer = setTimeout(async () => {
					state.refreshTimer = null;
					if (state.authenticated) {
						try {
							await loadDashboard();
						} catch (error) {
							handleRequestError(
								error,
								'Failed to refresh dashboard.'
							);
						}
					}
				}, 200);
			}

			function renderMetrics(container, values) {
				container.replaceChildren();
				values.forEach(([label, value]) => {
					const item = document.createElement('div');
					item.className = 'metric';

					const itemLabel = document.createElement('span');
					itemLabel.className = 'metric-label';
					itemLabel.textContent = label;

					const itemValue = document.createElement('span');
					itemValue.className = 'metric-value';
					itemValue.textContent = value;

					item.append(itemLabel, itemValue);
					container.appendChild(item);
				});
			}

			function formatHumanLabel(value, fallback = 'Unknown') {
				const normalized = String(value || '')
					.trim()
					.replace(/[-_]+/g, ' ')
					.toLowerCase();
				if (!normalized) {
					return fallback;
				}
				return normalized
					.split(/\s+/)
					.filter(Boolean)
					.map(
						token => token.charAt(0).toUpperCase() + token.slice(1)
					)
					.join(' ');
			}

			function statusBadge(value) {
				const badge = document.createElement('span');
				badge.className = `status ${(value || 'unknown').toLowerCase()}`;
				badge.textContent = formatHumanLabel(value, 'Unknown');
				return badge;
			}

			function severityBadge(value) {
				const badge = document.createElement('span');
				badge.className = `severity ${(value || 'info').toLowerCase()}`;
				badge.textContent = value || 'info';
				return badge;
			}

			function formatTimestamp(value) {
				if (!value) {
					return '—';
				}
				const date = new Date(value);
				if (Number.isNaN(date.getTime())) {
					return value;
				}
				return date.toLocaleString();
			}

			function formatBytes(value) {
				const bytes = Number(value) || 0;
				if (!Number.isFinite(bytes) || bytes <= 0) {
					return '0 B';
				}
				const units = ['B', 'KB', 'MB', 'GB', 'TB'];
				let size = bytes;
				let unitIndex = 0;
				while (size >= 1024 && unitIndex < units.length - 1) {
					size /= 1024;
					unitIndex += 1;
				}
				const precision = size >= 10 || unitIndex === 0 ? 0 : 1;
				return `${size.toFixed(precision)} ${units[unitIndex]}`;
			}

			function formatDuration(totalSeconds) {
				if (totalSeconds === null || totalSeconds === undefined) {
					return '—';
				}

				const seconds = Math.max(0, Number(totalSeconds) || 0);
				const hours = Math.floor(seconds / 3600);
				const minutes = Math.floor((seconds % 3600) / 60);
				const remainingSeconds = seconds % 60;
				const parts = [];

				if (hours > 0) {
					parts.push(`${hours}h`);
				}
				if (minutes > 0 || hours > 0) {
					parts.push(`${minutes}m`);
				}
				parts.push(`${remainingSeconds}s`);
				return parts.join(' ');
			}

			function deriveElapsedSeconds(startedAt, completedAt) {
				if (!startedAt) {
					return null;
				}
				const started = new Date(startedAt);
				if (Number.isNaN(started.getTime())) {
					return null;
				}
				const completed = completedAt ? new Date(completedAt) : new Date();
				if (Number.isNaN(completed.getTime())) {
					return null;
				}
				return Math.max(
					0,
					Math.floor((completed.getTime() - started.getTime()) / 1000)
				);
			}

			function computeRate(totalCount, startedAt, completedAt) {
				const elapsedSeconds = deriveElapsedSeconds(startedAt, completedAt);
				const count = Math.max(0, Number(totalCount) || 0);
				if (!elapsedSeconds || elapsedSeconds <= 0 || count <= 0) {
					return null;
				}
				return count / elapsedSeconds;
			}

			function estimateEtaSecondsFromProgress(progressPercent, elapsedSeconds) {
				const progress = Number(progressPercent);
				const elapsed = Number(elapsedSeconds);
				if (
					!Number.isFinite(progress) ||
					!Number.isFinite(elapsed) ||
					progress <= 0 ||
					progress >= 100 ||
					elapsed <= 0
				) {
					return null;
				}
				return Math.max(
					0,
					Math.round((elapsed * (100 - progress)) / progress)
				);
			}

			function estimateEtaSecondsFromCounts(completedCount, totalCount, elapsedSeconds) {
				const completed = Math.max(0, Number(completedCount) || 0);
				const total = Math.max(0, Number(totalCount) || 0);
				const elapsed = Number(elapsedSeconds);
				if (
					!Number.isFinite(elapsed) ||
					elapsed <= 0 ||
					total <= 0 ||
					completed <= 0 ||
					completed >= total
				) {
					return null;
				}
				return Math.max(
					0,
					Math.round((elapsed * (total - completed)) / completed)
				);
			}

			function formatEta(value) {
				if (value === null || value === undefined) {
					return '—';
				}
				return formatDuration(value);
			}

			function formatRate(value, unit) {
				if (value === null || value === undefined || !Number.isFinite(value)) {
					return '—';
				}
				const precision = value >= 100 ? 0 : value >= 10 ? 1 : 2;
				return `${value.toFixed(precision)} ${unit}`;
			}

			function formatPortScanRateLimit(value) {
				const numeric = Math.max(0, Number(value) || 0);
				if (numeric === 0) {
					return 'Unlimited';
				}
				return String(numeric);
			}

			function describeScannerTuning(target) {
				if (!target) {
					return null;
				}
				const parts = [];
				if (target.max_active_tasks) {
					parts.push(`task slots ${target.max_active_tasks}`);
				}
				if (target.agent_concurrency) {
					parts.push(`scan concurrency ${target.agent_concurrency}`);
				}
				const senderThreads =
					normalizePositiveInteger(target.scanner_sender_threads);
				const receiverThreads =
					normalizePositiveInteger(target.scanner_receiver_threads);
				if (senderThreads || receiverThreads) {
					parts.push(
						`scanner threads ${senderThreads || '—'}/${receiverThreads || '—'}`
					);
				}
				if (
					target.scanner_default_rate !== null &&
					target.scanner_default_rate !== undefined
				) {
					parts.push(
						`scanner default rate ${formatPortScanRateLimit(
							target.scanner_default_rate
						)}`
					);
				}
				return parts.length ? parts.join(' • ') : null;
			}

			function rateFromMillis(value) {
				const numeric = Math.max(0, Number(value) || 0);
				if (!numeric) {
					return null;
				}
				return numeric / 1000;
			}

			function formatIntervalSeconds(totalSeconds) {
				const seconds = Math.max(0, Number(totalSeconds) || 0);
				if (seconds <= 0) {
					return 'manual';
				}
				if (seconds % 3600 === 0) {
					return `${seconds / 3600}h`;
				}
				if (seconds % 60 === 0) {
					return `${seconds / 60}m`;
				}
				return `${seconds}s`;
			}

			function formatList(values, fallback = '—') {
				return values && values.length ? values.join(', ') : fallback;
			}

			function formatTargetStrategy(value) {
				const normalized = String(value || 'hybrid')
					.trim()
					.replace(/_/g, ' ')
					.toLowerCase();
				if (!normalized) {
					return 'Hybrid';
				}
				return normalized.charAt(0).toUpperCase() + normalized.slice(1);
			}

			function formatCoverageSource(value) {
				const normalized = String(value || 'unknown')
					.trim()
					.replace(/[-_]+/g, ' ')
					.toLowerCase();
				if (!normalized) {
					return 'Unknown';
				}
				return normalized
					.split(/\s+/)
					.filter(Boolean)
					.map(
						token => token.charAt(0).toUpperCase() + token.slice(1)
					)
					.join(' ');
			}

			function formatDiscoveryProvenanceSummary(discoveryProvenance) {
				const entries = Array.isArray(discoveryProvenance)
					? discoveryProvenance.filter(entry => entry && entry.path)
					: [];
				if (!entries.length) {
					return 'Persisted discovery: none';
				}
				const preview = entries
					.slice(0, 2)
					.map(
						entry => `${entry.path} (${entry.source || 'unknown'})`
					)
					.join(', ');
				const suffix =
					entries.length > 2 ? ` +${entries.length - 2} more` : '';
				return `Persisted discovery: ${preview}${suffix}`;
			}

			function buildTargetLookup(targets) {
				const lookup = new Map();
				(Array.isArray(targets) ? targets : []).forEach(target => {
					if (target && Number.isInteger(target.id)) {
						lookup.set(target.id, target);
					}
				});
				return lookup;
			}

			function formatRepositoryRelatedTargets(
				relatedTargetIds,
				targetsById
			) {
				const targetIds = Array.isArray(relatedTargetIds)
					? relatedTargetIds
							.map(value => Number(value))
							.filter(
								value => Number.isInteger(value) && value > 0
							)
					: [];
				if (!targetIds.length) {
					return 'Related targets: none';
				}
				const labels = targetIds.map(targetId => {
					const target = targetsById.get(targetId);
					return target
						? `${target.label} (#${targetId})`
						: `#${targetId}`;
				});
				return `Related targets: ${labels.join(', ')}`;
			}

			function formatGobusterSummary(gobuster) {
				if (!gobuster || !gobuster.enabled) {
					return 'Directory probing: disabled';
				}

				const parts = ['Directory probing: enabled'];
				if (
					Array.isArray(gobuster.wordlist) &&
					gobuster.wordlist.length
				) {
					parts.push(
						`${gobuster.wordlist.length} word${gobuster.wordlist.length === 1 ? '' : 's'}`
					);
				} else {
					parts.push('default wordlist');
				}
				if (
					Array.isArray(gobuster.extensions) &&
					gobuster.extensions.length
				) {
					parts.push(`ext ${gobuster.extensions.join(', ')}`);
				}
				if (gobuster.add_slash) {
					parts.push('slash variants');
				}
				if (gobuster.discover_backup) {
					parts.push('backup variants');
				}
				return parts.join(' • ');
			}

			function hasTargetGobusterOverride(gobuster) {
				return Boolean(
					gobuster &&
					(gobuster.enabled ||
						(Array.isArray(gobuster.wordlist) &&
							gobuster.wordlist.length) ||
						(Array.isArray(gobuster.extensions) &&
							gobuster.extensions.length) ||
						gobuster.add_slash ||
						gobuster.discover_backup)
				);
			}

			function renderGobusterDefaults(scanDefaults) {
				const defaults = scanDefaults || {};
				const pills = [];
				pills.push(`Concurrency: ${defaults.concurrency || 0}`);
				pills.push(
					`Per host: ${defaults.max_concurrent_requests_per_host || 0}`
				);
				pills.push(
					`Per target: ${defaults.max_parallel_paths_per_target || 0}`
				);
				pills.push(
					defaults.directory_probing_enabled
						? 'Enabled globally'
						: 'Disabled globally'
				);
				pills.push(
					defaults.directory_probing_wordlist_count
						? `${defaults.directory_probing_wordlist_count} default words`
						: 'No default wordlist'
				);
				if (
					Array.isArray(defaults.directory_probing_extensions) &&
					defaults.directory_probing_extensions.length
				) {
					pills.push(
						`Extensions: ${defaults.directory_probing_extensions.join(', ')}`
					);
				}
				if (defaults.directory_probing_add_slash) {
					pills.push('Slash variants');
				}
				if (defaults.directory_probing_discover_backup) {
					pills.push('Backup variants');
				}

				elements.gobusterDefaultsPills.replaceChildren();
				pills.forEach(label => {
					const pill = document.createElement('span');
					pill.className = 'pill';
					pill.textContent = label;
					elements.gobusterDefaultsPills.appendChild(pill);
				});

				document.getElementById('scan-request-engine-mode').value =
					defaults.request_engine_mode ?? 'staged';
				document.getElementById('scan-concurrency').value =
					defaults.concurrency ?? '';
				document.getElementById('scan-probe-concurrency').value =
					defaults.probe_concurrency ?? '';
				document.getElementById('scan-connect-timeout-secs').value =
					defaults.connect_timeout_secs ?? '';
				document.getElementById('scan-probe-request-timeout-secs').value =
					defaults.probe_request_timeout_secs ?? '';
				document.getElementById('scan-deep-request-timeout-secs').value =
					defaults.deep_request_timeout_secs ?? '';
				document.getElementById('scan-request-timeout-secs').value =
					defaults.request_timeout_secs ?? '';
				document.getElementById('scan-max-response-bytes').value =
					defaults.max_response_bytes ?? '';
				document.getElementById('scan-poll-interval-seconds').value =
					defaults.poll_interval_seconds ?? '';
				document.getElementById('scan-max-paths-per-target').value =
					defaults.max_paths_per_target ?? '';
				document.getElementById(
					'scan-max-discovered-paths-per-target'
				).value = defaults.max_discovered_paths_per_target ?? '';
				document.getElementById(
					'scan-max-parallel-paths-per-target'
				).value = defaults.max_parallel_paths_per_target ?? '';
				document.getElementById(
					'scan-probe-max-concurrent-requests-per-host'
				).value = defaults.probe_max_concurrent_requests_per_host ?? '';
				document.getElementById(
					'scan-deep-max-concurrent-requests-per-host'
				).value = defaults.deep_max_concurrent_requests_per_host ?? '';
				document.getElementById(
					'scan-max-concurrent-requests-per-host'
				).value = defaults.max_concurrent_requests_per_host ?? '';
				document.getElementById('scan-host-backoff-initial-ms').value =
					defaults.host_backoff_initial_ms ?? '';
				document.getElementById('scan-host-backoff-max-ms').value =
					defaults.host_backoff_max_ms ?? '';
				document.getElementById('scan-enable-path-discovery').checked =
					Boolean(defaults.enable_path_discovery);
				document.getElementById('scan-allow-invalid-tls').checked =
					Boolean(defaults.allow_invalid_tls);
				document.getElementById(
					'scan-directory-probing-enabled'
				).checked = Boolean(defaults.directory_probing_enabled);
				document.getElementById(
					'scan-directory-probing-wordlist'
				).value = Array.isArray(defaults.directory_probing_wordlist)
					? defaults.directory_probing_wordlist.join(', ')
					: '';
				document.getElementById(
					'scan-directory-probing-extensions'
				).value = Array.isArray(defaults.directory_probing_extensions)
					? defaults.directory_probing_extensions.join(', ')
					: '';
				document.getElementById(
					'scan-directory-probing-add-slash'
				).checked = Boolean(defaults.directory_probing_add_slash);
				document.getElementById(
					'scan-directory-probing-discover-backup'
				).checked = Boolean(defaults.directory_probing_discover_backup);

				elements.gobusterDefaultsNote.textContent =
					defaults.directory_probing_enabled
						? 'These defaults apply to all targets automatically unless a stored target-specific override exists from earlier configuration.'
						: 'Global directory probing is disabled. Targets currently use only their explicit paths and the built-in live discovery behavior.';
			}

			function formatFindingDiscoveryProvenance(entry) {
				if (!entry || !entry.path) {
					return null;
				}
				const details = [entry.source || 'unknown source'];
				if (typeof entry.score === 'number') {
					details.push(`score ${entry.score}`);
				}
				if (typeof entry.depth === 'number') {
					details.push(`depth ${entry.depth}`);
				}
				return `Discovery provenance: ${entry.path} • ${details.join(' • ')}`;
			}

			function findFindingPublicationRecord(findingId) {
				return (
					(state.findingPublications || []).find(
						record => record.finding_id === findingId
					) || null
				);
			}

			function upsertFindingPublicationRecord(nextRecord) {
				if (!nextRecord || !Number.isInteger(nextRecord.finding_id)) {
					return;
				}
				const records = Array.isArray(state.findingPublications)
					? [...state.findingPublications]
					: [];
				const existingIndex = records.findIndex(
					record => record.finding_id === nextRecord.finding_id
				);
				if (existingIndex >= 0) {
					records[existingIndex] = nextRecord;
				} else {
					records.unshift(nextRecord);
				}
				state.findingPublications = records;
				safeRender('findingPublications (upsert)', () => renderFindingPublications(records));
			}

			function describeFindingPublication(record) {
				if (!record) {
					return 'Not yet reviewed for public publication.';
				}
				const parts = [
					`Reviewed ${formatTimestamp(record.reviewed_at)}`
				];
				if (record.reviewed_by) {
					parts.push(`by ${record.reviewed_by}`);
				}
				if (record.published_at) {
					parts.push(
						`published ${formatTimestamp(record.published_at)}`
					);
				}
				return parts.join(' • ');
			}

			async function loadFindingPublications() {
				const records = await request('/api/findings/publications', {
					method: 'GET'
				});
				state.findingPublications = Array.isArray(records)
					? records
					: [];
				safeRender('findingPublications (load)', () =>
					renderFindingPublications(state.findingPublications)
				);
			}

			function renderFindingPublications(records) {
				elements.publicationRecordsList.replaceChildren();
				const entries = (Array.isArray(records) ? records : [])
					.filter(Boolean)
					.slice()
					.sort((left, right) => {
						const leftTime = Date.parse(
							left.updated_at || left.reviewed_at || left.published_at || ''
						);
						const rightTime = Date.parse(
							right.updated_at || right.reviewed_at || right.published_at || ''
						);
						return (Number.isNaN(rightTime) ? 0 : rightTime) - (Number.isNaN(leftTime) ? 0 : leftTime);
					});
				const publishedCount = entries.filter(
					record => record.status === 'published'
				).length;
				const suppressedCount = entries.filter(
					record => record.status === 'suppressed'
				).length;

				elements.publicationRecordsEmpty.classList.toggle(
					'hidden',
					entries.length > 0
				);
				elements.publicationRecordsEmpty.textContent =
					'No public publication decisions recorded yet.';
				elements.publicationRecordsNote.textContent = canModeratePublicFindings()
					? 'No public publication decisions recorded yet. Search findings to review new disclosures or revise existing summaries.'
					: 'No public publication decisions recorded yet. This session has read-only access to publication history.';
				if (!entries.length) {
					return;
				}

				const visibilityNote = canModeratePublicFindings()
					? 'Search findings to review new disclosures or revise existing summaries.'
					: 'This session has read-only access to publication history.';
				elements.publicationRecordsNote.textContent = `Showing ${entries.length} reviewed records • ${publishedCount} published • ${suppressedCount} suppressed. ${visibilityNote}`;
				entries.forEach(record => {
					const item = document.createElement('li');
					item.className = 'list-item';

					const heading = document.createElement('div');
					heading.className = 'finding-heading';
					const label = document.createElement('strong');
					label.textContent = `Finding #${record.finding_id} • ${record.detector}`;
					heading.append(
						label,
						severityBadge(record.severity),
						statusBadge(record.status)
					);

					const target = document.createElement('p');
					const targetCode = document.createElement('code');
					targetCode.textContent = `${record.target_base_url || ''}${record.path || ''}`;
					target.appendChild(targetCode);

					const summary = document.createElement('p');
					summary.className = 'muted';
					summary.textContent = record.public_summary || 'No public summary recorded.';

					const detail = document.createElement('small');
					detail.className = 'muted';
					detail.textContent = `Observed ${formatTimestamp(record.observed_at)} • Reviewed ${formatTimestamp(record.reviewed_at)}${record.reviewed_by ? ` by ${record.reviewed_by}` : ''}${record.published_at ? ` • Published ${formatTimestamp(record.published_at)}` : ''}`;

					item.append(heading, target, summary, detail);
					if (
						canViewPrivatePublicationNotes() &&
						record.reviewer_notes
					) {
						const notes = document.createElement('small');
						notes.className = 'muted';
						notes.textContent = `Reviewer notes: ${record.reviewer_notes}`;
						item.appendChild(notes);
					}

					elements.publicationRecordsList.appendChild(item);
				});
			}


			async function moderateFindingPublication(
				finding,
				status,
				summaryValue,
				reviewerNotesValue,
				feedbackElement,
				buttons
			) {
				if (!finding || !Number.isInteger(finding.id)) {
					return;
				}

				const payload = { status };
				const publicSummary = normalizeOptionalText(summaryValue);
				payload.public_summary = publicSummary ?? '';
				const reviewerNotes = normalizeOptionalText(reviewerNotesValue);
				payload.reviewer_notes = reviewerNotes ?? '';

				feedbackElement.textContent = 'Saving publication decision…';
				feedbackElement.className = 'muted';
				feedbackElement.classList.remove('hidden');
				(buttons || []).forEach(button => {
					button.disabled = true;
				});

				try {
					const record = await request(
						`/api/findings/${finding.id}/publication`,
						{
							method: 'POST',
							body: JSON.stringify(payload)
						}
					);
					upsertFindingPublicationRecord(record);
					safeRender('findings (publication update)', () => renderFindings(state.visibleFindings || []));
					if (elements.findingsQueryStatus) {
						elements.findingsQueryStatus.textContent = `${describeFindingsQuery(state.findingsQuery)} Public publication updated for finding #${finding.id}.`;
					}
					feedbackElement.textContent = `Saved ${status} publication for finding #${finding.id}.`;
					feedbackElement.className = 'muted';
				} catch (error) {
					feedbackElement.textContent =
						error.message || 'Failed to update public publication.';
					feedbackElement.className = 'error';
					return;
				} finally {
					(buttons || []).forEach(button => {
						button.disabled = false;
					});
				}
			}

			function renderSummary(latestRun, latestSummary) {
				const summary = latestSummary || {
					run_id: latestRun?.id || 0,
					status: latestRun?.status || 'queued',
					total_targets: latestRun?.total_targets || 0,
					completed_targets: latestRun?.completed_targets || 0,
					requests_total: latestRun?.requests_total || 0,
					findings_total: latestRun?.findings_total || 0,
					errors_total: latestRun?.errors_total || 0,
					started_at: latestRun?.started_at || null,
					completed_at: latestRun?.completed_at || null,
					progress: {
						pending_targets: 0,
						in_progress_targets: 0,
						succeeded_targets: 0,
						failed_targets: 0,
						last_activity_at:
							latestRun?.completed_at ||
							latestRun?.started_at ||
							null,
						elapsed_seconds: null
					}
				};
				const progress = summary.progress || {};
				const summaryElapsedSeconds =
					progress.elapsed_seconds ??
					deriveElapsedSeconds(
						summary.started_at || latestRun?.started_at,
						summary.completed_at || latestRun?.completed_at
					);
				const summaryEtaSeconds = estimateEtaSecondsFromCounts(
					summary.completed_targets || 0,
					summary.total_targets || 0,
					summaryElapsedSeconds
				);
				const summaryRequestRate = computeRate(
					summary.requests_total || 0,
					summary.started_at || latestRun?.started_at,
					summary.completed_at || latestRun?.completed_at
				);
				const summaryTargetRate = computeRate(
					summary.completed_targets || 0,
					summary.started_at || latestRun?.started_at,
					summary.completed_at || latestRun?.completed_at
				);

				renderMetrics(elements.summaryMetrics, [
					['Run ID', summary.run_id ? `#${summary.run_id}` : 'None'],
					['Status', summary.status || 'queued'],
					[
						'Targets',
						`${summary.completed_targets || 0}/${summary.total_targets || 0}`
					],
					['Pending', `${progress.pending_targets || 0}`],
					['In flight', `${progress.in_progress_targets || 0}`],
					['Succeeded', `${progress.succeeded_targets || 0}`],
					['Failed', `${progress.failed_targets || 0}`],
					['Requests', `${summary.requests_total || 0}`],
					['Req/s', formatRate(summaryRequestRate, 'req/s')],
					['Findings', `${summary.findings_total || 0}`],
					['Errors', `${summary.errors_total || 0}`],
					[
						'Coverage sources',
						`${(summary.coverage_sources || []).length}`
					]
				]);

				const statusMetric = elements.summaryMetrics.children[1];
				const valueNode = statusMetric?.querySelector('.metric-value');
				if (valueNode) {
					valueNode.textContent = '';
					valueNode.appendChild(
						statusBadge(summary.status || 'queued')
					);
				}

				renderMetrics(elements.timingMetrics, [
					['Requested by', latestRun?.requested_by || 'system'],
					[
						'Started',
						formatTimestamp(
							summary.started_at || latestRun?.started_at
						)
					],
					[
						'Last activity',
						formatTimestamp(progress.last_activity_at)
					],
					[
						'Completed',
						formatTimestamp(
							summary.completed_at || latestRun?.completed_at
						)
					],
					['Elapsed', formatDuration(summaryElapsedSeconds)],
					['ETA', formatEta(summaryEtaSeconds)],
					['Targets/s', formatRate(summaryTargetRate, 'targets/s')],
					['Notes', latestRun?.notes || '—']
				]);
			}

			function renderTargets(targets) {
				elements.targetsBody.replaceChildren();
				const hasTargets = Array.isArray(targets) && targets.length > 0;
				elements.targetsEmpty.classList.toggle('hidden', hasTargets);

				if (!hasTargets) {
					return;
				}

				targets.forEach(target => {
					const row = document.createElement('tr');

					const labelCell = document.createElement('td');
					labelCell.textContent = target.label;

					const urlCell = document.createElement('td');
					const code = document.createElement('code');
					code.textContent = target.base_url;
					urlCell.appendChild(code);

					const scopeCell = document.createElement('td');
					scopeCell.textContent = formatList(target.paths);
					const detail = document.createElement('small');
					detail.textContent = `Tags: ${formatList(target.tags, 'none')}`;
					scopeCell.appendChild(detail);
					const authDetail = document.createElement('small');
					authDetail.textContent = `Request profile: ${target.request_profile || 'public'}`;
					scopeCell.appendChild(authDetail);
					const strategyDetail = document.createElement('small');
					strategyDetail.append('Strategy ');
					strategyDetail.appendChild(
						statusBadge(formatTargetStrategy(target.strategy))
					);
					scopeCell.appendChild(strategyDetail);
					const provenanceDetail = document.createElement('small');
					provenanceDetail.textContent =
						formatDiscoveryProvenanceSummary(
							target.discovery_provenance
						);
					scopeCell.appendChild(provenanceDetail);
					const gobusterDetail = document.createElement('small');
					gobusterDetail.textContent = formatGobusterSummary(
						target.gobuster
					);
					scopeCell.appendChild(gobusterDetail);

					const statusCell = document.createElement('td');
					statusCell.appendChild(
						statusBadge(target.enabled ? 'active' : 'disabled')
					);

					row.append(labelCell, urlCell, scopeCell, statusCell);
					elements.targetsBody.appendChild(row);
				});
			}

			function renderRepositories(repositories, targets) {
				elements.repositoriesList.replaceChildren();
				const entries = Array.isArray(repositories)
					? repositories.filter(Boolean)
					: [];
				const hasRepositories = entries.length > 0;
				elements.repositoriesEmpty.classList.toggle(
					'hidden',
					hasRepositories
				);
				if (!hasRepositories) {
					return;
				}

				const targetsById = buildTargetLookup(targets);
				entries.forEach(repository => {
					const item = document.createElement('li');
					item.className = 'list-item';

					const heading = document.createElement('div');
					heading.className = 'finding-heading';
					const label = document.createElement('strong');
					label.textContent = repository.name || 'Unnamed repository';
					heading.append(
						label,
						statusBadge(repository.status || 'tracked')
					);

					const remote = document.createElement('p');
					remote.className = 'muted';
					remote.append('GitHub ');
					const githubUrl = document.createElement('code');
					githubUrl.textContent = repository.github_url || '—';
					remote.appendChild(githubUrl);

					const localPath = document.createElement('small');
					localPath.className = 'muted';
					localPath.append('Local path ');
					const localPathCode = document.createElement('code');
					localPathCode.textContent = repository.local_path || '—';
					localPath.appendChild(localPathCode);

					const relatedTargets = document.createElement('small');
					relatedTargets.className = 'muted';
					relatedTargets.textContent = formatRepositoryRelatedTargets(
						repository.related_target_ids,
						targetsById
					);

					item.append(heading, remote, localPath, relatedTargets);

					if (repository.description) {
						const description = document.createElement('small');
						description.className = 'muted';
						description.textContent = repository.description;
						item.appendChild(description);
					}

					elements.repositoriesList.appendChild(item);
				});
			}

			function renderBinDatasetStatus(status) {
				elements.binDatasetStatusList.replaceChildren();
				const hasStatus = Boolean(status && status.record_count);
				elements.binDatasetStatusEmpty.classList.toggle(
					'hidden',
					hasStatus
				);
				if (!hasStatus) {
					return;
				}

				const item = document.createElement('li');
				item.className = 'list-item';

				const heading = document.createElement('div');
				heading.className = 'finding-heading';
				const label = document.createElement('strong');
				label.textContent =
					status.repository_name ||
					status.local_path ||
					'Imported BIN dataset';
				heading.append(label, statusBadge('ready'));

				const detail = document.createElement('p');
				detail.className = 'muted';
				detail.textContent = `${status.record_count || 0} BIN entries • imported ${formatTimestamp(status.imported_at)}`;

				const source = document.createElement('small');
				source.className = 'muted';
				source.textContent = `Source: ${status.csv_path || 'unknown CSV'}${status.repository_id ? ` • repo #${status.repository_id}` : ''}`;

				item.append(heading, detail, source);
				elements.binDatasetStatusList.appendChild(item);
			}

			function renderArchiveStatus(status) {
				const archiveStatus = status || null;
				if (!archiveStatus?.enabled) {
					renderMetrics(elements.archiveMetrics, [
						['Backend', 'Disabled'],
						['Hot window', '—'],
						['Pressure', 'normal'],
						['Pointers', '0']
					]);
					elements.archiveNote.textContent =
						'Cold archive is disabled. Hot history remains entirely in Dragonfly.';
					return;
				}

				const latestJob = Array.isArray(archiveStatus.recent_archive_jobs)
					? archiveStatus.recent_archive_jobs[0]
					: null;
				renderMetrics(elements.archiveMetrics, [
					[
						'Backend',
						String(archiveStatus.backend || 'b2_s3')
							.replace(/_/g, ' ')
							.toUpperCase()
					],
					[
						'Hot window',
						`${archiveStatus.current_hot_retention_days || 0} days`
					],
					[
						'Pressure',
						formatHumanLabel(archiveStatus.pressure_mode || 'normal')
					],
					['Pointers', `${archiveStatus.pointers_total || 0}`],
					[
						'Used memory',
						formatBytes(archiveStatus.used_memory_bytes || 0)
					],
					[
						'Namespace size',
						formatBytes(archiveStatus.namespace_estimated_bytes || 0)
					]
				]);

				if (!latestJob) {
					elements.archiveNote.textContent =
						`Archive is enabled with a target hot window of ${archiveStatus.target_hot_retention_days || 0} days, but no archive pass has completed yet.`;
					return;
				}

				const archivedKinds = Array.isArray(latestJob.kinds)
					? latestJob.kinds
							.filter(entry => entry && entry.record_count)
							.map(
								entry =>
									`${entry.kind}: ${entry.record_count}`
							)
					: [];
				const jobStatus = formatHumanLabel(latestJob.status || 'completed');
				const archivedSummary = archivedKinds.length
					? `Kinds ${archivedKinds.join(' • ')}.`
					: 'No records moved during the last pass.';
				elements.archiveNote.textContent =
					`Last archive job #${latestJob.id} finished ${jobStatus.toLowerCase()} at ${formatTimestamp(latestJob.completed_at || latestJob.started_at)} with ${latestJob.archived_record_count || 0} records across ${latestJob.archived_object_count || 0} object(s). ${archivedSummary}`;
			}

			function renderBinLookupResults(response) {
				elements.binLookupResults.replaceChildren();
				const matches = Array.isArray(response?.matches)
					? response.matches
					: [];
				const hasMatches = matches.length > 0;
				elements.binLookupResultsEmpty.classList.toggle(
					'hidden',
					hasMatches
				);
				elements.binLookupResultsEmpty.textContent = response
					? 'No BIN matches were extracted from the submitted text.'
					: 'No BIN lookups have been run yet.';
				if (!hasMatches) {
					return;
				}

				matches.forEach(match => {
					const item = document.createElement('li');
					item.className = 'list-item';

					const heading = document.createElement('div');
					heading.className = 'finding-heading';
					const label = document.createElement('strong');
					label.textContent = `BIN ${match.bin}`;
					const countPill = document.createElement('span');
					countPill.className = 'pill';
					countPill.textContent = `${match.occurrences || 0} hit${(match.occurrences || 0) === 1 ? '' : 's'}`;
					heading.append(label, countPill);

					const metadata = match.metadata || {};
					const detail = document.createElement('p');
					detail.className = 'muted';
					detail.textContent =
						[
							metadata.brand,
							metadata.card_type,
							metadata.category,
							metadata.issuer,
							metadata.country_name
						]
							.filter(Boolean)
							.join(' • ') || 'No metadata found';

					const lines = document.createElement('small');
					lines.className = 'muted';
					lines.textContent = `Lines: ${Array.isArray(match.line_numbers) && match.line_numbers.length ? match.line_numbers.join(', ') : 'n/a'}`;

					item.append(heading, detail, lines);

					const linePreviews = Array.isArray(match.line_previews)
						? match.line_previews
						: [];
					if (linePreviews.length) {
						const previewsHeading = document.createElement('small');
						previewsHeading.className = 'muted';
						previewsHeading.textContent = 'Matched line contents:';
						item.appendChild(previewsHeading);

						linePreviews.forEach(preview => {
							const previewLine = document.createElement('small');
							previewLine.className = 'muted';
							previewLine.append(`Line ${preview.line_number}: `);
							const previewCode = document.createElement('code');
							previewCode.textContent = preview.text || '';
							previewLine.appendChild(previewCode);
							item.appendChild(previewLine);
						});
					}

					elements.binLookupResults.appendChild(item);
				});
			}

			function renderRuns(runs) {
				elements.runsList.replaceChildren();
				const entries = (Array.isArray(runs) ? runs : []).filter(run =>
					matchesWorkerPoolFilter(
						run?.scope?.worker_pool || null,
						state.runWorkerPoolFilter
					)
				);
				const hasRuns = entries.length > 0;
				elements.runsEmpty.classList.toggle('hidden', hasRuns);
				if (!hasRuns) {
					elements.runsEmpty.textContent = state.runWorkerPoolFilter
						? 'No scan runs matched the current worker-pool filter.'
						: 'No scan runs recorded yet.';
					return;
				}

				entries.forEach(run => {
					const item = document.createElement('li');
					item.className = 'list-item';
					const runRequestRate = computeRate(
						run.requests_total || 0,
						run.started_at,
						run.completed_at
					);
					const runTargetRate = computeRate(
						run.completed_targets || 0,
						run.started_at,
						run.completed_at
					);
					const runElapsedSeconds = deriveElapsedSeconds(
						run.started_at,
						run.completed_at
					);
					const runEtaSeconds = estimateEtaSecondsFromCounts(
						run.completed_targets || 0,
						run.total_targets || 0,
						runElapsedSeconds
					);

					const heading = document.createElement('strong');
					heading.textContent = `Run #${run.id}`;
					heading.appendChild(statusBadge(run.status));

					const body = document.createElement('p');
					body.className = 'muted';
					body.textContent = `${run.completed_targets}/${run.total_targets} targets • ${run.requests_total} requests • ${run.findings_total} findings • ${run.errors_total} errors • ${formatRate(runRequestRate, 'req/s')}`;

					const scope = document.createElement('small');
					scope.className = 'muted';
					scope.textContent = `Scope: ${formatRunScope(run.scope)}`;

					const footer = document.createElement('small');
					footer.className = 'muted';
					footer.textContent = `Requested by ${run.requested_by || 'system'} • Started ${formatTimestamp(run.started_at)} • Completed ${formatTimestamp(run.completed_at)} • Elapsed ${formatDuration(runElapsedSeconds)} • ETA ${formatEta(runEtaSeconds)} • ${formatRate(runTargetRate, 'targets/s')}`;

					item.append(heading, body, scope, footer);
					const activeAuthorizedExecution =
						describeActiveAuthorizedExecution(run);
					if (activeAuthorizedExecution) {
						const executionDetail =
							document.createElement('small');
						executionDetail.className = 'muted';
						executionDetail.textContent =
							activeAuthorizedExecution;
						item.appendChild(executionDetail);
					}
					if (
						canManageWorkers() &&
						['queued', 'in_progress'].includes(run.status)
					) {
						const actions = document.createElement('div');
						actions.className = 'card-actions';
						const stopButton = document.createElement('button');
						stopButton.type = 'button';
						stopButton.className = 'secondary';
						stopButton.textContent = 'Stop run';
						stopButton.addEventListener('click', async () => {
							stopButton.disabled = true;
							try {
								await request(`/api/runs/${run.id}/stop`, {
									method: 'POST'
								});
								prependEvent(`Stopped run #${run.id}.`);
								await loadDashboard();
							} catch (error) {
								handleRequestError(error, 'Failed to stop run.');
							} finally {
								stopButton.disabled = false;
							}
						});
						actions.appendChild(stopButton);
						item.appendChild(actions);
					}
					elements.runsList.appendChild(item);
				});
			}

			function renderSchedules(schedules) {
				elements.schedulesList.replaceChildren();
				const hasSchedules =
					Array.isArray(schedules) && schedules.length > 0;
				elements.schedulesEmpty.classList.toggle(
					'hidden',
					hasSchedules
				);
				if (!hasSchedules) {
					return;
				}

				schedules.forEach(schedule => {
					const item = document.createElement('li');
					item.className = 'list-item';

					const heading = document.createElement('div');
					heading.className = 'finding-heading';
					const label = document.createElement('strong');
					label.textContent = schedule.label;
					heading.append(
						label,
						statusBadge(schedule.enabled ? 'active' : 'disabled')
					);
					if (schedule.last_queued_run_status) {
						heading.append(
							statusBadge(schedule.last_queued_run_status)
						);
					}

					const body = document.createElement('p');
					body.className = 'muted';
					body.textContent = `Every ${formatIntervalSeconds(schedule.interval_seconds)} • Next ${formatTimestamp(schedule.next_run_at)}`;

					const scope = document.createElement('small');
					scope.className = 'muted';
					scope.textContent = `Scope: ${formatRunScope(schedule.scope)}`;

					const detail = document.createElement('small');
					detail.className = 'muted';
					if (schedule.last_queued_run_id) {
						detail.textContent = `Last queued run #${schedule.last_queued_run_id} • Started ${formatTimestamp(schedule.last_queued_run_started_at)} • Completed ${formatTimestamp(schedule.last_queued_run_completed_at)}`;
					} else {
						detail.textContent = `Requested by ${schedule.requested_by || 'system'} • No scheduled run queued yet`;
					}

					item.append(heading, body, scope, detail);
					const activeAuthorizedExecution =
						describeActiveAuthorizedExecution(schedule);
					if (activeAuthorizedExecution) {
						const executionDetail =
							document.createElement('small');
						executionDetail.className = 'muted';
						executionDetail.textContent =
							activeAuthorizedExecution;
						item.appendChild(executionDetail);
					}

					if (schedule.last_error) {
						const errorDetail = document.createElement('small');
						errorDetail.className = 'muted';
						errorDetail.textContent = `Last issue: ${schedule.last_error}`;
						item.appendChild(errorDetail);
					}

					elements.schedulesList.appendChild(item);
				});
			}

			function renderFindings(findings) {
				state.visibleFindings = Array.isArray(findings) ? findings : [];
				elements.findingsList.replaceChildren();
				const hasFindings = state.visibleFindings.length > 0;
				elements.findingsEmpty.classList.toggle('hidden', hasFindings);
				elements.findingsEmpty.textContent = hasActiveFindingsQuery(
					state.findingsQuery
				)
					? 'No redacted findings matched the current search.'
					: 'No redacted findings recorded yet.';
				if (!hasFindings) {
					return;
				}

				state.visibleFindings.forEach(finding => {
					const publicationRecord = findFindingPublicationRecord(
						finding.id
					);
					const item = document.createElement('li');
					item.className = 'list-item';

					const heading = document.createElement('div');
					heading.className = 'finding-heading';
					const label = document.createElement('strong');
					label.textContent = `${finding.target_label} • ${finding.detector}`;
					heading.append(label, severityBadge(finding.severity));
					if (finding.confidence) {
						heading.append(
							statusBadge(
								formatFindingConfidence(finding.confidence)
							)
						);
					}
					heading.append(
						statusBadge(
							formatTargetStrategy(finding.target_strategy)
						),
						statusBadge(publicationRecord?.status || 'unreviewed')
					);

					const body = document.createElement('p');
					const pathCode = document.createElement('code');
					pathCode.textContent = finding.path;
					const separator = document.createTextNode(' · ');
					const valueCode = document.createElement('code');
					valueCode.textContent = finding.redacted_value;
					body.append(pathCode, separator, valueCode);

					const evidence = document.createElement('small');
					evidence.className = 'muted';
					evidence.textContent = `${finding.evidence} • ${formatTimestamp(finding.discovered_at)}`;

					const matchedSignals = document.createElement('small');
					matchedSignals.className = 'muted';
					matchedSignals.textContent =
						Array.isArray(finding.matched_signals) &&
						finding.matched_signals.length
							? `Matched signals: ${finding.matched_signals.join(', ')}`
							: 'Matched signals unavailable';

					const reviewLabels = document.createElement('small');
					reviewLabels.className = 'muted';
					reviewLabels.textContent =
						Array.isArray(finding.review_labels) &&
						finding.review_labels.length
							? `Review labels: ${finding.review_labels.join(', ')}`
							: 'Review labels unavailable';

					const publicationState = document.createElement('small');
					publicationState.className = 'muted';
					publicationState.textContent =
						describeFindingPublication(publicationRecord);

					const publicationSummary = document.createElement('p');
					publicationSummary.className = 'muted';
					publicationSummary.textContent =
						publicationRecord?.public_summary
							? `Public summary: ${publicationRecord.public_summary}`
							: 'Public summary will use the server default unless you provide an override during review.';

					item.append(
						heading,
						body,
						evidence,
						matchedSignals,
						reviewLabels,
						publicationState,
						publicationSummary
					);

					if (finding.plugin_metadata) {
						const pluginMeta = document.createElement('small');
						pluginMeta.className = 'muted';
						const details = [
							`Plugin ${finding.plugin_metadata.plugin_id}`,
							formatPluginCatalogValue(
								finding.plugin_metadata.plugin_family
							),
							formatPluginCatalogValue(
								finding.plugin_metadata.leakix_label
							),
							formatPluginCatalogValue(
								finding.plugin_metadata.execution_mode
							)
						];
						if (finding.plugin_metadata.product_name) {
							details.push(finding.plugin_metadata.product_name);
						}
						if (finding.plugin_metadata.product_version) {
							details.push(
								`version ${finding.plugin_metadata.product_version}`
							);
						}
						if (
							Array.isArray(finding.plugin_metadata.cve_ids) &&
							finding.plugin_metadata.cve_ids.length
						) {
							details.push(
								`CVEs ${finding.plugin_metadata.cve_ids.join(', ')}`
							);
						}
						if (finding.plugin_metadata.kev_matched === true) {
							details.push('KEV');
						}
						if (finding.plugin_metadata.implementation_source) {
							details.push(
								formatImplementationSource(
									finding.plugin_metadata.implementation_source
								)
							);
						}
						pluginMeta.textContent = details.join(' • ');
						item.appendChild(pluginMeta);
					}

					if (
						canViewPrivatePublicationNotes() &&
						publicationRecord?.reviewer_notes
					) {
						const reviewerNotes = document.createElement('small');
						reviewerNotes.className = 'muted';
						reviewerNotes.textContent = `Reviewer notes: ${publicationRecord.reviewer_notes}`;
						item.appendChild(reviewerNotes);
					}

					const provenance = formatFindingDiscoveryProvenance(
						finding.discovery_provenance
					);
					if (provenance) {
						const provenanceDetail =
							document.createElement('small');
						provenanceDetail.className = 'muted';
						provenanceDetail.textContent = provenance;
						item.appendChild(provenanceDetail);
					}

					if (canModeratePublicFindings()) {
						const publicationPanel = document.createElement('div');
						publicationPanel.className = 'finding-publication';

						const summaryLabel = document.createElement('label');
						summaryLabel.textContent = 'Public summary override';
						const summaryInput = document.createElement('textarea');
						summaryInput.placeholder =
							'Optional public summary shown on the public site';
						summaryInput.value =
							publicationRecord?.public_summary || '';
						summaryLabel.appendChild(summaryInput);

						const reviewerNotesLabel = document.createElement('label');
						reviewerNotesLabel.textContent = 'Reviewer notes';
						const reviewerNotesInput = document.createElement('textarea');
						reviewerNotesInput.placeholder =
							'Optional private notes for operator review history';
						reviewerNotesInput.value =
							publicationRecord?.reviewer_notes || '';
						reviewerNotesLabel.appendChild(reviewerNotesInput);

						const actions = document.createElement('div');
						actions.className = 'actions inline-actions';
						const publishButton = document.createElement('button');
						publishButton.type = 'button';
						publishButton.textContent =
							publicationRecord?.status === 'published'
								? 'Update publication'
								: 'Publish';
						const suppressButton = document.createElement('button');
						suppressButton.type = 'button';
						suppressButton.textContent =
							publicationRecord?.status === 'suppressed'
								? 'Keep suppressed'
								: 'Suppress';
						actions.append(publishButton, suppressButton);

						const feedback = document.createElement('small');
						feedback.className = 'muted hidden';

						publishButton.addEventListener('click', async () => {
							await moderateFindingPublication(
								finding,
								'published',
								summaryInput.value,
								reviewerNotesInput.value,
								feedback,
								[publishButton, suppressButton]
							);
						});
						suppressButton.addEventListener('click', async () => {
							await moderateFindingPublication(
								finding,
								'suppressed',
								summaryInput.value,
								reviewerNotesInput.value,
								feedback,
								[publishButton, suppressButton]
							);
						});

						publicationPanel.append(
							summaryLabel,
							reviewerNotesLabel,
							actions,
							feedback
						);
						item.appendChild(publicationPanel);
					}

					elements.findingsList.appendChild(item);
				});
			}

			function renderFailedTargets(failedTargets) {
				elements.failedTargetsList.replaceChildren();
				const hasFailedTargets =
					Array.isArray(failedTargets) && failedTargets.length > 0;
				elements.failedTargetsEmpty.classList.toggle(
					'hidden',
					hasFailedTargets
				);
				if (!hasFailedTargets) {
					return;
				}

				failedTargets.forEach(target => {
					const item = document.createElement('li');
					item.className = 'list-item';

					const heading = document.createElement('div');
					heading.className = 'finding-heading';
					const label = document.createElement('strong');
					label.textContent = target.target_label;
					heading.append(label, statusBadge('failed'));

					const body = document.createElement('p');
					const baseUrl = document.createElement('code');
					baseUrl.textContent = target.target_base_url;
					body.append(
						baseUrl,
						document.createTextNode(` · ${target.error}`)
					);

					const detail = document.createElement('small');
					detail.className = 'muted';
					detail.textContent = `${target.requests_count} requests • ${target.findings_count} findings • completed ${formatTimestamp(target.completed_at || target.started_at)}`;

					item.append(heading, body, detail);
					elements.failedTargetsList.appendChild(item);
				});
			}

			function renderDetectorDistribution(detectorDistribution) {
				elements.detectorDistributionList.replaceChildren();
				const hasDetectorDistribution =
					Array.isArray(detectorDistribution) &&
					detectorDistribution.length > 0;
				elements.detectorDistributionEmpty.classList.toggle(
					'hidden',
					hasDetectorDistribution
				);
				if (!hasDetectorDistribution) {
					return;
				}

				detectorDistribution.forEach(entry => {
					const item = document.createElement('li');
					item.className = 'list-item';

					const heading = document.createElement('div');
					heading.className = 'finding-heading';
					const label = document.createElement('strong');
					label.textContent = entry.detector;
					heading.append(label, severityBadge(entry.severity));

					const detail = document.createElement('small');
					detail.className = 'muted';
					detail.textContent = `${entry.findings_total} findings across ${entry.affected_targets} targets`;

					item.append(heading, detail);
					elements.detectorDistributionList.appendChild(item);
				});
			}

			function renderCoverageSources(coverageSources) {
				elements.coverageSourcesList.replaceChildren();
				const entries = Array.isArray(coverageSources)
					? coverageSources.filter(Boolean)
					: [];
				const hasCoverageSources = entries.length > 0;
				elements.coverageSourcesEmpty.classList.toggle(
					'hidden',
					hasCoverageSources
				);
				if (!hasCoverageSources) {
					return;
				}

				entries.slice(0, 10).forEach(entry => {
					const item = document.createElement('li');
					item.className = 'list-item';

					const heading = document.createElement('div');
					heading.className = 'finding-heading';
					const label = document.createElement('strong');
					label.textContent = formatCoverageSource(entry.source);
					heading.append(label);

					const primary = document.createElement('small');
					primary.className = 'muted';
					primary.textContent = `${entry.findings_count || 0} findings • ${entry.documents_scanned || 0} docs • ${entry.discovered_paths || 0} discovered`;

					const secondary = document.createElement('small');
					secondary.className = 'muted';
					secondary.textContent = `${entry.requested_paths || 0} requested • ${entry.queued_paths || 0} queued`;

					item.append(heading, primary, secondary);
					elements.coverageSourcesList.appendChild(item);
				});
			}

			function createPill(label, extraClass = '') {
				const pill = document.createElement('span');
				pill.className = extraClass ? `pill ${extraClass}` : 'pill';
				pill.textContent = label;
				return pill;
			}

			function formatWorkerPoolName(value) {
				return value || 'Unassigned';
			}

			function formatHostPort(host, port) {
				if (!host) {
					return '—';
				}
				return port ? `${host}:${port}` : host;
			}

			function isWorkerOnline(worker) {
				if (!worker?.expires_at) {
					return false;
				}
				const expiresAt = new Date(worker.expires_at);
				return (
					!Number.isNaN(expiresAt.getTime()) &&
					expiresAt.getTime() > Date.now()
				);
			}

			function workerEnrollmentTokenState(token) {
				if (token?.revoked_at) {
					return 'revoked';
				}
				if (token?.expires_at) {
					const expiresAt = new Date(token.expires_at);
					if (
						!Number.isNaN(expiresAt.getTime()) &&
						expiresAt.getTime() <= Date.now()
					) {
						return 'expired';
					}
				}
				if (token?.single_use && token?.used_at) {
					return 'used';
				}
				return 'active';
			}

			function formatWorkerCapabilities(worker) {
				const capabilities = [];
				if (worker?.supports_runs) {
					capabilities.push('scan runs');
				}
				if (worker?.supports_port_scans) {
					capabilities.push('port scans');
				}
				if (worker?.supports_bootstrap) {
					capabilities.push('bootstrap');
				}
				return capabilities.length
					? capabilities.join(', ')
					: 'metadata only';
			}

			function formatEnrollmentTokenCapabilities(token) {
				const capabilities = [];
				if (token?.allow_runs) {
					capabilities.push('scan runs');
				}
				if (token?.allow_port_scans) {
					capabilities.push('port scans');
				}
				if (token?.allow_bootstrap) {
					capabilities.push('bootstrap');
				}
				return capabilities.length
					? capabilities.join(', ')
					: 'metadata only';
			}

			function formatBootstrapPolicy(policy) {
				if (!policy || !policy.enabled) {
					return 'Bootstrap disabled';
				}
				const parts = ['Bootstrap enabled'];
				if (policy.worker_pool) {
					parts.push(`pool ${policy.worker_pool}`);
				}
				if (Array.isArray(policy.tags) && policy.tags.length) {
					parts.push(`tags ${policy.tags.join(', ')}`);
				}
				return parts.join(' • ');
			}

			function formatFollowOnRunPolicy(policy) {
				if (!policy || !policy.enabled) {
					return 'Follow-on scan disabled';
				}
				const parts = ['Follow-on scan enabled'];
				if (policy.worker_pool) {
					parts.push(`pool ${policy.worker_pool}`);
				}
				if (policy.selection_mode) {
					parts.push(`mode ${policy.selection_mode}`);
				}
				return parts.join(' • ');
			}

			function defaultBootstrapTokenLabel(candidate) {
				const normalizedHost = String(candidate?.discovered_host || '')
					.trim()
					.toLowerCase()
					.replace(/[^a-z0-9]+/g, '-')
					.replace(/^-+|-+$/g, '');
				const suffix =
					normalizedHost || `candidate-${candidate?.id || 'worker'}`;
				return `bootstrap-${suffix}`;
			}

			function findBootstrapCandidateById(
				candidateId,
				candidates = state.dashboardSnapshot?.bootstrap_candidates || []
			) {
				const numericId = Number(candidateId);
				return (
					(Array.isArray(candidates) ? candidates : []).find(
						candidate => candidate && candidate.id === numericId
					) || null
				);
			}

			function candidateOptionLabel(candidate) {
				const segments = [
					`#${candidate.id}`,
					formatHostPort(
						candidate.discovered_host,
						candidate.discovered_port
					)
				];
				if (candidate.worker_pool) {
					segments.push(`pool ${candidate.worker_pool}`);
				}
				if (Array.isArray(candidate.tags) && candidate.tags.length) {
					segments.push(candidate.tags.join(', '));
				}
				return segments.join(' • ');
			}

			function setBootstrapApprovalEnabled(enabled) {
				Array.from(elements.bootstrapApprovalForm.elements).forEach(
					element => {
						element.disabled = !enabled;
					}
				);
				syncBootstrapDispatchVisibility();
			}

			function availableBootstrapProvisioners(
				snapshot = state.dashboardSnapshot
			) {
				const names = new Set();
				const extensions = Array.isArray(snapshot?.extensions)
					? snapshot.extensions
					: [];
				extensions.forEach(manifest => {
					const name = String(manifest?.name || '').trim();
					const kind = String(manifest?.kind || '')
						.trim()
						.toLowerCase();
					const enabled = manifest?.enabled !== false;
					if (enabled && kind === 'provisioner' && name) {
						names.add(name);
					}
				});

				const workers = Array.isArray(snapshot?.workers)
					? snapshot.workers
					: [];
				workers.forEach(worker => {
					(Array.isArray(worker?.provisioners)
						? worker.provisioners
						: []
					).forEach(name => {
						const normalized = String(name || '').trim();
						if (normalized) {
							names.add(normalized);
						}
					});
				});

				return Array.from(names).sort((left, right) =>
					left.localeCompare(right)
				);
			}

			function defaultBootstrapProvisionerName(
				snapshot = state.dashboardSnapshot
			) {
				const provisioners = availableBootstrapProvisioners(snapshot);
				return provisioners.length === 1 ? provisioners[0] : '';
			}

			function syncBootstrapProvisionerOptions(
				snapshot = state.dashboardSnapshot
			) {
				if (
					!elements.bootstrapProvisionerOptions ||
					!elements.bootstrapDispatchProvisioner
				) {
					return;
				}
				const provisioners = availableBootstrapProvisioners(snapshot);
				elements.bootstrapProvisionerOptions.replaceChildren();
				provisioners.forEach(name => {
					const option = document.createElement('option');
					option.value = name;
					elements.bootstrapProvisionerOptions.appendChild(option);
				});
				if (!elements.bootstrapDispatchProvisioner.value) {
					const fallback = defaultBootstrapProvisionerName(snapshot);
					if (fallback) {
						elements.bootstrapDispatchProvisioner.value = fallback;
					}
				}
			}

			function syncBootstrapDispatchVisibility() {
				const dispatchEnabled = Boolean(
					elements.bootstrapDispatchEnabled?.checked
				);
				if (
					dispatchEnabled &&
					elements.bootstrapDispatchProvisioner &&
					!elements.bootstrapDispatchProvisioner.value
				) {
					const fallback = defaultBootstrapProvisionerName();
					if (fallback) {
						elements.bootstrapDispatchProvisioner.value = fallback;
					}
				}
				elements.bootstrapDispatchFields?.classList.toggle(
					'hidden',
					!dispatchEnabled
				);
				[
					elements.bootstrapDispatchProvisioner,
					elements.bootstrapDispatchExecutorPool,
					elements.bootstrapDispatchExecutorTags,
					elements.bootstrapDispatchNotes
				]
					.filter(Boolean)
					.forEach(element => {
						element.disabled =
							!dispatchEnabled ||
							Boolean(
								elements.bootstrapDispatchEnabled?.disabled
							);
					});
			}

			function findBootstrapJobsForCandidate(
				candidateId,
				jobs = state.dashboardSnapshot?.bootstrap_jobs || []
			) {
				const numericId = Number(candidateId);
				return (Array.isArray(jobs) ? jobs : []).filter(
					job => job && job.candidate_id === numericId
				);
			}

			function formatBootstrapJobExecutor(job) {
				const parts = [];
				if (job?.executor_worker_pool) {
					parts.push(`pool ${job.executor_worker_pool}`);
				}
				if (
					Array.isArray(job?.executor_tags) &&
					job.executor_tags.length
				) {
					parts.push(`tags ${job.executor_tags.join(', ')}`);
				}
				return parts.length
					? parts.join(' • ')
					: 'any bootstrap-capable worker';
			}

			function populateBootstrapApprovalDefaults(candidate) {
				if (!candidate) {
					resetBootstrapApprovalFormDefaults();
					return;
				}
				document.getElementById('bootstrap-label').value =
					defaultBootstrapTokenLabel(candidate);
				document.getElementById('bootstrap-pool').value =
					candidate.worker_pool || '';
				document.getElementById('bootstrap-tags').value = Array.isArray(
					candidate.tags
				)
					? candidate.tags.join(', ')
					: '';
				document.getElementById('bootstrap-expiry').value = '';
				document.getElementById('bootstrap-allow-runs').checked = true;
				document.getElementById('bootstrap-allow-port-scans').checked =
					true;
				document.getElementById('bootstrap-allow-bootstrap').checked =
					false;
				document.getElementById('bootstrap-single-use').checked = true;
				document.getElementById('bootstrap-notes').value =
					candidate.notes || '';
				elements.bootstrapDispatchEnabled.checked = true;
				elements.bootstrapDispatchProvisioner.value =
					defaultBootstrapProvisionerName();
				elements.bootstrapDispatchExecutorPool.value = '';
				elements.bootstrapDispatchExecutorTags.value = '';
				elements.bootstrapDispatchNotes.value = '';
				syncBootstrapDispatchVisibility();
				clearSecretPanel(
					elements.bootstrapTokenSecretPanel,
					elements.bootstrapTokenSecretTitle,
					'Bootstrap enrollment token issued',
					elements.bootstrapTokenSecretValue
				);
			}

			function syncBootstrapCandidateOptions(candidates) {
				const pendingCandidates = (
					Array.isArray(candidates) ? candidates : []
				).filter(
					candidate =>
						candidate && candidate.status === 'pending_approval'
				);
				const previousValue = elements.bootstrapCandidateId.value;
				elements.bootstrapCandidateId.replaceChildren();

				if (!pendingCandidates.length) {
					const option = document.createElement('option');
					option.value = '';
					option.textContent = 'No pending candidates';
					elements.bootstrapCandidateId.appendChild(option);
					setBootstrapApprovalEnabled(false);
					resetBootstrapApprovalFormDefaults();
					return;
				}

				pendingCandidates.forEach(candidate => {
					const option = document.createElement('option');
					option.value = String(candidate.id);
					option.textContent = candidateOptionLabel(candidate);
					elements.bootstrapCandidateId.appendChild(option);
				});

				const nextValue = pendingCandidates.some(
					candidate => String(candidate.id) === previousValue
				)
					? previousValue
					: String(pendingCandidates[0].id);
				elements.bootstrapCandidateId.value = nextValue;
				setBootstrapApprovalEnabled(true);

				if (!previousValue || previousValue !== nextValue) {
					populateBootstrapApprovalDefaults(
						findBootstrapCandidateById(nextValue, pendingCandidates)
					);
				}
			}

			async function updateWorkerLifecycle(worker, lifecycleState) {
				const updated = await request(
					`/api/workers/${encodeURIComponent(worker.worker_id)}/lifecycle`,
					{
						method: 'POST',
						body: JSON.stringify({
							lifecycle_state: lifecycleState
						})
					}
				);
				prependEvent(
					`Worker ${worker.display_name || worker.worker_id} moved to ${formatHumanLabel(lifecycleState)}.`
				);
				await loadDashboard();
				return updated;
			}

			async function requestWorkerRemoteUpdate(worker) {
				const updated = await request(
					`/api/workers/${encodeURIComponent(worker.worker_id)}/remote-update`,
					{
						method: 'POST'
					}
				);
				prependEvent(
					`Queued a remote update for ${worker.display_name || worker.worker_id}.`
				);
				await loadDashboard();
				return updated;
			}

			async function requestAllWorkerRemoteUpdates() {
				const updated = await request('/api/workers/remote-update-all', {
					method: 'POST'
				});
				const count = Array.isArray(updated) ? updated.length : 0;
				prependEvent(
					count
						? `Queued remote updates for ${count} worker${count === 1 ? '' : 's'}.`
						: 'No eligible workers needed a remote update.'
				);
				await loadDashboard();
				return updated;
			}

			async function queueWorkerRemoteCommand(worker, command, timeoutSeconds) {
				const queued = await request(
					`/api/workers/${encodeURIComponent(worker.worker_id)}/remote-commands`,
					{
						method: 'POST',
						body: JSON.stringify({
							command,
							timeout_seconds: timeoutSeconds || null
						})
					}
				);
				prependEvent(
					`Queued remote debug command on ${worker.display_name || worker.worker_id}.`
				);
				await loadDashboard();
				return queued;
			}

			async function revokeWorkerEnrollmentToken(token) {
				const revoked = await request(
					`/api/worker-enrollment-tokens/${token.id}/revoke`,
					{
						method: 'POST'
					}
				);
				prependEvent(`Revoked enrollment token ${token.label}.`);
				await loadDashboard();
				return revoked;
			}

			function renderWorkerMetrics(snapshot) {
				const workers = Array.isArray(snapshot?.workers)
					? snapshot.workers
					: [];
				const workerThroughputSummary = snapshot?.worker_throughput_summary || null;
				const pools = Array.isArray(snapshot?.worker_pools)
					? snapshot.worker_pools
					: [];
				const tokens = Array.isArray(snapshot?.worker_enrollment_tokens)
					? snapshot.worker_enrollment_tokens
					: [];
				const candidates = Array.isArray(snapshot?.bootstrap_candidates)
					? snapshot.bootstrap_candidates
					: [];
				const jobs = Array.isArray(snapshot?.bootstrap_jobs)
					? snapshot.bootstrap_jobs
					: [];
				const portScans = Array.isArray(snapshot?.recent_port_scans)
					? snapshot.recent_port_scans
					: [];
				const onlineWorkers = workers.filter(worker =>
					isWorkerOnline(worker)
				).length;
				const drainingWorkers = workers.filter(
					worker => worker.lifecycle_state === 'draining'
				).length;
				const activeTokens = tokens.filter(
					token => workerEnrollmentTokenState(token) === 'active'
				).length;
				const pendingCandidates = candidates.filter(
					candidate => candidate.status === 'pending_approval'
				).length;
				const queuedBootstrapJobs = jobs.filter(
					job => job.status === 'queued'
				).length;
				const inProgressBootstrapJobs = jobs.filter(
					job => job.status === 'in_progress'
				).length;
				const queuedPortScans = portScans.filter(
					scan => scan.status === 'queued'
				).length;
				const inProgressPortScans = portScans.filter(
					scan => scan.status === 'in_progress'
				).length;
				const totalRequestRate = rateFromMillis(
					workerThroughputSummary?.total_request_rate_millis
				);
				const averageRequestRate = rateFromMillis(
					workerThroughputSummary?.average_request_rate_millis
				);
				const totalTargetRate = rateFromMillis(
					workerThroughputSummary?.total_target_rate_millis
				);
				const averageTargetRate = rateFromMillis(
					workerThroughputSummary?.average_target_rate_millis
				);
				const totalEndpointRate = rateFromMillis(
					workerThroughputSummary?.total_endpoint_rate_millis
				);
				const averageEndpointRate = rateFromMillis(
					workerThroughputSummary?.average_endpoint_rate_millis
				);
				const totalProbeRate = rateFromMillis(
					workerThroughputSummary?.total_probe_rate_millis
				);
				const averageProbeRate = rateFromMillis(
					workerThroughputSummary?.average_probe_rate_millis
				);
				const totalReceiveRate = rateFromMillis(
					workerThroughputSummary?.total_receive_rate_millis
				);
				const averageReceiveRate = rateFromMillis(
					workerThroughputSummary?.average_receive_rate_millis
				);

				renderMetrics(elements.workerMetrics, [
					['Workers', `${onlineWorkers}/${workers.length} online`],
					[
						'Active workers',
						`${workerThroughputSummary?.active_workers || 0}`
					],
					['Draining', `${drainingWorkers}`],
					['Pools', `${pools.length}`],
					['Fleet req/s', formatRate(totalRequestRate, 'req/s')],
					['Avg req/s', formatRate(averageRequestRate, 'req/s')],
					['Fleet targets/s', formatRate(totalTargetRate, 'targets/s')],
					['Avg targets/s', formatRate(averageTargetRate, 'targets/s')],
					[
						'Fleet endpoints/s',
						formatRate(totalEndpointRate, 'endpoints/s')
					],
					[
						'Avg endpoints/s',
						formatRate(averageEndpointRate, 'endpoints/s')
					],
					['Fleet probes/s', formatRate(totalProbeRate, 'p/s')],
					['Avg probes/s', formatRate(averageProbeRate, 'p/s')],
					['Fleet recv/s', formatRate(totalReceiveRate, 'p/s')],
					['Avg recv/s', formatRate(averageReceiveRate, 'p/s')],
					['Active tokens', `${activeTokens}`],
					['Pending approvals', `${pendingCandidates}`],
					['Queued bootstrap', `${queuedBootstrapJobs}`],
					['Active bootstrap', `${inProgressBootstrapJobs}`],
					['Queued scans', `${queuedPortScans}`],
					['Active scans', `${inProgressPortScans}`]
				]);

				const visibility = canManageWorkers()
					? 'You can manage worker lifecycle and enrollment from this dashboard.'
					: 'This session has read-only worker visibility.';
				const approvals = canApproveBootstrapCandidates()
					? 'Bootstrap candidate approvals are enabled.'
					: 'Bootstrap approvals are read-only.';
				const platformCounts = new Map();
				workers.forEach(worker => {
					const platform = formatWorkerPlatform(worker);
					platformCounts.set(
						platform,
						(platformCounts.get(platform) || 0) + 1
					);
				});
				const platformSummary = Array.from(platformCounts.entries())
					.sort((left, right) => left[0].localeCompare(right[0]))
					.map(([platform, count]) => `${platform} × ${count}`)
					.join(' • ');
				const liveSummary = workerThroughputSummary
					? ` Live throughput updated ${formatTimestamp(
							workerThroughputSummary.updated_at
					  )}.`
					: '';
				elements.workerFleetNote.textContent = `${visibility} ${approvals}${liveSummary}${
					platformSummary ? ` Platforms: ${platformSummary}.` : ''
				}`;
			}

			function buildWorkerActivityMap(snapshot) {
				const entries = Array.isArray(snapshot?.worker_activity)
					? snapshot.worker_activity
					: [];
				return new Map(
					entries
						.filter(entry => entry && entry.worker_id)
						.map(entry => [entry.worker_id, entry])
				);
			}

			function summarizeWorkerActivity(activity) {
				if (!activity || activity.kind === 'idle') {
					return 'Idle';
				}
				const parts = [activity.label || formatHumanLabel(activity.kind)];
				if (activity.active_job_count) {
					parts.push(`${activity.active_job_count} job${activity.active_job_count === 1 ? '' : 's'}`);
				}
				const rates = [];
				const requestRate = rateFromMillis(activity.request_rate_millis);
				const targetRate = rateFromMillis(activity.target_rate_millis);
				const endpointRate = rateFromMillis(activity.endpoint_rate_millis);
				const probeRate = rateFromMillis(activity.probe_rate_millis);
				const receiveRate = rateFromMillis(activity.receive_rate_millis);
				if (requestRate) {
					rates.push(formatRate(requestRate, 'req/s'));
				}
				if (targetRate) {
					rates.push(formatRate(targetRate, 'targets/s'));
				}
				if (endpointRate) {
					rates.push(formatRate(endpointRate, 'endpoints/s'));
				}
				if (probeRate) {
					rates.push(formatRate(probeRate, 'p/s'));
				}
				if (receiveRate) {
					rates.push(formatRate(receiveRate, 'recv/s'));
				}
				if (rates.length > 0) {
					parts.push(rates.join(' • '));
				}
				if (activity.progress_percent !== null && activity.progress_percent !== undefined) {
					parts.push(`${activity.progress_percent}%`);
				}
				const activityEtaSeconds = estimateEtaSecondsFromProgress(
					activity.progress_percent,
					deriveElapsedSeconds(activity.started_at, null)
				);
				if (activityEtaSeconds !== null) {
					parts.push(`ETA ${formatEta(activityEtaSeconds)}`);
				}
				if (activity.last_activity_at) {
					parts.push(`Last activity ${formatTimestamp(activity.last_activity_at)}`);
				}
				return parts.join(' • ');
			}

			function renderWorkerPools(pools) {
				elements.workerPoolsList.replaceChildren();
				const entries = (Array.isArray(pools) ? pools : []).filter(
					Boolean
				);
				const hasPools = entries.length > 0;
				elements.workerPoolsEmpty.classList.toggle('hidden', hasPools);
				if (!hasPools) {
					return;
				}

				entries
					.slice()
					.sort((left, right) =>
						(left.name || '').localeCompare(right.name || '')
					)
					.forEach(pool => {
						const item = document.createElement('li');
						item.className = 'list-item';

						const heading = document.createElement('div');
						heading.className = 'finding-heading';
						const label = document.createElement('strong');
						label.textContent = pool.name || 'Unnamed pool';
						heading.append(
							label,
							createPill(
								`${pool.online_workers || 0}/${pool.total_workers || 0} online`
							)
						);
						if (pool.pending_bootstrap_candidates) {
							heading.appendChild(
								createPill(
									`${pool.pending_bootstrap_candidates} pending approvals`
								)
							);
						}

						const lifecycle = document.createElement('small');
						lifecycle.className = 'muted';
						lifecycle.textContent = [
							`${pool.active_workers || 0} active`,
							`${pool.draining_workers || 0} draining`,
							`${pool.disabled_workers || 0} disabled`,
							`${pool.revoked_workers || 0} revoked`
						].join(' • ');

						const workQueue = document.createElement('small');
						workQueue.className = 'muted';
						workQueue.textContent = [
							`${pool.active_enrollment_tokens || 0} active token${(pool.active_enrollment_tokens || 0) === 1 ? '' : 's'}`,
							`${pool.queued_port_scans || 0} queued scan${(pool.queued_port_scans || 0) === 1 ? '' : 's'}`,
							`${pool.in_progress_port_scans || 0} running scan${(pool.in_progress_port_scans || 0) === 1 ? '' : 's'}`
						].join(' • ');

						item.append(heading, lifecycle, workQueue);
						elements.workerPoolsList.appendChild(item);
					});
			}

			function renderPortScans(portScans) {
				elements.portScansList.replaceChildren();
				const entries = (
					Array.isArray(portScans) ? portScans : []
				).filter(Boolean);
				const hasPortScans = entries.length > 0;
				elements.portScansEmpty.classList.toggle(
					'hidden',
					hasPortScans
				);
				if (!hasPortScans) {
					return;
				}

				entries.forEach(scan => {
					const item = document.createElement('li');
					item.className = 'list-item';
					const scanElapsedSeconds = deriveElapsedSeconds(
						scan.started_at,
						scan.completed_at
					);
					const scanEtaSeconds = estimateEtaSecondsFromProgress(
						scan.current_progress_percent,
						scanElapsedSeconds
					);
					const endpointRate = computeRate(
						scan.discovered_endpoints_total || 0,
						scan.started_at,
						scan.completed_at
					);
					const importRate = computeRate(
						scan.imported_targets_total || 0,
						scan.started_at,
						scan.completed_at
					);
					const probeRate = rateFromMillis(scan.current_probe_rate_millis);
					const receiveRate = rateFromMillis(scan.current_receive_rate_millis);

					const heading = document.createElement('div');
					heading.className = 'finding-heading';
					const label = document.createElement('strong');
					label.textContent = `Port scan #${scan.id}`;
					heading.append(label, statusBadge(scan.status));
					if (scan.worker_pool) {
						heading.appendChild(
							createPill(`Pool ${scan.worker_pool}`)
						);
					}
					if (scan.bootstrap_policy?.enabled) {
						heading.appendChild(createPill('Bootstrap enabled'));
					}
					if (scan.follow_on_run_policy?.enabled) {
						heading.appendChild(createPill('Follow-on scan'));
					}
					if ((scan.shard_total || 0) > 1) {
						heading.appendChild(
							createPill(`Sharded ×${scan.shard_total}`)
						);
					}
					if (scan.queued_run_id) {
						heading.appendChild(
							createPill(`Run #${scan.queued_run_id}`)
						);
					}
					if (
						Array.isArray(scan.follow_on_run_ids) &&
						scan.follow_on_run_ids.length > 1
					) {
						heading.appendChild(
							createPill(
								`${scan.follow_on_run_ids.length} follow-on runs`
							)
						);
					}

					const target = document.createElement('p');
					target.className = 'muted';
					target.innerHTML = '';
					const rangeCode = document.createElement('code');
					rangeCode.textContent = scan.target_range || '—';
					const portsCode = document.createElement('code');
					portsCode.textContent = scan.ports || '—';
					target.append(
						'Range ',
						rangeCode,
						' • Ports ',
						portsCode,
						` • Schemes ${formatHumanLabel(scan.schemes, 'Auto')}`
					);

					const detail = document.createElement('small');
					detail.className = 'muted';
					detail.textContent = [
						`Requested by ${scan.requested_by || 'system'}`,
						`Rate ${formatPortScanRateLimit(scan.rate_limit)}`,
						scan.scanner_sender_threads ||
						scan.scanner_receiver_threads
							? `Threads ${scan.scanner_sender_threads || 'worker default'}/${scan.scanner_receiver_threads || 'worker default'}`
							: null,
						`Tags ${formatList(scan.tags, 'none')}`,
						scan.current_progress_percent !== null &&
						scan.current_progress_percent !== undefined
							? `Progress ${scan.current_progress_percent}%`
							: null,
						scanEtaSeconds !== null
							? `ETA ${formatEta(scanEtaSeconds)}`
							: null,
						probeRate ? `Probes ${formatRate(probeRate, 'p/s')}` : null,
						receiveRate ? `Recv ${formatRate(receiveRate, 'p/s')}` : null,
						formatFollowOnRunPolicy(scan.follow_on_run_policy),
						formatBootstrapPolicy(scan.bootstrap_policy)
					].filter(Boolean).join(' • ');

					const totals = document.createElement('small');
					totals.className = 'muted';
					totals.textContent = [
						`${scan.discovered_endpoints_total || 0} endpoints`,
						`${formatRate(endpointRate, 'endpoints/s')}`,
						`${(scan.protocol_findings || []).length} protocol matches`,
						`${scan.imported_targets_total || 0} imported targets`,
						`${formatRate(importRate, 'targets/s')}`,
						`${scan.bootstrap_candidates_total || 0} bootstrap candidates`,
						`Completed ${formatTimestamp(scan.completed_at)}`,
						`Elapsed ${formatDuration(scanElapsedSeconds)}`
					].join(' • ');

					item.append(heading, target, detail, totals);
					if (
						Array.isArray(scan.follow_on_run_ids) &&
						scan.follow_on_run_ids.length
					) {
						const followOnRuns = document.createElement('small');
						followOnRuns.className = 'muted';
						followOnRuns.textContent = `Follow-on runs: ${scan.follow_on_run_ids
							.map(runId => `#${runId}`)
							.join(', ')}`;
						item.appendChild(followOnRuns);
					}
					const activeAuthorizedExecution =
						describeActiveAuthorizedExecution(scan);
					if (activeAuthorizedExecution) {
						const executionDetail =
							document.createElement('small');
						executionDetail.className = 'muted';
						executionDetail.textContent =
							activeAuthorizedExecution;
						item.appendChild(executionDetail);
					}
					if (Array.isArray(scan.protocol_findings) && scan.protocol_findings.length) {
						const protocolFindings = document.createElement('small');
						protocolFindings.className = 'muted';
						protocolFindings.textContent = `Protocol findings: ${scan.protocol_findings
							.slice(0, 6)
							.map(match =>
								`${match.plugin_metadata?.plugin_id || 'plugin'}${
									match.plugin_metadata?.implementation_source
										? ` (${formatImplementationSource(match.plugin_metadata.implementation_source)})`
										: ''
								} ${match.host}:${match.port}`
							)
							.join(' • ')}${
							scan.protocol_findings.length > 6
								? ` • +${scan.protocol_findings.length - 6} more`
								: ''
						}`;
						item.appendChild(protocolFindings);
					}
					if (scan.notes) {
						const notes = document.createElement('small');
						notes.className = 'muted';
						notes.textContent = scan.notes;
						item.appendChild(notes);
					}
					if (
						canManageWorkers() &&
						['queued', 'in_progress'].includes(scan.status)
					) {
						const actions = document.createElement('div');
						actions.className = 'card-actions';
						const stopButton = document.createElement('button');
						stopButton.type = 'button';
						stopButton.className = 'secondary';
						stopButton.textContent = 'Stop scan';
						stopButton.addEventListener('click', async () => {
							stopButton.disabled = true;
							try {
								await request(`/api/port-scans/${scan.id}/stop`, {
									method: 'POST'
								});
								prependEvent(`Stopped port scan #${scan.id}.`);
								await loadDashboard();
							} catch (error) {
								handleRequestError(
									error,
									'Failed to stop port scan.'
								);
							} finally {
								stopButton.disabled = false;
							}
						});
						actions.appendChild(stopButton);
						item.appendChild(actions);
					}
					elements.portScansList.appendChild(item);
				});
			}

			function renderWorkerRemoteCommands(commands) {
				elements.workerRemoteCommandsList.replaceChildren();
				const entries = (Array.isArray(commands) ? commands : []).filter(
					Boolean
				);
				const hasCommands = entries.length > 0;
				elements.workerRemoteCommandsEmpty.classList.toggle(
					'hidden',
					hasCommands
				);
				if (!hasCommands) {
					return;
				}

				entries.forEach(command => {
					const item = document.createElement('li');
					item.className = 'list-item';

					const heading = document.createElement('div');
					heading.className = 'finding-heading';
					const label = document.createElement('strong');
					label.textContent = `#${command.id} • ${command.worker_id}`;
					heading.append(label, statusBadge(command.status));

					const shell = document.createElement('code');
					shell.textContent = command.command || '—';

					const detail = document.createElement('small');
					detail.className = 'muted';
					detail.textContent = [
						`Requested by ${command.requested_by || 'operator'}`,
						`Timeout ${command.timeout_seconds || 0}s`,
						`Started ${formatTimestamp(command.started_at)}`,
						`Finished ${formatTimestamp(command.completed_at)}`
					].join(' • ');

					item.append(heading, shell, detail);

					if (command.stdout) {
						const stdout = document.createElement('pre');
						stdout.textContent = `stdout:\n${command.stdout}`;
						item.appendChild(stdout);
					}
					if (command.stderr) {
						const stderr = document.createElement('pre');
						stderr.textContent = `stderr:\n${command.stderr}`;
						item.appendChild(stderr);
					}
					if (command.error) {
						const error = document.createElement('small');
						error.className = 'error';
						error.textContent = command.error;
						item.appendChild(error);
					}

					elements.workerRemoteCommandsList.appendChild(item);
				});
			}

			function renderWorkers(workers) {
				elements.workersList.replaceChildren();
				const workerActivityById = buildWorkerActivityMap(
					state.dashboardSnapshot
				);
				const entries = (Array.isArray(workers) ? workers : [])
					.filter(Boolean)
					.filter(worker =>
						matchesWorkerPoolFilter(
							worker?.worker_pool || null,
							state.workerPoolFilter
						)
					)
					.filter(worker => {
						const mode = state.workerHealthFilter || 'all';
						if (mode === 'healthy') {
							return isWorkerControlPlaneHealthy(worker);
						}
						if (mode === 'unhealthy') {
							return !isWorkerControlPlaneHealthy(worker);
						}
						return true;
					});
				const eligibleRemoteUpdateWorkers = entries.filter(
					worker =>
						worker &&
						worker.supports_remote_updates &&
						worker.lifecycle_state !== 'revoked' &&
						!worker.remote_update_requested_at
				);
				elements.workersRemoteUpdateAll.disabled =
					eligibleRemoteUpdateWorkers.length === 0;
				elements.workersRemoteUpdateAll.textContent =
					eligibleRemoteUpdateWorkers.length > 0
						? `Update all (${eligibleRemoteUpdateWorkers.length})`
						: 'Update all';
				const hasWorkers = entries.length > 0;
				elements.workersEmpty.classList.toggle('hidden', hasWorkers);
				if (!hasWorkers) {
					elements.workersEmpty.textContent =
						state.workerPoolFilter || state.workerHealthFilter !== 'all'
							? 'No workers matched the current filters.'
							: 'No workers have registered yet.';
					return;
				}

				let currentPlatformGroup = null;

				entries
					.slice()
					.sort((left, right) =>
						`${formatWorkerPlatform(left)}::${left.display_name || left.worker_id || ''}`.localeCompare(
							`${formatWorkerPlatform(right)}::${right.display_name || right.worker_id || ''}`
						)
					)
					.forEach(worker => {
						const platformGroup = formatWorkerPlatform(worker);
						if (platformGroup !== currentPlatformGroup) {
							currentPlatformGroup = platformGroup;
							const groupItem = document.createElement('li');
							groupItem.className = 'list-item';
							const groupLabel = document.createElement('strong');
							groupLabel.textContent = `Platform ${platformGroup}`;
							groupItem.appendChild(groupLabel);
							elements.workersList.appendChild(groupItem);
						}

						const item = document.createElement('li');
						item.className = 'list-item';

						const heading = document.createElement('div');
						heading.className = 'finding-heading';
						const label = document.createElement('strong');
						label.textContent =
							worker.display_name || worker.worker_id;
						heading.append(
							label,
							statusBadge(worker.lifecycle_state)
						);
						heading.appendChild(
							createPill(
								isWorkerOnline(worker) ? 'Online' : 'Offline'
							)
						);
						if (worker.worker_pool) {
							heading.appendChild(
								createPill(`Pool ${worker.worker_pool}`)
							);
						}
						heading.appendChild(
							createPill(formatWorkerPlatform(worker))
						);
						if (worker.supports_remote_updates) {
							heading.appendChild(createPill('Remote updates'));
						}
						if (worker.supports_remote_debug_commands) {
							heading.appendChild(createPill('Remote debug'));
						}
						if (worker.remote_update_requested_at) {
							heading.appendChild(createPill('Update queued'));
						}
						if (worker.latest_bundle_matches_installed === true) {
							heading.appendChild(createPill('Latest'));
						} else if (
							worker.latest_available_bundle_name &&
							worker.installed_bundle_name &&
							worker.latest_available_bundle_name !==
								worker.installed_bundle_name
						) {
							heading.appendChild(
								createPill('Update available')
							);
						}
						if (worker.control_plane_health_message) {
							heading.appendChild(createPill('Needs attention'));
						}

						const identity = document.createElement('p');
						identity.className = 'muted';
						identity.append('Worker ID ');
						const workerIdCode = document.createElement('code');
						workerIdCode.textContent = worker.worker_id;
						identity.appendChild(workerIdCode);

						const capabilities = document.createElement('small');
						capabilities.className = 'muted';
						capabilities.textContent = `Capabilities: ${formatWorkerCapabilities(worker)} • Tags ${formatList(worker.tags, 'none')}`;

						const adapters = document.createElement('small');
						adapters.className = 'muted';
						adapters.textContent = `Scanner adapters: ${formatList(worker.scanner_adapters, 'none')}`;

						const network = document.createElement('small');
						network.className = 'muted';
						const localIps =
							Array.isArray(worker.local_ip_addresses) &&
							worker.local_ip_addresses.length > 0
								? worker.local_ip_addresses.join(', ')
								: 'none';
						const publicIp = worker.public_ip_address || 'unknown';
						const publicCheckedAt = worker.public_ip_checked_at
							? ` (${formatTimestamp(worker.public_ip_checked_at)})`
							: '';
						network.textContent = `Local IPs: ${localIps} • Public IP: ${publicIp}${publicCheckedAt}`;

						const timing = document.createElement('small');
						timing.className = 'muted';
						timing.textContent = [
							`Registered ${formatTimestamp(worker.registered_at)}`,
							`Last seen ${formatTimestamp(worker.last_seen_at)}`,
							`Lease until ${formatTimestamp(worker.expires_at)}`
						].join(' • ');

						item.append(
							heading,
							identity,
							capabilities,
							adapters,
							network,
							timing
						);
						if (
							worker.installed_bundle_name ||
							worker.latest_available_bundle_name
						) {
							const buildInfo = document.createElement('small');
							buildInfo.className = 'muted';
							buildInfo.textContent = `Installed build: ${
								worker.installed_bundle_name || 'unknown'
							} • Latest build: ${
								worker.latest_available_bundle_name || 'unknown'
							}`;
							item.appendChild(buildInfo);
						}
						const workerActivity = workerActivityById.get(
							worker.worker_id
						);
						const activity = document.createElement('small');
						activity.className = 'muted';
						activity.textContent = `Live summary: ${summarizeWorkerActivity(
							workerActivity
						)}`;
						item.appendChild(activity);
						const tuningSummary = describeScannerTuning(worker);
						if (tuningSummary) {
							const tuning = document.createElement('small');
							tuning.className = 'muted';
							tuning.textContent = `Worker tuning: ${tuningSummary}`;
							item.appendChild(tuning);
						}
						if (worker.control_plane_health_message) {
							const health = document.createElement('small');
							health.className = 'error';
							health.textContent = worker.control_plane_health_message;
							item.appendChild(health);
						}
						if (worker.remote_update_requested_at) {
							const remoteUpdate = document.createElement('small');
							remoteUpdate.className = 'muted';
							remoteUpdate.textContent = `Remote update requested ${formatTimestamp(worker.remote_update_requested_at)}${
								worker.latest_available_bundle_name
									? ` • target ${worker.latest_available_bundle_name}`
									: ''
							}`;
							item.appendChild(remoteUpdate);
						}
						if (worker.remote_update_status) {
							const remoteUpdateStatus =
								document.createElement('small');
							remoteUpdateStatus.className = 'muted';
							remoteUpdateStatus.textContent = `Update status: ${formatHumanLabel(worker.remote_update_status)} • ${formatTimestamp(worker.remote_update_status_updated_at)}${
								worker.remote_update_status_message
									? ` • ${worker.remote_update_status_message}`
									: ''
							}`;
							item.appendChild(remoteUpdateStatus);
						}
						if (worker.enrollment_token_id) {
							const enrollment = document.createElement('small');
							enrollment.className = 'muted';
							enrollment.textContent = `Enrollment token #${worker.enrollment_token_id}`;
							item.appendChild(enrollment);
						}

						if (
							canManageWorkers() &&
							worker.lifecycle_state !== 'revoked'
						) {
							const actions = document.createElement('div');
							actions.className = 'actions';

							const lifecycleActions = [];
							if (worker.lifecycle_state === 'active') {
								lifecycleActions.push({
									label: 'Drain',
									state: 'draining'
								});
								lifecycleActions.push({
									label: 'Disable',
									state: 'disabled'
								});
								lifecycleActions.push({
									label: 'Revoke',
									state: 'revoked',
									className: 'danger',
									confirm: `Revoke worker ${worker.display_name || worker.worker_id}?`
								});
							} else if (worker.lifecycle_state === 'draining') {
								lifecycleActions.push({
									label: 'Activate',
									state: 'active',
									className: 'primary'
								});
								lifecycleActions.push({
									label: 'Disable',
									state: 'disabled'
								});
								lifecycleActions.push({
									label: 'Revoke',
									state: 'revoked',
									className: 'danger',
									confirm: `Revoke worker ${worker.display_name || worker.worker_id}?`
								});
							} else if (worker.lifecycle_state === 'disabled') {
								lifecycleActions.push({
									label: 'Activate',
									state: 'active',
									className: 'primary'
								});
								lifecycleActions.push({
									label: 'Revoke',
									state: 'revoked',
									className: 'danger',
									confirm: `Revoke worker ${worker.display_name || worker.worker_id}?`
								});
							}

							lifecycleActions.forEach(action => {
								const button = document.createElement('button');
								button.type = 'button';
								button.textContent = action.label;
								if (action.className) {
									button.className = action.className;
								}
								button.addEventListener('click', async () => {
									try {
										if (
											action.confirm &&
											!window.confirm(action.confirm)
										) {
											return;
										}
										await updateWorkerLifecycle(
											worker,
											action.state
										);
									} catch (error) {
										handleRequestError(
											error,
											`Failed to update worker ${worker.worker_id}.`
										);
									}
								});
								actions.appendChild(button);
							});

							if (worker.supports_remote_updates) {
								const updateButton = document.createElement('button');
								updateButton.type = 'button';
								updateButton.textContent = worker.remote_update_requested_at
									? 'Update queued'
									: 'Update';
								updateButton.disabled = Boolean(
									worker.remote_update_requested_at
								);
								updateButton.addEventListener('click', async () => {
									try {
										if (
											!window.confirm(
												`Queue a remote self-update for ${worker.display_name || worker.worker_id}?`
											)
										) {
											return;
										}
										await requestWorkerRemoteUpdate(worker);
									} catch (error) {
										handleRequestError(
											error,
											`Failed to queue a remote update for ${worker.worker_id}.`
										);
									}
								});
								actions.appendChild(updateButton);
							}

							if (worker.supports_remote_debug_commands) {
								const commandButton = document.createElement('button');
								commandButton.type = 'button';
								commandButton.textContent = 'Run cmd';
								commandButton.addEventListener('click', async () => {
									const command = window.prompt(
										`Run a remote debug command on ${worker.display_name || worker.worker_id}:`,
										'id; uname -a; ip a'
									);
									if (!command || !command.trim()) {
										return;
									}
									const timeoutRaw = window.prompt(
										'Timeout in seconds',
										'30'
									);
									const timeoutSeconds = normalizePositiveInteger(
										String(timeoutRaw || '').trim()
									);
									try {
										await queueWorkerRemoteCommand(
											worker,
											command.trim(),
											timeoutSeconds
										);
									} catch (error) {
										handleRequestError(
											error,
											`Failed to queue a remote debug command for ${worker.worker_id}.`
										);
									}
								});
								actions.appendChild(commandButton);
							}

							item.appendChild(actions);
						}

						elements.workersList.appendChild(item);
					});
			}

			function isWorkerControlPlaneHealthy(worker) {
				return !worker?.control_plane_health_message;
			}

			function formatWorkerPlatform(worker) {
				const operatingSystem =
					String(worker?.operating_system || '').trim() || 'unknown-os';
				const architecture =
					String(worker?.architecture || '').trim() || 'unknown-arch';
				const platform =
					String(worker?.platform || '').trim() ||
					`${operatingSystem}-${architecture}`;
				return platform;
			}

			function renderWorkerEnrollmentTokens(tokens) {
				elements.workerTokensList.replaceChildren();
				const entries = (Array.isArray(tokens) ? tokens : []).filter(
					Boolean
				);
				const hasTokens = entries.length > 0;
				elements.workerTokensEmpty.classList.toggle(
					'hidden',
					hasTokens
				);
				if (!hasTokens) {
					return;
				}

				entries
					.slice()
					.sort((left, right) =>
						String(right.created_at || '').localeCompare(
							String(left.created_at || '')
						)
					)
					.forEach(token => {
						const item = document.createElement('li');
						item.className = 'list-item';

						const stateLabel = workerEnrollmentTokenState(token);
						const heading = document.createElement('div');
						heading.className = 'finding-heading';
						const label = document.createElement('strong');
						label.textContent = token.label || `Token #${token.id}`;
						heading.append(label, statusBadge(stateLabel));
						if (token.worker_pool) {
							heading.appendChild(
								createPill(`Pool ${token.worker_pool}`)
							);
						}
						if (token.single_use) {
							heading.appendChild(createPill('Single use'));
						}

						const detail = document.createElement('small');
						detail.className = 'muted';
						detail.textContent = `Capabilities: ${formatEnrollmentTokenCapabilities(token)} • Tags ${formatList(token.tags, 'none')}`;

						const lifecycle = document.createElement('small');
						lifecycle.className = 'muted';
						lifecycle.textContent = [
							`Created by ${token.created_by || 'system'}`,
							`Created ${formatTimestamp(token.created_at)}`,
							`Expires ${formatTimestamp(token.expires_at)}`
						].join(' • ');

						item.append(heading, detail, lifecycle);
						if (token.used_by_worker_id || token.used_at) {
							const usage = document.createElement('small');
							usage.className = 'muted';
							usage.textContent = `Used by ${token.used_by_worker_id || 'unknown worker'} • ${formatTimestamp(token.used_at)}`;
							item.appendChild(usage);
						}
						if (token.revoked_at) {
							const revoked = document.createElement('small');
							revoked.className = 'muted';
							revoked.textContent = `Revoked ${formatTimestamp(token.revoked_at)}`;
							item.appendChild(revoked);
						}

						if (canManageWorkers() && stateLabel === 'active') {
							const actions = document.createElement('div');
							actions.className = 'actions';
							const revokeButton =
								document.createElement('button');
							revokeButton.type = 'button';
							revokeButton.className = 'danger';
							revokeButton.textContent = 'Revoke token';
							revokeButton.addEventListener('click', async () => {
								try {
									if (
										!window.confirm(
											`Revoke enrollment token ${token.label}?`
										)
									) {
										return;
									}
									await revokeWorkerEnrollmentToken(token);
								} catch (error) {
									handleRequestError(
										error,
										`Failed to revoke token ${token.label}.`
									);
								}
							});
							actions.appendChild(revokeButton);
							item.appendChild(actions);
						}

						elements.workerTokensList.appendChild(item);
					});
			}

			function renderBootstrapCandidates(candidates) {
				elements.bootstrapCandidatesList.replaceChildren();
				const entries = (
					Array.isArray(candidates) ? candidates : []
				).filter(Boolean);
				const hasCandidates = entries.length > 0;
				elements.bootstrapCandidatesEmpty.classList.toggle(
					'hidden',
					hasCandidates
				);
				if (!hasCandidates) {
					return;
				}

				entries
					.slice()
					.sort((left, right) =>
						String(right.updated_at || '').localeCompare(
							String(left.updated_at || '')
						)
					)
					.forEach(candidate => {
						const item = document.createElement('li');
						item.className = 'list-item';

						const heading = document.createElement('div');
						heading.className = 'finding-heading';
						const label = document.createElement('strong');
						label.textContent = formatHostPort(
							candidate.discovered_host,
							candidate.discovered_port
						);
						heading.append(label, statusBadge(candidate.status));
						if (candidate.worker_pool) {
							heading.appendChild(
								createPill(`Pool ${candidate.worker_pool}`)
							);
						}

						const source = document.createElement('small');
						source.className = 'muted';
						source.textContent = [
							`Port scan #${candidate.port_scan_id}`,
							`Requested by ${candidate.requested_by || 'system'}`,
							`Tags ${formatList(candidate.tags, 'none')}`
						].join(' • ');

						const detailParts = [
							`Created ${formatTimestamp(candidate.created_at)}`,
							`Updated ${formatTimestamp(candidate.updated_at)}`
						];
						if (candidate.approved_by) {
							detailParts.push(
								`Approved by ${candidate.approved_by}`
							);
						}
						if (candidate.enrollment_token_id) {
							detailParts.push(
								`Token #${candidate.enrollment_token_id}`
							);
						}
						if (candidate.worker_id) {
							detailParts.push(`Worker ${candidate.worker_id}`);
						}
						const detail = document.createElement('small');
						detail.className = 'muted';
						detail.textContent = detailParts.join(' • ');

						item.append(heading, source, detail);
						if (candidate.notes) {
							const notes = document.createElement('small');
							notes.className = 'muted';
							notes.textContent = candidate.notes;
							item.appendChild(notes);
						}

						const relatedJobs = findBootstrapJobsForCandidate(
							candidate.id
						);
						if (relatedJobs.length) {
							const related = document.createElement('small');
							related.className = 'muted';
							related.textContent = `Bootstrap jobs: ${relatedJobs
								.slice()
								.sort(
									(left, right) =>
										Number(right.id || 0) -
										Number(left.id || 0)
								)
								.map(
									job =>
										`#${job.id} ${formatHumanLabel(job.status)} via ${job.provisioner}`
								)
								.join(' • ')}`;
							item.appendChild(related);
						}

						if (
							canApproveBootstrapCandidates() &&
							candidate.status === 'pending_approval'
						) {
							const actions = document.createElement('div');
							actions.className = 'actions';
							const reviewButton =
								document.createElement('button');
							reviewButton.type = 'button';
							reviewButton.className = 'primary';
							reviewButton.textContent = 'Review candidate';
							reviewButton.addEventListener('click', () => {
								elements.bootstrapCandidateId.value = String(
									candidate.id
								);
								populateBootstrapApprovalDefaults(candidate);
								elements.bootstrapApprovalForm.scrollIntoView({
									behavior: 'smooth',
									block: 'center'
								});
							});
							actions.appendChild(reviewButton);
							item.appendChild(actions);
						}

						elements.bootstrapCandidatesList.appendChild(item);
					});
			}

			function renderBootstrapJobs(jobs) {
				elements.bootstrapJobsList.replaceChildren();
				const entries = (Array.isArray(jobs) ? jobs : []).filter(
					Boolean
				);
				const hasJobs = entries.length > 0;
				elements.bootstrapJobsEmpty.classList.toggle('hidden', hasJobs);
				if (!hasJobs) {
					return;
				}

				entries
					.slice()
					.sort((left, right) =>
						String(right.updated_at || '').localeCompare(
							String(left.updated_at || '')
						)
					)
					.forEach(job => {
						const item = document.createElement('li');
						item.className = 'list-item';

						const heading = document.createElement('div');
						heading.className = 'finding-heading';
						const label = document.createElement('strong');
						label.textContent = `#${job.id} • ${formatHostPort(job.discovered_host, job.discovered_port)}`;
						heading.append(label, statusBadge(job.status));
						heading.appendChild(
							createPill(`Candidate #${job.candidate_id}`)
						);
						heading.appendChild(
							createPill(`Provisioner ${job.provisioner}`)
						);
						if (job.claimed_by_worker_id) {
							heading.appendChild(
								createPill(`Worker ${job.claimed_by_worker_id}`)
							);
						}

						const scope = document.createElement('small');
						scope.className = 'muted';
						scope.textContent = [
							`Executor ${formatBootstrapJobExecutor(job)}`,
							`Enrollment pool ${job.worker_pool || 'any'}`,
							`Enrollment tags ${formatList(job.tags, 'none')}`
						].join(' • ');

						const detailParts = [
							`Queued ${formatTimestamp(job.created_at)}`,
							`Updated ${formatTimestamp(job.updated_at)}`,
							`Attempts ${job.attempt_count || 0}`
						];
						if (job.started_at) {
							detailParts.push(
								`Started ${formatTimestamp(job.started_at)}`
							);
						}
						if (job.completed_at) {
							detailParts.push(
								`Finished ${formatTimestamp(job.completed_at)}`
							);
						}
						if (job.approved_by) {
							detailParts.push(`Approved by ${job.approved_by}`);
						}
						if (job.requested_by) {
							detailParts.push(
								`Requested by ${job.requested_by}`
							);
						}
						if (job.enrollment_token_id) {
							detailParts.push(
								`Token #${job.enrollment_token_id}`
							);
						}
						const detail = document.createElement('small');
						detail.className = 'muted';
						detail.textContent = detailParts.join(' • ');

						item.append(heading, scope, detail);
						if (job.notes) {
							const notes = document.createElement('small');
							notes.className = 'muted';
							notes.textContent = job.notes;
							item.appendChild(notes);
						}

						elements.bootstrapJobsList.appendChild(item);
					});
			}

			function prependEvent(text) {
				const item = document.createElement('li');
				item.className = 'list-item';
				item.textContent = `${new Date().toLocaleTimeString()} — ${text}`;
				elements.eventsList.prepend(item);
				while (elements.eventsList.children.length > 20) {
					elements.eventsList.removeChild(
						elements.eventsList.lastElementChild
					);
				}
				elements.eventsEmpty.classList.add('hidden');
			}

			function applyApiEvent(event) {
				if (!event || typeof event !== 'object') {
					return;
				}
				if (event.type === 'public_finding_moderated' && event.finding) {
					upsertFindingPublicationRecord(event.finding);
					safeRender('findings (event stream)', () => renderFindings(state.visibleFindings || []));
				}
			}

			function describeEvent(event) {
				switch (event.type) {
					case 'port_scan_queued':
						return `Port scan #${event.port_scan.id} queued for ${event.port_scan.target_range}`;
					case 'port_scan_started':
						return `Port scan #${event.port_scan.id} started`;
					case 'port_scan_completed': {
						const queuedRun = event.queued_run?.id
							? ` • queued run #${event.queued_run.id}`
							: '';
						const protocolMatches = (event.port_scan.protocol_findings || []).length;
						const protocolNote = protocolMatches
							? ` • ${protocolMatches} protocol match${
									protocolMatches === 1 ? '' : 'es'
							  }`
							: '';
						return `Port scan #${event.port_scan.id} completed with ${event.port_scan.discovered_endpoints_total || 0} endpoints${protocolNote}${queuedRun}`;
					}
					case 'port_scan_failed':
						return `Port scan #${event.port_scan.id} failed: ${event.error}`;
					case 'port_scan_stopped':
						return `Port scan #${event.port_scan.id} stopped by operator`;
					case 'worker_state_changed':
						return `Worker ${event.worker.display_name || event.worker.worker_id} is now ${formatHumanLabel(event.worker.lifecycle_state)}`;
					case 'worker_remote_update_requested':
						return `Worker ${event.worker.display_name || event.worker.worker_id} queued for a remote update`;
					case 'worker_remote_command_queued':
						return `Queued remote command #${event.command.id} for ${event.command.worker_id}`;
					case 'worker_remote_command_started':
						return `Remote command #${event.command.id} started on ${event.command.worker_id}`;
					case 'worker_remote_command_completed':
						return `Remote command #${event.command.id} completed on ${event.command.worker_id}`;
					case 'worker_remote_command_failed':
						return `Remote command #${event.command.id} failed on ${event.command.worker_id}: ${event.error}`;
					case 'worker_enrollment_token_issued':
						return `Enrollment token ${event.token.label} issued`;
					case 'worker_enrollment_token_revoked':
						return `Enrollment token ${event.token.label} revoked`;
					case 'worker_bootstrap_candidate_created':
						return `Bootstrap candidate #${event.candidate.id} discovered at ${formatHostPort(event.candidate.discovered_host, event.candidate.discovered_port)}`;
					case 'worker_bootstrap_candidate_approved':
						return `Bootstrap candidate #${event.candidate.id} approved with token ${event.token.label}`;
					case 'worker_bootstrap_candidate_rejected':
						return `Bootstrap candidate #${event.candidate.id} rejected`;
					case 'worker_bootstrap_job_queued':
						return `Bootstrap job #${event.job.id} queued for ${formatHostPort(event.job.discovered_host, event.job.discovered_port)} via ${event.job.provisioner}`;
					case 'worker_bootstrap_job_started':
						return `Bootstrap job #${event.job.id} started on ${event.job.claimed_by_worker_id || 'bootstrap worker'}`;
					case 'worker_bootstrap_job_completed':
						return `Bootstrap job #${event.job.id} completed for ${formatHostPort(event.job.discovered_host, event.job.discovered_port)}`;
					case 'worker_bootstrap_job_failed':
						return `Bootstrap job #${event.job.id} failed: ${event.error}`;
					case 'run_queued':
						return `Run #${event.run.id} queued by ${event.run.requested_by || 'system'}`;
					case 'run_started':
						return `Run #${event.run.id} started`;
					case 'stats_updated': {
						const progress = event.summary.progress || {};
						return `Run #${event.run_id} progress ${event.summary.completed_targets}/${event.summary.total_targets} targets • ${progress.in_progress_targets || 0} active • ${progress.failed_targets || 0} failed`;
					}
					case 'finding_recorded':
						return `Finding ${event.finding.detector} on ${event.finding.target_label}`;
					case 'public_finding_moderated': {
						const action = formatHumanLabel(event.finding?.status || 'reviewed');
						const detector = event.finding?.detector
							? ` • ${event.finding.detector}`
							: '';
						return `Public disclosure for finding #${event.finding?.finding_id || 'unknown'} marked ${action}${detector}`;
					}
					case 'run_completed':
						return `Run #${event.run.id} completed with ${event.summary.findings_total} findings`;
					case 'run_failed':
						return `Run #${event.run.id} failed: ${event.error}`;
					default:
						return 'Received runtime event';
				}
			}

			async function loadDashboard() {
				if (state.dashboardLoading) {
					return;
				}
				state.dashboardLoading = true;
				try {
					const snapshot = await request('/api/dashboard');
					state.dashboardSnapshot = snapshot;
					syncBootstrapProvisionerOptions(snapshot);
					applyWorkerManagementVisibility();
					safeRender('summary', () => renderSummary(snapshot.latest_run, snapshot.latest_summary));
					safeRender('workerMetrics', () => renderWorkerMetrics(snapshot));
					safeRender('workerPools', () => renderWorkerPools(snapshot.worker_pools || []));
					safeRender('portScans', () => renderPortScans(snapshot.recent_port_scans || []));
					safeRender('workers', () => renderWorkers(snapshot.workers || []));
					safeRender('workerRemoteCommands', () => renderWorkerRemoteCommands(
						snapshot.recent_worker_remote_commands || []
					));
					safeRender('workerEnrollmentTokens', () => renderWorkerEnrollmentTokens(
						snapshot.worker_enrollment_tokens || []
					));
					safeRender('bootstrapCandidates', () => renderBootstrapCandidates(snapshot.bootstrap_candidates || []));
					safeRender('bootstrapJobs', () => renderBootstrapJobs(snapshot.bootstrap_jobs || []));
					safeRender('bootstrapCandidateOptions', () => syncBootstrapCandidateOptions(
						snapshot.bootstrap_candidates || []
					));
					safeRender('targets', () => renderTargets(snapshot.targets || []));
					safeRender('repositories', () => renderRepositories(
						snapshot.repositories || [],
						snapshot.targets || []
					));
					safeRender('runs', () => renderRuns(snapshot.recent_runs || []));
					safeRender('schedules', () => renderSchedules(snapshot.schedules || []));
					safeRender('failedTargets', () => renderFailedTargets(snapshot.latest_failed_targets || []));
					safeRender('detectorDistribution', () => renderDetectorDistribution(
						snapshot.latest_detector_distribution || []
					));
					safeRender('coverageSources', () => renderCoverageSources(
						snapshot.latest_summary?.coverage_sources || []
					));
					safeRender('gobusterDefaults', () => renderGobusterDefaults(snapshot.scan_defaults || {}));
					safeRender('binDatasetStatus', () => renderBinDatasetStatus(snapshot.bin_dataset_status || null));
					safeRender('archiveStatus', () => renderArchiveStatus(snapshot.archive_status || null));
					await safeAsync('findings', loadFindings);
					await safeAsync('pluginCatalog', loadPluginCatalog);
					safeRender('activeAuthorizedGateUi', syncActiveAuthorizedGateUi);
					if (elements.connectionState) {
						if (elements.connectionState) elements.connectionState.textContent =
							'Dashboard updated successfully.';
					}
				} finally {
					state.dashboardLoading = false;
				}
			}

			async function ensureSession() {
				try {
					const session = await request('/api/me', { method: 'GET' });
					setAuthenticated(session);
					await loadDashboard();
					connectEvents();
				} catch (error) {
					if (error.status === 401) {
						setUnauthenticated();
						return;
					}
					handleRequestError(
						error,
						'Unable to initialize dashboard.'
					);
				}
			}

			function connectEvents() {
				if (!state.authenticated || state.eventSource) {
					return;
				}
				// Pages without an events sink don't need a live activity stream.
				if (!elements.eventsList) {
					return;
				}

				const source = new EventSource('/api/events/stream');
				source.addEventListener('api_event', message => {
					try {
						const payload = JSON.parse(message.data);
						applyApiEvent(payload);
						prependEvent(describeEvent(payload));
						if (elements.connectionState) {
							if (elements.connectionState) elements.connectionState.textContent =
								'Live event stream connected.';
						}
						scheduleRefresh();
					} catch (error) {
						console.error('Failed to decode event payload', error);
					}
				});
				source.addEventListener('keepalive', () => {
					if (elements.connectionState) elements.connectionState.textContent =
						'Live event stream connected.';
				});
				source.onerror = async () => {
					closeEvents();
					if (elements.connectionState) elements.connectionState.textContent =
						'Live event stream reconnecting.';
					try {
						await request('/api/me', { method: 'GET' });
						if (state.authenticated) {
							state.reconnectTimer = setTimeout(
								connectEvents,
								1500
							);
						}
					} catch (error) {
						if (error.status === 401) {
							setUnauthenticated(
								'Session expired. Sign in again.'
							);
						}
					}
				};
				state.eventSource = source;
			}

			function splitList(value) {
				return value
					.split(',')
					.map(item => item.trim())
					.filter(Boolean);
			}

			function splitNumericList(value) {
				return splitList(value)
					.map(item => Number(item))
					.filter(item => Number.isInteger(item) && item > 0);
			}

			function normalizePositiveInteger(value) {
				const numeric = Number(value);
				return Number.isInteger(numeric) && numeric > 0
					? numeric
					: null;
			}

			function normalizeOptionalText(value) {
				const normalized = String(value || '').trim();
				return normalized ? normalized : null;
			}

			function normalizeWorkerPoolFilterValue(value) {
				return String(value || '').trim().toLowerCase();
			}

			function matchesWorkerPoolFilter(workerPool, filterValue) {
				const filter = normalizeWorkerPoolFilterValue(filterValue);
				if (!filter) {
					return true;
				}
				const normalizedPool = normalizeWorkerPoolFilterValue(
					workerPool || ''
				);
				if (['unassigned', 'none', 'global', 'any'].includes(filter)) {
					return !normalizedPool;
				}
				return normalizedPool.includes(filter);
			}

			function hasActiveFindingsQuery(query) {
				if (!query || typeof query !== 'object') {
					return false;
				}
				return Boolean(
					normalizeOptionalText(query.q) ||
						normalizeOptionalText(query.severity) ||
						normalizeOptionalText(query.confidence) ||
						normalizeOptionalText(query.detector) ||
						normalizeOptionalText(query.plugin_id) ||
						normalizeOptionalText(query.plugin_family) ||
						normalizeOptionalText(query.execution_mode) ||
						normalizeOptionalText(query.leakix_label) ||
						normalizeOptionalText(query.path_prefix) ||
						(Array.isArray(query.tags) &&
							query.tags.some(tag => normalizeOptionalText(tag))) ||
						(Array.isArray(query.review_labels) &&
							query.review_labels.some(label =>
								normalizeOptionalText(label)
							)) ||
						normalizePositiveInteger(query.run_id) ||
						normalizePositiveInteger(query.target_id) ||
						normalizePositiveInteger(query.limit)
				);
			}

			function buildFindingsQuery() {
				const query = {
					q: document.getElementById('findings-query').value.trim(),
					severity: document
						.getElementById('findings-severity')
						.value.trim(),
					confidence: document
						.getElementById('findings-confidence')
						.value.trim(),
					detector: document
						.getElementById('findings-detector')
						.value.trim(),
					plugin_id: document
						.getElementById('findings-plugin-id')
						.value.trim(),
					plugin_family: document
						.getElementById('findings-plugin-family')
						.value.trim(),
					execution_mode: document
						.getElementById('findings-execution-mode')
						.value.trim(),
					leakix_label: document
						.getElementById('findings-leakix-label')
						.value.trim(),
					path_prefix: document
						.getElementById('findings-path-prefix')
						.value.trim(),
					tags: splitList(
						document.getElementById('findings-tags').value.trim()
					),
					review_labels: splitList(
						document
							.getElementById('findings-review-labels')
							.value.trim()
					),
					run_id: normalizePositiveInteger(
						document.getElementById('findings-run-id').value.trim()
					),
					target_id: normalizePositiveInteger(
						document
							.getElementById('findings-target-id')
							.value.trim()
					),
					limit: normalizePositiveInteger(
						document.getElementById('findings-limit').value.trim()
					)
				};

				if (!query.q) {
					delete query.q;
				}
				if (!query.severity) {
					delete query.severity;
				}
				if (!query.confidence) {
					delete query.confidence;
				}
				if (!query.detector) {
					delete query.detector;
				}
				if (!query.plugin_id) {
					delete query.plugin_id;
				}
				if (!query.plugin_family) {
					delete query.plugin_family;
				}
				if (!query.execution_mode) {
					delete query.execution_mode;
				}
				if (!query.leakix_label) {
					delete query.leakix_label;
				}
				if (!query.path_prefix) {
					delete query.path_prefix;
				}
				if (!query.tags.length) {
					delete query.tags;
				}
				if (!query.review_labels.length) {
					delete query.review_labels;
				}
				if (!query.run_id) {
					delete query.run_id;
				}
				if (!query.target_id) {
					delete query.target_id;
				}
				if (!query.limit) {
					delete query.limit;
				} else {
					query.limit = Math.max(1, Math.min(250, query.limit));
				}

				return hasActiveFindingsQuery(query) ? query : null;
			}

			function findingsQueryToSearchParams(query) {
				const params = new URLSearchParams();
				if (!query) {
					return params;
				}

				if (query.limit) {
					params.set('limit', String(query.limit));
				}
				if (query.run_id) {
					params.set('run_id', String(query.run_id));
				}
				if (query.target_id) {
					params.set('target_id', String(query.target_id));
				}
				if (query.severity) {
					params.set('severity', query.severity);
				}
				if (query.confidence) {
					params.set('confidence', query.confidence);
				}
				if (query.detector) {
					params.set('detector', query.detector);
				}
				if (query.plugin_id) {
					params.set('plugin_id', query.plugin_id);
				}
				if (query.plugin_family) {
					params.set('plugin_family', query.plugin_family);
				}
				if (query.execution_mode) {
					params.set('execution_mode', query.execution_mode);
				}
				if (query.leakix_label) {
					params.set('leakix_label', query.leakix_label);
				}
				if (query.path_prefix) {
					params.set('path_prefix', query.path_prefix);
				}
				if (query.q) {
					params.set('q', query.q);
				}
				(query.tags || []).forEach(tag => params.append('tags', tag));
				(query.review_labels || []).forEach(label =>
					params.append('review_labels', label)
				);
				return params;
			}

			function describeFindingsQuery(query) {
				if (!hasActiveFindingsQuery(query)) {
					return 'Showing recent findings from the latest dashboard snapshot.';
				}

				const parts = [];
				if (query.q) {
					parts.push(`text "${query.q}"`);
				}
				if (query.severity) {
					parts.push(`severity ${query.severity}`);
				}
				if (query.confidence) {
					parts.push(`confidence ${query.confidence}`);
				}
				if (query.detector) {
					parts.push(`detector ${query.detector}`);
				}
				if (query.plugin_id) {
					parts.push(`plugin ${query.plugin_id}`);
				}
				if (query.plugin_family) {
					parts.push(
						`family ${formatPluginCatalogValue(query.plugin_family)}`
					);
				}
				if (query.execution_mode) {
					parts.push(
						`mode ${formatPluginCatalogValue(query.execution_mode)}`
					);
				}
				if (query.leakix_label) {
					parts.push(
						`label ${formatPluginCatalogValue(query.leakix_label)}`
					);
				}
				if (query.path_prefix) {
					parts.push(`path ${query.path_prefix}`);
				}
				if (query.tags && query.tags.length) {
					parts.push(`tags ${query.tags.join(', ')}`);
				}
				if (query.review_labels && query.review_labels.length) {
					parts.push(
						`review labels ${query.review_labels.join(', ')}`
					);
				}
				if (query.run_id) {
					parts.push(`run #${query.run_id}`);
				}
				if (query.target_id) {
					parts.push(`target #${query.target_id}`);
				}
				if (query.limit) {
					parts.push(`limit ${query.limit}`);
				}
				return `Showing findings filtered by ${parts.join(' • ')}.`;
			}

			function formatPluginCatalogValue(value) {
				return String(value || '')
					.split('_')
					.map(part =>
						part ? `${part[0].toUpperCase()}${part.slice(1)}` : ''
					)
					.join(' ');
			}

			function formatFindingConfidence(value) {
				return value
					? `Confidence ${formatPluginCatalogValue(value)}`
					: 'Confidence unknown';
			}

			function formatImplementationSource(value) {
				return value
					? formatPluginCatalogValue(value)
					: 'Implementation source unavailable';
			}

			function formatCoverageStatus(value) {
				return value
					? formatPluginCatalogValue(value)
					: 'Coverage unavailable';
			}

			function normalizeBooleanLike(value) {
				if (typeof value === 'boolean') {
					return value;
				}
				if (typeof value === 'number') {
					return value !== 0;
				}
				if (typeof value === 'string') {
					const normalized = value.trim().toLowerCase();
					if (normalized === 'true') {
						return true;
					}
					if (normalized === 'false') {
						return false;
					}
				}
				return null;
			}

			function lookupPolicyBoolean(candidates, keys) {
				for (const candidate of candidates) {
					if (!candidate || typeof candidate !== 'object') {
						continue;
					}
					for (const key of keys) {
						const normalized = normalizeBooleanLike(candidate[key]);
						if (normalized !== null) {
							return normalized;
						}
					}
				}
				return null;
			}

			function resolveActiveAuthorizedGateState() {
				const candidates = [
					state.dashboardSnapshot?.plugin_execution_policy,
					state.dashboardSnapshot?.active_authorized_execution_policy,
					state.dashboardSnapshot?.plugin_policy,
					state.pluginCatalog?.policy,
					state.pluginCatalog?.summary
				];
				const supported = lookupPolicyBoolean(candidates, [
					'active_authorized_supported',
					'supports_active_authorized',
					'active_authorized_available'
				]);
				const enabled = lookupPolicyBoolean(candidates, [
					'active_authorized_gate_enabled',
					'active_authorized_enabled',
					'allow_active_authorized_execution'
				]);
				if (enabled === true) {
					return {
						shortLabel: 'Gate enabled',
						note: 'Global active-authorized execution is enabled. Opted-in runs, schedules, and port scans can execute active-authorized plugins.',
						enabled: true,
						supported
					};
				}
				if (enabled === false) {
					return {
						shortLabel: 'Gate disabled',
						note: 'Global active-authorized execution is disabled. Opt-in controls stay visible but active-authorized plugins remain suppressed until the gate is enabled.',
						enabled: false,
						supported
					};
				}
				if (supported === false) {
					return {
						shortLabel: 'Gate unavailable',
						note: 'This server does not publish active-authorized execution support yet. The UI keeps the controls visible for forward compatibility and defaults them to off.',
						enabled: null,
						supported: false
					};
				}
				return {
					shortLabel: 'Gate pending',
					note: 'Active-authorized execution support has not been published by the server yet. Controls default to off and should be treated as no-op until backend support lands.',
					enabled: null,
					supported: null
				};
			}

			function syncActiveAuthorizedGateUi() {
				const gate = resolveActiveAuthorizedGateState();
				[
					elements.runActiveAuthorizedGate,
					elements.scheduleActiveAuthorizedGate,
					elements.portScanActiveAuthorizedGate
				]
					.filter(Boolean)
					.forEach(element => {
						element.textContent = gate.shortLabel;
					});
				[
					elements.runActiveAuthorizedNote,
					elements.scheduleActiveAuthorizedNote,
					elements.portScanActiveAuthorizedNote,
					elements.pluginCatalogGateNote
				]
					.filter(Boolean)
					.forEach(element => {
						element.textContent = gate.note;
					});
			}

			function buildActiveAuthorizedExecutionPayload(checkboxId) {
				return {
					enabled: Boolean(document.getElementById(checkboxId)?.checked)
				};
			}

			function normalizeActiveAuthorizedExecution(record) {
				if (!record || typeof record !== 'object') {
					return null;
				}
				if (typeof record.active_authorized_execution === 'object') {
					const normalized = normalizeBooleanLike(
						record.active_authorized_execution?.enabled
					);
					if (normalized !== null) {
						return normalized;
					}
				}
				const rootKeys = [
					'allow_active_authorized_execution',
					'active_authorized_enabled',
					'allow_active_authorized_plugins'
				];
				for (const key of rootKeys) {
					const normalized = normalizeBooleanLike(record[key]);
					if (normalized !== null) {
						return normalized;
					}
				}
				return null;
			}

			function describeActiveAuthorizedExecution(record) {
				const enabled = normalizeActiveAuthorizedExecution(record);
				if (enabled === true) {
					return 'Active-authorized opt-in enabled';
				}
				if (enabled === false) {
					return 'Active-authorized opt-in off';
				}
				return null;
			}

			function hasActivePluginCatalogQuery(query) {
				if (!query || typeof query !== 'object') {
					return false;
				}
				return Boolean(
					normalizeOptionalText(query.q) ||
						normalizeOptionalText(query.family) ||
						normalizeOptionalText(query.leakix_label) ||
						normalizeOptionalText(query.execution_mode) ||
						normalizeOptionalText(query.status) ||
						normalizeOptionalText(query.coverage_status) ||
						normalizePositiveInteger(query.limit)
				);
			}

			function buildPluginCatalogQuery() {
				const query = {
					q: document.getElementById('plugins-query').value.trim(),
					family: document.getElementById('plugins-family').value.trim(),
					leakix_label: document
						.getElementById('plugins-label')
						.value.trim(),
					execution_mode: document
						.getElementById('plugins-execution-mode')
						.value.trim(),
					status: document
						.getElementById('plugins-status')
						.value.trim(),
					coverage_status: document
						.getElementById('plugins-coverage-status')
						.value.trim(),
					limit: normalizePositiveInteger(
						document.getElementById('plugins-limit').value.trim()
					)
				};

				Object.keys(query).forEach(key => {
					if (!query[key]) {
						delete query[key];
					}
				});
				if (query.limit) {
					query.limit = Math.max(1, Math.min(500, query.limit));
				}
				return hasActivePluginCatalogQuery(query) ? query : null;
			}

			function pluginCatalogQueryToSearchParams(query) {
				const params = new URLSearchParams();
				if (!query) {
					return params;
				}
				Object.entries(query).forEach(([key, value]) => {
					if (value) {
						params.set(key, String(value));
					}
				});
				return params;
			}

			function describePluginCatalogQuery(response, query) {
				const summary = response?.summary || {};
				const filteredTotal = Array.isArray(response?.plugins)
					? response.plugins.length
					: 0;
				const base = `${filteredTotal} shown • ${summary.total || 0} total • ${summary.first_class_total || 0} first class • ${summary.external_scanner_only_total || 0} external scanner only`;
				if (!hasActivePluginCatalogQuery(query)) {
					return `Showing full plugin catalog. ${base}.`;
				}

				const parts = [];
				if (query.q) {
					parts.push(`text "${query.q}"`);
				}
				if (query.family) {
					parts.push(`family ${formatPluginCatalogValue(query.family)}`);
				}
				if (query.leakix_label) {
					parts.push(`label ${formatPluginCatalogValue(query.leakix_label)}`);
				}
				if (query.execution_mode) {
					parts.push(
						`mode ${formatPluginCatalogValue(query.execution_mode)}`
					);
				}
				if (query.status) {
					parts.push(`status ${formatPluginCatalogValue(query.status)}`);
				}
				if (query.coverage_status) {
					parts.push(
						`coverage ${formatCoverageStatus(query.coverage_status)}`
					);
				}
				if (query.limit) {
					parts.push(`limit ${query.limit}`);
				}
				return `Showing plugins filtered by ${parts.join(' • ')}. ${base}.`;
			}

			function renderPluginCatalog(response) {
				state.pluginCatalog = response || null;
				const plugins = Array.isArray(response?.plugins)
					? response.plugins
					: [];
				elements.pluginCatalogList.replaceChildren();
				elements.pluginCatalogEmpty.classList.toggle(
					'hidden',
					plugins.length > 0
				);
				elements.pluginCatalogEmpty.textContent = hasActivePluginCatalogQuery(
					state.pluginCatalogQuery
				)
					? 'No plugin entries matched the current filters.'
					: 'No plugin entries are available right now.';
				elements.pluginQueryStatus.textContent = describePluginCatalogQuery(
					response,
					state.pluginCatalogQuery
				);
				if (!response?.summary) {
					elements.pluginCatalogNote.textContent =
						'Plugin catalog data is not available yet.';
					return;
				}

				elements.pluginCatalogNote.textContent = `Modeled registry: ${response.summary.total} total • ${response.summary.first_class_total} first class • ${response.summary.external_scanner_only_total} external scanner only • ${response.summary.public_total} Public • ${response.summary.trusted_pro_total} Trusted / Pro.`;
				syncActiveAuthorizedGateUi();

				plugins.forEach(plugin => {
					const item = document.createElement('li');
					item.className = 'list-item';

					const heading = document.createElement('div');
					heading.className = 'finding-heading';
					const label = document.createElement('strong');
					label.textContent = `${plugin.plugin_id} • ${plugin.display_name}`;
					heading.append(
						label,
						statusBadge(plugin.leakix_label),
						statusBadge(plugin.family),
						statusBadge(plugin.execution_mode),
						statusBadge(plugin.status)
					);
					if (plugin.coverage_status) {
						heading.appendChild(
							createPill(
								formatCoverageStatus(plugin.coverage_status)
							)
						);
					}
					if (plugin.implementation_source) {
						heading.appendChild(
							createPill(
								formatImplementationSource(
									plugin.implementation_source
								)
							)
						);
					}

					const details = document.createElement('small');
					details.className = 'muted';
					const notes = plugin.notes ? ` • ${plugin.notes}` : '';
					const activeFlag = plugin.requires_authorized_active_mode
						? ` • requires authorized active mode (${resolveActiveAuthorizedGateState().shortLabel.toLowerCase()})`
						: '';
					const coverage = plugin.coverage_status
						? ` • ${formatCoverageStatus(plugin.coverage_status)}`
						: '';
					const implementationSource = plugin.implementation_source
						? ` • ${formatImplementationSource(plugin.implementation_source)}`
						: '';
					const coverageNote = plugin.coverage_note
						? ` • ${plugin.coverage_note}`
						: '';
					details.textContent = `Default severity ${plugin.default_severity}${coverage}${implementationSource}${notes}${activeFlag}${coverageNote}`;

					item.append(heading, details);
					elements.pluginCatalogList.appendChild(item);
				});
			}

			async function loadPluginCatalog() {
				if (!elements.pluginCatalogList && !elements.pluginQueryForm) return;
				const params = pluginCatalogQueryToSearchParams(
					state.pluginCatalogQuery
				);
				const suffix = params.toString() ? `?${params.toString()}` : '';
				const response = await request(`/api/plugins${suffix}`, {
					method: 'GET'
				});
				if (elements.pluginQueryError) elements.pluginQueryError.classList.add('hidden');
				safeRender('pluginCatalog (load)', () => renderPluginCatalog(response));
			}

			async function resetPluginCatalogSearch() {
				state.pluginCatalogQuery = null;
				if (elements.pluginQueryForm) elements.pluginQueryForm.reset();
				if (elements.pluginQueryError) elements.pluginQueryError.classList.add('hidden');
				await loadPluginCatalog();
			}

			async function loadFindings() {
				if (!elements.findingsList && !elements.findingsQueryForm) return;
				await loadFindingPublications();
				if (!hasActiveFindingsQuery(state.findingsQuery)) {
					if (elements.findingsQueryError) elements.findingsQueryError.classList.add('hidden');
					safeRender('findings (loadFindings, no query)', () =>
						renderFindings(state.dashboardSnapshot?.recent_findings || [])
					);
					if (elements.findingsQueryStatus) {
						elements.findingsQueryStatus.textContent = describeFindingsQuery(null);
					}
					return;
				}

				const params = findingsQueryToSearchParams(state.findingsQuery);
				const findings = await request(
					`/api/findings?${params.toString()}`,
					{ method: 'GET' }
				);
				if (elements.findingsQueryError) elements.findingsQueryError.classList.add('hidden');
				safeRender('findings (loadFindings, queried)', () => renderFindings(findings || []));
				if (elements.findingsQueryStatus) {
					elements.findingsQueryStatus.textContent = describeFindingsQuery(state.findingsQuery);
				}
			}

			async function resetFindingsSearch() {
				state.findingsQuery = null;
				if (elements.findingsQueryForm) elements.findingsQueryForm.reset();
				if (elements.findingsQueryError) elements.findingsQueryError.classList.add('hidden');
				await loadFindingPublications();
				safeRender('findings (resetSearch)', () =>
					renderFindings(state.dashboardSnapshot?.recent_findings || [])
				);
				if (elements.findingsQueryStatus) {
					elements.findingsQueryStatus.textContent = describeFindingsQuery(null);
				}
			}

			function buildRunScope(
				targetIdsInputId,
				tagsInputId,
				failedOnlyInputId,
				workerPoolInputId
			) {
				const targetIds = splitNumericList(
					document.getElementById(targetIdsInputId).value.trim()
				);
				const tags = splitList(
					document.getElementById(tagsInputId).value.trim()
				);
				const workerPool = normalizeOptionalText(
					document.getElementById(workerPoolInputId).value.trim()
				);
				const failedOnly =
					document.getElementById(failedOnlyInputId).checked;
				if (!targetIds.length && !tags.length && !workerPool && !failedOnly) {
					return null;
				}
				return {
					target_ids: targetIds,
					tags,
					worker_pool: workerPool,
					failed_only: failedOnly
				};
			}

			function resetRunScope(
				targetIdsInputId,
				tagsInputId,
				failedOnlyInputId,
				workerPoolInputId
			) {
				document.getElementById(targetIdsInputId).value = '';
				document.getElementById(tagsInputId).value = '';
				document.getElementById(workerPoolInputId).value = '';
				document.getElementById(failedOnlyInputId).checked = false;
			}

			function buildPortScanPayload() {
				const bootstrapEnabled = Boolean(
					document.getElementById('port-scan-bootstrap-enabled')
						?.checked
				);
				const followOnEnabled = Boolean(
					document.getElementById('port-scan-follow-on-enabled')
						?.checked
				);
				return {
					target_range: document
						.getElementById('port-scan-target-range')
						.value.trim(),
					ports: document
						.getElementById('port-scan-ports')
						.value.trim(),
					schemes:
						document
							.getElementById('port-scan-schemes')
							.value.trim() || 'auto',
					tags: splitList(
						document.getElementById('port-scan-tags').value.trim()
					),
					rate_limit:
						normalizePositiveInteger(
							document
								.getElementById('port-scan-rate-limit')
								.value.trim()
						) || 0,
					scanner_sender_threads: normalizePositiveInteger(
						document
							.getElementById('port-scan-sender-threads')
							.value.trim()
					),
					scanner_receiver_threads: normalizePositiveInteger(
						document
							.getElementById('port-scan-receiver-threads')
							.value.trim()
					),
					worker_pool: normalizeOptionalText(
						document.getElementById('port-scan-worker-pool').value
					),
					follow_on_run_policy: {
						enabled: followOnEnabled,
						worker_pool: followOnEnabled
							? normalizeOptionalText(
									document.getElementById(
										'port-scan-follow-on-pool'
									).value
								)
							: null,
						selection_mode:
							document.getElementById(
								'port-scan-follow-on-selection-mode'
							).value || 'validated'
					},
					bootstrap_policy: {
						enabled: bootstrapEnabled,
						worker_pool: bootstrapEnabled
							? normalizeOptionalText(
									document.getElementById(
										'port-scan-bootstrap-pool'
									).value
								)
							: null,
						tags: bootstrapEnabled
							? splitList(
									document
										.getElementById(
											'port-scan-bootstrap-tags'
										)
										.value.trim()
								)
							: []
					},
					active_authorized_execution:
						buildActiveAuthorizedExecutionPayload(
							'port-scan-active-authorized-enabled'
						)
				};
			}

			function buildScanSettingsPayload() {
				const wordlist = splitList(
					document
						.getElementById('scan-directory-probing-wordlist')
						.value.trim()
				);
				const extensions = splitList(
					document
						.getElementById('scan-directory-probing-extensions')
						.value.trim()
				);
				return {
					request_engine_mode:
						document.getElementById('scan-request-engine-mode').value ||
						'staged',
					concurrency:
						normalizePositiveInteger(
							document
								.getElementById('scan-concurrency')
								.value.trim()
						) || 0,
					probe_concurrency:
						normalizePositiveInteger(
							document
								.getElementById('scan-probe-concurrency')
								.value.trim()
						) || 0,
					connect_timeout_secs:
						normalizePositiveInteger(
							document
								.getElementById('scan-connect-timeout-secs')
								.value.trim()
						) || 0,
					probe_request_timeout_secs:
						normalizePositiveInteger(
							document
								.getElementById(
									'scan-probe-request-timeout-secs'
								)
								.value.trim()
						) || 0,
					deep_request_timeout_secs:
						normalizePositiveInteger(
							document
								.getElementById(
									'scan-deep-request-timeout-secs'
								)
								.value.trim()
						) || 0,
					request_timeout_secs:
						normalizePositiveInteger(
							document
								.getElementById('scan-request-timeout-secs')
								.value.trim()
						) || 0,
					max_response_bytes:
						normalizePositiveInteger(
							document
								.getElementById('scan-max-response-bytes')
								.value.trim()
						) || 0,
					max_paths_per_target:
						normalizePositiveInteger(
							document
								.getElementById('scan-max-paths-per-target')
								.value.trim()
						) || 0,
					max_parallel_paths_per_target:
						normalizePositiveInteger(
							document
								.getElementById(
									'scan-max-parallel-paths-per-target'
								)
								.value.trim()
						) || 0,
					probe_max_concurrent_requests_per_host:
						normalizePositiveInteger(
							document
								.getElementById(
									'scan-probe-max-concurrent-requests-per-host'
								)
								.value.trim()
						) || 0,
					deep_max_concurrent_requests_per_host:
						normalizePositiveInteger(
							document
								.getElementById(
									'scan-deep-max-concurrent-requests-per-host'
								)
								.value.trim()
						) || 0,
					max_concurrent_requests_per_host:
						normalizePositiveInteger(
							document
								.getElementById(
									'scan-max-concurrent-requests-per-host'
								)
								.value.trim()
						) || 0,
					enable_path_discovery: document.getElementById(
						'scan-enable-path-discovery'
					).checked,
					max_discovered_paths_per_target:
						normalizePositiveInteger(
							document
								.getElementById(
									'scan-max-discovered-paths-per-target'
								)
								.value.trim()
						) || 0,
					host_backoff_initial_ms:
						normalizePositiveInteger(
							document
								.getElementById('scan-host-backoff-initial-ms')
								.value.trim()
						) || 0,
					host_backoff_max_ms:
						normalizePositiveInteger(
							document
								.getElementById('scan-host-backoff-max-ms')
								.value.trim()
						) || 0,
					poll_interval_seconds:
						normalizePositiveInteger(
							document
								.getElementById('scan-poll-interval-seconds')
								.value.trim()
						) || 0,
					allow_invalid_tls: document.getElementById(
						'scan-allow-invalid-tls'
					).checked,
					directory_probing_enabled: document.getElementById(
						'scan-directory-probing-enabled'
					).checked,
					directory_probing_wordlist_count: wordlist.length,
					directory_probing_wordlist: wordlist,
					directory_probing_extensions: extensions,
					directory_probing_add_slash: document.getElementById(
						'scan-directory-probing-add-slash'
					).checked,
					directory_probing_discover_backup: document.getElementById(
						'scan-directory-probing-discover-backup'
					).checked
				};
			}

			function buildBinDatasetImportPayload() {
				const repositoryId = normalizePositiveInteger(
					document
						.getElementById('bin-dataset-repository-id')
						.value.trim()
				);
				const localPath = document
					.getElementById('bin-dataset-local-path')
					.value.trim();
				const csvPath = document
					.getElementById('bin-dataset-csv-path')
					.value.trim();
				return {
					repository_id: repositoryId || null,
					local_path: localPath || null,
					csv_path: csvPath || null
				};
			}

			function buildBinLookupPayload() {
				const text = document.getElementById('bin-lookup-text').value;
				const limit = normalizePositiveInteger(
					document.getElementById('bin-lookup-limit').value.trim()
				);
				return {
					text,
					limit: limit || null
				};
			}

			function buildWorkerEnrollmentTokenPayload() {
				return {
					label: document
						.getElementById('worker-token-label')
						.value.trim(),
					worker_pool: normalizeOptionalText(
						document.getElementById('worker-token-pool').value
					),
					tags: splitList(
						document
							.getElementById('worker-token-tags')
							.value.trim()
					),
					allow_runs: document.getElementById(
						'worker-token-allow-runs'
					).checked,
					allow_port_scans: document.getElementById(
						'worker-token-allow-port-scans'
					).checked,
					allow_bootstrap: document.getElementById(
						'worker-token-allow-bootstrap'
					).checked,
					single_use: document.getElementById(
						'worker-token-single-use'
					).checked,
					expires_in_seconds: normalizePositiveInteger(
						document
							.getElementById('worker-token-expiry')
							.value.trim()
					)
				};
			}

			function buildBootstrapApprovalPayload() {
				const dispatchEnabled = Boolean(
					elements.bootstrapDispatchEnabled?.checked
				);
				return {
					label: normalizeOptionalText(
						document.getElementById('bootstrap-label').value
					),
					worker_pool: normalizeOptionalText(
						document.getElementById('bootstrap-pool').value
					),
					tags: splitList(
						document.getElementById('bootstrap-tags').value.trim()
					),
					allow_runs: document.getElementById('bootstrap-allow-runs')
						.checked,
					allow_port_scans: document.getElementById(
						'bootstrap-allow-port-scans'
					).checked,
					allow_bootstrap: document.getElementById(
						'bootstrap-allow-bootstrap'
					).checked,
					single_use: document.getElementById('bootstrap-single-use')
						.checked,
					expires_in_seconds: normalizePositiveInteger(
						document.getElementById('bootstrap-expiry').value.trim()
					),
					notes: normalizeOptionalText(
						document.getElementById('bootstrap-notes').value
					),
					dispatch: dispatchEnabled
						? {
								enabled: true,
								provisioner: normalizeOptionalText(
									elements.bootstrapDispatchProvisioner.value
								),
								executor_worker_pool: normalizeOptionalText(
									elements.bootstrapDispatchExecutorPool.value
								),
								executor_tags: splitList(
									elements.bootstrapDispatchExecutorTags.value.trim()
								),
								notes: normalizeOptionalText(
									elements.bootstrapDispatchNotes.value
								)
							}
						: {
								enabled: false,
								provisioner: null,
								executor_worker_pool: null,
								executor_tags: [],
								notes: null
							}
				};
			}

			function buildBootstrapRejectionPayload() {
				return {
					notes: normalizeOptionalText(
						document.getElementById('bootstrap-notes').value
					)
				};
			}

			function formatRunScope(scope) {
				if (!scope) {
					return 'all enabled targets';
				}
				const parts = [];
				if (scope.target_ids && scope.target_ids.length) {
					parts.push(`Targets ${scope.target_ids.join(', ')}`);
				}
				if (scope.tags && scope.tags.length) {
					parts.push(`Tags ${scope.tags.join(', ')}`);
				}
				if (scope.worker_pool) {
					parts.push(`Pool ${scope.worker_pool}`);
				}
				if (scope.failed_only) {
					parts.push('Failed only');
				}
				return parts.length ? parts.join(' • ') : 'all enabled targets';
			}

			function handleRequestError(error, fallbackMessage) {
				console.error(error);
				if (error.status === 401) {
					setUnauthenticated('Session expired. Sign in again.');
					return;
				}
				if (elements.connectionState) elements.connectionState.textContent =
					error.message || fallbackMessage;
			}

			elements.findingsQueryForm.addEventListener(
				'submit',
				async event => {
					event.preventDefault();
					elements.findingsQueryError.classList.add('hidden');
					state.findingsQuery = buildFindingsQuery();

					try {
						await loadFindings();
					} catch (error) {
						elements.findingsQueryError.textContent =
							error.message || 'Failed to search findings.';
						elements.findingsQueryError.classList.remove('hidden');
					}
				}
			);

			elements.findingsQueryResetButton.addEventListener(
				'click',
				async () => {
					try {
						await resetFindingsSearch();
					} catch (error) {
						elements.findingsQueryError.textContent =
							error.message || 'Failed to reset findings search.';
						elements.findingsQueryError.classList.remove('hidden');
						return;
					}
					if (!state.dashboardSnapshot) {
						try {
							await loadDashboard();
						} catch (error) {
							handleRequestError(
								error,
								'Failed to refresh dashboard.'
							);
						}
					}
				}
			);

			elements.runsWorkerPoolFilter?.addEventListener('input', () => {
				state.runWorkerPoolFilter =
					elements.runsWorkerPoolFilter.value || '';
				safeRender('runs (filter)', () =>
					renderRuns(state.dashboardSnapshot?.recent_runs || [])
				);
			});

			elements.workersWorkerPoolFilter?.addEventListener('input', () => {
				state.workerPoolFilter =
					elements.workersWorkerPoolFilter.value || '';
				safeRender('workers (pool filter)', () =>
					renderWorkers(state.dashboardSnapshot?.workers || [])
				);
			});

			elements.workersHealthFilter?.addEventListener('change', () => {
				state.workerHealthFilter =
					elements.workersHealthFilter.value || 'all';
				safeRender('workers (health filter)', () =>
					renderWorkers(state.dashboardSnapshot?.workers || [])
				);
			});

			elements.pluginQueryForm.addEventListener('submit', async event => {
				event.preventDefault();
				elements.pluginQueryError.classList.add('hidden');
				state.pluginCatalogQuery = buildPluginCatalogQuery();

				try {
					await loadPluginCatalog();
				} catch (error) {
					elements.pluginQueryError.textContent =
						error.message || 'Failed to filter plugin catalog.';
					elements.pluginQueryError.classList.remove('hidden');
				}
			});

			elements.pluginQueryResetButton.addEventListener(
				'click',
				async () => {
					try {
						await resetPluginCatalogSearch();
					} catch (error) {
						elements.pluginQueryError.textContent =
							error.message ||
							'Failed to reset plugin catalog filters.';
						elements.pluginQueryError.classList.remove('hidden');
					}
				}
			);

			elements.loginForm.addEventListener('submit', async event => {
				event.preventDefault();
				const username = document
					.getElementById('username')
					.value.trim();
				const password = document.getElementById('password').value;

				try {
					const session = await request('/api/session', {
						method: 'POST',
						body: JSON.stringify({ username, password })
					});
					setAuthenticated(session);
					await loadDashboard();
					connectEvents();
					elements.loginForm.reset();
				} catch (error) {
					elements.authError.textContent =
						error.status === 401
							? 'Invalid username or password.'
							: error.message || 'Login failed.';
					elements.authError.classList.remove('hidden');
				}
			});

			elements.logoutButton.addEventListener('click', async () => {
				try {
					await request('/api/session', { method: 'DELETE' });
				} finally {
					setUnauthenticated();
				}
			});

			elements.refreshButton.addEventListener('click', async () => {
				try {
					await loadDashboard();
				} catch (error) {
					handleRequestError(error, 'Failed to refresh dashboard.');
				}
			});

			elements.scanSettingsForm.addEventListener(
				'submit',
				async event => {
					event.preventDefault();
					elements.scanSettingsError.classList.add('hidden');

					try {
						const payload = buildScanSettingsPayload();
						const saved = await request('/api/scan-settings', {
							method: 'POST',
							body: JSON.stringify(payload)
						});
						if (state.dashboardSnapshot) {
							state.dashboardSnapshot.scan_defaults = saved;
						}
						renderGobusterDefaults(saved || {});
						prependEvent('Updated global scan settings.');
						if (elements.connectionState) elements.connectionState.textContent =
							'Global scan settings updated.';
					} catch (error) {
						elements.scanSettingsError.textContent =
							error.message || 'Failed to save scan settings.';
						elements.scanSettingsError.classList.remove('hidden');
					}
				}
			);

			elements.binDatasetImportForm.addEventListener(
				'submit',
				async event => {
					event.preventDefault();
					elements.binDatasetImportError.classList.add('hidden');

					try {
						const payload = buildBinDatasetImportPayload();
						const status = await request(
							'/api/bin-dataset/import',
							{
								method: 'POST',
								body: JSON.stringify(payload)
							}
						);
						if (state.dashboardSnapshot) {
							state.dashboardSnapshot.bin_dataset_status = status;
						}
						renderBinDatasetStatus(status || null);
						prependEvent('Imported BIN dataset into Dragonfly.');
						if (elements.connectionState) elements.connectionState.textContent =
							'BIN dataset imported successfully.';
					} catch (error) {
						elements.binDatasetImportError.textContent =
							error.message || 'Failed to import BIN dataset.';
						elements.binDatasetImportError.classList.remove(
							'hidden'
						);
					}
				}
			);

			elements.binLookupForm.addEventListener('submit', async event => {
				event.preventDefault();
				elements.binLookupError.classList.add('hidden');

				try {
					const payload = buildBinLookupPayload();
					const response = await request('/api/bin-lookup', {
						method: 'POST',
						body: JSON.stringify(payload)
					});
					renderBinLookupResults(response || null);
					if (elements.connectionState) elements.connectionState.textContent =
						'BIN lookup completed.';
				} catch (error) {
					elements.binLookupError.textContent =
						error.message || 'Failed to lookup BIN metadata.';
					elements.binLookupError.classList.remove('hidden');
				}
			});

			elements.workerTokenForm.addEventListener('submit', async event => {
				event.preventDefault();
				elements.workerTokenError.classList.add('hidden');

				try {
					const payload = buildWorkerEnrollmentTokenPayload();
					const issued = await request(
						'/api/worker-enrollment-tokens',
						{
							method: 'POST',
							body: JSON.stringify(payload)
						}
					);
					elements.workerTokenForm.reset();
					resetWorkerTokenFormDefaults();
					showSecretPanel(
						elements.workerTokenSecretPanel,
						elements.workerTokenSecretTitle,
						`Enrollment token issued for ${issued.record.label}`,
						elements.workerTokenSecretValue,
						issued.token
					);
					prependEvent(
						`Issued enrollment token ${issued.record.label}.`
					);
					await loadDashboard();
				} catch (error) {
					elements.workerTokenError.textContent =
						error.message || 'Failed to issue enrollment token.';
					elements.workerTokenError.classList.remove('hidden');
				}
			});

			elements.bootstrapDispatchEnabled.addEventListener('change', () => {
				syncBootstrapDispatchVisibility();
			});

			elements.portScanBootstrapEnabled?.addEventListener(
				'change',
				() => {
					syncPortScanBootstrapVisibility();
				}
			);

			elements.bootstrapCandidateId.addEventListener('change', () => {
				const candidate = findBootstrapCandidateById(
					elements.bootstrapCandidateId.value
				);
				populateBootstrapApprovalDefaults(candidate);
			});

			elements.bootstrapApprovalForm.addEventListener(
				'submit',
				async event => {
					event.preventDefault();
					elements.bootstrapApprovalError.classList.add('hidden');
					const candidateId = normalizePositiveInteger(
						elements.bootstrapCandidateId.value
					);
					if (!candidateId) {
						elements.bootstrapApprovalError.textContent =
							'Select a pending candidate first.';
						elements.bootstrapApprovalError.classList.remove(
							'hidden'
						);
						return;
					}

					try {
						const payload = buildBootstrapApprovalPayload();
						const approval = await request(
							`/api/bootstrap-candidates/${candidateId}/approve`,
							{
								method: 'POST',
								body: JSON.stringify(payload)
							}
						);
						showSecretPanel(
							elements.bootstrapTokenSecretPanel,
							elements.bootstrapTokenSecretTitle,
							`Bootstrap token issued for ${approval.candidate.discovered_host}`,
							elements.bootstrapTokenSecretValue,
							approval.token.token
						);
						prependEvent(
							`Approved bootstrap candidate #${approval.candidate.id}.`
						);
						await loadDashboard();
					} catch (error) {
						elements.bootstrapApprovalError.textContent =
							error.message ||
							'Failed to approve bootstrap candidate.';
						elements.bootstrapApprovalError.classList.remove(
							'hidden'
						);
					}
				}
			);

			elements.bootstrapRejectButton.addEventListener(
				'click',
				async () => {
					elements.bootstrapApprovalError.classList.add('hidden');
					const candidateId = normalizePositiveInteger(
						elements.bootstrapCandidateId.value
					);
					if (!candidateId) {
						elements.bootstrapApprovalError.textContent =
							'Select a pending candidate first.';
						elements.bootstrapApprovalError.classList.remove(
							'hidden'
						);
						return;
					}
					if (
						!window.confirm(
							`Reject bootstrap candidate #${candidateId}?`
						)
					) {
						return;
					}

					try {
						const payload = buildBootstrapRejectionPayload();
						const candidate = await request(
							`/api/bootstrap-candidates/${candidateId}/reject`,
							{
								method: 'POST',
								body: JSON.stringify(payload)
							}
						);
						clearSecretPanel(
							elements.bootstrapTokenSecretPanel,
							elements.bootstrapTokenSecretTitle,
							'Bootstrap enrollment token issued',
							elements.bootstrapTokenSecretValue
						);
						prependEvent(
							`Rejected bootstrap candidate #${candidate.id}.`
						);
						await loadDashboard();
					} catch (error) {
						elements.bootstrapApprovalError.textContent =
							error.message ||
							'Failed to reject bootstrap candidate.';
						elements.bootstrapApprovalError.classList.remove(
							'hidden'
						);
					}
				}
			);

			elements.queueButton.addEventListener('click', async () => {
				try {
					await request('/api/runs', {
						method: 'POST',
						body: JSON.stringify({
							active_authorized_execution: { enabled: false }
						})
					});
					prependEvent('Queued a new run from the dashboard.');
					await loadDashboard();
				} catch (error) {
					handleRequestError(error, 'Failed to queue run.');
				}
			});

			elements.targetForm.addEventListener('submit', async event => {
				event.preventDefault();
				elements.targetError.classList.add('hidden');

				const label = document
					.getElementById('target-label')
					.value.trim();
				const baseUrl = document
					.getElementById('target-base-url')
					.value.trim();
				const strategy =
					document.getElementById('target-strategy').value.trim() ||
					'hybrid';
				const paths = splitList(
					document.getElementById('target-paths').value.trim()
				);
				const tags = splitList(
					document.getElementById('target-tags').value.trim()
				);
				const requestProfile = document
					.getElementById('target-request-profile')
					.value.trim();

				try {
					await request('/api/targets', {
						method: 'POST',
						body: JSON.stringify({
							label,
							base_url: baseUrl,
							strategy,
							paths,
							tags,
							request_profile: requestProfile || null
						})
					});
					elements.targetForm.reset();
					prependEvent(`Saved target ${label}.`);
					await loadDashboard();
				} catch (error) {
					elements.targetError.textContent =
						error.message || 'Failed to save target.';
					elements.targetError.classList.remove('hidden');
				}
			});

			elements.runForm.addEventListener('submit', async event => {
				event.preventDefault();
				elements.runError.classList.add('hidden');
				const scope = buildRunScope(
					'run-target-ids',
					'run-tags',
					'run-failed-only',
					'run-worker-pool'
				);

				try {
					await request('/api/runs', {
						method: 'POST',
						body: JSON.stringify({
							scope,
							active_authorized_execution:
								buildActiveAuthorizedExecutionPayload(
									'run-active-authorized-enabled'
								)
						})
					});
					resetRunScope(
						'run-target-ids',
						'run-tags',
						'run-failed-only',
						'run-worker-pool'
					);
					document.getElementById(
						'run-active-authorized-enabled'
					).checked = false;
					prependEvent(
						`Queued scoped run (${formatRunScope(scope)}).`
					);
					await loadDashboard();
				} catch (error) {
					elements.runError.textContent =
						error.message || 'Failed to queue scoped run.';
					elements.runError.classList.remove('hidden');
				}
			});

			elements.scheduleForm.addEventListener('submit', async event => {
				event.preventDefault();
				elements.scheduleError.classList.add('hidden');

				const label = document
					.getElementById('schedule-label')
					.value.trim();
				const intervalMinutes = Number(
					document.getElementById('schedule-interval-minutes').value
				);
				const enabled =
					document.getElementById('schedule-enabled').value ===
					'true';
				const scope = buildRunScope(
					'schedule-target-ids',
					'schedule-tags',
					'schedule-failed-only',
					'schedule-worker-pool'
				);

				if (!Number.isFinite(intervalMinutes) || intervalMinutes <= 0) {
					elements.scheduleError.textContent =
						'Interval must be greater than zero minutes.';
					elements.scheduleError.classList.remove('hidden');
					return;
				}

				try {
					await request('/api/schedules', {
						method: 'POST',
						body: JSON.stringify({
							label,
							interval_seconds: Math.max(
								60,
								Math.round(intervalMinutes * 60)
							),
							enabled,
							scope,
							active_authorized_execution:
								buildActiveAuthorizedExecutionPayload(
									'schedule-active-authorized-enabled'
								)
						})
					});
					elements.scheduleForm.reset();
					document.getElementById('schedule-enabled').value = 'true';
					resetRunScope(
						'schedule-target-ids',
						'schedule-tags',
						'schedule-failed-only',
						'schedule-worker-pool'
					);
					document.getElementById(
						'schedule-active-authorized-enabled'
					).checked = false;
					prependEvent(
						`Saved schedule ${label} (${formatRunScope(scope)}).`
					);
					await loadDashboard();
				} catch (error) {
					elements.scheduleError.textContent =
						error.message || 'Failed to save schedule.';
					elements.scheduleError.classList.remove('hidden');
				}
			});

			elements.portScanForm?.addEventListener('submit', async event => {
				event.preventDefault();
				elements.portScanError.classList.add('hidden');

				try {
					const payload = buildPortScanPayload();
					await request('/api/port-scans', {
						method: 'POST',
						body: JSON.stringify(payload)
					});
					elements.portScanForm.reset();
					resetPortScanFormDefaults();
					prependEvent(
						`Queued port scan for ${payload.target_range} on ${payload.ports}${payload.follow_on_run_policy?.enabled ? ' with follow-on host scanning' : ''}.`
					);
					await loadDashboard();
				} catch (error) {
					elements.portScanError.textContent =
						error.message || 'Failed to queue port scan.';
					elements.portScanError.classList.remove('hidden');
				}
			});

			elements.workersRemoteUpdateAll.addEventListener(
				'click',
				async () => {
					try {
						if (
							!window.confirm(
								'Queue a remote self-update for all eligible workers?'
							)
						) {
							return;
						}
						await requestAllWorkerRemoteUpdates();
					} catch (error) {
						handleRequestError(
							error,
							'Failed to queue remote updates for workers.'
						);
					}
				}
			);

			window.addEventListener('beforeunload', closeEvents);
			syncPortScanBootstrapVisibility();
			elements.portScanFollowOnEnabled?.addEventListener(
				'change',
				syncPortScanFollowOnVisibility
			);
			syncPortScanFollowOnVisibility();
			syncActiveAuthorizedGateUi();
			ensureSession();

			// Mobile section-nav toggle + sticky-header height tracking.
			// Layout-only — no API calls.
			(() => {
				const appbar = document.getElementById('appbar');
				const toggle = document.getElementById('appbar-nav-toggle');
				const nav = document.getElementById('appbar-nav');
				if (!appbar || !toggle || !nav) return;
				const close = () => {
					appbar.classList.remove('nav-open');
					toggle.setAttribute('aria-expanded', 'false');
				};
				toggle.addEventListener('click', () => {
					const open = appbar.classList.toggle('nav-open');
					toggle.setAttribute(
						'aria-expanded',
						open ? 'true' : 'false'
					);
				});
				nav.addEventListener('click', event => {
					if (event.target.closest('a')) close();
				});
				document.addEventListener('keydown', event => {
					if (
						event.key === 'Escape' &&
						appbar.classList.contains('nav-open')
					) {
						close();
						toggle.focus();
					}
				});

				// Keep --appbar-height in sync with the actual rendered height
				// so scroll-padding-top / scroll-margin-top on anchor targets
				// land below the appbar even when responsive rules wrap the
				// nav/status onto extra rows. The CSS fallback (64px) applies
				// while the appbar is still hidden (pre-auth).
				const root = document.documentElement;
				const updateAppbarHeight = () => {
					const h = Math.round(
						appbar.getBoundingClientRect().height
					);
					if (h > 0) {
						root.style.setProperty(
							'--appbar-height',
							h + 'px'
						);
					}
				};
				updateAppbarHeight();
				if (typeof ResizeObserver !== 'undefined') {
					new ResizeObserver(updateAppbarHeight).observe(appbar);
				} else {
					window.addEventListener('resize', updateAppbarHeight);
				}
			})();

			// Pilot scaffolding: expose state on window for cross-page reuse.
			if (typeof state !== 'undefined') { window.AppState = state; }
