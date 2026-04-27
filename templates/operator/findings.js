				// Findings page sub-tab toggle and gated EventSource lifecycle.
				//
				// shared.js owns the form/list/event/publication renderers.
				// This file only adds the page-level concerns the shell can't
				// handle: switching between Search / Live / Publications panes,
				// and opening the EventSource lazily so the operator does not
				// hold a streaming connection open while looking at Search or
				// Publications. shared.js intentionally does not auto-open the
				// stream anymore.
				(function setupFindingsPage() {
					const subtabs = document.getElementById('findings-subtabs');
					if (!subtabs) {
						return;
					}

					const buttons = Array.from(
						subtabs.querySelectorAll('[data-subtab]')
					);
					const panes = {
						search: document.getElementById('findings-pane-search'),
						live: document.getElementById('findings-pane-live'),
						publications: document.getElementById(
							'findings-pane-publications'
						)
					};

					// connectEvents() in shared.js is itself idempotent on
					// state.eventSource, but we keep an explicit page-level flag so
					// closeEventStreamIfOpen() is symmetric and doesn't need to
					// reach into shared state.
					let eventStreamOpen = false;

					function openEventStreamIfNeeded() {
						if (eventStreamOpen || typeof connectEvents !== 'function') {
							return;
						}
						connectEvents();
						eventStreamOpen = true;
					}

					function closeEventStreamIfOpen() {
						if (!eventStreamOpen) {
							return;
						}
						if (typeof closeEvents === 'function') {
							closeEvents();
						}
						eventStreamOpen = false;
					}

					function activate(name) {
						buttons.forEach(button => {
							const isActive = button.dataset.subtab === name;
							button.setAttribute(
								'aria-selected',
								isActive ? 'true' : 'false'
							);
							button.classList.toggle('is-active', isActive);
						});
						Object.entries(panes).forEach(([paneName, paneEl]) => {
							if (paneEl) {
								paneEl.classList.toggle(
									'hidden',
									paneName !== name
								);
							}
						});

						if (name === 'live') {
							openEventStreamIfNeeded();
						} else {
							closeEventStreamIfOpen();
						}
					}

					buttons.forEach(button => {
						button.addEventListener('click', () => {
							const next = button.dataset.subtab;
							if (next && panes[next]) {
								activate(next);
							}
						});
					});

					// Default-active: Search. Live stays cold until requested.
					activate('search');

					window.addEventListener('beforeunload', closeEventStreamIfOpen);
				})();
