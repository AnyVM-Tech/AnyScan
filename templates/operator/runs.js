				// Runs page-specific JS.
				//
				// Same pilot caveat as overview.js: shared.js still owns the form
				// handlers and renderers for #run-form, #schedules-list,
				// #schedule-form, #port-scan-form (plus the
				// #port-scan-follow-on-fields / #port-scan-bootstrap-fields
				// visibility toggles). It looks them up by id at boot time and
				// self-initializes once injected into the shell, so we do not
				// re-register those handlers here. As follower PRs extract
				// section-specific JS out of shared.js, the runs-only handlers
				// will move into this file.
				//
				// What is page-local: the Active / Schedules / Port-scans sub-tab
				// switcher. Tabs use [data-subtab]; panes use [data-subtab-pane].
				// We toggle aria-selected on the tab buttons and the .hidden
				// utility class on the panes (already provided by shared.css).
				(function initRunsSubtabs() {
					const tabs = Array.from(
						document.querySelectorAll('#page-runs [data-subtab]')
					);
					const panes = Array.from(
						document.querySelectorAll('#page-runs [data-subtab-pane]')
					);
					if (tabs.length === 0 || panes.length === 0) {
						return;
					}
					function activate(name) {
						tabs.forEach((tab) => {
							const isActive = tab.dataset.subtab === name;
							tab.setAttribute(
								'aria-selected',
								isActive ? 'true' : 'false'
							);
						});
						panes.forEach((pane) => {
							const isActive = pane.dataset.subtabPane === name;
							pane.classList.toggle('hidden', !isActive);
						});
					}
					tabs.forEach((tab) => {
						tab.addEventListener('click', () => {
							activate(tab.dataset.subtab);
						});
					});
					activate('active');
				})();
