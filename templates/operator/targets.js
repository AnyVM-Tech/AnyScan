				// Targets page-specific JS.
				//
				// The Inventory and BIN-tools data renderers (renderTargets,
				// renderRuns, renderRepositories, renderBinDatasetStatus,
				// renderBinLookupResults, plus the bin-dataset-import-form and
				// bin-lookup-form submit handlers, plus the target-form save
				// handler) currently live in shared.js because the dashboard
				// refresh loop and the Overview page also call them. A future
				// cleanup PR will hoist them out; for now this file only owns
				// the in-page sub-tab toggle.
				(() => {
					const page = document.getElementById('page-targets');
					if (!page) return;
					const tabs = page.querySelectorAll('[data-subtab]');
					const panes = page.querySelectorAll('[data-subtab-pane]');
					if (!tabs.length || !panes.length) return;

					const activate = name => {
						tabs.forEach(tab => {
							const isActive = tab.dataset.subtab === name;
							if (isActive) {
								tab.setAttribute('aria-current', 'page');
							} else {
								tab.removeAttribute('aria-current');
							}
						});
						panes.forEach(pane => {
							pane.hidden = pane.dataset.subtabPane !== name;
						});
					};

					tabs.forEach(tab => {
						tab.addEventListener('click', () => {
							activate(tab.dataset.subtab);
						});
					});
				})();
