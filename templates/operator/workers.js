				// Workers page-specific JS.
				//
				// Worker / token / bootstrap renderers still live in shared.js
				// (alongside the rest of the legacy bootstrap) and self-initialize
				// when injected into the shell, so this file only needs to wire
				// the Fleet / Tokens / Bootstrap sub-tab toggle. As follower PRs
				// extract section-specific JS out of shared.js, the workers-only
				// handlers will land here.
				(function initWorkersSubTabs() {
					const root = document.getElementById('page-workers');
					if (!root) {
						return;
					}
					const tabs = root.querySelectorAll('[data-workers-tab]');
					const panes = root.querySelectorAll('[data-workers-pane]');
					if (tabs.length === 0 || panes.length === 0) {
						return;
					}

					function activate(tabKey) {
						tabs.forEach((tab) => {
							tab.setAttribute(
								'aria-selected',
								tab.dataset.workersTab === tabKey
									? 'true'
									: 'false'
							);
						});
						panes.forEach((pane) => {
							pane.classList.toggle(
								'hidden',
								pane.dataset.workersPane !== tabKey
							);
						});
					}

					tabs.forEach((tab) => {
						tab.addEventListener('click', () => {
							activate(tab.dataset.workersTab);
						});
					});

					// Default-active sub-tab: Fleet.
					activate('fleet');
				})();
