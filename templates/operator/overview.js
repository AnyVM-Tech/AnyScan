			// Overview page-specific JS placeholder.
			//
			// Pilot note: the canonical shared script (shared.js) currently bundles
			// the entire legacy bootstrap, formatters, auth flow, and all section
			// renderers — including renderSummary/renderTimings/renderArchive and the
			// gobuster-defaults/scan-settings/target-form handlers that drive this
			// page. That script already self-initializes when injected into the
			// shell, so no extra page-level wiring is needed for overview at this
			// time. As follower PRs extract section-specific JS out of shared.js,
			// the overview-only handlers will land here and the duplication will
			// disappear.
