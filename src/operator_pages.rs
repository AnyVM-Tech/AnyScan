// Operator-console page rendering scaffolding.
//
// Pilot scope: ships the shared shell + the Overview page. Follower PRs will
// add Targets/Runs/Workers/Findings/Catalog/Coverage by reusing `render_page`
// and providing their own body/page_js partials.
//
// Templating uses plain `String::replace` rather than handlebars/tera —
// `format!` is a poor fit because the embedded CSS and JS contain literal
// `{`/`}` braces that would otherwise need escaping.

use axum::response::Html;

/// Render an operator page by injecting the shared CSS, nav, body partial,
/// shared JS and page-specific JS into the shell template.
pub fn render_page(active_nav: &str, body_partial: &str, page_js: &str) -> Html<String> {
    let nav = render_nav(active_nav);
    let html = include_str!("../templates/operator/shell.html")
        .replace("{shared_css}", include_str!("../templates/operator/shared.css"))
        .replace("{nav}", &nav)
        .replace("{body}", body_partial)
        .replace("{shared_js}", include_str!("../templates/operator/shared.js"))
        .replace("{page_js}", page_js);
    Html(html)
}

/// Render the appbar nav, marking the link whose `data-nav` matches `active`
/// with `aria-current="page"`.
fn render_nav(active: &str) -> String {
    let template = include_str!("../templates/operator/nav.html");
    let needle = format!("data-nav=\"{}\"", active);
    template.replace(&needle, &format!("{} aria-current=\"page\"", needle))
}

pub async fn operator_overview() -> Html<String> {
    render_page(
        "overview",
        include_str!("../templates/operator/overview.html"),
        include_str!("../templates/operator/overview.js"),
    )
}

pub async fn operator_targets() -> Html<String> {
    render_page(
        "targets",
        include_str!("../templates/operator/targets.html"),
        include_str!("../templates/operator/targets.js"),
    )
}

pub async fn operator_runs() -> Html<String> {
    render_page(
        "runs",
        include_str!("../templates/operator/runs.html"),
        include_str!("../templates/operator/runs.js"),
    )
}

pub async fn operator_workers() -> Html<String> {
    render_page(
        "workers",
        include_str!("../templates/operator/workers.html"),
        include_str!("../templates/operator/workers.js"),
    )
}

pub async fn operator_findings() -> Html<String> {
    render_page(
        "findings",
        include_str!("../templates/operator/findings.html"),
        include_str!("../templates/operator/findings.js"),
    )
}

pub async fn operator_coverage() -> Html<String> {
    render_page(
        "coverage",
        include_str!("../templates/operator/coverage.html"),
        include_str!("../templates/operator/coverage.js"),
    )
}

pub async fn operator_catalog() -> Html<String> {
    render_page(
        "catalog",
        include_str!("../templates/operator/catalog.html"),
        include_str!("../templates/operator/catalog.js"),
    )
}

/// The seven section slugs that make up the operator console nav. Kept here so
/// tests (and any future helpers) share one source of truth — the rendered
/// `templates/operator/nav.html` is the actual product of record.
#[cfg(test)]
pub(crate) const OPERATOR_NAV_SLUGS: &[&str] = &[
    "overview", "targets", "runs", "workers", "findings", "catalog", "coverage",
];


#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::response::Redirect;
    use axum::routing::get;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn operator_overview_serves_shell_and_overview_ids() {
        let app = Router::new().route("/app/overview", get(operator_overview));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("operator overview test listener should bind");
        let address = listener
            .local_addr()
            .expect("operator overview test listener should report local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("operator overview test server should stay available");
        });

        let url = format!("http://{}/app/overview", address);
        let response = reqwest::get(&url)
            .await
            .expect("GET /app/overview should succeed");
        assert_eq!(response.status(), 200);
        let body = response
            .text()
            .await
            .expect("operator overview body should be utf-8");

        assert!(
            body.contains("id=\"appbar-nav\""),
            "rendered body should contain the appbar nav (shell scaffolding)"
        );
        assert!(
            body.contains("aria-current=\"page\""),
            "rendered body should mark the active nav link with aria-current"
        );
        assert!(
            body.contains("id=\"summary-metrics\""),
            "rendered body should contain the overview summary-metrics container"
        );

        server.abort();
    }

    #[tokio::test]
    async fn operator_targets_serves_shell_and_targets_ids() {
        let app = Router::new().route("/app/targets", get(operator_targets));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("operator targets test listener should bind");
        let address = listener
            .local_addr()
            .expect("operator targets test listener should report local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("operator targets test server should stay available");
        });

        let url = format!("http://{}/app/targets", address);
        let response = reqwest::get(&url)
            .await
            .expect("GET /app/targets should succeed");
        assert_eq!(response.status(), 200);
        let body = response
            .text()
            .await
            .expect("operator targets body should be utf-8");

        assert!(
            body.contains("id=\"appbar-nav\""),
            "rendered body should contain the appbar nav (shell scaffolding)"
        );
        assert!(
            body.contains("aria-current=\"page\""),
            "rendered body should mark the active nav link with aria-current"
        );
        assert!(
            body.contains("id=\"targets-body\""),
            "rendered body should contain the targets-body table tbody"
        );
        assert!(
            body.contains("id=\"bin-lookup-form\""),
            "rendered body should contain the bin-lookup-form"
        );

        server.abort();
    }

    #[tokio::test]
    async fn operator_workers_serves_shell_and_workers_ids() {
        let app = Router::new().route("/app/workers", get(operator_workers));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("operator workers test listener should bind");
        let address = listener
            .local_addr()
            .expect("operator workers test listener should report local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("operator workers test server should stay available");
        });

        let url = format!("http://{}/app/workers", address);
        let response = reqwest::get(&url)
            .await
            .expect("GET /app/workers should succeed");
        assert_eq!(response.status(), 200);
        let body = response
            .text()
            .await
            .expect("operator workers body should be utf-8");

        assert!(
            body.contains("id=\"appbar-nav\""),
            "rendered body should contain the appbar nav (shell scaffolding)"
        );
        assert!(
            body.contains("aria-current=\"page\""),
            "rendered body should mark the active nav link with aria-current"
        );
        assert!(
            body.contains("id=\"workers-list\""),
            "rendered body should contain the workers-list container"
        );
        assert!(
            body.contains("id=\"worker-tokens-list\""),
            "rendered body should contain the worker-tokens-list container"
        );
        assert!(
            body.contains("id=\"bootstrap-jobs-list\""),
            "rendered body should contain the bootstrap-jobs-list container"
        );

        server.abort();
    }

    #[tokio::test]
    async fn operator_findings_serves_shell_and_findings_ids() {
        let app = Router::new().route("/app/findings", get(operator_findings));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("operator findings test listener should bind");
        let address = listener
            .local_addr()
            .expect("operator findings test listener should report local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("operator findings test server should stay available");
        });

        let url = format!("http://{}/app/findings", address);
        let response = reqwest::get(&url)
            .await
            .expect("GET /app/findings should succeed");
        assert_eq!(response.status(), 200);
        let body = response
            .text()
            .await
            .expect("operator findings body should be utf-8");

        assert!(
            body.contains("id=\"appbar-nav\""),
            "rendered body should contain the appbar nav (shell scaffolding)"
        );
        assert!(
            body.contains("aria-current=\"page\""),
            "rendered body should mark the active nav link with aria-current"
        );
        assert!(
            body.contains("id=\"findings-search-form\""),
            "rendered body should contain the findings search form"
        );
        assert!(
            body.contains("id=\"events-list\""),
            "rendered body should contain the live events list"
        );
        assert!(
            body.contains("id=\"publication-records-list\""),
            "rendered body should contain the publication records list"
        );

        server.abort();
    }

    #[test]
    fn render_nav_marks_active_link() {
        let nav = render_nav("overview");
        assert!(nav.contains("data-nav=\"overview\" aria-current=\"page\""));
        assert!(!nav.contains("data-nav=\"targets\" aria-current=\"page\""));
    }

    #[tokio::test]
    async fn operator_runs_serves_shell_and_runs_ids() {
        let app = Router::new().route("/app/runs", get(operator_runs));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("operator runs test listener should bind");
        let address = listener
            .local_addr()
            .expect("operator runs test listener should report local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("operator runs test server should stay available");
        });

        let url = format!("http://{}/app/runs", address);
        let response = reqwest::get(&url)
            .await
            .expect("GET /app/runs should succeed");
        assert_eq!(response.status(), 200);
        let body = response
            .text()
            .await
            .expect("operator runs body should be utf-8");

        assert!(body.contains("id=\"appbar-nav\""));
        assert!(body.contains("data-nav=\"runs\" aria-current=\"page\""));
        assert!(body.contains("id=\"run-form\""));
        assert!(body.contains("id=\"schedules-list\""));
        assert!(body.contains("id=\"port-scan-form\""));

        server.abort();
    }

    #[tokio::test]
    async fn operator_coverage_serves_shell_and_coverage_ids() {
        let app = Router::new().route("/app/coverage", get(operator_coverage));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("operator coverage test listener should bind");
        let address = listener
            .local_addr()
            .expect("operator coverage test listener should report local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("operator coverage test server should stay available");
        });

        let url = format!("http://{}/app/coverage", address);
        let response = reqwest::get(&url)
            .await
            .expect("GET /app/coverage should succeed");
        assert_eq!(response.status(), 200);
        let body = response
            .text()
            .await
            .expect("operator coverage body should be utf-8");

        assert!(
            body.contains("id=\"appbar-nav\""),
            "rendered body should contain the appbar nav (shell scaffolding)"
        );
        assert!(
            body.contains("aria-current=\"page\""),
            "rendered body should mark the active nav link with aria-current"
        );
        assert!(
            body.contains("id=\"failed-targets-list\""),
            "rendered body should contain the failed-targets-list container"
        );
        assert!(
            body.contains("id=\"detector-distribution-list\""),
            "rendered body should contain the detector-distribution-list container"
        );
        assert!(
            body.contains("id=\"coverage-sources-list\""),
            "rendered body should contain the coverage-sources-list container"
        );

        server.abort();
    }

    #[tokio::test]
    async fn operator_catalog_serves_shell_and_catalog_ids() {
        let app = Router::new().route("/app/catalog", get(operator_catalog));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("operator catalog test listener should bind");
        let address = listener
            .local_addr()
            .expect("operator catalog test listener should report local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("operator catalog test server should stay available");
        });

        let url = format!("http://{}/app/catalog", address);
        let response = reqwest::get(&url)
            .await
            .expect("GET /app/catalog should succeed");
        assert_eq!(response.status(), 200);
        let body = response
            .text()
            .await
            .expect("operator catalog body should be utf-8");

        assert!(
            body.contains("id=\"appbar-nav\""),
            "rendered body should contain the appbar nav (shell scaffolding)"
        );
        assert!(
            body.contains("aria-current=\"page\""),
            "rendered body should mark the active nav link with aria-current"
        );
        assert!(
            body.contains("id=\"plugins-search-form\""),
            "rendered body should contain the plugin catalog search form"
        );
        assert!(
            body.contains("id=\"plugin-catalog-list\""),
            "rendered body should contain the plugin catalog list container"
        );

        server.abort();
    }

    /// `/app` is a stable bookmark; confirm the route handler issues an HTTP 307
    /// redirect to `/app/overview` so legacy bookmarks land on the new section
    /// page.
    #[tokio::test]
    async fn operator_app_redirects_to_overview() {
        async fn operator_app() -> Redirect {
            Redirect::temporary("/app/overview")
        }

        let app = Router::new()
            .route("/app", get(operator_app))
            .route("/app/overview", get(operator_overview));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("operator_app redirect test listener should bind");
        let address = listener
            .local_addr()
            .expect("operator_app redirect test listener should report local addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("operator_app redirect test server should stay available");
        });

        // Use a non-redirecting client so we can inspect the 307 itself rather
        // than chase it.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("non-redirecting reqwest client should build");
        let response = client
            .get(format!("http://{}/app", address))
            .send()
            .await
            .expect("GET /app should succeed");

        assert_eq!(
            response.status().as_u16(),
            307,
            "GET /app should issue a 307 redirect to /app/overview",
        );
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .expect("redirect response should carry a Location header")
            .to_str()
            .expect("Location header should be ASCII");
        assert_eq!(location, "/app/overview");

        server.abort();
    }

    /// Every section page must expose the full nav so users can move between
    /// sections without retyping URLs. Render the shell once per slug and
    /// assert all seven hrefs appear AND exactly one link is marked
    /// `aria-current="page"` (the active one for that page).
    #[test]
    fn operator_nav_links_to_all_seven_pages() {
        let expected_hrefs: Vec<String> = OPERATOR_NAV_SLUGS
            .iter()
            .map(|slug| format!("href=\"/app/{}\"", slug))
            .collect();

        for active in OPERATOR_NAV_SLUGS {
            // Body/page_js can be empty — we are only validating the nav scaffolding.
            let Html(body) = render_page(active, "", "");

            for expected in &expected_hrefs {
                assert!(
                    body.contains(expected),
                    "rendered page for slug `{active}` should contain nav link `{expected}`",
                );
            }

            let aria_current_count = body.matches("aria-current=\"page\"").count();
            assert_eq!(
                aria_current_count, 1,
                "page for slug `{active}` should have exactly one aria-current=\"page\" link, found {aria_current_count}",
            );
            let active_marker = format!("data-nav=\"{}\" aria-current=\"page\"", active);
            assert!(
                body.contains(&active_marker),
                "page for slug `{active}` should mark its own nav link with aria-current",
            );
        }
    }
}
