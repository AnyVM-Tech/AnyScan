//! Tech-stack fingerprint driven path expansion.
//!
//! Given a fetched document (path + headers + body + content-type), detect
//! technologies likely hosting the response (WordPress, Spring Boot,
//! GitLab, etc.) and emit targeted candidate paths that are high-value
//! exposures for that tech.
//!
//! This module is read-only with respect to the rest of the scanner — it is
//! intended to be wired into `fetcher::discover_candidate_path_candidates`
//! as an additional source of discovery hints. See PR description for the
//! integration patch.

use std::collections::{HashMap, HashSet};

/// Single candidate path produced by tech-stack fingerprinting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechPathCandidate {
    pub path: String,
    pub source: &'static str,
    pub score: u16,
}

/// Technologies the fingerprinter knows how to recognize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TechFingerprint {
    WordPress,
    Drupal,
    Joomla,
    Magento,
    PhpMyAdmin,
    Adminer,
    SpringBoot,
    Tomcat,
    Jenkins,
    GitLab,
    Confluence,
    Jira,
    Grafana,
    Kibana,
    Prometheus,
    Elasticsearch,
    DjangoAdmin,
    RailsApp,
    LaravelApp,
    NextCloud,
    Gitea,
    Nginx,
    ApacheHttpd,
    IIS,
    NodeJsExpress,
    PhpGeneric,
    SonarQube,
    Kubernetes,
    Docker,
    DotNetMvc,
    Mlflow,
    JupyterHub,
    TensorBoard,
    Streamlit,
    Gradio,
    Airflow,
    NextJs,
    NuxtJs,
    SvelteKit,
    Astro,
    Remix,
    Vite,
}

impl TechFingerprint {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WordPress => "wordpress",
            Self::Drupal => "drupal",
            Self::Joomla => "joomla",
            Self::Magento => "magento",
            Self::PhpMyAdmin => "phpmyadmin",
            Self::Adminer => "adminer",
            Self::SpringBoot => "spring-boot",
            Self::Tomcat => "tomcat",
            Self::Jenkins => "jenkins",
            Self::GitLab => "gitlab",
            Self::Confluence => "confluence",
            Self::Jira => "jira",
            Self::Grafana => "grafana",
            Self::Kibana => "kibana",
            Self::Prometheus => "prometheus",
            Self::Elasticsearch => "elasticsearch",
            Self::DjangoAdmin => "django",
            Self::RailsApp => "rails",
            Self::LaravelApp => "laravel",
            Self::NextCloud => "nextcloud",
            Self::Gitea => "gitea",
            Self::Nginx => "nginx",
            Self::ApacheHttpd => "apache",
            Self::IIS => "iis",
            Self::NodeJsExpress => "express",
            Self::PhpGeneric => "php",
            Self::SonarQube => "sonarqube",
            Self::Kubernetes => "kubernetes",
            Self::Docker => "docker",
            Self::DotNetMvc => "aspnet-mvc",
            Self::Mlflow => "mlflow",
            Self::JupyterHub => "jupyterhub",
            Self::TensorBoard => "tensorboard",
            Self::Streamlit => "streamlit",
            Self::Gradio => "gradio",
            Self::Airflow => "airflow",
            Self::NextJs => "nextjs",
            Self::NuxtJs => "nuxtjs",
            Self::SvelteKit => "sveltekit",
            Self::Astro => "astro",
            Self::Remix => "remix",
            Self::Vite => "vite",
        }
    }

    fn source_tag(&self) -> &'static str {
        match self {
            Self::WordPress => "tech-wordpress",
            Self::Drupal => "tech-drupal",
            Self::Joomla => "tech-joomla",
            Self::Magento => "tech-magento",
            Self::PhpMyAdmin => "tech-phpmyadmin",
            Self::Adminer => "tech-adminer",
            Self::SpringBoot => "tech-spring-boot",
            Self::Tomcat => "tech-tomcat",
            Self::Jenkins => "tech-jenkins",
            Self::GitLab => "tech-gitlab",
            Self::Confluence => "tech-confluence",
            Self::Jira => "tech-jira",
            Self::Grafana => "tech-grafana",
            Self::Kibana => "tech-kibana",
            Self::Prometheus => "tech-prometheus",
            Self::Elasticsearch => "tech-elasticsearch",
            Self::DjangoAdmin => "tech-django",
            Self::RailsApp => "tech-rails",
            Self::LaravelApp => "tech-laravel",
            Self::NextCloud => "tech-nextcloud",
            Self::Gitea => "tech-gitea",
            Self::Nginx => "tech-nginx",
            Self::ApacheHttpd => "tech-apache",
            Self::IIS => "tech-iis",
            Self::NodeJsExpress => "tech-express",
            Self::PhpGeneric => "tech-php",
            Self::SonarQube => "tech-sonarqube",
            Self::Kubernetes => "tech-kubernetes",
            Self::Docker => "tech-docker",
            Self::DotNetMvc => "tech-aspnet-mvc",
            Self::Mlflow => "tech-mlflow",
            Self::JupyterHub => "tech-jupyterhub",
            Self::TensorBoard => "tech-tensorboard",
            Self::Streamlit => "tech-streamlit",
            Self::Gradio => "tech-gradio",
            Self::Airflow => "tech-airflow",
            Self::NextJs => "tech-nextjs",
            Self::NuxtJs => "tech-nuxtjs",
            Self::SvelteKit => "tech-sveltekit",
            Self::Astro => "tech-astro",
            Self::Remix => "tech-remix",
            Self::Vite => "tech-vite",
        }
    }
}

/// Top-level entry: detect tech fingerprints in a fetched document and emit
/// targeted candidate paths from the curated wordlists.
///
/// The score floor is high (>=820) because tech-fingerprint hits are
/// authoritative — we are only suggesting paths because we observed strong
/// evidence the host is running this software.
pub fn tech_path_candidates(
    path: &str,
    content_type: Option<&str>,
    headers: &[(String, String)],
    body: &str,
) -> Vec<TechPathCandidate> {
    let fingerprints = detect_tech_fingerprints(path, content_type, headers, body);
    candidates_for_fingerprints(&fingerprints)
}

/// Heuristic fingerprint detection from path / headers / body.
pub fn detect_tech_fingerprints(
    path: &str,
    content_type: Option<&str>,
    headers: &[(String, String)],
    body: &str,
) -> Vec<TechFingerprint> {
    let lowered_path = path.trim().to_ascii_lowercase();
    // Guard against UTF-8 boundary panics: a raw byte slice at
    // MAX_BODY_INSPECT_BYTES can land inside a multi-byte codepoint and
    // panic. `str::get` returns None on a non-boundary index; fall back to
    // the full body in that (rare) case rather than crashing fingerprint
    // detection for that target.
    let lowered_body = body
        .get(..MAX_BODY_INSPECT_BYTES)
        .unwrap_or(body)
        .to_ascii_lowercase();
    let lowered_ct = content_type
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    let mut header_index: Vec<(String, String)> = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        header_index.push((name.to_ascii_lowercase(), value.to_ascii_lowercase()));
    }
    let header_value = |name: &str| -> Option<&str> {
        header_index
            .iter()
            .find(|(header_name, _)| header_name == name)
            .map(|(_, value)| value.as_str())
    };
    let any_header_value_contains = |needle: &str| -> bool {
        header_index
            .iter()
            .any(|(_, value)| value.contains(needle))
    };
    let any_header_eq = |name: &str| -> bool {
        header_index
            .iter()
            .any(|(header_name, _)| header_name == name)
    };

    let mut fingerprints = Vec::new();

    // WordPress
    if lowered_body.contains("/wp-content/")
        || lowered_body.contains("/wp-includes/")
        || lowered_body.contains("wp-emoji-release")
        || lowered_body.contains("name=\"generator\" content=\"wordpress")
        || lowered_path.contains("/wp-")
    {
        push_unique(&mut fingerprints, TechFingerprint::WordPress);
    }

    // Drupal
    if lowered_body.contains("drupal.settings")
        || lowered_body.contains("/sites/default/files/")
        || lowered_body.contains("name=\"generator\" content=\"drupal")
        || any_header_eq("x-drupal-cache")
        || any_header_eq("x-generator")
            && header_value("x-generator")
                .map(|value| value.contains("drupal"))
                .unwrap_or(false)
    {
        push_unique(&mut fingerprints, TechFingerprint::Drupal);
    }

    // Joomla
    if lowered_body.contains("/components/com_") || lowered_body.contains("joomla!")
        || lowered_body.contains("name=\"generator\" content=\"joomla")
    {
        push_unique(&mut fingerprints, TechFingerprint::Joomla);
    }

    // Magento
    if lowered_body.contains("magento")
        && (lowered_body.contains("mage/cookies")
            || lowered_body.contains("/skin/frontend/")
            || lowered_body.contains("var basemediaurl"))
        || lowered_path.contains("/magento")
    {
        push_unique(&mut fingerprints, TechFingerprint::Magento);
    }

    // phpMyAdmin
    if lowered_body.contains("phpmyadmin")
        || lowered_path.contains("/phpmyadmin")
        || lowered_path.contains("/pma/")
    {
        push_unique(&mut fingerprints, TechFingerprint::PhpMyAdmin);
    }

    // Adminer
    if lowered_body.contains("adminer")
        && (lowered_body.contains("login - adminer")
            || lowered_body.contains("class=\"adminer"))
    {
        push_unique(&mut fingerprints, TechFingerprint::Adminer);
    }

    // Spring Boot / Spring framework
    if lowered_body.contains("whitelabel error page")
        || lowered_body.contains("spring framework")
        || lowered_path.contains("/actuator/")
        || lowered_body.contains("\"_links\"") && lowered_body.contains("\"actuator\"")
        || any_header_value_contains("springframework")
    {
        push_unique(&mut fingerprints, TechFingerprint::SpringBoot);
    }

    // Tomcat
    if lowered_body.contains("apache tomcat")
        || header_value("server")
            .map(|value| value.contains("apache-coyote") || value.contains("tomcat"))
            .unwrap_or(false)
    {
        push_unique(&mut fingerprints, TechFingerprint::Tomcat);
    }

    // Jenkins
    if lowered_body.contains("jenkins")
        && (lowered_body.contains("x-jenkins") || lowered_body.contains("class=\"jenkins"))
        || any_header_eq("x-jenkins")
        || any_header_eq("x-jenkins-session")
        || any_header_eq("x-hudson")
    {
        push_unique(&mut fingerprints, TechFingerprint::Jenkins);
    }

    // GitLab
    if any_header_eq("x-gitlab-meta")
        || any_header_eq("x-gitlab-feature-category")
        || lowered_body.contains("gitlab.com")
            && lowered_body.contains("gon.gitlab_logo")
        || lowered_body.contains("data-page=\"sessions:new\"")
        || lowered_body.contains("gitlab-workhorse")
    {
        push_unique(&mut fingerprints, TechFingerprint::GitLab);
    }

    // Atlassian Confluence
    if lowered_body.contains("confluence")
        && (lowered_body.contains("atlassian")
            || lowered_body.contains("ajs-version-number"))
        || any_header_eq("x-confluence-request-time")
    {
        push_unique(&mut fingerprints, TechFingerprint::Confluence);
    }

    // Atlassian Jira
    if any_header_eq("x-atlassian-token")
        || any_header_eq("x-ausername")
        || lowered_body.contains("jira-frontend")
        || (lowered_body.contains("atlassian")
            && (lowered_body.contains("jira") || lowered_body.contains("/secure/dashboard.jspa")))
    {
        push_unique(&mut fingerprints, TechFingerprint::Jira);
    }

    // Grafana
    if lowered_body.contains("grafana-app")
        || lowered_body.contains("window.grafanabootdata")
        || lowered_body.contains("<title>grafana")
        || any_header_eq("x-grafana-org-id")
    {
        push_unique(&mut fingerprints, TechFingerprint::Grafana);
    }

    // Kibana
    if lowered_body.contains("kbn-name")
        || any_header_eq("kbn-name")
        || any_header_eq("kbn-version")
        || lowered_body.contains("data-test-subj=\"kibanachromewrapper\"")
    {
        push_unique(&mut fingerprints, TechFingerprint::Kibana);
    }

    // Prometheus. The exposition format is `# HELP name ...` / `# TYPE name <kind>`
    // (case-insensitive after to_ascii_lowercase). Match either the landing
    // page tagline or `/metrics` returning a body with both HELP and TYPE
    // markers, or a TYPE line for a `prometheus_*` self-metric (server
    // exposes its own metrics under the `prometheus_` prefix).
    if lowered_body.contains("prometheus time series collection")
        || lowered_body.contains("# type prometheus_")
        || lowered_path == "/metrics"
            && lowered_body.contains("# help ")
            && lowered_body.contains("# type ")
    {
        push_unique(&mut fingerprints, TechFingerprint::Prometheus);
    }

    // Elasticsearch
    if lowered_body.contains("\"cluster_name\"") && lowered_body.contains("\"tagline\"")
        && lowered_body.contains("you know, for search")
        || any_header_eq("x-elastic-product")
    {
        push_unique(&mut fingerprints, TechFingerprint::Elasticsearch);
    }

    // Django (admin / debug pages)
    if lowered_body.contains("django administration")
        || lowered_body.contains("__admin_media_prefix__")
        || lowered_body.contains("django version")
            && lowered_body.contains("traceback")
        || any_header_value_contains("wsgiserver/")
            && lowered_ct.starts_with("text/html")
    {
        push_unique(&mut fingerprints, TechFingerprint::DjangoAdmin);
    }

    // Rails
    if any_header_eq("x-runtime") && any_header_eq("x-request-id")
        && lowered_body.contains("rails")
        || lowered_body.contains("ruby on rails")
        || lowered_path.contains("/rails/info/")
        || lowered_body.contains("data-turbolinks")
    {
        push_unique(&mut fingerprints, TechFingerprint::RailsApp);
    }

    // Laravel (PHP)
    if lowered_body.contains("laravel_session")
        || any_header_eq("x-laravel-session")
        || lowered_body.contains("laravel.css")
        || lowered_body.contains("laravel framework")
    {
        push_unique(&mut fingerprints, TechFingerprint::LaravelApp);
    }

    // NextCloud / ownCloud
    if lowered_body.contains("nextcloud")
        && (lowered_body.contains("data-system=") || lowered_body.contains("nc-default"))
        || lowered_body.contains("oc.config")
        || lowered_body.contains("owncloud")
            && lowered_body.contains("data-requesttoken")
    {
        push_unique(&mut fingerprints, TechFingerprint::NextCloud);
    }

    // Gitea
    if lowered_body.contains("powered by gitea")
        || header_value("server")
            .map(|value| value.contains("gitea"))
            .unwrap_or(false)
    {
        push_unique(&mut fingerprints, TechFingerprint::Gitea);
    }

    // Nginx (raw server header — value for derived sensitive paths is low,
    // but useful to enable nginx-specific defaults).
    if header_value("server")
        .map(|value| value.starts_with("nginx"))
        .unwrap_or(false)
    {
        push_unique(&mut fingerprints, TechFingerprint::Nginx);
    }

    // Apache httpd (avoid matching Apache-Coyote / Apache Tomcat which both
    // start with the same vendor token).
    if header_value("server")
        .map(|value| {
            value.starts_with("apache")
                && !value.contains("tomcat")
                && !value.contains("coyote")
        })
        .unwrap_or(false)
    {
        push_unique(&mut fingerprints, TechFingerprint::ApacheHttpd);
    }

    // IIS
    if header_value("server")
        .map(|value| value.contains("microsoft-iis") || value.contains("iis/"))
        .unwrap_or(false)
        || any_header_eq("x-aspnet-version")
        || any_header_eq("x-aspnetmvc-version")
    {
        push_unique(&mut fingerprints, TechFingerprint::IIS);
    }

    if any_header_eq("x-aspnetmvc-version") || lowered_body.contains("__viewstate") {
        push_unique(&mut fingerprints, TechFingerprint::DotNetMvc);
    }

    // Node.js / Express
    if header_value("x-powered-by")
        .map(|value| value.contains("express"))
        .unwrap_or(false)
    {
        push_unique(&mut fingerprints, TechFingerprint::NodeJsExpress);
    }

    // PHP generic
    if header_value("x-powered-by")
        .map(|value| value.starts_with("php/") || value.contains("php/"))
        .unwrap_or(false)
        || any_header_eq("x-php-original-url")
    {
        push_unique(&mut fingerprints, TechFingerprint::PhpGeneric);
    }

    // SonarQube
    if lowered_body.contains("sonarqube")
        && (lowered_body.contains("data-react-component")
            || lowered_body.contains("window.sonarqube"))
    {
        push_unique(&mut fingerprints, TechFingerprint::SonarQube);
    }

    // Kubernetes API (the `/api` and `/openapi/v2` discovery indices are extremely
    // distinctive when reachable).
    if lowered_body.contains("\"kind\":\"status\"") && lowered_body.contains("\"apiversion\"")
        || lowered_body.contains("\"groupversion\"")
            && lowered_body.contains("\"versions\"")
            && lowered_body.contains("\"serveraddressbyclientcidrs\"")
    {
        push_unique(&mut fingerprints, TechFingerprint::Kubernetes);
    }

    // Docker registry / docker daemon API
    if any_header_eq("docker-distribution-api-version")
        || any_header_eq("docker-content-digest")
        || lowered_body.contains("\"repositories\":[")
            && lowered_path.contains("/v2/_catalog")
    {
        push_unique(&mut fingerprints, TechFingerprint::Docker);
    }

    // MLflow
    if lowered_body.contains("<title>mlflow</title>")
        || lowered_body.contains("mlflow-static/")
    {
        push_unique(&mut fingerprints, TechFingerprint::Mlflow);
    }

    // JupyterHub
    if lowered_body.contains("<title>jupyterhub")
        || lowered_body.contains("jupyterhub")
    {
        push_unique(&mut fingerprints, TechFingerprint::JupyterHub);
    }

    // TensorBoard
    if lowered_body.contains("<title>tensorboard</title>")
        || lowered_body.contains("tf-tensorboard")
    {
        push_unique(&mut fingerprints, TechFingerprint::TensorBoard);
    }

    // Streamlit
    if lowered_body.contains("<title>streamlit</title>")
        || lowered_body.contains("stapp")
    {
        push_unique(&mut fingerprints, TechFingerprint::Streamlit);
    }

    // Gradio
    if lowered_body.contains("<gradio-app")
        || lowered_body.contains("gradio-container")
    {
        push_unique(&mut fingerprints, TechFingerprint::Gradio);
    }

    // Airflow
    if lowered_body.contains("<title>airflow</title>")
        || lowered_body.contains("apache airflow")
    {
        push_unique(&mut fingerprints, TechFingerprint::Airflow);
    }

    // Next.js (React meta-framework). The `__NEXT_DATA__` script tag is
    // emitted on every SSR/SSG page; `_next/static/chunks/` is the canonical
    // bundler output prefix.
    if lowered_body.contains("<script id=\"__next_data__\"")
        || lowered_body.contains("_next/static/chunks/")
        || lowered_path.starts_with("/_next/")
    {
        push_unique(&mut fingerprints, TechFingerprint::NextJs);
    }

    // Nuxt.js (Vue meta-framework).
    if lowered_body.contains("window.__nuxt__=")
        || lowered_body.contains("/_nuxt/entry.")
        || lowered_path.starts_with("/_nuxt/")
    {
        push_unique(&mut fingerprints, TechFingerprint::NuxtJs);
    }

    // SvelteKit.
    if lowered_body.contains("data-sveltekit-")
        || lowered_body.contains("/_app/immutable/chunks/")
        || lowered_path.starts_with("/_app/")
    {
        push_unique(&mut fingerprints, TechFingerprint::SvelteKit);
    }

    // Astro.
    if lowered_body.contains("<astro-island")
        || lowered_body.contains("/_astro/")
        || lowered_path.starts_with("/_astro/")
    {
        push_unique(&mut fingerprints, TechFingerprint::Astro);
    }

    // Remix.
    if lowered_body.contains("window.__remixcontext=")
        || lowered_body.contains("/build/manifest-")
        || lowered_path.starts_with("/__remix/")
    {
        push_unique(&mut fingerprints, TechFingerprint::Remix);
    }

    // Vite (dev server / build tool).
    if lowered_body.contains("<script type=\"module\" src=\"/@vite/client")
        || lowered_body.contains("__vite__")
        || lowered_path.starts_with("/@vite/")
    {
        push_unique(&mut fingerprints, TechFingerprint::Vite);
    }

    fingerprints
}

const MAX_BODY_INSPECT_BYTES: usize = 65_536;

fn push_unique(fingerprints: &mut Vec<TechFingerprint>, fingerprint: TechFingerprint) {
    if !fingerprints.contains(&fingerprint) {
        fingerprints.push(fingerprint);
    }
}

/// Materialize curated path lists for the detected fingerprints.
///
/// The lists below are intentionally conservative — every entry has a
/// real-world history of producing exposure findings (admin login pages,
/// leaked configs, version disclosure, debug endpoints, default
/// credentials, info pages). Generic scan paths (e.g. `/robots.txt`) are
/// omitted because they are already covered by other discovery layers.
pub fn candidates_for_fingerprints(
    fingerprints: &[TechFingerprint],
) -> Vec<TechPathCandidate> {
    let mut results: Vec<TechPathCandidate> = Vec::new();
    // Map normalized path -> index in `results`. When two fingerprints
    // contribute the same path (e.g. `/version` is in both KUBERNETES_PATHS
    // at 850 and DOCKER_PATHS at 880), keep the higher score and the
    // source that produced it so queue priority reflects the strongest
    // signal rather than insertion order.
    let mut seen: HashMap<String, usize> = HashMap::new();

    for fingerprint in fingerprints {
        for entry in paths_for_fingerprint(*fingerprint) {
            push_path_candidate(&mut results, &mut seen, *entry, fingerprint.source_tag());
        }
    }

    results
}

fn push_path_candidate(
    results: &mut Vec<TechPathCandidate>,
    seen: &mut HashMap<String, usize>,
    entry: TechPathEntry,
    source: &'static str,
) {
    let normalized = normalize_path(entry.path);
    if let Some(&index) = seen.get(&normalized) {
        let existing = &mut results[index];
        if entry.score > existing.score {
            existing.score = entry.score;
            existing.source = source;
        }
        return;
    }
    let index = results.len();
    results.push(TechPathCandidate {
        path: normalized.clone(),
        source,
        score: entry.score,
    });
    seen.insert(normalized, index);
}

fn normalize_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

#[derive(Debug, Clone, Copy)]
struct TechPathEntry {
    path: &'static str,
    score: u16,
}

const fn entry(path: &'static str, score: u16) -> TechPathEntry {
    TechPathEntry { path, score }
}

fn paths_for_fingerprint(fingerprint: TechFingerprint) -> &'static [TechPathEntry] {
    match fingerprint {
        TechFingerprint::WordPress => WORDPRESS_PATHS,
        TechFingerprint::Drupal => DRUPAL_PATHS,
        TechFingerprint::Joomla => JOOMLA_PATHS,
        TechFingerprint::Magento => MAGENTO_PATHS,
        TechFingerprint::PhpMyAdmin => PHPMYADMIN_PATHS,
        TechFingerprint::Adminer => ADMINER_PATHS,
        TechFingerprint::SpringBoot => SPRING_BOOT_PATHS,
        TechFingerprint::Tomcat => TOMCAT_PATHS,
        TechFingerprint::Jenkins => JENKINS_PATHS,
        TechFingerprint::GitLab => GITLAB_PATHS,
        TechFingerprint::Confluence => CONFLUENCE_PATHS,
        TechFingerprint::Jira => JIRA_PATHS,
        TechFingerprint::Grafana => GRAFANA_PATHS,
        TechFingerprint::Kibana => KIBANA_PATHS,
        TechFingerprint::Prometheus => PROMETHEUS_PATHS,
        TechFingerprint::Elasticsearch => ELASTICSEARCH_PATHS,
        TechFingerprint::DjangoAdmin => DJANGO_PATHS,
        TechFingerprint::RailsApp => RAILS_PATHS,
        TechFingerprint::LaravelApp => LARAVEL_PATHS,
        TechFingerprint::NextCloud => NEXTCLOUD_PATHS,
        TechFingerprint::Gitea => GITEA_PATHS,
        TechFingerprint::Nginx => NGINX_PATHS,
        TechFingerprint::ApacheHttpd => APACHE_PATHS,
        TechFingerprint::IIS => IIS_PATHS,
        TechFingerprint::NodeJsExpress => EXPRESS_PATHS,
        TechFingerprint::PhpGeneric => PHP_GENERIC_PATHS,
        TechFingerprint::SonarQube => SONARQUBE_PATHS,
        TechFingerprint::Kubernetes => KUBERNETES_PATHS,
        TechFingerprint::Docker => DOCKER_PATHS,
        TechFingerprint::DotNetMvc => DOTNET_MVC_PATHS,
        TechFingerprint::Mlflow => MLFLOW_PATHS,
        TechFingerprint::JupyterHub => JUPYTERHUB_PATHS,
        TechFingerprint::TensorBoard => TENSORBOARD_PATHS,
        TechFingerprint::Streamlit => STREAMLIT_PATHS,
        TechFingerprint::Gradio => GRADIO_PATHS,
        TechFingerprint::Airflow => AIRFLOW_PATHS,
        TechFingerprint::NextJs => NEXTJS_PATHS,
        TechFingerprint::NuxtJs => NUXTJS_PATHS,
        TechFingerprint::SvelteKit => SVELTEKIT_PATHS,
        TechFingerprint::Astro => ASTRO_PATHS,
        TechFingerprint::Remix => REMIX_PATHS,
        TechFingerprint::Vite => VITE_PATHS,
    }
}

// =====================================================================
// Curated wordlists. Score floors:
//   960 - admin login / unauthenticated config exposure (high yield)
//   920 - software-specific leaked file / credential dump path
//   880 - dashboard / debug / metrics page
//   850 - version / health / info endpoint
//   820 - software-specific feature endpoint with moderate yield
// =====================================================================

const WORDPRESS_PATHS: &[TechPathEntry] = &[
    entry("/wp-login.php", 960),
    entry("/wp-admin/", 960),
    entry("/wp-admin/install.php", 950),
    entry("/wp-admin/setup-config.php", 950),
    entry("/wp-config.php", 940),
    entry("/wp-config.php.bak", 940),
    entry("/wp-config.php.old", 935),
    entry("/wp-config.php.save", 935),
    entry("/wp-config.php.swp", 930),
    entry("/wp-config.php~", 930),
    entry("/wp-config-sample.php", 880),
    entry("/.wp-config.php.swp", 925),
    entry("/xmlrpc.php", 920),
    entry("/wp-cron.php", 880),
    entry("/wp-trackback.php", 850),
    entry("/wp-json/", 880),
    entry("/wp-json/wp/v2/users", 940),
    entry("/wp-json/wp/v2/users/?per_page=1", 935),
    entry("/wp-json/wp/v2/posts", 870),
    entry("/wp-json/wp/v2/pages", 870),
    entry("/wp-json/wp/v2/media", 860),
    entry("/wp-json/oembed/1.0/embed", 830),
    entry("/?author=1", 880),
    entry("/wp-content/debug.log", 940),
    entry("/wp-content/uploads/", 870),
    entry("/wp-content/backup-db/", 920),
    entry("/wp-content/plugins/", 850),
    entry("/wp-content/themes/", 850),
    entry("/wp-includes/", 830),
    entry("/readme.html", 870),
    entry("/license.txt", 850),
    entry("/wp-admin/admin-ajax.php", 850),
    entry("/wp-admin/load-scripts.php", 840),
    entry("/wp-admin/load-styles.php", 840),
    entry("/wp-admin/plugins.php", 880),
    entry("/wp-admin/users.php", 900),
];

const DRUPAL_PATHS: &[TechPathEntry] = &[
    entry("/CHANGELOG.txt", 880),
    entry("/INSTALL.txt", 850),
    entry("/MAINTAINERS.txt", 830),
    entry("/sites/default/settings.php", 940),
    entry("/sites/default/settings.php.save", 940),
    entry("/sites/default/settings.php.bak", 940),
    entry("/sites/default/files/", 850),
    entry("/sites/default/private/", 920),
    entry("/user/login", 950),
    entry("/user/register", 880),
    entry("/admin/", 950),
    entry("/admin/config", 950),
    entry("/admin/people", 920),
    entry("/admin/structure", 880),
    entry("/admin/reports/status", 920),
    entry("/admin/reports/dblog", 900),
    entry("/jsonapi/", 880),
    entry("/?q=user/login", 880),
    entry("/?q=admin", 880),
    entry("/core/CHANGELOG.txt", 880),
    entry("/core/install.php", 920),
    entry("/cron.php", 870),
    entry("/install.php", 920),
    entry("/update.php", 920),
];

const JOOMLA_PATHS: &[TechPathEntry] = &[
    entry("/administrator/", 960),
    entry("/administrator/index.php", 960),
    entry("/administrator/manifests/files/joomla.xml", 940),
    entry("/configuration.php", 950),
    entry("/configuration.php.bak", 940),
    entry("/configuration.php-dist", 920),
    entry("/htaccess.txt", 850),
    entry("/web.config.txt", 880),
    entry("/language/en-GB/en-GB.xml", 850),
    entry("/components/com_users/", 850),
    entry("/api/index.php/v1/users", 920),
    entry("/installation/", 940),
    entry("/cli/", 880),
    entry("/joomla.xml", 880),
];

const MAGENTO_PATHS: &[TechPathEntry] = &[
    entry("/admin", 960),
    entry("/index.php/admin", 960),
    entry("/downloader/", 940),
    entry("/RELEASE_NOTES.txt", 880),
    entry("/app/etc/local.xml", 950),
    entry("/app/etc/env.php", 950),
    entry("/app/etc/config.php", 920),
    entry("/var/log/exception.log", 920),
    entry("/var/log/system.log", 880),
    entry("/dev/tests/acceptance/", 850),
    entry("/setup/", 880),
    entry("/rest/V1/products", 880),
    entry("/rest/V1/customers/me", 940),
    entry("/rest/V1/integration/admin/token", 920),
    entry("/static/version1/frontend/", 820),
];

const PHPMYADMIN_PATHS: &[TechPathEntry] = &[
    entry("/phpmyadmin/", 960),
    entry("/phpmyadmin/index.php", 960),
    entry("/phpmyadmin/config-db.php", 940),
    entry("/phpmyadmin/setup/index.php", 950),
    entry("/pma/", 960),
    entry("/pma/index.php", 960),
    entry("/myadmin/", 940),
    entry("/dbadmin/", 920),
    entry("/mysql/", 880),
    entry("/sqlweb/", 880),
    entry("/phpmyadmin/Documentation.html", 850),
    entry("/phpmyadmin/scripts/setup.php", 940),
    entry("/phpmyadmin/themes/pmahomme/img/logo_right.png", 820),
];

const ADMINER_PATHS: &[TechPathEntry] = &[
    entry("/adminer.php", 960),
    entry("/adminer/", 960),
    entry("/adminer-4.8.1.php", 950),
    entry("/adminer-4.8.1-en.php", 940),
    entry("/db/adminer.php", 940),
    entry("/sql/adminer.php", 940),
];

const SPRING_BOOT_PATHS: &[TechPathEntry] = &[
    entry("/actuator", 920),
    entry("/actuator/", 920),
    entry("/actuator/env", 960),
    entry("/actuator/configprops", 960),
    entry("/actuator/heapdump", 960),
    entry("/actuator/threaddump", 940),
    entry("/actuator/beans", 920),
    entry("/actuator/mappings", 920),
    entry("/actuator/loggers", 880),
    entry("/actuator/health", 850),
    entry("/actuator/info", 850),
    entry("/actuator/metrics", 880),
    entry("/actuator/conditions", 880),
    entry("/actuator/auditevents", 920),
    entry("/actuator/httptrace", 920),
    entry("/actuator/trace", 920),
    entry("/actuator/dump", 920),
    entry("/actuator/jolokia", 920),
    entry("/actuator/jolokia/list", 920),
    entry("/actuator/refresh", 880),
    entry("/actuator/restart", 880),
    entry("/actuator/shutdown", 920),
    entry("/actuator/gateway/routes", 920),
    entry("/actuator/scheduledtasks", 880),
    entry("/jolokia/list", 940),
    entry("/jolokia/", 920),
    entry("/env", 920),
    entry("/configprops", 920),
    entry("/heapdump", 940),
    entry("/threaddump", 920),
    entry("/beans", 880),
    entry("/mappings", 880),
    entry("/dump", 920),
    entry("/trace", 920),
    entry("/error", 850),
];

const TOMCAT_PATHS: &[TechPathEntry] = &[
    entry("/manager/html", 960),
    entry("/manager/status", 920),
    entry("/manager/text", 920),
    entry("/manager/jmxproxy", 940),
    entry("/host-manager/html", 960),
    entry("/host-manager/text", 920),
    entry("/admin/", 920),
    entry("/examples/servlets/", 850),
    entry("/examples/jsp/", 850),
    entry("/docs/RELEASE-NOTES.txt", 880),
    entry("/RELEASE-NOTES.txt", 880),
];

const JENKINS_PATHS: &[TechPathEntry] = &[
    entry("/login", 920),
    entry("/manage", 940),
    entry("/script", 960),
    entry("/scriptText", 960),
    entry("/asynchPeople/", 920),
    entry("/computer/", 880),
    entry("/credentials/", 940),
    entry("/credentials/store/system/domain/_/", 920),
    entry("/job/", 850),
    entry("/api/json", 880),
    entry("/api/json?pretty=true", 880),
    entry("/api/xml", 850),
    entry("/whoAmI/", 920),
    entry("/people/", 880),
    entry("/cli", 940),
    entry("/securityRealm/user/admin", 920),
    entry("/configureSecurity/", 940),
    entry("/systemInfo", 880),
    entry("/log/all", 880),
    entry("/jenkins/login", 920),
    entry("/jenkins/script", 960),
    entry("/static/", 820),
];

const GITLAB_PATHS: &[TechPathEntry] = &[
    entry("/users/sign_in", 960),
    entry("/users/sign_up", 880),
    entry("/admin", 960),
    entry("/admin/sidekiq", 940),
    entry("/api/v4/version", 940),
    entry("/api/v4/projects", 920),
    entry("/api/v4/users", 940),
    entry("/api/v4/runners", 920),
    entry("/api/v4/internal/", 940),
    entry("/api/v4/groups", 920),
    entry("/api/v4/metadata", 920),
    entry("/-/metrics", 920),
    entry("/-/health", 850),
    entry("/-/readiness", 850),
    entry("/-/liveness", 850),
    entry("/help", 850),
    entry("/explore/projects", 850),
    entry("/dashboard", 880),
    entry("/.well-known/openid-configuration", 880),
];

const CONFLUENCE_PATHS: &[TechPathEntry] = &[
    entry("/login.action", 940),
    entry("/dologin.action", 920),
    entry("/spaces/viewspacesummary.action", 920),
    entry("/spaces/spacedirectory.action", 880),
    entry("/admin/", 940),
    entry("/admin/users/browseusers.action", 940),
    entry("/admin/configurePermissions.action", 920),
    entry("/admin/license.action", 920),
    entry("/setup/setupserver.action", 920),
    entry("/setup/setupbundleorlicense.action", 920),
    entry("/rest/api/content", 880),
    entry("/rest/api/space", 880),
    entry("/rest/api/group", 880),
    entry("/rest/api/user", 920),
    entry("/rest/tinymce/1/macro/preview", 920),
    entry("/wiki/login.action", 940),
    entry("/wiki/", 880),
    entry("/wiki/dologin.action", 920),
    entry("/wiki/admin/", 940),
];

const JIRA_PATHS: &[TechPathEntry] = &[
    entry("/login.jsp", 940),
    entry("/secure/Dashboard.jspa", 940),
    entry("/secure/admin/ViewLicense.jspa", 920),
    entry("/secure/admin/user/UserBrowser.jspa", 940),
    entry("/secure/admin/InstrumentedCacheManagerStats.jspa", 920),
    entry("/secure/admin/IntegrityChecker.jspa", 920),
    entry("/rest/api/2/serverInfo", 940),
    entry("/rest/api/2/dashboard", 880),
    entry("/rest/api/2/issue", 880),
    entry("/rest/api/2/user", 920),
    entry("/rest/api/3/serverInfo", 940),
    entry("/rest/auth/1/session", 880),
    entry("/jira/login.jsp", 940),
    entry("/jira/secure/Dashboard.jspa", 920),
    entry("/jira/rest/api/2/serverInfo", 920),
    entry("/sr/jira.issueviews:searchrequest-xml/temp/SearchRequest.xml", 920),
    entry("/issuenavigator!default.jspa", 850),
];

const GRAFANA_PATHS: &[TechPathEntry] = &[
    entry("/login", 940),
    entry("/api/health", 850),
    entry("/api/admin/users", 960),
    entry("/api/admin/settings", 940),
    entry("/api/admin/stats", 920),
    entry("/api/orgs", 940),
    entry("/api/datasources", 940),
    entry("/api/dashboards/home", 880),
    entry("/api/search?query=&type=dash-db", 880),
    entry("/api/users/search", 920),
    entry("/api/teams/search", 880),
    entry("/api/serviceaccounts/search", 920),
    entry("/api/snapshots", 850),
    entry("/api/plugins", 850),
    entry("/api/frontend/settings", 850),
    entry("/d/", 880),
    entry("/render/", 880),
    entry("/connections/datasources", 850),
];

const KIBANA_PATHS: &[TechPathEntry] = &[
    entry("/api/status", 920),
    entry("/api/security/role", 920),
    entry("/api/saved_objects/_find?type=visualization", 880),
    entry("/api/saved_objects/_find?type=dashboard", 880),
    entry("/api/saved_objects/_find?type=index-pattern", 920),
    entry("/api/console/proxy?path=_cluster/health", 940),
    entry("/api/console/proxy?path=_cat/indices", 940),
    entry("/api/console/proxy?path=.kibana/_search", 940),
    entry("/api/index_management/indices", 880),
    entry("/api/spaces/space", 880),
    entry("/login", 880),
    entry("/app/management/security/users", 940),
    entry("/app/dev_tools", 880),
    entry("/internal/security/me", 920),
];

const PROMETHEUS_PATHS: &[TechPathEntry] = &[
    entry("/", 850),
    entry("/-/healthy", 850),
    entry("/-/ready", 850),
    entry("/-/reload", 920),
    entry("/-/quit", 940),
    entry("/api/v1/status/config", 940),
    entry("/api/v1/status/runtimeinfo", 920),
    entry("/api/v1/status/buildinfo", 880),
    entry("/api/v1/status/flags", 920),
    entry("/api/v1/targets", 880),
    entry("/api/v1/alerts", 880),
    entry("/api/v1/rules", 880),
    entry("/api/v1/labels", 850),
    entry("/api/v1/series", 850),
    entry("/metrics", 880),
    entry("/graph", 850),
];

const ELASTICSEARCH_PATHS: &[TechPathEntry] = &[
    entry("/", 940),
    entry("/_cluster/health", 880),
    entry("/_cluster/state", 920),
    entry("/_cluster/settings", 920),
    entry("/_cluster/stats", 920),
    entry("/_nodes", 920),
    entry("/_nodes/stats", 880),
    entry("/_cat/indices?v", 920),
    entry("/_cat/nodes?v", 880),
    entry("/_cat/aliases?v", 850),
    entry("/_cat/health?v", 850),
    entry("/_cat/templates?v", 850),
    entry("/_search", 920),
    entry("/_settings", 880),
    entry("/_security/_authenticate", 880),
    entry("/_xpack", 850),
    entry("/_snapshot", 880),
];

const DJANGO_PATHS: &[TechPathEntry] = &[
    entry("/admin/", 960),
    entry("/admin/login/", 960),
    entry("/admin/logout/", 850),
    entry("/admin/password_change/", 880),
    entry("/admin/auth/user/", 940),
    entry("/admin/auth/group/", 880),
    entry("/admin/sites/site/", 880),
    entry("/__debug__/", 920),
    entry("/__debug__/sql_select/", 880),
    entry("/static/admin/css/base.css", 850),
    entry("/static/admin/js/SelectFilter2.js", 820),
    entry("/silk/", 920),
    entry("/silk/requests/", 920),
    entry("/api-auth/login/", 880),
    entry("/api/", 850),
    entry("/accounts/login/", 880),
    entry("/accounts/profile/", 850),
    entry("/jet/", 880),
    entry("/grappelli/", 850),
];

const RAILS_PATHS: &[TechPathEntry] = &[
    entry("/rails/info/properties", 940),
    entry("/rails/info/routes", 940),
    entry("/rails/info", 880),
    entry("/rails/conductor/action_mailbox/inbound_emails", 880),
    entry("/rails/db/", 920),
    entry("/rails/mailers", 880),
    entry("/sidekiq", 940),
    entry("/sidekiq/", 940),
    entry("/admin/sidekiq", 940),
    entry("/blazer", 920),
    entry("/blazer/queries", 920),
    entry("/letter_opener", 880),
    entry("/que/", 880),
    entry("/resque/", 940),
    entry("/resque/overview", 940),
    entry("/users/sign_in", 940),
    entry("/users/sign_up", 850),
    entry("/admin", 920),
    entry("/admin/login", 920),
    entry("/active_admin/", 920),
    entry("/avo/", 880),
    entry("/grafana/", 850),
    entry("/manifest.json", 820),
];

const LARAVEL_PATHS: &[TechPathEntry] = &[
    entry("/.env", 960),
    entry("/.env.example", 880),
    entry("/.env.backup", 940),
    entry("/.env.old", 940),
    entry("/.env.production", 950),
    entry("/.env.dev", 940),
    entry("/.env.local", 940),
    entry("/storage/logs/laravel.log", 940),
    entry("/storage/logs/laravel-2024-01-01.log", 880),
    entry("/_ignition/health-check", 940),
    entry("/_ignition/execute-solution", 960),
    entry("/_debugbar/open", 920),
    entry("/_debugbar/clockwork/", 920),
    entry("/telescope/", 940),
    entry("/telescope", 940),
    entry("/horizon/", 920),
    entry("/horizon", 920),
    entry("/horizon/api/jobs", 920),
    entry("/api/user", 880),
    entry("/login", 880),
    entry("/register", 850),
    entry("/storage/", 850),
    entry("/public/", 820),
    entry("/index.php?REBEL=MEOW", 880),
];

const NEXTCLOUD_PATHS: &[TechPathEntry] = &[
    entry("/login", 920),
    entry("/status.php", 940),
    entry("/index.php/login", 920),
    entry("/index.php/settings/admin", 940),
    entry("/ocs/v1.php/cloud/users", 940),
    entry("/ocs/v2.php/cloud/users", 940),
    entry("/ocs/v2.php/apps/serverinfo/api/v1/info", 940),
    entry("/remote.php/dav/", 880),
    entry("/remote.php/webdav/", 880),
    entry("/index.php/apps/files/", 850),
    entry("/data/", 880),
    entry("/config/config.php", 950),
];

const GITEA_PATHS: &[TechPathEntry] = &[
    entry("/user/login", 920),
    entry("/user/sign_up", 880),
    entry("/-/admin/users", 940),
    entry("/-/admin/config", 940),
    entry("/-/admin/auths", 920),
    entry("/api/v1/version", 920),
    entry("/api/v1/users/search", 920),
    entry("/api/v1/repos/search", 880),
    entry("/api/v1/admin/users", 940),
    entry("/explore/repos", 850),
    entry("/issues", 850),
    entry("/metrics", 850),
];

const NGINX_PATHS: &[TechPathEntry] = &[
    entry("/nginx_status", 920),
    entry("/status", 850),
    entry("/server-status", 850),
    entry("/.well-known/acme-challenge/", 850),
    entry("/basic_status", 880),
];

const APACHE_PATHS: &[TechPathEntry] = &[
    entry("/server-status", 940),
    entry("/server-info", 920),
    entry("/server-status?refresh=1", 880),
    entry("/icons/", 820),
    entry("/cgi-bin/", 880),
    entry("/manual/", 850),
    entry("/.htaccess", 850),
    entry("/.htpasswd", 940),
];

const IIS_PATHS: &[TechPathEntry] = &[
    entry("/iisstart.htm", 850),
    entry("/web.config", 940),
    entry("/web.config.bak", 940),
    entry("/web.config.old", 920),
    entry("/web.config.txt", 920),
    entry("/global.asax", 920),
    entry("/global.asa", 880),
    entry("/AspNetMVC/", 880),
    entry("/Trace.axd", 940),
    entry("/elmah.axd", 940),
    entry("/wsman", 880),
    entry("/wstools.htm", 850),
];

const EXPRESS_PATHS: &[TechPathEntry] = &[
    entry("/api", 850),
    entry("/api-docs", 880),
    entry("/api-docs.json", 880),
    entry("/health", 850),
    entry("/healthz", 850),
    entry("/status", 850),
    entry("/swagger.json", 880),
    entry("/_status", 850),
    entry("/_health", 850),
];

const PHP_GENERIC_PATHS: &[TechPathEntry] = &[
    entry("/info.php", 940),
    entry("/phpinfo.php", 940),
    entry("/test.php", 880),
    entry("/index.php?-s", 920),
    entry("/server-info.php", 880),
    entry("/php_info.php", 880),
    entry("/_phpinfo.php", 880),
];

const SONARQUBE_PATHS: &[TechPathEntry] = &[
    entry("/api/system/status", 880),
    entry("/api/system/info", 940),
    entry("/api/system/health", 880),
    entry("/api/users/search", 940),
    entry("/api/permissions/users", 940),
    entry("/api/settings/values", 940),
    entry("/api/components/search?qualifiers=TRK", 880),
    entry("/sessions/new", 880),
    entry("/sessions/init", 880),
    entry("/account/", 850),
];

const KUBERNETES_PATHS: &[TechPathEntry] = &[
    entry("/api", 850),
    entry("/api/v1", 850),
    entry("/api/v1/namespaces", 920),
    entry("/api/v1/secrets", 960),
    entry("/api/v1/configmaps", 940),
    entry("/api/v1/pods", 880),
    entry("/api/v1/nodes", 880),
    entry("/apis", 850),
    entry("/openapi/v2", 880),
    entry("/openapi/v3", 880),
    entry("/version", 850),
    entry("/healthz", 850),
    entry("/readyz", 850),
    entry("/livez", 850),
    entry("/metrics", 880),
    entry("/api/v1/namespaces/kube-system/secrets", 960),
];

const DOCKER_PATHS: &[TechPathEntry] = &[
    entry("/v2/", 880),
    entry("/v2/_catalog", 940),
    entry("/v2/_catalog?n=10000", 940),
    entry("/info", 940),
    entry("/version", 880),
    entry("/containers/json", 940),
    entry("/images/json", 920),
    entry("/networks", 920),
    entry("/volumes", 920),
    entry("/services", 920),
    entry("/nodes", 920),
    entry("/secrets", 940),
];

const DOTNET_MVC_PATHS: &[TechPathEntry] = &[
    entry("/Account/Login", 940),
    entry("/Account/Register", 850),
    entry("/swagger/index.html", 880),
    entry("/swagger/v1/swagger.json", 920),
    entry("/Trace.axd", 940),
    entry("/elmah.axd", 940),
    entry("/Telerik.Web.UI.WebResource.axd", 880),
    entry("/Reserved.ReportViewerWebControl.axd", 880),
];

const MLFLOW_PATHS: &[TechPathEntry] = &[
    entry("/api/2.0/mlflow/runs/search", 880),
    entry("/api/2.0/mlflow/experiments/list", 880),
    entry("/api/2.0/mlflow/registered-models/search", 880),
    entry("/get-artifact", 850),
    entry("/ajax-api/2.0/preview/mlflow/artifacts/list", 850),
    entry("/api/2.0/mlflow/experiments/search", 850),
    entry("/api/2.0/mlflow/model-versions/search", 850),
    entry("/api/2.0/mlflow/runs/get", 820),
];

const JUPYTERHUB_PATHS: &[TechPathEntry] = &[
    entry("/hub/api", 880),
    entry("/hub/api/info", 880),
    entry("/hub/login", 880),
    entry("/user/", 850),
    entry("/services/", 850),
    entry("/tree", 850),
    entry("/api/contents", 820),
    entry("/hub/admin", 880),
];

const TENSORBOARD_PATHS: &[TechPathEntry] = &[
    entry("/data/runs", 880),
    entry("/data/plugin/scalars/scalars", 850),
    entry("/data/plugin/projector/runs", 850),
    entry("/index.json", 820),
    entry("/data/plugin/graphs/graph", 820),
    entry("/data/plugin/text/text", 820),
];

const STREAMLIT_PATHS: &[TechPathEntry] = &[
    entry("/_stcore/health", 880),
    entry("/_stcore/host-config", 880),
    entry("/_stcore/stream", 850),
    entry("/static/static/", 820),
    entry("/healthz", 850),
    entry("/_stcore/allowed-message-origins", 820),
];

const GRADIO_PATHS: &[TechPathEntry] = &[
    entry("/info", 880),
    entry("/config", 880),
    entry("/file=", 850),
    entry("/gradio_api/", 850),
    entry("/run/predict", 850),
    entry("/queue/join", 820),
    entry("/queue/data", 820),
];

const AIRFLOW_PATHS: &[TechPathEntry] = &[
    entry("/api/v1/dags", 880),
    entry("/api/v1/dagRuns", 880),
    entry("/api/v1/connections", 880),
    entry("/api/v1/variables", 880),
    entry("/health", 850),
    entry("/login/?next=/", 850),
    entry("/admin/", 850),
    entry("/api/v1/pools", 820),
    entry("/api/v1/users", 880),
];

// Modern JS framework wordlists. These are bundler-output prefixes and
// build-time manifests that frequently leak route maps, server payloads,
// and source-mapped server bundles when shipped to production unstripped.
const NEXTJS_PATHS: &[TechPathEntry] = &[
    entry("/_next/data/", 860),
    entry("/_next/image", 830),
    entry("/_next/static/", 850),
    entry("/_next/server/", 880),
    entry("/_buildManifest.js", 870),
    entry("/_ssgManifest.js", 870),
    entry("/api/auth/session", 870),
    entry("/_next/webpack-hmr", 840),
];

const NUXTJS_PATHS: &[TechPathEntry] = &[
    entry("/_nuxt/", 850),
    entry("/__nuxt_error", 870),
    entry("/.nuxt/dist/client/manifest.json", 880),
    entry("/api/_content/", 840),
    entry("/api/_nuxt_island/", 830),
];

const SVELTEKIT_PATHS: &[TechPathEntry] = &[
    entry("/.svelte-kit/", 880),
    entry("/_app/version.json", 850),
    entry("/_app/immutable/", 840),
    entry("/__data.json", 870),
];

const ASTRO_PATHS: &[TechPathEntry] = &[
    entry("/_astro/", 850),
    entry("/_astro/page.", 830),
    entry("/_image?href=", 830),
];

const REMIX_PATHS: &[TechPathEntry] = &[
    entry("/__remix/", 860),
    entry("/__manifest", 870),
    entry("/build/", 840),
    entry("/build/manifest-*.js", 850),
];

const VITE_PATHS: &[TechPathEntry] = &[
    entry("/@vite/client", 880),
    entry("/@vite/env", 870),
    entry("/__vite_ping", 850),
    entry("/.vite/manifest.json", 880),
];

// =====================================================================
// Sensitive backup / VCS leakage variant generator (path -> variants).
//
// Given a discovered file path or directory prefix, derive additional
// candidate paths that are common sensitive sibling files (backup
// variants of the discovered file, plus VCS / IDE leakage paths at the
// same parent directory).  Existing code already handles `.json -> .bak`
// and `.js -> .js.map`; this generator covers PHP, ASPX, JSP, TXT, YAML,
// XML, conf, and the universal VCS/IDE leakage set.
// =====================================================================

const BACKUP_SUFFIXES: &[&str] = &[
    ".bak", ".old", ".orig", ".save", ".tmp", ".swp", ".swo", "~", ".copy",
];

const SENSITIVE_PARENT_PATHS: &[(&str, u16)] = &[
    ("/.git/HEAD", 940),
    ("/.git/config", 940),
    ("/.git/index", 880),
    ("/.git/logs/HEAD", 880),
    ("/.git/refs/heads/main", 850),
    ("/.git/refs/heads/master", 850),
    ("/.git/packed-refs", 850),
    ("/.svn/entries", 920),
    ("/.svn/wc.db", 920),
    ("/.hg/store/00manifest.i", 920),
    ("/.bzr/branch/last-revision", 880),
    ("/.DS_Store", 920),
    ("/.idea/workspace.xml", 920),
    ("/.idea/modules.xml", 880),
    ("/.idea/vcs.xml", 850),
    ("/.vscode/sftp.json", 920),
    ("/.vscode/launch.json", 850),
    ("/.vscode/settings.json", 850),
];

/// For a discovered path, emit additional candidate paths that are
/// commonly leaked alongside (backup/swap copies of the file and
/// VCS/IDE leakage at the parent directory level).
pub fn sensitive_variant_candidates(path: &str) -> Vec<TechPathCandidate> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut results: Vec<TechPathCandidate> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for variant in backup_variants_for(trimmed) {
        if seen.insert(variant.clone()) {
            let score = backup_variant_score(&variant);
            results.push(TechPathCandidate {
                path: variant,
                source: "sensitive-backup-variant",
                score,
            });
        }
    }

    // Lifecycle expansion for `.env*` discoveries: when a `.env`-family
    // file is found in a directory, the same directory is highly likely
    // to host other lifecycle/environment variants (`.env.local`,
    // `.env.production`, etc.). Emit the rest of the family so dynamic
    // discovery surfaces them too — operators do not have to opt into
    // the full static `dotenv-variants` profile to benefit.
    for variant in dotenv_lifecycle_variants_for(trimmed) {
        if seen.insert(variant.clone()) {
            results.push(TechPathCandidate {
                path: variant,
                source: "sensitive-dotenv-variant",
                score: 920,
            });
        }
    }

    let directory_for_leaks = if trimmed.ends_with('/') {
        trimmed.trim_end_matches('/').to_string()
    } else {
        let parent = parent_directory(trimmed);
        if parent.is_empty() || parent == "/" {
            String::new()
        } else {
            parent.trim_end_matches('/').to_string()
        }
    };
    let parent_normalized = directory_for_leaks;

    for (suffix, score) in SENSITIVE_PARENT_PATHS {
        let derived = if parent_normalized.is_empty() {
            (*suffix).to_string()
        } else {
            format!("{parent_normalized}{suffix}")
        };
        if seen.insert(derived.clone()) {
            results.push(TechPathCandidate {
                path: derived,
                source: "sensitive-vcs-leak",
                score: *score,
            });
        }
    }

    results
}

fn backup_variants_for(path: &str) -> Vec<String> {
    let lowered = path.to_ascii_lowercase();

    // Directory-style paths and obvious binary assets are skipped — backup
    // variants of `/images/` or `/index.html.png` are noise.
    if path.ends_with('/') {
        return Vec::new();
    }
    if has_noise_suffix(&lowered) {
        return Vec::new();
    }
    if !is_backup_eligible(&lowered) {
        return Vec::new();
    }

    let mut variants = Vec::new();
    for suffix in BACKUP_SUFFIXES {
        variants.push(format!("{path}{suffix}"));
    }

    if let Some(filename_index) = path.rfind('/') {
        let (parent, file_name) = path.split_at(filename_index + 1);
        if !file_name.is_empty() && !file_name.starts_with('.') {
            variants.push(format!("{parent}.{file_name}.swp"));
            variants.push(format!("{parent}.{file_name}.swo"));
        }
    }

    variants
}

fn has_noise_suffix(lowered: &str) -> bool {
    const NOISE: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff",
        ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".mp3", ".webm", ".pdf",
        ".css", ".scss", ".sass", ".less",
    ];
    NOISE.iter().any(|suffix| lowered.ends_with(suffix))
}

fn is_backup_eligible(lowered: &str) -> bool {
    const ELIGIBLE: &[&str] = &[
        ".php", ".phtml", ".aspx", ".asp", ".ashx", ".asmx", ".jsp", ".jspx",
        ".do", ".action", ".rb", ".py", ".pl", ".cgi", ".sh", ".env",
        ".env.local", ".env.production", ".env.dev", ".conf", ".config",
        ".cfg", ".ini", ".xml", ".yml", ".yaml", ".toml", ".sql", ".db",
        ".sqlite", ".sqlite3", ".tar", ".tar.gz", ".tgz", ".zip", ".7z",
        ".rar", ".log", ".txt", ".md",
    ];
    ELIGIBLE.iter().any(|suffix| lowered.ends_with(suffix))
}

fn backup_variant_score(variant: &str) -> u16 {
    let lowered = variant.to_ascii_lowercase();
    if lowered.contains(".env") {
        return 920;
    }
    if lowered.contains("config")
        || lowered.contains("settings")
        || lowered.contains("secrets")
    {
        return 880;
    }
    if lowered.ends_with(".swp") || lowered.ends_with(".swo") {
        return 860;
    }
    820
}

// Lifecycle / framework / edge-case suffixes for the `.env` family.
// When `/foo/.env` is discovered we emit `/foo/.env.local`,
// `/foo/.env.production`, etc.
const DOTENV_LIFECYCLE_SUFFIXES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.staging",
    ".env.test",
    ".env.testing",
    ".env.dev",
    ".env.prod",
    ".env.qa",
    ".env.uat",
    ".env.example",
    ".env.sample",
    ".env.dist",
    ".env.template",
    ".env.default",
    ".env.development.local",
    ".env.production.local",
    ".env.staging.local",
    ".env.test.local",
    ".env.docker",
    ".env.compose",
    ".env.shared",
    ".env.atlas",
    ".env.vault",
    ".env.vercel",
    ".env.netlify",
    ".env.heroku",
    ".env.bak",
    ".env.old",
    ".env.orig",
    ".env.save",
    ".env.swp",
    ".env.swo",
    ".env~",
    ".envrc",
    ".flaskenv",
];

fn dotenv_lifecycle_variants_for(path: &str) -> Vec<String> {
    if path.ends_with('/') {
        return Vec::new();
    }

    let (parent_with_slash, file_name) = match path.rfind('/') {
        Some(idx) => (&path[..=idx], &path[idx + 1..]),
        None => return Vec::new(),
    };

    if !is_dotenv_family_basename(file_name) {
        return Vec::new();
    }

    DOTENV_LIFECYCLE_SUFFIXES
        .iter()
        .map(|suffix| format!("{parent_with_slash}{suffix}"))
        .collect()
}

fn is_dotenv_family_basename(file_name: &str) -> bool {
    let lowered = file_name.to_ascii_lowercase();
    if lowered.is_empty() {
        return false;
    }
    matches!(
        lowered.as_str(),
        "dotenv"
            | ".dotenv"
            | "env"
            | "env.local"
            | "env.production"
            | ".envrc"
            | ".flaskenv"
    ) || lowered.starts_with(".env")
        || lowered.starts_with("env.")
        || lowered.starts_with(".env_")
}

fn parent_directory(path: &str) -> &str {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/";
    }
    let without_trailing = trimmed.trim_end_matches('/');
    if let Some((directory, _)) = without_trailing.rsplit_once('/') {
        if directory.is_empty() { "/" } else { directory }
    } else {
        "/"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_only(body: &str) -> Vec<TechFingerprint> {
        detect_tech_fingerprints("/", None, &[], body)
    }

    fn header_only(name: &str, value: &str) -> Vec<TechFingerprint> {
        detect_tech_fingerprints(
            "/",
            None,
            &[(name.to_string(), value.to_string())],
            "",
        )
    }

    #[test]
    fn detects_wordpress_from_body() {
        let body = r#"<link rel='stylesheet' href='https://example.com/wp-content/themes/twentytwentyone/style.css'>"#;
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::WordPress));
    }

    #[test]
    fn detects_wordpress_from_generator_meta() {
        let body = r#"<meta name="generator" content="WordPress 6.4.2" />"#;
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::WordPress));
    }

    #[test]
    fn detects_drupal_from_settings_marker() {
        let body = r#"<script>jQuery.extend(Drupal.settings, {"basePath":"/"})</script>"#;
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::Drupal));
    }

    #[test]
    fn detects_joomla_from_components_path() {
        let body = r#"<a href="/components/com_users/login.html">Login</a>"#;
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::Joomla));
    }

    #[test]
    fn detects_spring_boot_from_actuator_path() {
        let fps =
            detect_tech_fingerprints("/actuator/health", Some("application/json"), &[], "{}");
        assert!(fps.contains(&TechFingerprint::SpringBoot));
    }

    #[test]
    fn detects_spring_boot_from_whitelabel_error() {
        let body = "<html><body><h1>Whitelabel Error Page</h1></body></html>";
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::SpringBoot));
    }

    #[test]
    fn detects_jenkins_from_x_jenkins_header() {
        let fps = header_only("X-Jenkins", "2.426.3");
        assert!(fps.contains(&TechFingerprint::Jenkins));
    }

    #[test]
    fn detects_gitlab_from_x_gitlab_header() {
        let fps = header_only("X-Gitlab-Meta", "{\"correlation_id\":\"abc\"}");
        assert!(fps.contains(&TechFingerprint::GitLab));
    }

    #[test]
    fn detects_grafana_from_body() {
        let body = "<body><grafana-app></grafana-app></body>";
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::Grafana));
    }

    #[test]
    fn detects_kibana_from_kbn_name_header() {
        let fps = header_only("kbn-name", "kibana");
        assert!(fps.contains(&TechFingerprint::Kibana));
    }

    #[test]
    fn detects_prometheus_from_metrics_exposition_format() {
        let body = "# HELP go_gc_duration_seconds Summary of the GC.\n\
                    # TYPE go_gc_duration_seconds summary\n\
                    go_gc_duration_seconds{quantile=\"0\"} 1.2e-05\n";
        let fps =
            detect_tech_fingerprints("/metrics", Some("text/plain"), &[], body);
        assert!(fps.contains(&TechFingerprint::Prometheus));
    }

    #[test]
    fn detects_prometheus_from_self_metric_type_line() {
        // Prometheus servers expose their own internals under the
        // `prometheus_*` namespace — a `# TYPE prometheus_xxx ...` line is
        // distinctive even when path != /metrics.
        let body = "# HELP prometheus_build_info A metric with a constant '1' value.\n\
                    # TYPE prometheus_build_info gauge\n";
        let fps =
            detect_tech_fingerprints("/api/v1/status/buildinfo", None, &[], body);
        assert!(fps.contains(&TechFingerprint::Prometheus));
    }

    #[test]
    fn fingerprint_detection_does_not_panic_on_large_utf8_body_at_byte_boundary() {
        // Build a body that exceeds MAX_BODY_INSPECT_BYTES and contains
        // multi-byte codepoints straddling the 65_536 boundary. A naive
        // `body[..65_536]` slice would panic; the boundary-safe path must
        // succeed and return a valid (possibly empty) fingerprint list.
        let mut body = String::with_capacity(MAX_BODY_INSPECT_BYTES + 64);
        // Fill up to one byte short of the boundary with ASCII.
        body.push_str(&"a".repeat(MAX_BODY_INSPECT_BYTES - 1));
        // 4-byte codepoint: '🦀' = U+1F980, which spans the boundary.
        body.push('🦀');
        // Pad past the boundary so the slice attempt actually triggers.
        body.push_str(&"b".repeat(64));
        let fps = detect_tech_fingerprints("/", None, &[], &body);
        assert!(fps.is_empty() || fps.iter().all(|f| !matches!(f, TechFingerprint::Prometheus)));
    }

    #[test]
    fn detects_phpmyadmin_from_path() {
        let fps =
            detect_tech_fingerprints("/phpmyadmin/index.php", None, &[], "");
        assert!(fps.contains(&TechFingerprint::PhpMyAdmin));
    }

    #[test]
    fn detects_django_from_admin_marker() {
        let body = "<title>Site administration | Django administration</title>";
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::DjangoAdmin));
    }

    #[test]
    fn detects_nginx_from_server_header() {
        let fps = header_only("Server", "nginx/1.21.4");
        assert!(fps.contains(&TechFingerprint::Nginx));
    }

    #[test]
    fn detects_iis_from_server_header() {
        let fps = header_only("Server", "Microsoft-IIS/10.0");
        assert!(fps.contains(&TechFingerprint::IIS));
    }

    #[test]
    fn detects_apache_distinct_from_tomcat() {
        let fps = header_only("Server", "Apache/2.4.41 (Ubuntu)");
        assert!(fps.contains(&TechFingerprint::ApacheHttpd));
        assert!(!fps.contains(&TechFingerprint::Tomcat));
    }

    #[test]
    fn detects_tomcat_from_apache_coyote_header() {
        let fps = header_only("Server", "Apache-Coyote/1.1");
        assert!(fps.contains(&TechFingerprint::Tomcat));
        assert!(!fps.contains(&TechFingerprint::ApacheHttpd));
    }

    #[test]
    fn empty_inputs_produce_no_fingerprints() {
        let fps = detect_tech_fingerprints("/", None, &[], "");
        assert!(fps.is_empty());
    }

    #[test]
    fn detects_nextjs_from_next_data_script_tag() {
        let body = r#"<html><script id="__NEXT_DATA__" type="application/json">{}</script></html>"#;
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::NextJs));
    }

    #[test]
    fn detects_nuxtjs_from_window_nuxt_assignment() {
        let body = r#"<script>window.__NUXT__={config:{}}</script>"#;
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::NuxtJs));
    }

    #[test]
    fn detects_sveltekit_from_data_attributes() {
        let body = r#"<body data-sveltekit-preload-data="hover"></body>"#;
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::SvelteKit));
    }

    #[test]
    fn detects_astro_from_island_element() {
        let body = r#"<astro-island uid="abc"></astro-island>"#;
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::Astro));
    }

    #[test]
    fn detects_remix_from_remix_context_assignment() {
        let body = r#"<script>window.__remixContext={state:{loaderData:{}}}</script>"#;
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::Remix));
    }

    #[test]
    fn detects_vite_from_client_module_script() {
        let body = r#"<script type="module" src="/@vite/client"></script>"#;
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::Vite));
    }

    #[test]
    fn wordpress_paths_include_wp_login_and_users_endpoint() {
        let candidates = candidates_for_fingerprints(&[TechFingerprint::WordPress]);
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"/wp-login.php"));
        assert!(paths.contains(&"/wp-json/wp/v2/users"));
        assert!(paths.contains(&"/xmlrpc.php"));
        assert!(paths.contains(&"/wp-config.php.bak"));
    }

    #[test]
    fn spring_boot_paths_include_actuator_dump_endpoints() {
        let candidates = candidates_for_fingerprints(&[TechFingerprint::SpringBoot]);
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"/actuator/heapdump"));
        assert!(paths.contains(&"/actuator/env"));
        assert!(paths.contains(&"/actuator/jolokia"));
        assert!(paths.contains(&"/jolokia/list"));
    }

    #[test]
    fn detects_mlflow_from_title() {
        let body = "<html><head><title>MLflow</title></head><body>...</body></html>";
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::Mlflow));
    }

    #[test]
    fn detects_jupyterhub_from_body() {
        let body = "<html><head><title>JupyterHub</title></head><body>JupyterHub login</body></html>";
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::JupyterHub));
    }

    #[test]
    fn detects_tensorboard_from_body() {
        let body = "<html><head><title>TensorBoard</title></head><body><tf-tensorboard></tf-tensorboard></body></html>";
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::TensorBoard));
    }

    #[test]
    fn detects_streamlit_from_body() {
        let body = "<html><head><title>Streamlit</title></head><body><div class=\"stApp\"></div></body></html>";
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::Streamlit));
    }

    #[test]
    fn detects_gradio_from_body() {
        let body = "<html><body><gradio-app src=\"http://localhost:7860\"></gradio-app></body></html>";
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::Gradio));
    }

    #[test]
    fn detects_airflow_from_body() {
        let body = "<html><head><title>Airflow</title></head><body>Apache Airflow</body></html>";
        let fps = body_only(body);
        assert!(fps.contains(&TechFingerprint::Airflow));
    }

    #[test]
    fn mlflow_paths_include_runs_search_and_artifacts_list() {
        let candidates = candidates_for_fingerprints(&[TechFingerprint::Mlflow]);
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"/api/2.0/mlflow/runs/search"));
        assert!(paths.contains(&"/api/2.0/mlflow/experiments/list"));
        assert!(paths.contains(&"/ajax-api/2.0/preview/mlflow/artifacts/list"));
    }

    #[test]
    fn jenkins_paths_include_script_console() {
        let candidates = candidates_for_fingerprints(&[TechFingerprint::Jenkins]);
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"/script"));
        assert!(paths.contains(&"/scriptText"));
        assert!(paths.contains(&"/credentials/"));
    }

    #[test]
    fn fingerprint_paths_are_normalized_with_leading_slash() {
        let candidates = candidates_for_fingerprints(&[TechFingerprint::WordPress]);
        for candidate in &candidates {
            assert!(
                candidate.path.starts_with('/'),
                "path {} missing leading slash",
                candidate.path
            );
        }
    }

    #[test]
    fn duplicate_fingerprints_dedupe_paths() {
        let with_duplicates = candidates_for_fingerprints(&[
            TechFingerprint::WordPress,
            TechFingerprint::WordPress,
        ]);
        let single = candidates_for_fingerprints(&[TechFingerprint::WordPress]);
        assert_eq!(with_duplicates.len(), single.len());
    }

    #[test]
    fn duplicate_paths_across_fingerprints_keep_highest_score() {
        // `/version` appears in both Kubernetes (score 850) and Docker
        // (score 880). When both fire we must keep the higher score and
        // the corresponding source tag so queue priority reflects the
        // strongest signal — regardless of fingerprint ordering.
        let kubernetes_first = candidates_for_fingerprints(&[
            TechFingerprint::Kubernetes,
            TechFingerprint::Docker,
        ]);
        let docker_first = candidates_for_fingerprints(&[
            TechFingerprint::Docker,
            TechFingerprint::Kubernetes,
        ]);

        for ordering in [&kubernetes_first, &docker_first] {
            let version = ordering
                .iter()
                .find(|c| c.path == "/version")
                .expect("/version should be present when both fingerprints fire");
            assert_eq!(
                version.score, 880,
                "score should be the higher of 850 (k8s) and 880 (docker)"
            );
            assert_eq!(
                version.source, "tech-docker",
                "source should be the tag of the higher-scoring fingerprint"
            );
        }
    }

    #[test]
    fn integrated_entry_point_returns_path_set() {
        let body = r#"<link rel='stylesheet' href='/wp-content/themes/twentytwenty/style.css'>"#;
        let candidates = tech_path_candidates("/", Some("text/html"), &[], body);
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"/wp-login.php"));
        assert!(paths.contains(&"/wp-json/wp/v2/users"));
    }

    #[test]
    fn sensitive_variant_for_php_yields_backup_set() {
        let candidates = sensitive_variant_candidates("/index.php");
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"/index.php.bak"));
        assert!(paths.contains(&"/index.php.old"));
        assert!(paths.contains(&"/index.php~"));
        assert!(paths.contains(&"/index.php.swp"));
        assert!(paths.contains(&"/.index.php.swp"));
        assert!(paths.contains(&"/.git/HEAD"));
        assert!(paths.contains(&"/.svn/entries"));
        assert!(paths.contains(&"/.DS_Store"));
    }

    #[test]
    fn sensitive_variant_for_directory_returns_only_vcs_leak() {
        let candidates = sensitive_variant_candidates("/admin/");
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.iter().all(|p| !p.ends_with(".bak")));
        assert!(paths.contains(&"/admin/.git/HEAD"));
        assert!(paths.contains(&"/admin/.DS_Store"));
    }

    #[test]
    fn sensitive_variant_skips_image_assets() {
        let candidates = sensitive_variant_candidates("/static/logo.png");
        for candidate in &candidates {
            assert!(!candidate.path.ends_with(".png.bak"));
            assert!(!candidate.path.ends_with(".png.swp"));
        }
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"/static/.git/HEAD"));
    }

    #[test]
    fn sensitive_variant_for_env_yields_high_score_backups() {
        let candidates = sensitive_variant_candidates("/.env");
        let env_bak = candidates
            .iter()
            .find(|c| c.path == "/.env.bak")
            .expect(".env.bak should be derived");
        assert!(env_bak.score >= 900, "env.bak score = {}", env_bak.score);
    }

    #[test]
    fn nested_path_keeps_parent_directory_for_vcs_leak() {
        let candidates = sensitive_variant_candidates("/api/v1/users.json");
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"/api/v1/.git/HEAD"));
        assert!(paths.contains(&"/api/v1/.DS_Store"));
    }

    #[test]
    fn sensitive_variant_for_root_env_emits_lifecycle_family() {
        let candidates = sensitive_variant_candidates("/.env");
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();

        // Lifecycle / framework variants in the same directory.
        assert!(paths.contains(&"/.env.production"));
        assert!(paths.contains(&"/.env.staging"));
        assert!(paths.contains(&"/.env.development"));
        assert!(paths.contains(&"/.env.local"));
        assert!(paths.contains(&"/.env.test"));
        assert!(paths.contains(&"/.env.docker"));
        assert!(paths.contains(&"/.env.vault"));

        // The lifecycle source tag identifies the new generator.
        let prod = candidates
            .iter()
            .find(|c| c.path == "/.env.production")
            .expect(".env.production should be derived");
        assert_eq!(prod.source, "sensitive-dotenv-variant");
        assert!(prod.score >= 900, "lifecycle score = {}", prod.score);
    }

    #[test]
    fn sensitive_variant_for_subdir_env_keeps_parent_directory() {
        let candidates = sensitive_variant_candidates("/api/.env");
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();

        assert!(paths.contains(&"/api/.env.local"));
        assert!(paths.contains(&"/api/.env.production"));
        assert!(paths.contains(&"/api/.env.staging"));
        assert!(paths.contains(&"/api/.env.development.local"));
        // No leakage into the root directory.
        assert!(!paths.contains(&"/.env.production"));
    }

    #[test]
    fn sensitive_variant_for_env_local_still_includes_other_lifecycle() {
        // A discovered `.env.local` should also surface `.env.production`,
        // `.env.staging`, etc. — not just backups of `.env.local` itself.
        let candidates = sensitive_variant_candidates("/.env.local");
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"/.env.production"));
        assert!(paths.contains(&"/.env.staging"));
        assert!(paths.contains(&"/.envrc"));
    }

    #[test]
    fn sensitive_variant_for_envrc_treated_as_dotenv_family() {
        let candidates = sensitive_variant_candidates("/.envrc");
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        assert!(paths.contains(&"/.env"));
        assert!(paths.contains(&"/.env.production"));
    }

    #[test]
    fn sensitive_variant_non_env_file_skips_lifecycle_expansion() {
        // A regular file should not get any `sensitive-dotenv-variant`
        // entries — only backup variants and VCS leaks.
        let candidates = sensitive_variant_candidates("/index.php");
        assert!(
            candidates
                .iter()
                .all(|c| c.source != "sensitive-dotenv-variant"),
            "non-.env path should not yield dotenv lifecycle variants"
        );
    }
}
