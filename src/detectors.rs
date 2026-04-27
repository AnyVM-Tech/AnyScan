use std::{
    collections::HashSet,
    io::Write,
    process::{Command, Stdio},
};

use crate::{
    config::AppConfig,
    core::{ExtensionManifest, FindingCandidate, FindingConfidence, Severity, redact_secret},
    fetcher::FetchedDocument,
    plugins::build_plugin_metadata,
};
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use sha2::{Digest, Sha256};
use toml::Value as TomlValue;
use tracing::error;
use url::Url;

#[derive(Debug, Clone)]
enum DetectorPrefilter {
    BodyContainsAny(&'static [&'static str]),
    PathContainsAny(&'static [&'static str]),
    PathOrBodyContainsAny {
        path_hints: &'static [&'static str],
        body_literals: &'static [&'static str],
    },
}

enum DetectorKind {
    Regex(&'static Regex),
    Structured(fn(&FetchedDocument) -> Vec<StructuredMatch>),
}

struct DetectorDefinition {
    name: &'static str,
    severity: Severity,
    kind: DetectorKind,
    prefilter: DetectorPrefilter,
}

struct StructuredMatch {
    start: usize,
    end: usize,
    evidence_value: String,
    secret_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StructuredScalarField {
    key: String,
    value: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalFindingCandidate {
    detector: String,
    severity: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    secret_value: Option<String>,
    #[serde(default)]
    redacted_value: Option<String>,
    #[serde(default)]
    evidence: Option<String>,
    #[serde(default)]
    evidence_value: Option<String>,
    #[serde(default)]
    start: Option<usize>,
    #[serde(default)]
    end: Option<usize>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    confidence: Option<String>,
    #[serde(default)]
    matched_signals: Vec<String>,
    #[serde(default)]
    review_labels: Vec<String>,
    #[serde(default)]
    plugin_id: Option<String>,
    #[serde(default)]
    product_name: Option<String>,
    #[serde(default)]
    product_version: Option<String>,
    #[serde(default)]
    cpe: Option<String>,
    #[serde(default)]
    cve_ids: Vec<String>,
    #[serde(default)]
    kev_matched: Option<bool>,
    #[serde(default)]
    service_protocol: Option<String>,
    #[serde(default)]
    service_port: Option<u16>,
}

#[derive(Debug, Serialize)]
struct ExternalDetectorInvocation<'a> {
    detector_pack: &'a str,
    path: &'a str,
    url: &'a str,
    status: u16,
    content_type: Option<&'a str>,
    headers: &'a [(String, String)],
    body: &'a str,
    truncated: bool,
    coverage_source: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextValueKind {
    BroadSecret,
    Password,
    ConnectionString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextualValueSource {
    BodyAssignment,
    StructuredField,
    ResponseHeader,
    ResponseCookie,
    InlineScriptConfig,
    InlineScriptDecoded,
    HtmlAttribute,
    UrlFragment,
    UrlQuery,
}

#[derive(Debug, Clone)]
struct ContextualAssignmentRule {
    name: &'static str,
    severity: Severity,
    keywords: &'static [&'static str],
    value_kind: ContextValueKind,
    min_value_len: usize,
}

static OPENAI_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b").expect("valid regex"));
static AWS_ACCESS_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("valid regex"));
static GITHUB_PAT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b").expect("valid regex"));
static GITHUB_APP_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bgh(?:o|u|s|r)_[A-Za-z0-9_]{20,}\b").expect("valid regex"));
static ANTHROPIC_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b").expect("valid regex"));
static GOOGLE_API_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").expect("valid regex"));
static OPENROUTER_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bsk-or-v1-[A-Za-z0-9_-]{20,}\b").expect("valid regex"));
static STRIPE_LIVE_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b").expect("valid regex"));
static GITLAB_PAT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bglpat-[A-Za-z0-9_-]{20,}\b").expect("valid regex"));
static GITHUB_PAT_FINE_GRAINED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{82}\b").expect("valid regex"));
static CLOUDFLARE_API_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[A-Za-z0-9_-]{40}\b").expect("valid regex"));
static DATADOG_API_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[a-f0-9]{32}\b").expect("valid regex"));
static JWT_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
        .expect("valid regex")
});
static HUGGINGFACE_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bhf_[A-Za-z0-9]{20,}\b").expect("valid regex"));
static SENDGRID_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b").expect("valid regex")
});
static PYPI_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bpypi-[A-Za-z0-9_-]{20,}\b").expect("valid regex"));
static NPM_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").expect("valid regex"));
static GOOGLE_OAUTH_ACCESS_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bya29\.[0-9A-Za-z._-]{20,}\b").expect("valid regex"));
static SHOPIFY_ADMIN_API_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bshpat_[A-Za-z0-9]{20,}\b").expect("valid regex"));
static TELEGRAM_BOT_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b").expect("valid regex"));
static SLACK_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{10,}\b").expect("valid regex"));
static SLACK_APP_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bxapp-[0-9A-Za-z-]{20,}\b").expect("valid regex"));
static SLACK_WEBHOOK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+\b").expect("valid regex")
});
static DISCORD_WEBHOOK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9._-]+\b")
        .expect("valid regex")
});
static SCREENCONNECT_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:screenconnect|connectwise\s+control)[^0-9]{0,40}(?P<version>\d+\.\d+\.\d+(?:\.\d+)?)",
    )
    .expect("valid regex")
});
static GOANYWHERE_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:goanywhere(?:\s*mft)?)[^0-9]{0,40}(?P<version>\d+\.\d+\.\d+)")
        .expect("valid regex")
});
static SOLR_SPEC_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)"solr-spec-version"\s*:\s*"(?P<version>\d+\.\d+\.\d+)""#)
        .expect("valid regex")
});
static DATABASE_URL_WITH_CREDS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:@\s/]+:[^@\s/]+@[^\s"'<>]+\b"#)
        .expect("valid regex")
});
static AZURE_STORAGE_CONNECTION_STRING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"DefaultEndpointsProtocol=[^;\r\n]+;AccountName=[^;\r\n]+;AccountKey=[A-Za-z0-9+/=]{20,}(?:;[^\r\n]+)*",
    )
    .expect("valid regex")
});
static PRIVATE_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    )
    .expect("valid regex")
});
static CONTEXTUAL_ASSIGNMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?mi)(?P<key>["']?[A-Za-z_][A-Za-z0-9_.-]{1,63}["']?)\s*(?:=|:)\s*(?P<value>"[^"\r\n]{4,}"|'[^'\r\n]{4,}'|`[^`\r\n]{4,}`|(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}|[A-Za-z][A-Za-z0-9+.-]*://[^\s"'`]+|[A-Za-z0-9_./+=:@$%?!;-]{4,})"#)
        .expect("valid regex")
});
static NPMRC_AUTH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?mi)^\s*(?:[^\r\n=:]+:)?(?P<key>_authToken|_auth|npmAuthToken)\s*[=:]\s*(?P<value>"[^"\r\n]+"|'[^'\r\n]+'|[^\s#;]+)"#,
    )
    .expect("valid regex")
});
static PYPIRC_PASSWORD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?mi)^\s*password\s*=\s*(?P<value>[^\r\n#;]+)").expect("valid regex")
});
static NETRC_PASSWORD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?mi)\bpassword\s+(?P<value>[^\s#]+)").expect("valid regex"));
static SCRIPT_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)<script\b(?P<attrs>[^>]*)>(?P<body>.*?)</script>").expect("valid regex")
});
static HTML_TAG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)<(?P<tag>[a-zA-Z][a-zA-Z0-9:-]*)\b(?P<attrs>[^>]*)>"#).expect("valid regex")
});
static HTML_ATTRIBUTE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)(?P<name>[A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*(?P<value>"[^"]*"|'[^']*')"#)
        .expect("valid regex")
});
static STORAGE_SET_ITEM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?P<store>localstorage|sessionstorage)\s*\.\s*setitem\(\s*(?P<key>"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`)\s*,\s*(?P<value>"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`)\s*\)"#,
    )
    .expect("valid regex")
});
static STORAGE_PROPERTY_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?P<store>localstorage|sessionstorage)\s*(?:\.\s*(?P<key_name>[A-Za-z_][A-Za-z0-9_-]*)|\[\s*(?P<key_literal>"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`)\s*\])\s*=\s*(?P<value>"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`)"#,
    )
    .expect("valid regex")
});
static DOCUMENT_COOKIE_ASSIGNMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)document\s*\.\s*cookie\s*=\s*(?P<value>"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`)"#)
        .expect("valid regex")
});
static COOKIE_LIBRARY_SET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:cookies?|cookieStore)\s*\.\s*set\(\s*(?P<key>"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`)\s*,\s*(?P<value>"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`)"#,
    )
    .expect("valid regex")
});
static JSON_PARSE_STRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)json\.parse\(\s*(?P<value>"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`)\s*\)"#,
    )
    .expect("valid regex")
});
static ATOB_STRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)atob\(\s*(?P<value>"[A-Za-z0-9+/=_-]{16,}"|'[A-Za-z0-9+/=_-]{16,}'|`[A-Za-z0-9+/=_-]{16,}`)\s*\)"#)
        .expect("valid regex")
});
static DECODE_URI_COMPONENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)decodeURIComponent\(\s*(?P<value>"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`)\s*\)"#,
    )
    .expect("valid regex")
});
static DECODE_URI_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)decodeURI\(\s*(?P<value>"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`)\s*\)"#,
    )
    .expect("valid regex")
});
static UNESCAPE_STRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)unescape\(\s*(?P<value>"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`)\s*\)"#,
    )
    .expect("valid regex")
});
static FRAGMENT_BLOB_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:https?://[^\s"'<>`]+)?#(?P<fragment>[A-Za-z0-9_=%&./:+-]{8,})"#)
        .expect("valid regex")
});
// Detects verbose server-side error pages and stack traces leaked in HTTP
// response bodies. Combines fingerprints for Java, Python, .NET (YSOD),
// Rails, and Node.js stack traces into a single alternation so a single
// finding category covers the family of disclosures.
static VERBOSE_STACK_TRACE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        # Java: at com.foo.Bar(Bar.java:42)
        \bat\s+(?:com|org|net|io)\.[\w$.]+\([\w$.]+\.java:\d+\)
        |
        # Python: Traceback (most recent call last):\n  File "..."
        Traceback\ \(most\ recent\ call\ last\):\s*\n\s*File\ "
        |
        # .NET YSOD title or framework exception type marker
        <title>Server\ Error\ in\ '/'\ Application
        |
        \[(?:NullReferenceException|InvalidOperationException|ArgumentException)
        |
        # Rails diagnostic title or ActiveRecord exception
        <title>Action\ Controller:\ Exception\ caught
        |
        ActiveRecord::(?:RecordNotFound|StatementInvalid)
        |
        # Node.js: TypeError: msg\n    at fn (file.js:LINE:COL)
        \b(?:TypeError|ReferenceError|SyntaxError):\s+.+\n\s+at\s+.+\s+\(.+\.js:\d+:\d+\)
        "#,
    )
    .expect("valid regex")
});

fn exact_detector(
    name: &'static str,
    severity: Severity,
    regex: &'static Regex,
    literals: &'static [&'static str],
) -> DetectorDefinition {
    DetectorDefinition {
        name,
        severity,
        kind: DetectorKind::Regex(regex),
        prefilter: DetectorPrefilter::BodyContainsAny(literals),
    }
}

fn structured_detector(
    name: &'static str,
    severity: Severity,
    prefilter: DetectorPrefilter,
    scanner: fn(&FetchedDocument) -> Vec<StructuredMatch>,
) -> DetectorDefinition {
    DetectorDefinition {
        name,
        severity,
        kind: DetectorKind::Structured(scanner),
        prefilter,
    }
}

static DETECTORS: Lazy<Vec<DetectorDefinition>> = Lazy::new(|| {
    vec![
        structured_detector(
            "firebase_admin_service_account_private_key",
            Severity::Critical,
            DetectorPrefilter::PathOrBodyContainsAny {
                path_hints: &[
                    "firebase",
                    "firebase-adminsdk",
                    "service-account",
                    "service_account",
                ],
                body_literals: &[
                    "firebase-adminsdk",
                    "private_key_id",
                    "client_email",
                    "gserviceaccount.com",
                    "service_account",
                ],
            },
            scan_firebase_admin_service_account_private_keys,
        ),
        structured_detector(
            "google_service_account_private_key",
            Severity::Critical,
            DetectorPrefilter::PathOrBodyContainsAny {
                path_hints: &[
                    "google",
                    "gcloud",
                    "service-account",
                    "service_account",
                    "credentials",
                ],
                body_literals: &[
                    "private_key_id",
                    "client_email",
                    "gserviceaccount.com",
                    "service_account",
                    "token_uri",
                ],
            },
            scan_google_service_account_private_keys,
        ),
        structured_detector(
            "google_authorized_user_refresh_token",
            Severity::High,
            DetectorPrefilter::PathOrBodyContainsAny {
                path_hints: &[
                    "application_default_credentials",
                    "authorized_user",
                    "google",
                    "oauth",
                ],
                body_literals: &[
                    "authorized_user",
                    "refresh_token",
                    "client_id",
                    "googleusercontent.com",
                ],
            },
            scan_google_authorized_user_refresh_tokens,
        ),
        exact_detector(
            "private_key_material",
            Severity::Critical,
            &PRIVATE_KEY,
            &["PRIVATE KEY"],
        ),
        exact_detector(
            "anthropic_api_key",
            Severity::High,
            &ANTHROPIC_KEY,
            &["sk-ant-"],
        ),
        exact_detector(
            "openrouter_api_key",
            Severity::High,
            &OPENROUTER_KEY,
            &["sk-or-v1-"],
        ),
        exact_detector("openai_api_key", Severity::High, &OPENAI_KEY, &["sk-"]),
        exact_detector("google_api_key", Severity::High, &GOOGLE_API_KEY, &["AIza"]),
        exact_detector(
            "google_oauth_access_token",
            Severity::High,
            &GOOGLE_OAUTH_ACCESS_TOKEN,
            &["ya29."],
        ),
        exact_detector(
            "stripe_live_api_key",
            Severity::High,
            &STRIPE_LIVE_KEY,
            &["sk_live_", "rk_live_"],
        ),
        exact_detector(
            "aws_access_key_id",
            Severity::High,
            &AWS_ACCESS_KEY,
            &["AKIA"],
        ),
        exact_detector(
            "github_pat_fine_grained",
            Severity::High,
            &GITHUB_PAT_FINE_GRAINED,
            &["github_pat_"],
        ),
        exact_detector(
            "github_personal_access_token",
            Severity::High,
            &GITHUB_PAT,
            &["ghp_", "github_pat_"],
        ),
        exact_detector(
            "github_app_or_oauth_token",
            Severity::High,
            &GITHUB_APP_TOKEN,
            &["gho_", "ghu_", "ghs_", "ghr_"],
        ),
        exact_detector(
            "gitlab_personal_access_token",
            Severity::High,
            &GITLAB_PAT,
            &["glpat-"],
        ),
        exact_detector(
            "huggingface_access_token",
            Severity::High,
            &HUGGINGFACE_TOKEN,
            &["hf_"],
        ),
        exact_detector("sendgrid_api_key", Severity::High, &SENDGRID_KEY, &["SG."]),
        exact_detector("pypi_api_token", Severity::High, &PYPI_TOKEN, &["pypi-"]),
        exact_detector("npm_access_token", Severity::High, &NPM_TOKEN, &["npm_"]),
        exact_detector(
            "shopify_admin_api_token",
            Severity::High,
            &SHOPIFY_ADMIN_API_TOKEN,
            &["shpat_"],
        ),
        exact_detector(
            "telegram_bot_token",
            Severity::High,
            &TELEGRAM_BOT_TOKEN,
            &["TELEGRAM", "telegram", "BOT_TOKEN", "bot_token"],
        ),
        exact_detector(
            "slack_access_token",
            Severity::High,
            &SLACK_TOKEN,
            &["xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"],
        ),
        exact_detector(
            "slack_app_token",
            Severity::High,
            &SLACK_APP_TOKEN,
            &["xapp-"],
        ),
        exact_detector(
            "slack_webhook",
            Severity::Medium,
            &SLACK_WEBHOOK,
            &["hooks.slack.com/services/"],
        ),
        exact_detector(
            "discord_webhook",
            Severity::Medium,
            &DISCORD_WEBHOOK,
            &["discord.com/api/webhooks/", "discordapp.com/api/webhooks/"],
        ),
        structured_detector(
            "aws_shared_credentials_secret_access_key",
            Severity::High,
            DetectorPrefilter::PathOrBodyContainsAny {
                path_hints: &[".aws/credentials", ".aws/config"],
                body_literals: &[
                    "aws_secret_access_key",
                    "aws_access_key_id",
                    "aws_session_token",
                ],
            },
            scan_aws_shared_credentials_secret_access_keys,
        ),
        structured_detector(
            "aws_shared_credentials_session_token",
            Severity::High,
            DetectorPrefilter::PathOrBodyContainsAny {
                path_hints: &[".aws/credentials", ".aws/config"],
                body_literals: &[
                    "aws_session_token",
                    "aws_secret_access_key",
                    "aws_access_key_id",
                ],
            },
            scan_aws_shared_credentials_session_tokens,
        ),
        structured_detector(
            "azure_service_principal_client_secret",
            Severity::High,
            DetectorPrefilter::PathOrBodyContainsAny {
                path_hints: &["azure", "service-principal", "credential"],
                body_literals: &[
                    "tenantId",
                    "tenant_id",
                    "subscriptionId",
                    "subscription_id",
                    "clientId",
                    "client_id",
                    "appId",
                    "app_id",
                    "clientSecret",
                    "client_secret",
                ],
            },
            scan_azure_service_principal_client_secrets,
        ),
        structured_detector(
            "google_oauth_client_secret",
            Severity::High,
            DetectorPrefilter::PathOrBodyContainsAny {
                path_hints: &["google", "oauth", "client-secret", "credentials"],
                body_literals: &[
                    "client_secret",
                    "clientSecret",
                    "accounts.google.com",
                    "oauth2.googleapis.com",
                    "googleusercontent.com",
                    "auth_uri",
                    "token_uri",
                ],
            },
            scan_google_oauth_client_secrets,
        ),
        structured_detector(
            "npm_registry_auth",
            Severity::High,
            DetectorPrefilter::PathOrBodyContainsAny {
                path_hints: &[".npmrc", ".yarnrc", ".yarnrc.yml"],
                body_literals: &["_authToken=", "_auth=", "npmAuthToken:"],
            },
            scan_npm_registry_auth,
        ),
        structured_detector(
            "pypirc_password",
            Severity::High,
            DetectorPrefilter::PathContainsAny(&[".pypirc"]),
            scan_pypirc_passwords,
        ),
        structured_detector(
            "netrc_machine_password",
            Severity::High,
            DetectorPrefilter::PathContainsAny(&[".netrc"]),
            scan_netrc_passwords,
        ),
        structured_detector(
            "docker_registry_auth",
            Severity::High,
            DetectorPrefilter::PathOrBodyContainsAny {
                path_hints: &[".docker/config.json", ".dockerconfigjson", "docker-config"],
                body_literals: &["\"auths\"", "\"identitytoken\"", "\"auth\""],
            },
            scan_docker_registry_auth,
        ),
        structured_detector(
            "kubeconfig_embedded_credential",
            Severity::High,
            DetectorPrefilter::PathOrBodyContainsAny {
                path_hints: &["kubeconfig", ".kube/config"],
                body_literals: &[
                    "client-key-data",
                    "client-certificate-data",
                    "access-token",
                    "refresh-token",
                    "current-context",
                ],
            },
            scan_kubeconfig_credentials,
        ),
        structured_detector(
            "cloudflare_api_token",
            Severity::High,
            DetectorPrefilter::BodyContainsAny(&[
                "cloudflare",
                "Cloudflare",
                "CLOUDFLARE",
                "CF_API_TOKEN",
                "X-Auth-Email",
            ]),
            scan_cloudflare_api_tokens,
        ),
        structured_detector(
            "datadog_api_key",
            Severity::High,
            DetectorPrefilter::BodyContainsAny(&[
                "datadog",
                "Datadog",
                "DATADOG",
                "DD_API_KEY",
                "DD_APP_KEY",
                "dd-agent",
            ]),
            scan_datadog_api_keys,
        ),
        structured_detector(
            "jwt_alg_none",
            Severity::High,
            DetectorPrefilter::BodyContainsAny(&["eyJ"]),
            scan_jwt_alg_none_tokens,
        ),
    ]
});

static CONTEXTUAL_ASSIGNMENT_RULES: Lazy<Vec<ContextualAssignmentRule>> = Lazy::new(|| {
    vec![
        ContextualAssignmentRule {
            name: "generic_connection_string",
            severity: Severity::High,
            keywords: &[
                "database_url",
                "databaseurl",
                "db_url",
                "dburl",
                "connection_string",
                "connectionstring",
                "conn_string",
                "connstring",
                "dsn",
                "jdbc_url",
                "jdbcurl",
                "redis_url",
                "redisurl",
                "mongodb_uri",
                "mongodburi",
                "postgres_url",
                "postgresurl",
                "mysql_url",
                "mysqlurl",
                "amqp_url",
                "amqpurl",
            ],
            value_kind: ContextValueKind::ConnectionString,
            min_value_len: 12,
        },
        ContextualAssignmentRule {
            name: "generic_authorization_header",
            severity: Severity::High,
            keywords: &[
                "authorization",
                "auth_header",
                "authheader",
                "bearer_token",
                "bearertoken",
            ],
            value_kind: ContextValueKind::BroadSecret,
            min_value_len: 12,
        },
        ContextualAssignmentRule {
            name: "generic_api_key",
            severity: Severity::High,
            keywords: &[
                "key",
                "api_key",
                "apikey",
                "app_key",
                "appkey",
                "access_key",
                "accesskey",
                "auth_key",
                "authkey",
                "private_key",
                "privatekey",
                "public_api_key",
                "publicapi_key",
                "publicapikey",
                "service_key",
                "servicekey",
                "license_key",
                "licensekey",
                "sdk_key",
                "sdkkey",
                "master_key",
                "masterkey",
                "consumer_key",
                "consumerkey",
                "encryption_key",
                "encryptionkey",
                "secret_access_key",
                "secretaccesskey",
            ],
            value_kind: ContextValueKind::BroadSecret,
            min_value_len: 12,
        },
        ContextualAssignmentRule {
            name: "generic_client_secret",
            severity: Severity::High,
            keywords: &[
                "secret",
                "client_secret",
                "clientsecret",
                "consumer_secret",
                "consumersecret",
                "signing_secret",
                "signingsecret",
                "webhook_secret",
                "webhooksecret",
                "app_secret",
                "appsecret",
                "secret_key",
                "secretkey",
                "api_secret",
                "apisecret",
                "session_secret",
                "sessionsecret",
                "jwt_secret",
                "jwtsecret",
                "private_secret",
                "privatesecret",
                "encryption_secret",
                "encryptionsecret",
                "bot_secret",
                "botsecret",
            ],
            value_kind: ContextValueKind::BroadSecret,
            min_value_len: 12,
        },
        ContextualAssignmentRule {
            name: "generic_session_cookie",
            severity: Severity::High,
            keywords: &[
                "session",
                "sessionid",
                "sessid",
                "session_token",
                "sessiontoken",
                "connect_sid",
                "remember_me",
                "rememberme",
                "auth_cookie",
                "authcookie",
            ],
            value_kind: ContextValueKind::BroadSecret,
            min_value_len: 12,
        },
        ContextualAssignmentRule {
            name: "generic_access_token",
            severity: Severity::High,
            keywords: &[
                "access_token",
                "accesstoken",
                "auth_token",
                "authtoken",
                "api_token",
                "apitoken",
                "private_token",
                "privatetoken",
                "service_token",
                "servicetoken",
                "bot_token",
                "bottoken",
                "auth",
                "session_token",
                "sessiontoken",
                "refresh_token",
                "refreshtoken",
                "id_token",
                "idtoken",
                "token",
            ],
            value_kind: ContextValueKind::BroadSecret,
            min_value_len: 12,
        },
        ContextualAssignmentRule {
            name: "generic_password",
            severity: Severity::High,
            keywords: &["password", "passwd", "pwd", "passphrase"],
            value_kind: ContextValueKind::Password,
            min_value_len: 10,
        },
        ContextualAssignmentRule {
            name: "generic_credential",
            severity: Severity::High,
            keywords: &[
                "credential",
                "credentials",
                "creds",
                "auth_value",
                "auth_secret",
                "authsecret",
            ],
            value_kind: ContextValueKind::BroadSecret,
            min_value_len: 12,
        },
    ]
});

const STRUCTURED_SECRET_FIELD_HINTS: &[&str] = &[
    "apiKey",
    "api_key",
    "apiSecret",
    "api_secret",
    "accessKey",
    "access_key",
    "serviceKey",
    "service_key",
    "licenseKey",
    "license_key",
    "masterKey",
    "master_key",
    "clientSecret",
    "client_secret",
    "sessionSecret",
    "session_secret",
    "signingSecret",
    "signing_secret",
    "webhookSecret",
    "webhook_secret",
    "privateToken",
    "private_token",
    "accessToken",
    "access_token",
    "authToken",
    "auth_token",
    "connectionString",
    "connection_string",
    "databaseUrl",
    "database_url",
    "credential",
    "credentials",
    "password",
    "passphrase",
    "passwd",
    "secret",
    "token",
];

#[derive(Debug, Clone, Default)]
pub struct DetectorEngine {
    external_packs: Vec<ExtensionManifest>,
}

impl DetectorEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_config(config: &AppConfig) -> Result<Self> {
        Ok(Self {
            external_packs: config
                .enabled_extension_manifests()?
                .into_iter()
                .filter(ExtensionManifest::is_detector_pack)
                .collect(),
        })
    }

    pub fn has_external_packs(&self) -> bool {
        !self.external_packs.is_empty()
    }

    pub fn scan_document(&self, document: &FetchedDocument) -> Vec<FindingCandidate> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();

        scan_detectors(document, &mut seen, &mut findings);
        scan_verbose_stack_traces(document, &mut seen, &mut findings);
        scan_contextual_assignments(document, &mut seen, &mut findings);
        scan_structured_contextual_assignments(document, &mut seen, &mut findings);
        scan_header_policy_detectors(document, &mut seen, &mut findings);
        scan_response_header_contextual_assignments(document, &mut seen, &mut findings);
        scan_cookie_header_contextual_assignments(document, &mut seen, &mut findings);
        scan_inline_script_contextual_assignments(document, &mut seen, &mut findings);
        scan_inline_storage_contextual_assignments(document, &mut seen, &mut findings);
        scan_html_attribute_contextual_assignments(document, &mut seen, &mut findings);
        scan_url_fragment_contextual_assignments(document, &mut seen, &mut findings);
        scan_url_query_contextual_assignments(document, &mut seen, &mut findings);
        scan_phase_one_plugin_findings(document, &mut seen, &mut findings);
        scan_external_detector_packs(document, &mut seen, &mut findings, &self.external_packs);

        findings
    }
}

fn scan_detectors(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    for detector in candidate_detectors(document) {
        match detector.kind {
            DetectorKind::Regex(regex) => {
                for matched in regex.find_iter(&document.body) {
                    push_finding_candidate(
                        findings,
                        seen,
                        document,
                        detector.name,
                        &detector.severity,
                        matched.start(),
                        matched.end(),
                        matched.as_str(),
                        matched.as_str(),
                    );
                }
            }
            DetectorKind::Structured(scanner) => {
                for matched in scanner(document) {
                    push_finding_candidate(
                        findings,
                        seen,
                        document,
                        detector.name,
                        &detector.severity,
                        matched.start,
                        matched.end,
                        &matched.evidence_value,
                        &matched.secret_value,
                    );
                }
            }
        }
    }
}

// Verbose error pages and stack traces in HTTP response bodies leak server
// internals (file paths, framework versions, query fragments). The detector
// is gated by a tight set of literal substrings so the regex only runs on
// bodies that already look like an error disclosure, and emits one finding
// per matching location with evidence truncated to ~200 characters.
const VERBOSE_STACK_TRACE_PREFILTER: &[&str] = &[
    "Traceback (most recent call last)",
    "at com.",
    "at org.",
    "at net.",
    "at io.",
    "Server Error in",
    "Action Controller",
    "ActiveRecord::",
    "TypeError:",
    "ReferenceError:",
    "SyntaxError:",
];

const VERBOSE_STACK_TRACE_EVIDENCE_CHARS: usize = 200;

fn scan_verbose_stack_traces(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    if !VERBOSE_STACK_TRACE_PREFILTER
        .iter()
        .any(|literal| document.body.contains(literal))
    {
        return;
    }

    for matched in VERBOSE_STACK_TRACE_RE.find_iter(&document.body) {
        let snippet = abbreviate_prefix(matched.as_str().trim(), VERBOSE_STACK_TRACE_EVIDENCE_CHARS);
        push_metadata_secret_finding_candidate(
            findings,
            seen,
            document,
            "verbose_stack_trace_disclosure",
            &Severity::Low,
            &snippet,
            &snippet,
            Some(FindingConfidence::High),
            vec!["stack_trace_disclosure".to_string()],
            vec!["verbose_error_disclosure".to_string()],
        );
    }
}

fn scan_contextual_assignments(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    for captures in CONTEXTUAL_ASSIGNMENT_RE.captures_iter(&document.body) {
        let Some(key_match) = captures.name("key") else {
            continue;
        };
        let Some(value_match) = captures.name("value") else {
            continue;
        };

        let key = normalize_contextual_key(key_match.as_str());
        let Some(rule) = contextual_assignment_rule(&key) else {
            continue;
        };

        let normalized_value = normalize_contextual_value(value_match.as_str());
        if !validate_contextual_value(
            document,
            &key,
            &normalized_value,
            rule,
            ContextualValueSource::BodyAssignment,
        ) {
            continue;
        }

        push_finding_candidate(
            findings,
            seen,
            document,
            rule.name,
            &rule.severity,
            value_match.start(),
            value_match.end(),
            value_match.as_str(),
            &normalized_value,
        );
    }
}

fn scan_structured_contextual_assignments(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    if !should_scan_structured_fields(document) {
        return;
    }

    for field in structured_scalar_fields(document) {
        let key = normalize_contextual_key(&field.key);
        let Some(rule) = contextual_assignment_rule(&key) else {
            continue;
        };

        let normalized_value = normalize_contextual_value(&field.value);
        if !validate_contextual_value(
            document,
            &key,
            &normalized_value,
            rule,
            ContextualValueSource::StructuredField,
        ) {
            continue;
        }

        let Some(matched) = structured_match_from_value(document, &normalized_value) else {
            continue;
        };

        push_finding_candidate(
            findings,
            seen,
            document,
            rule.name,
            &rule.severity,
            matched.start,
            matched.end,
            &matched.evidence_value,
            &matched.secret_value,
        );
    }
}

fn scan_external_detector_packs(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
    external_packs: &[ExtensionManifest],
) {
    for manifest in external_packs {
        match run_external_detector_pack(document, manifest) {
            Ok(candidates) => {
                for candidate in candidates {
                    let dedupe_key = format!("{}:{}", candidate.path, candidate.fingerprint);
                    if seen.insert(dedupe_key) {
                        findings.push(candidate);
                    }
                }
            }
            Err(error) => {
                error!(
                    detector_pack = %manifest.name,
                    path = %document.path,
                    %error,
                    "external detector pack failed"
                );
            }
        }
    }
}

fn scan_header_policy_detectors(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    let acao = extract_header_value(document, "access-control-allow-origin");
    let acac = extract_header_value(document, "access-control-allow-credentials");
    let credentials_true = acac
        .as_deref()
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if let Some(origin_value) = acao.as_deref() {
        let trimmed_origin = origin_value.trim();
        if trimmed_origin == "*" && credentials_true {
            push_header_policy_finding(
                findings,
                seen,
                document,
                "open_cors_with_credentials",
                Severity::High,
                FindingConfidence::High,
                trimmed_origin,
                &format!(
                    "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true (status={})",
                    document.status
                ),
                vec![
                    "access_control_allow_origin_wildcard".to_string(),
                    "access_control_allow_credentials_true".to_string(),
                ],
                vec!["cors_misconfiguration".to_string()],
            );
        } else if credentials_true && looks_like_reflective_origin(trimmed_origin) {
            push_header_policy_finding(
                findings,
                seen,
                document,
                "open_cors_reflective_origin",
                Severity::High,
                FindingConfidence::Medium,
                trimmed_origin,
                &format!(
                    "Access-Control-Allow-Origin reflected a specific origin alongside Access-Control-Allow-Credentials: true (status={})",
                    document.status
                ),
                vec![
                    "access_control_allow_origin_specific".to_string(),
                    "access_control_allow_credentials_true".to_string(),
                ],
                vec!["cors_misconfiguration".to_string()],
            );
        }
    }

    if request_url_is_https(document)
        && extract_header_value(document, "strict-transport-security").is_none()
    {
        push_header_policy_finding(
            findings,
            seen,
            document,
            "missing_hsts_on_https",
            Severity::Low,
            FindingConfidence::High,
            "",
            &format!(
                "HTTPS response did not include a Strict-Transport-Security header (status={})",
                document.status
            ),
            vec!["missing_strict_transport_security".to_string()],
            vec!["transport_security".to_string()],
        );
    }

    if let Some(csp) = extract_header_value(document, "content-security-policy") {
        if let Some(directive) = csp_has_unsafe_in_script_or_default(&csp) {
            push_header_policy_finding(
                findings,
                seen,
                document,
                "weak_csp_unsafe_directives",
                Severity::Medium,
                FindingConfidence::High,
                &csp,
                &format!(
                    "Content-Security-Policy {directive} contains unsafe-inline or unsafe-eval (status={})",
                    document.status
                ),
                vec![format!("csp_{directive}_unsafe").replace('-', "_")],
                vec!["weak_csp".to_string()],
            );
        }
    }
}

fn push_header_policy_finding(
    findings: &mut Vec<FindingCandidate>,
    seen: &mut HashSet<String>,
    document: &FetchedDocument,
    detector_name: &str,
    severity: Severity,
    confidence: FindingConfidence,
    header_value: &str,
    evidence: &str,
    matched_signals: Vec<String>,
    review_labels: Vec<String>,
) {
    let redacted_value = truncate_header_value(header_value, 200);
    let fingerprint_source =
        format!("{detector_name}:{}:{header_value}", document.path);
    let fingerprint = fingerprint(&fingerprint_source);
    let dedupe_key = format!("{}:{detector_name}:{fingerprint}", document.path);
    if !seen.insert(dedupe_key) {
        return;
    }

    findings.push(FindingCandidate {
        detector: detector_name.to_string(),
        severity,
        path: document.path.clone(),
        redacted_value,
        evidence: evidence.trim().to_string(),
        fingerprint,
        confidence: Some(confidence),
        matched_signals,
        review_labels,
        plugin_metadata: None,
    });
}

fn truncate_header_value(value: &str, limit: usize) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= limit {
        return trimmed.to_string();
    }
    let truncated: String = trimmed.chars().take(limit).collect();
    format!("{truncated}...")
}

fn looks_like_reflective_origin(value: &str) -> bool {
    let candidate = value.trim();
    if candidate.is_empty() || candidate == "*" || candidate.eq_ignore_ascii_case("null") {
        return false;
    }
    if candidate.contains(',') {
        return false;
    }
    if let Ok(parsed) = Url::parse(candidate) {
        let scheme = parsed.scheme();
        return scheme == "http" || scheme == "https";
    }
    false
}

fn request_url_is_https(document: &FetchedDocument) -> bool {
    Url::parse(&document.url)
        .map(|url| url.scheme().eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

fn csp_has_unsafe_in_script_or_default(csp: &str) -> Option<&'static str> {
    for directive_chunk in csp.split(';') {
        let trimmed = directive_chunk.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut tokens = trimmed.split_ascii_whitespace();
        let Some(name) = tokens.next() else {
            continue;
        };
        let lowered_name = name.to_ascii_lowercase();
        let directive_label = match lowered_name.as_str() {
            "script-src" => "script-src",
            "default-src" => "default-src",
            _ => continue,
        };
        for token in tokens {
            let lowered_token = token.trim_matches(&['\'', '"'][..]).to_ascii_lowercase();
            if lowered_token == "unsafe-inline" || lowered_token == "unsafe-eval" {
                return Some(directive_label);
            }
        }
    }
    None
}

fn scan_response_header_contextual_assignments(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    for (header_name, header_value) in &document.headers {
        let key = normalize_contextual_key(header_name);
        let Some(rule) = contextual_assignment_rule(&key) else {
            continue;
        };
        let normalized_value = normalize_contextual_value(header_value);
        if !validate_contextual_value(
            document,
            &key,
            &normalized_value,
            rule,
            ContextualValueSource::ResponseHeader,
        ) {
            continue;
        }

        push_metadata_secret_finding_candidate(
            findings,
            seen,
            document,
            rule.name,
            &rule.severity,
            &normalized_value,
            &format!(
                "HTTP response header {} exposed a secret-like value.",
                header_name.trim()
            ),
            Some(FindingConfidence::High),
            vec!["response_header".to_string(), key.clone()],
            vec!["response_header_secret".to_string()],
        );
    }
}

fn scan_url_query_contextual_assignments(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    let Ok(url) = Url::parse(&document.url) else {
        return;
    };

    for (query_name, query_value) in url.query_pairs() {
        let key = normalize_contextual_key(&query_name);
        let Some(rule) = contextual_assignment_rule(&key) else {
            continue;
        };
        let normalized_value = normalize_contextual_value(&query_value);
        if !validate_contextual_value(
            document,
            &key,
            &normalized_value,
            rule,
            ContextualValueSource::UrlQuery,
        ) {
            continue;
        }

        push_metadata_secret_finding_candidate(
            findings,
            seen,
            document,
            rule.name,
            &rule.severity,
            &normalized_value,
            &format!(
                "URL query parameter {} exposed a secret-like value.",
                query_name.trim()
            ),
            Some(FindingConfidence::Medium),
            vec!["url_query".to_string(), key.clone()],
            vec!["query_secret".to_string()],
        );
    }
}

fn scan_url_fragment_contextual_assignments(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    for captures in FRAGMENT_BLOB_RE.captures_iter(&document.body) {
        let Some(fragment_blob) = captures.name("fragment").map(|value| value.as_str()) else {
            continue;
        };
        for (fragment_name, fragment_value) in parse_fragment_assignments(fragment_blob) {
            let key = normalize_contextual_key(&fragment_name);
            let Some(rule) = contextual_assignment_rule(&key) else {
                continue;
            };
            let normalized_value = normalize_contextual_value(&fragment_value);
            if !validate_contextual_value(
                document,
                &key,
                &normalized_value,
                rule,
                ContextualValueSource::UrlFragment,
            ) {
                continue;
            }

            push_metadata_secret_finding_candidate(
                findings,
                seen,
                document,
                rule.name,
                &rule.severity,
                &normalized_value,
                &format!(
                    "URL fragment parameter {} exposed a secret-like value.",
                    fragment_name.trim()
                ),
                Some(FindingConfidence::Medium),
                vec!["url_fragment".to_string(), key.clone()],
                vec!["fragment_secret".to_string()],
            );
        }
    }
}

fn scan_cookie_header_contextual_assignments(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    for (header_name, header_value) in &document.headers {
        let normalized_header = normalize_contextual_key(header_name);
        match normalized_header.as_str() {
            "set_cookie" => {
                if let Some((cookie_name, cookie_value)) =
                    parse_cookie_header_assignment(header_value, true)
                {
                    process_cookie_candidate(
                        document,
                        seen,
                        findings,
                        header_name,
                        &cookie_name,
                        &cookie_value,
                    );
                }
            }
            "cookie" => {
                for (cookie_name, cookie_value) in
                    parse_cookie_header_assignments(header_value, false)
                {
                    process_cookie_candidate(
                        document,
                        seen,
                        findings,
                        header_name,
                        &cookie_name,
                        &cookie_value,
                    );
                }
            }
            _ => {}
        }
    }
}

fn scan_inline_script_contextual_assignments(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    for captures in SCRIPT_BLOCK_RE.captures_iter(&document.body) {
        let attrs = captures
            .name("attrs")
            .map(|value| parse_html_attributes(value.as_str()))
            .unwrap_or_default();
        let Some(script_body) = captures.name("body").map(|value| value.as_str()) else {
            continue;
        };
        if !script_tag_looks_like_config(&attrs, script_body) {
            continue;
        }

        scan_contextual_assignments_in_blob(
            document,
            seen,
            findings,
            script_body,
            ContextualValueSource::InlineScriptConfig,
            "Inline script config exposed a secret-like {} value.",
            "inline_script",
        );

        for decoded in extract_decoded_inline_script_blobs(script_body) {
            scan_contextual_assignments_in_blob(
                document,
                seen,
                findings,
                &decoded,
                ContextualValueSource::InlineScriptDecoded,
                "Decoded inline script config exposed a secret-like {} value.",
                "inline_script_decoded",
            );
        }
    }
}

fn scan_inline_storage_contextual_assignments(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    for captures in SCRIPT_BLOCK_RE.captures_iter(&document.body) {
        let Some(script_body) = captures.name("body").map(|value| value.as_str()) else {
            continue;
        };

        for setter in STORAGE_SET_ITEM_RE.captures_iter(script_body) {
            let Some(key_literal) = setter.name("key").map(|value| value.as_str()) else {
                continue;
            };
            let Some(value_literal) = setter.name("value").map(|value| value.as_str()) else {
                continue;
            };
            let Some(storage_name) = setter.name("store").map(|value| value.as_str()) else {
                continue;
            };
            let Some(decoded_key) = decode_javascript_string_literal(key_literal) else {
                continue;
            };
            let Some(decoded_value) = decode_javascript_string_literal(value_literal) else {
                continue;
            };
            process_inline_storage_candidate(
                document,
                seen,
                findings,
                storage_name,
                &decoded_key,
                &decoded_value,
            );
        }

        for setter in STORAGE_PROPERTY_ASSIGN_RE.captures_iter(script_body) {
            let Some(storage_name) = setter.name("store").map(|value| value.as_str()) else {
                continue;
            };
            let decoded_key =
                if let Some(key_name) = setter.name("key_name").map(|value| value.as_str()) {
                    key_name.to_string()
                } else {
                    let Some(key_literal) = setter.name("key_literal").map(|value| value.as_str())
                    else {
                        continue;
                    };
                    let Some(decoded_key) = decode_javascript_string_literal(key_literal) else {
                        continue;
                    };
                    decoded_key
                };
            let Some(value_literal) = setter.name("value").map(|value| value.as_str()) else {
                continue;
            };
            let Some(decoded_value) = decode_javascript_string_literal(value_literal) else {
                continue;
            };
            process_inline_storage_candidate(
                document,
                seen,
                findings,
                storage_name,
                &decoded_key,
                &decoded_value,
            );
        }

        for cookie_assignment in DOCUMENT_COOKIE_ASSIGNMENT_RE.captures_iter(script_body) {
            let Some(raw_cookie_value) =
                cookie_assignment.name("value").map(|value| value.as_str())
            else {
                continue;
            };
            let Some(decoded_cookie_value) = decode_javascript_string_literal(raw_cookie_value)
            else {
                continue;
            };
            for (cookie_name, cookie_value) in
                parse_cookie_header_assignments(&decoded_cookie_value, false)
            {
                process_inline_cookie_candidate(
                    document,
                    seen,
                    findings,
                    "document.cookie",
                    &cookie_name,
                    &cookie_value,
                );
            }
        }

        for cookie_setter in COOKIE_LIBRARY_SET_RE.captures_iter(script_body) {
            let Some(key_literal) = cookie_setter.name("key").map(|value| value.as_str()) else {
                continue;
            };
            let Some(value_literal) = cookie_setter.name("value").map(|value| value.as_str())
            else {
                continue;
            };
            let Some(decoded_key) = decode_javascript_string_literal(key_literal) else {
                continue;
            };
            let Some(decoded_value) = decode_javascript_string_literal(value_literal) else {
                continue;
            };
            process_inline_cookie_candidate(
                document,
                seen,
                findings,
                "Cookies.set",
                &decoded_key,
                &decoded_value,
            );
        }
    }
}

fn scan_contextual_assignments_in_blob(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
    blob: &str,
    source: ContextualValueSource,
    evidence_template: &str,
    signal_label: &str,
) {
    for assignment in CONTEXTUAL_ASSIGNMENT_RE.captures_iter(blob) {
        let Some(key_match) = assignment.name("key") else {
            continue;
        };
        let Some(value_match) = assignment.name("value") else {
            continue;
        };

        let key = normalize_contextual_key(key_match.as_str());
        let Some(rule) = contextual_assignment_rule(&key) else {
            continue;
        };
        let normalized_value = normalize_contextual_value(value_match.as_str());
        if !validate_contextual_value(document, &key, &normalized_value, rule, source) {
            continue;
        }

        push_metadata_secret_finding_candidate(
            findings,
            seen,
            document,
            rule.name,
            &rule.severity,
            &normalized_value,
            &evidence_template.replace("{}", key_match.as_str().trim_matches(&['\"', '\''][..])),
            Some(FindingConfidence::Medium),
            vec![signal_label.to_string(), key.clone()],
            vec!["inline_script_secret".to_string()],
        );
    }
}

fn scan_html_attribute_contextual_assignments(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    for captures in HTML_TAG_RE.captures_iter(&document.body) {
        let Some(tag_match) = captures.name("tag") else {
            continue;
        };
        let Some(attrs_match) = captures.name("attrs") else {
            continue;
        };
        let tag = tag_match.as_str().to_ascii_lowercase();
        let attrs = parse_html_attributes(attrs_match.as_str());
        if attrs.is_empty() {
            continue;
        }

        if tag == "meta" {
            let Some(key) = html_meta_key(&attrs) else {
                continue;
            };
            let Some(value) = html_attribute_value(&attrs, "content") else {
                continue;
            };
            process_html_attribute_candidate(document, seen, findings, &tag, &key, value);
            continue;
        }

        if let Some(value) = html_attribute_value(&attrs, "value") {
            if let Some(key) = html_attribute_value(&attrs, "name")
                .or_else(|| html_attribute_value(&attrs, "id"))
                .or_else(|| html_attribute_value(&attrs, "data-name"))
            {
                process_html_attribute_candidate(document, seen, findings, &tag, key, value);
            }
        }

        for (name, value) in &attrs {
            if name.starts_with("data-") {
                process_html_attribute_candidate(document, seen, findings, &tag, name, value);
                if html_attribute_blob_looks_like_config(name, value) {
                    let decoded_value = decode_html_entities_minimal(value);
                    let blob_value =
                        decode_percent_escapes(&decoded_value).unwrap_or(decoded_value.clone());
                    scan_contextual_assignments_in_blob(
                        document,
                        seen,
                        findings,
                        &blob_value,
                        ContextualValueSource::HtmlAttribute,
                        "HTML attribute blob exposed a secret-like {} value.",
                        "html_attribute_blob",
                    );
                    for decoded in extract_decoded_inline_script_blobs(&blob_value) {
                        scan_contextual_assignments_in_blob(
                            document,
                            seen,
                            findings,
                            &decoded,
                            ContextualValueSource::HtmlAttribute,
                            "Decoded HTML attribute blob exposed a secret-like {} value.",
                            "html_attribute_blob_decoded",
                        );
                    }
                }
            } else if html_attribute_blob_looks_like_config(name, value) {
                let decoded_value = decode_html_entities_minimal(value);
                let blob_value =
                    decode_percent_escapes(&decoded_value).unwrap_or(decoded_value.clone());
                scan_contextual_assignments_in_blob(
                    document,
                    seen,
                    findings,
                    &blob_value,
                    ContextualValueSource::HtmlAttribute,
                    "HTML attribute blob exposed a secret-like {} value.",
                    "html_attribute_blob",
                );
            }
        }
    }
}

fn process_cookie_candidate(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
    header_name: &str,
    cookie_name: &str,
    cookie_value: &str,
) {
    let key = normalize_contextual_key(cookie_name);
    let Some(rule) = contextual_assignment_rule(&key) else {
        return;
    };
    let normalized_value = normalize_contextual_value(cookie_value);
    if !validate_contextual_value(
        document,
        &key,
        &normalized_value,
        rule,
        ContextualValueSource::ResponseCookie,
    ) {
        return;
    }

    push_metadata_secret_finding_candidate(
        findings,
        seen,
        document,
        rule.name,
        &rule.severity,
        &normalized_value,
        &format!(
            "HTTP {} {} exposed a secret-like cookie value.",
            header_name.trim(),
            cookie_name.trim()
        ),
        Some(FindingConfidence::High),
        vec![
            "cookie_header".to_string(),
            normalize_contextual_key(header_name),
            key.clone(),
        ],
        vec!["cookie_secret".to_string()],
    );
}

fn process_inline_storage_candidate(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
    storage_name: &str,
    key_name: &str,
    value: &str,
) {
    let key = normalize_contextual_key(key_name);
    let Some(rule) = contextual_assignment_rule(&key) else {
        return;
    };
    let normalized_value = normalize_contextual_value(value);
    if !validate_contextual_value(
        document,
        &key,
        &normalized_value,
        rule,
        ContextualValueSource::InlineScriptConfig,
    ) {
        return;
    }

    push_metadata_secret_finding_candidate(
        findings,
        seen,
        document,
        rule.name,
        &rule.severity,
        &normalized_value,
        &format!(
            "Inline {} key {} exposed a secret-like value.",
            storage_name.trim(),
            key_name.trim()
        ),
        Some(FindingConfidence::Medium),
        vec![
            "inline_storage".to_string(),
            storage_name.trim().to_ascii_lowercase(),
            key.clone(),
        ],
        vec![
            "inline_script_secret".to_string(),
            "browser_storage_secret".to_string(),
        ],
    );
}

fn process_inline_cookie_candidate(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
    source_name: &str,
    cookie_name: &str,
    cookie_value: &str,
) {
    let key = normalize_contextual_key(cookie_name);
    let Some(rule) = contextual_assignment_rule(&key) else {
        return;
    };
    let normalized_value = normalize_contextual_value(cookie_value);
    if !validate_contextual_value(
        document,
        &key,
        &normalized_value,
        rule,
        ContextualValueSource::InlineScriptConfig,
    ) {
        return;
    }

    push_metadata_secret_finding_candidate(
        findings,
        seen,
        document,
        rule.name,
        &rule.severity,
        &normalized_value,
        &format!(
            "Inline {} assignment for {} exposed a secret-like value.",
            source_name.trim(),
            cookie_name.trim()
        ),
        Some(FindingConfidence::Medium),
        vec!["inline_cookie".to_string(), key.clone()],
        vec![
            "inline_script_secret".to_string(),
            "cookie_secret".to_string(),
        ],
    );
}

fn parse_cookie_header_assignments(value: &str, set_cookie: bool) -> Vec<(String, String)> {
    if set_cookie {
        parse_cookie_header_assignment(value, true)
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        value
            .split(';')
            .filter_map(|segment| parse_cookie_header_assignment(segment, false))
            .collect()
    }
}

fn parse_cookie_header_assignment(value: &str, set_cookie: bool) -> Option<(String, String)> {
    let segment = if set_cookie {
        value.split(';').next().unwrap_or("").trim()
    } else {
        value.trim()
    };
    let (name, raw_value) = segment.split_once('=')?;
    let normalized_name = name.trim();
    let normalized_value = raw_value.trim();
    if normalized_name.is_empty() || normalized_value.is_empty() {
        return None;
    }
    Some((normalized_name.to_string(), normalized_value.to_string()))
}

fn parse_fragment_assignments(value: &str) -> Vec<(String, String)> {
    let fragment = value.split('?').next_back().unwrap_or(value);
    url::form_urlencoded::parse(fragment.as_bytes())
        .filter_map(|(name, value)| {
            let normalized_name = name.trim();
            let normalized_value = value.trim();
            (!normalized_name.is_empty() && !normalized_value.is_empty())
                .then_some((normalized_name.to_string(), normalized_value.to_string()))
        })
        .collect()
}

fn script_tag_looks_like_config(attributes: &[(String, String)], body: &str) -> bool {
    let type_value = html_attribute_value(attributes, "type")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let id_value = html_attribute_value(attributes, "id")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let data_name_value = html_attribute_value(attributes, "data-name")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let attr_blob = format!("{type_value}\n{id_value}\n{data_name_value}");

    let lowered = body.to_ascii_lowercase();
    let markers = [
        "window.__",
        "window.config",
        "window.env",
        "window.runtime",
        "runtimeconfig",
        "runtime_config",
        "__next_data__",
        "__nuxt__",
        "publicruntimeconfig",
        "privateruntimeconfig",
        "import.meta.env",
        "bootstrap",
        "appconfig",
        "__env__",
    ];
    let body_or_attr_marked = markers.iter().any(|marker| lowered.contains(marker))
        || markers.iter().any(|marker| attr_blob.contains(marker))
        || id_value.contains("__next_data__")
        || id_value.contains("__nuxt__")
        || id_value.contains("apollo-state")
        || id_value.contains("bootstrap")
        || id_value.contains("runtime-config")
        || id_value.contains("runtimeconfig");

    let json_bootstrap = type_value.contains("json")
        && (body.trim_start().starts_with('{') || body.trim_start().starts_with('['));

    (body_or_attr_marked || json_bootstrap)
        && (body.contains('{') || body.contains('=') || body.contains(':'))
}

fn html_attribute_blob_looks_like_config(name: &str, value: &str) -> bool {
    let normalized_name = normalize_contextual_key(name);
    let decoded_html = decode_html_entities_minimal(value);
    let percent_decoded =
        decode_percent_escapes(&decoded_html).unwrap_or_else(|| decoded_html.clone());
    let lowered = percent_decoded.to_ascii_lowercase();
    let name_hints = [
        "data_state",
        "data_config",
        "data_bootstrap",
        "data_props",
        "data_options",
        "data_env",
        "data_settings",
        "x_data",
        "ng_init",
        "data_json",
    ];
    let marked_name = name_hints.iter().any(|hint| normalized_name.contains(hint));
    let marked_value = lowered.contains("api_key")
        || lowered.contains("access_token")
        || lowered.contains("private_token")
        || lowered.contains("session_secret")
        || lowered.contains("runtimeconfig")
        || lowered.contains("runtime_config")
        || lowered.contains("window.__")
        || lowered.contains("__next_data__")
        || lowered.contains("__nuxt__");

    (marked_name || marked_value)
        && (percent_decoded.trim_start().starts_with('{')
            || percent_decoded.trim_start().starts_with('[')
            || CONTEXTUAL_ASSIGNMENT_RE.is_match(&percent_decoded))
}

fn extract_decoded_inline_script_blobs(script_body: &str) -> Vec<String> {
    let mut blobs = Vec::new();

    for captures in JSON_PARSE_STRING_RE.captures_iter(script_body) {
        let Some(raw_literal) = captures.name("value").map(|value| value.as_str()) else {
            continue;
        };
        let Some(decoded) = decode_javascript_string_literal(raw_literal) else {
            continue;
        };
        if decoded_blob_looks_like_config(&decoded) {
            blobs.push(decoded);
        }
    }

    for captures in ATOB_STRING_RE.captures_iter(script_body) {
        let Some(raw_literal) = captures.name("value").map(|value| value.as_str()) else {
            continue;
        };
        let Some(encoded) = decode_javascript_string_literal(raw_literal) else {
            continue;
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            continue;
        };
        let Ok(decoded) = String::from_utf8(bytes) else {
            continue;
        };
        if decoded_blob_looks_like_config(&decoded) {
            blobs.push(decoded);
        }
    }

    for captures in DECODE_URI_COMPONENT_RE.captures_iter(script_body) {
        let Some(raw_literal) = captures.name("value").map(|value| value.as_str()) else {
            continue;
        };
        let Some(encoded) = decode_javascript_string_literal(raw_literal) else {
            continue;
        };
        let Some(decoded) = decode_percent_escapes(&encoded) else {
            continue;
        };
        if decoded_blob_looks_like_config(&decoded) {
            blobs.push(decoded);
        }
    }

    for captures in DECODE_URI_RE.captures_iter(script_body) {
        let Some(raw_literal) = captures.name("value").map(|value| value.as_str()) else {
            continue;
        };
        let Some(encoded) = decode_javascript_string_literal(raw_literal) else {
            continue;
        };
        let Some(decoded) = decode_percent_escapes(&encoded) else {
            continue;
        };
        if decoded_blob_looks_like_config(&decoded) {
            blobs.push(decoded);
        }
    }

    for captures in UNESCAPE_STRING_RE.captures_iter(script_body) {
        let Some(raw_literal) = captures.name("value").map(|value| value.as_str()) else {
            continue;
        };
        let Some(encoded) = decode_javascript_string_literal(raw_literal) else {
            continue;
        };
        let Some(decoded) = decode_percent_escapes(&encoded) else {
            continue;
        };
        if decoded_blob_looks_like_config(&decoded) {
            blobs.push(decoded);
        }
    }

    blobs
}

fn decoded_blob_looks_like_config(decoded: &str) -> bool {
    let trimmed = decoded.trim();
    trimmed.starts_with('{')
        || trimmed.starts_with('[')
        || CONTEXTUAL_ASSIGNMENT_RE.is_match(trimmed)
}

fn decode_javascript_string_literal(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let first = trimmed.chars().next()?;
    let last = trimmed.chars().last()?;
    if first != last || !matches!(first, '"' | '\'' | '`') {
        return None;
    }
    if first == '"' {
        return serde_json::from_str::<String>(trimmed).ok();
    }

    let inner = &trimmed[1..trimmed.len() - 1];
    let mut decoded = String::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }
        let Some(escaped) = chars.next() else {
            decoded.push('\\');
            break;
        };
        match escaped {
            '\\' => decoded.push('\\'),
            '\'' => decoded.push('\''),
            '"' => decoded.push('"'),
            '`' => decoded.push('`'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'x' => {
                let hex = [chars.next(), chars.next()]
                    .into_iter()
                    .flatten()
                    .collect::<String>();
                if hex.len() == 2 {
                    if let Ok(value) = u8::from_str_radix(&hex, 16) {
                        decoded.push(value as char);
                        continue;
                    }
                }
                decoded.push('x');
                decoded.push_str(&hex);
            }
            'u' => {
                if chars.clone().next() == Some('{') {
                    let _ = chars.next();
                    let mut hex = String::new();
                    for candidate in chars.by_ref() {
                        if candidate == '}' {
                            break;
                        }
                        hex.push(candidate);
                    }
                    if let Ok(value) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(value) {
                            decoded.push(ch);
                            continue;
                        }
                    }
                    decoded.push('u');
                    decoded.push('{');
                    decoded.push_str(&hex);
                    decoded.push('}');
                } else {
                    let hex = [chars.next(), chars.next(), chars.next(), chars.next()]
                        .into_iter()
                        .flatten()
                        .collect::<String>();
                    if hex.len() == 4 {
                        if let Ok(value) = u32::from_str_radix(&hex, 16) {
                            if let Some(ch) = char::from_u32(value) {
                                decoded.push(ch);
                                continue;
                            }
                        }
                    }
                    decoded.push('u');
                    decoded.push_str(&hex);
                }
            }
            other => decoded.push(other),
        }
    }
    Some(decoded)
}

fn decode_html_entities_minimal(value: &str) -> String {
    let mut decoded = value
        .replace("&quot;", "\"")
        .replace("&#34;", "\"")
        .replace("&#x22;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">");

    if decoded.contains("&#x") || decoded.contains("&#") {
        let mut normalized = String::new();
        let mut chars = decoded.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '&' && chars.peek() == Some(&'#') {
                let _ = chars.next();
                let is_hex = matches!(chars.peek(), Some('x') | Some('X'));
                if is_hex {
                    let _ = chars.next();
                }
                let mut digits = String::new();
                while let Some(candidate) = chars.peek().copied() {
                    if candidate == ';' {
                        let _ = chars.next();
                        break;
                    }
                    if candidate.is_ascii_hexdigit() {
                        digits.push(candidate);
                        let _ = chars.next();
                    } else {
                        digits.clear();
                        break;
                    }
                }
                if !digits.is_empty() {
                    let radix = if is_hex { 16 } else { 10 };
                    if let Ok(codepoint) = u32::from_str_radix(&digits, radix) {
                        if let Some(rendered) = char::from_u32(codepoint) {
                            normalized.push(rendered);
                            continue;
                        }
                    }
                }
                normalized.push('&');
                normalized.push('#');
                if is_hex {
                    normalized.push('x');
                }
                normalized.push_str(&digits);
                continue;
            }
            normalized.push(ch);
        }
        decoded = normalized;
    }

    decoded
}

fn decode_percent_escapes(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 1 < bytes.len() => {
                if bytes[index + 1] == b'u' || bytes[index + 1] == b'U' {
                    if index + 5 < bytes.len() {
                        let hex = &value[index + 2..index + 6];
                        if let Ok(codepoint) = u32::from_str_radix(hex, 16) {
                            if let Some(ch) = char::from_u32(codepoint) {
                                let mut buffer = [0u8; 4];
                                let rendered = ch.encode_utf8(&mut buffer);
                                decoded.extend_from_slice(rendered.as_bytes());
                                index += 6;
                                changed = true;
                                continue;
                            }
                        }
                    }
                } else if index + 2 < bytes.len() {
                    let hex = &value[index + 1..index + 3];
                    if let Ok(byte) = u8::from_str_radix(hex, 16) {
                        decoded.push(byte);
                        index += 3;
                        changed = true;
                        continue;
                    }
                }
                decoded.push(bytes[index]);
                index += 1;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
                changed = true;
            }
            other => {
                decoded.push(other);
                index += 1;
            }
        }
    }
    let decoded = String::from_utf8(decoded).ok()?;
    changed.then_some(decoded)
}

fn parse_html_attributes(raw: &str) -> Vec<(String, String)> {
    HTML_ATTRIBUTE_RE
        .captures_iter(raw)
        .filter_map(|captures| {
            let name = captures.name("name")?.as_str().trim().to_ascii_lowercase();
            let value = captures
                .name("value")?
                .as_str()
                .trim()
                .trim_matches(&['"', '\''][..])
                .to_string();
            (!name.is_empty() && !value.is_empty()).then_some((name, value))
        })
        .collect()
}

fn html_attribute_value<'a>(attributes: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find(|(attr_name, _)| attr_name == name)
        .map(|(_, value)| value.as_str())
}

fn html_meta_key<'a>(attributes: &'a [(String, String)]) -> Option<&'a str> {
    html_attribute_value(attributes, "name")
        .or_else(|| html_attribute_value(attributes, "property"))
        .or_else(|| html_attribute_value(attributes, "http-equiv"))
}

fn process_html_attribute_candidate(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
    tag: &str,
    raw_key: &str,
    raw_value: &str,
) {
    let key = normalize_contextual_key(raw_key);
    let Some(rule) = contextual_assignment_rule(&key) else {
        return;
    };
    let normalized_value = normalize_contextual_value(raw_value);
    if !validate_contextual_value(
        document,
        &key,
        &normalized_value,
        rule,
        ContextualValueSource::HtmlAttribute,
    ) {
        return;
    }

    push_metadata_secret_finding_candidate(
        findings,
        seen,
        document,
        rule.name,
        &rule.severity,
        &normalized_value,
        &format!(
            "HTML <{}> attribute {} exposed a secret-like value.",
            tag.trim(),
            raw_key.trim()
        ),
        Some(FindingConfidence::Medium),
        vec!["html_attribute".to_string(), tag.to_string(), key.clone()],
        vec!["html_attribute_secret".to_string()],
    );
}

fn run_external_detector_pack(
    document: &FetchedDocument,
    manifest: &ExtensionManifest,
) -> Result<Vec<FindingCandidate>> {
    let command = manifest
        .resolved_command()
        .ok_or_else(|| anyhow!("detector pack {} is missing a command", manifest.name))?;
    let invocation = serde_json::to_vec(&ExternalDetectorInvocation {
        detector_pack: &manifest.name,
        path: &document.path,
        url: &document.url,
        status: document.status,
        content_type: document.content_type.as_deref(),
        headers: &document.headers,
        body: &document.body,
        truncated: document.truncated,
        coverage_source: &document.coverage_source,
    })
    .context("failed to serialize detector pack invocation")?;

    let mut child = Command::new(&command)
        .args(&manifest.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn detector pack {}", manifest.name))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&invocation).with_context(|| {
            format!("failed to write detector pack input for {}", manifest.name)
        })?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("failed to wait for detector pack {}", manifest.name))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(anyhow!(
            "detector pack {} exited unsuccessfully{}",
            manifest.name,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    parse_external_detector_output(&stdout, document, manifest)
}

fn parse_external_detector_output(
    output: &str,
    document: &FetchedDocument,
    manifest: &ExtensionManifest,
) -> Result<Vec<FindingCandidate>> {
    match manifest.output_format() {
        "finding_json_lines" => parse_external_finding_json_lines(output, document),
        other => Err(anyhow!(
            "detector pack {} uses unsupported output format {}",
            manifest.name,
            other
        )),
    }
}

fn parse_external_finding_json_lines(
    output: &str,
    document: &FetchedDocument,
) -> Result<Vec<FindingCandidate>> {
    let mut findings = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: ExternalFindingCandidate = serde_json::from_str(line)
            .with_context(|| format!("invalid detector pack JSON line: {line}"))?;
        if let Some(candidate) = external_finding_candidate_from_record(&record, document)? {
            findings.push(candidate);
        }
    }
    Ok(findings)
}

fn external_finding_candidate_from_record(
    record: &ExternalFindingCandidate,
    document: &FetchedDocument,
) -> Result<Option<FindingCandidate>> {
    let detector = record.detector.trim();
    if detector.is_empty() {
        return Ok(None);
    }

    let severity = record
        .severity
        .trim()
        .to_ascii_lowercase()
        .parse::<Severity>()
        .map_err(|error| anyhow!(error))?;
    let path = record
        .path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(document.path.as_str())
        .to_string();

    let secret_value = record
        .secret_value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let fingerprint = match (
        secret_value.as_deref(),
        record
            .fingerprint
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
    ) {
        (Some(secret_value), Some(existing_fingerprint)) => {
            let computed_fingerprint = fingerprint(secret_value);
            if computed_fingerprint != existing_fingerprint {
                computed_fingerprint
            } else {
                existing_fingerprint.to_string()
            }
        }
        (Some(secret_value), None) => fingerprint(secret_value),
        (None, Some(existing_fingerprint)) => existing_fingerprint.to_string(),
        (None, None) => return Ok(None),
    };
    let redacted_value = match (
        secret_value.as_deref(),
        record
            .redacted_value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
    ) {
        (Some(secret_value), Some(redacted_value)) => {
            if redacted_value == secret_value {
                redact_secret(secret_value)
            } else {
                redacted_value.to_string()
            }
        }
        (Some(secret_value), None) => redact_secret(secret_value),
        (None, Some(redacted_value)) => redacted_value.to_string(),
        (None, None) => return Ok(None),
    };
    let evidence = if let Some(evidence) = record
        .evidence
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        evidence.to_string()
    } else if let Some(evidence_value) = record
        .evidence_value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let (start, end) = match (record.start, record.end) {
            (Some(start), Some(end)) if start < end && end <= document.body.len() => (start, end),
            _ => document
                .body
                .find(evidence_value)
                .map(|start| (start, start + evidence_value.len()))
                .unwrap_or((0, evidence_value.len().min(document.body.len()))),
        };
        build_evidence(document, start, end, evidence_value)
    } else {
        format!("external detector {detector} matched {redacted_value}")
    };
    let confidence = record
        .confidence
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse)
        .transpose()
        .map_err(|error: String| anyhow!("invalid external finding confidence: {error}"))?;

    Ok(Some(FindingCandidate {
        detector: detector.to_string(),
        severity,
        path,
        redacted_value,
        evidence,
        fingerprint,
        confidence,
        matched_signals: record.matched_signals.clone(),
        review_labels: record.review_labels.clone(),
        plugin_metadata: record.plugin_id.as_deref().and_then(|plugin_id| {
            let cve_ids = record
                .cve_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            build_plugin_metadata(
                plugin_id,
                record.product_name.as_deref(),
                record.product_version.as_deref(),
                record.cpe.as_deref(),
                &cve_ids,
                record.kev_matched,
                record.service_protocol.as_deref(),
                record.service_port,
            )
        }),
    }))
}

fn should_scan_structured_fields(document: &FetchedDocument) -> bool {
    is_contextual_secret_path(&document.path)
        || STRUCTURED_SECRET_FIELD_HINTS
            .iter()
            .any(|hint| document.body.contains(hint))
}

fn structured_scalar_fields(document: &FetchedDocument) -> Vec<StructuredScalarField> {
    let trimmed_body = document.body.trim();
    if trimmed_body.is_empty() {
        return Vec::new();
    }

    let lowered_path = document.path.to_ascii_lowercase();
    let mut fields = Vec::new();
    let mut seen = HashSet::new();

    let mut parsed_json = false;
    let mut parsed_yaml = false;
    let mut parsed_toml = false;

    if lowered_path.ends_with(".json")
        || lowered_path.ends_with(".webmanifest")
        || trimmed_body.starts_with('{')
        || trimmed_body.starts_with('[')
    {
        parsed_json = collect_json_structured_fields(trimmed_body, &mut fields, &mut seen);
    }

    if lowered_path.ends_with(".yaml")
        || lowered_path.ends_with(".yml")
        || lowered_path.ends_with("kubeconfig")
    {
        parsed_yaml = collect_yaml_structured_fields(trimmed_body, &mut fields, &mut seen);
    }

    if lowered_path.ends_with(".toml") {
        parsed_toml = collect_toml_structured_fields(trimmed_body, &mut fields, &mut seen);
    }

    if fields.is_empty()
        && !parsed_json
        && !parsed_yaml
        && !parsed_toml
        && (lowered_path.ends_with(".config")
            || lowered_path.ends_with(".conf")
            || lowered_path.contains("/config")
            || lowered_path.contains("/settings"))
    {
        collect_json_structured_fields(trimmed_body, &mut fields, &mut seen);
        collect_yaml_structured_fields(trimmed_body, &mut fields, &mut seen);
        collect_toml_structured_fields(trimmed_body, &mut fields, &mut seen);
    }

    fields
}

fn collect_json_structured_fields(
    body: &str,
    fields: &mut Vec<StructuredScalarField>,
    seen: &mut HashSet<StructuredScalarField>,
) -> bool {
    let Ok(json) = serde_json::from_str::<JsonValue>(body) else {
        return false;
    };
    collect_json_string_fields(None, &json, fields, seen);
    true
}

fn collect_json_string_fields(
    prefix: Option<&str>,
    value: &JsonValue,
    fields: &mut Vec<StructuredScalarField>,
    seen: &mut HashSet<StructuredScalarField>,
) {
    match value {
        JsonValue::Object(map) => {
            for (key, value) in map {
                let next_prefix = join_structured_field_path(prefix, key);
                collect_json_string_fields(Some(&next_prefix), value, fields, seen);
            }
        }
        JsonValue::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let next_prefix = join_structured_field_path(prefix, &index.to_string());
                collect_json_string_fields(Some(&next_prefix), value, fields, seen);
            }
        }
        JsonValue::String(string) => {
            if let Some(prefix) = prefix {
                push_structured_scalar_field(fields, seen, prefix, string);
            }
        }
        _ => {}
    }
}

fn collect_yaml_structured_fields(
    body: &str,
    fields: &mut Vec<StructuredScalarField>,
    seen: &mut HashSet<StructuredScalarField>,
) -> bool {
    let Ok(yaml) = serde_yaml::from_str::<YamlValue>(body) else {
        return false;
    };
    collect_yaml_string_fields(None, &yaml, fields, seen);
    true
}

fn collect_yaml_string_fields(
    prefix: Option<&str>,
    value: &YamlValue,
    fields: &mut Vec<StructuredScalarField>,
    seen: &mut HashSet<StructuredScalarField>,
) {
    match value {
        YamlValue::Mapping(map) => {
            for (key, value) in map {
                let Some(segment) = yaml_key_segment(key) else {
                    continue;
                };
                let next_prefix = join_structured_field_path(prefix, &segment);
                collect_yaml_string_fields(Some(&next_prefix), value, fields, seen);
            }
        }
        YamlValue::Sequence(values) => {
            for (index, value) in values.iter().enumerate() {
                let next_prefix = join_structured_field_path(prefix, &index.to_string());
                collect_yaml_string_fields(Some(&next_prefix), value, fields, seen);
            }
        }
        YamlValue::String(string) => {
            if let Some(prefix) = prefix {
                push_structured_scalar_field(fields, seen, prefix, string);
            }
        }
        _ => {}
    }
}

fn collect_toml_structured_fields(
    body: &str,
    fields: &mut Vec<StructuredScalarField>,
    seen: &mut HashSet<StructuredScalarField>,
) -> bool {
    let Ok(toml) = body.parse::<TomlValue>() else {
        return false;
    };
    collect_toml_string_fields(None, &toml, fields, seen);
    true
}

fn collect_toml_string_fields(
    prefix: Option<&str>,
    value: &TomlValue,
    fields: &mut Vec<StructuredScalarField>,
    seen: &mut HashSet<StructuredScalarField>,
) {
    match value {
        TomlValue::Table(table) => {
            for (key, value) in table {
                let next_prefix = join_structured_field_path(prefix, key);
                collect_toml_string_fields(Some(&next_prefix), value, fields, seen);
            }
        }
        TomlValue::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let next_prefix = join_structured_field_path(prefix, &index.to_string());
                collect_toml_string_fields(Some(&next_prefix), value, fields, seen);
            }
        }
        TomlValue::String(string) => {
            if let Some(prefix) = prefix {
                push_structured_scalar_field(fields, seen, prefix, string);
            }
        }
        _ => {}
    }
}

fn join_structured_field_path(prefix: Option<&str>, segment: &str) -> String {
    match prefix {
        Some(prefix) if !prefix.is_empty() => format!("{prefix}.{segment}"),
        _ => segment.to_string(),
    }
}

fn yaml_key_segment(value: &YamlValue) -> Option<String> {
    match value {
        YamlValue::String(string) => Some(string.clone()),
        YamlValue::Number(number) => Some(number.to_string()),
        YamlValue::Bool(boolean) => Some(boolean.to_string()),
        _ => None,
    }
}

fn push_structured_scalar_field(
    fields: &mut Vec<StructuredScalarField>,
    seen: &mut HashSet<StructuredScalarField>,
    key: &str,
    value: &str,
) {
    let field = StructuredScalarField {
        key: key.to_string(),
        value: value.to_string(),
    };
    if field.key.is_empty() || field.value.trim().is_empty() || !seen.insert(field.clone()) {
        return;
    }
    fields.push(field);
}

fn scan_aws_shared_credentials_secret_access_keys(
    document: &FetchedDocument,
) -> Vec<StructuredMatch> {
    scan_assignment_values_for_keys(document, &["aws_secret_access_key"], |value| {
        looks_like_high_entropy_secret(value) || looks_like_base64_secret(value)
    })
}

fn scan_aws_shared_credentials_session_tokens(document: &FetchedDocument) -> Vec<StructuredMatch> {
    scan_assignment_values_for_keys(document, &["aws_session_token"], |value| {
        looks_like_token_like_secret(value)
            || looks_like_high_entropy_secret(value)
            || looks_like_base64_secret(value)
    })
}

fn scan_azure_service_principal_client_secrets(document: &FetchedDocument) -> Vec<StructuredMatch> {
    let fields = structured_scalar_fields(document);
    let has_tenant = fields.iter().any(|field| {
        let key = normalize_contextual_key(&field.key);
        key_matches_keyword(&key, "tenant_id") || key_matches_keyword(&key, "tenantid")
    });
    let has_application = fields.iter().any(|field| {
        let key = normalize_contextual_key(&field.key);
        key_matches_keyword(&key, "client_id")
            || key_matches_keyword(&key, "clientid")
            || key_matches_keyword(&key, "app_id")
            || key_matches_keyword(&key, "appid")
    });
    if !has_tenant || !has_application {
        return Vec::new();
    }

    scan_structured_scalar_secret_fields(
        document,
        &fields,
        &["client_secret", "clientsecret"],
        |value| {
            looks_like_high_entropy_secret(value)
                || looks_like_token_like_secret(value)
                || looks_like_secretish_password(value)
        },
    )
}

fn scan_google_oauth_client_secrets(document: &FetchedDocument) -> Vec<StructuredMatch> {
    let fields = structured_scalar_fields(document);
    let has_google_client_id = fields.iter().any(|field| {
        let key = normalize_contextual_key(&field.key);
        let value = normalize_contextual_value(&field.value);
        key_matches_keyword(&key, "client_id")
            && value
                .to_ascii_lowercase()
                .contains("apps.googleusercontent.com")
    });
    let has_google_oauth_url = fields.iter().any(|field| {
        normalize_contextual_value(&field.value)
            .to_ascii_lowercase()
            .contains("googleapis.com")
            || normalize_contextual_value(&field.value)
                .to_ascii_lowercase()
                .contains("accounts.google.com")
    });
    if !has_google_client_id || !has_google_oauth_url {
        return Vec::new();
    }

    scan_structured_scalar_secret_fields(
        document,
        &fields,
        &["client_secret", "clientsecret"],
        |value| {
            looks_like_token_like_secret(value)
                || looks_like_high_entropy_secret(value)
                || looks_like_secretish_password(value)
        },
    )
}

fn scan_firebase_admin_service_account_private_keys(
    document: &FetchedDocument,
) -> Vec<StructuredMatch> {
    scan_google_service_account_private_keys_internal(document, true)
}

fn scan_google_service_account_private_keys(document: &FetchedDocument) -> Vec<StructuredMatch> {
    scan_google_service_account_private_keys_internal(document, false)
}

fn scan_google_service_account_private_keys_internal(
    document: &FetchedDocument,
    firebase_only: bool,
) -> Vec<StructuredMatch> {
    let fields = structured_scalar_fields(document);
    if !has_google_service_account_metadata(&fields) {
        return Vec::new();
    }

    let is_firebase_account = fields.iter().any(|field| {
        structured_field_matches_keyword(field, "client_email")
            && normalize_contextual_value(&field.value)
                .to_ascii_lowercase()
                .contains("firebase-adminsdk")
    }) || document.path.to_ascii_lowercase().contains("firebase");

    if firebase_only {
        if !is_firebase_account {
            return Vec::new();
        }
    } else if is_firebase_account {
        return Vec::new();
    }

    scan_structured_private_key_fields(document, &fields, &["private_key"])
}

fn scan_google_authorized_user_refresh_tokens(document: &FetchedDocument) -> Vec<StructuredMatch> {
    let fields = structured_scalar_fields(document);
    if !has_google_authorized_user_metadata(&fields) {
        return Vec::new();
    }

    scan_structured_scalar_secret_fields(
        document,
        &fields,
        &["refresh_token", "refreshtoken"],
        |value| looks_like_token_like_secret(value) || looks_like_high_entropy_secret(value),
    )
}

fn has_google_service_account_metadata(fields: &[StructuredScalarField]) -> bool {
    let has_service_account_type = fields.iter().any(|field| {
        structured_field_matches_keyword(field, "type")
            && normalize_contextual_value(&field.value).eq_ignore_ascii_case("service_account")
    });
    let has_gserviceaccount_email = fields.iter().any(|field| {
        structured_field_matches_keyword(field, "client_email")
            && normalize_contextual_value(&field.value)
                .to_ascii_lowercase()
                .ends_with(".gserviceaccount.com")
    });
    let has_private_key_id = fields.iter().any(|field| {
        structured_field_matches_keyword(field, "private_key_id")
            && normalize_contextual_value(&field.value).len() >= 16
    });

    has_service_account_type && has_gserviceaccount_email && has_private_key_id
}

fn has_google_authorized_user_metadata(fields: &[StructuredScalarField]) -> bool {
    let has_authorized_user_type = fields.iter().any(|field| {
        structured_field_matches_keyword(field, "type")
            && normalize_contextual_value(&field.value).eq_ignore_ascii_case("authorized_user")
    });
    let has_google_client_id = fields.iter().any(|field| {
        structured_field_matches_keyword(field, "client_id")
            && normalize_contextual_value(&field.value)
                .to_ascii_lowercase()
                .contains("apps.googleusercontent.com")
    });

    has_authorized_user_type && has_google_client_id
}

fn structured_field_matches_keyword(field: &StructuredScalarField, keyword: &str) -> bool {
    key_matches_keyword(&normalize_contextual_key(&field.key), keyword)
}

fn looks_like_private_key_block(value: &str) -> bool {
    let candidate = normalize_contextual_value(value);
    PRIVATE_KEY.is_match(&candidate) && candidate.contains("-----END")
}

fn scan_assignment_values_for_keys<F>(
    document: &FetchedDocument,
    keys: &[&str],
    validator: F,
) -> Vec<StructuredMatch>
where
    F: Fn(&str) -> bool,
{
    let mut matches = Vec::new();

    for captures in CONTEXTUAL_ASSIGNMENT_RE.captures_iter(&document.body) {
        let Some(key_match) = captures.name("key") else {
            continue;
        };
        let Some(value_match) = captures.name("value") else {
            continue;
        };

        let key = normalize_contextual_key(key_match.as_str());
        if !keys
            .iter()
            .any(|candidate| key_matches_keyword(&key, candidate))
        {
            continue;
        }

        let normalized_value = normalize_contextual_value(value_match.as_str());
        if looks_like_placeholder_secret(&normalized_value) || !validator(&normalized_value) {
            continue;
        }

        matches.push(StructuredMatch {
            start: value_match.start(),
            end: value_match.end(),
            evidence_value: value_match.as_str().to_string(),
            secret_value: normalized_value,
        });
    }

    matches
}

fn scan_structured_scalar_secret_fields<F>(
    document: &FetchedDocument,
    fields: &[StructuredScalarField],
    keys: &[&str],
    validator: F,
) -> Vec<StructuredMatch>
where
    F: Fn(&str) -> bool,
{
    let mut matches = Vec::new();

    for field in fields {
        let key = normalize_contextual_key(&field.key);
        if !keys
            .iter()
            .any(|candidate| key_matches_keyword(&key, candidate))
        {
            continue;
        }

        let normalized_value = normalize_contextual_value(&field.value);
        if looks_like_placeholder_secret(&normalized_value) || !validator(&normalized_value) {
            continue;
        }

        let Some(matched) = structured_match_from_value(document, &normalized_value) else {
            continue;
        };
        matches.push(matched);
    }

    matches
}

fn scan_structured_private_key_fields(
    document: &FetchedDocument,
    fields: &[StructuredScalarField],
    keys: &[&str],
) -> Vec<StructuredMatch> {
    let mut matches = Vec::new();

    for field in fields {
        let key = normalize_contextual_key(&field.key);
        if !keys
            .iter()
            .any(|candidate| key_matches_keyword(&key, candidate))
        {
            continue;
        }

        let normalized_value = normalize_contextual_value(&field.value);
        if looks_like_placeholder_secret(&normalized_value)
            || !looks_like_private_key_block(&normalized_value)
        {
            continue;
        }

        let Some(matched) = structured_body_match_from_value(document, &normalized_value) else {
            continue;
        };
        matches.push(matched);
    }

    matches
}

fn scan_npm_registry_auth(document: &FetchedDocument) -> Vec<StructuredMatch> {
    let mut matches = Vec::new();

    for captures in NPMRC_AUTH_RE.captures_iter(&document.body) {
        let Some(key_match) = captures.name("key") else {
            continue;
        };
        let Some(value_match) = captures.name("value") else {
            continue;
        };

        let key = key_match.as_str().to_ascii_lowercase();
        let normalized_value = normalize_contextual_value(value_match.as_str());
        if looks_like_placeholder_secret(&normalized_value) {
            continue;
        }

        let valid = if key == "_auth" {
            looks_like_high_entropy_secret(&normalized_value)
                || looks_like_base64_secret(&normalized_value)
                || looks_like_secretish_password(&normalized_value)
        } else {
            looks_like_token_like_secret(&normalized_value)
                || looks_like_high_entropy_secret(&normalized_value)
                || looks_like_base64_secret(&normalized_value)
        };
        if !valid {
            continue;
        }

        matches.push(StructuredMatch {
            start: value_match.start(),
            end: value_match.end(),
            evidence_value: value_match.as_str().to_string(),
            secret_value: normalized_value,
        });
    }

    matches
}

fn scan_pypirc_passwords(document: &FetchedDocument) -> Vec<StructuredMatch> {
    let mut matches = Vec::new();

    for captures in PYPIRC_PASSWORD_RE.captures_iter(&document.body) {
        let Some(value_match) = captures.name("value") else {
            continue;
        };
        let normalized_value = normalize_contextual_value(value_match.as_str());
        if looks_like_placeholder_secret(&normalized_value) {
            continue;
        }
        if !(looks_like_secretish_password(&normalized_value)
            || looks_like_token_like_secret(&normalized_value)
            || looks_like_high_entropy_secret(&normalized_value))
        {
            continue;
        }

        matches.push(StructuredMatch {
            start: value_match.start(),
            end: value_match.end(),
            evidence_value: value_match.as_str().to_string(),
            secret_value: normalized_value,
        });
    }

    matches
}

fn scan_netrc_passwords(document: &FetchedDocument) -> Vec<StructuredMatch> {
    let mut matches = Vec::new();

    for captures in NETRC_PASSWORD_RE.captures_iter(&document.body) {
        let Some(value_match) = captures.name("value") else {
            continue;
        };
        let normalized_value = normalize_contextual_value(value_match.as_str());
        if looks_like_placeholder_secret(&normalized_value) {
            continue;
        }
        if !(looks_like_secretish_password(&normalized_value)
            || looks_like_token_like_secret(&normalized_value)
            || looks_like_high_entropy_secret(&normalized_value))
        {
            continue;
        }

        matches.push(StructuredMatch {
            start: value_match.start(),
            end: value_match.end(),
            evidence_value: value_match.as_str().to_string(),
            secret_value: normalized_value,
        });
    }

    matches
}

fn scan_docker_registry_auth(document: &FetchedDocument) -> Vec<StructuredMatch> {
    let Ok(json) = serde_json::from_str::<JsonValue>(&document.body) else {
        return Vec::new();
    };
    let Some(auths) = json.get("auths").and_then(JsonValue::as_object) else {
        return Vec::new();
    };

    let mut matches = Vec::new();
    for auth_config in auths.values() {
        let Some(config) = auth_config.as_object() else {
            continue;
        };

        for key in ["auth", "identitytoken", "identityToken"] {
            let Some(value) = config.get(key).and_then(JsonValue::as_str) else {
                continue;
            };
            if looks_like_placeholder_secret(value) {
                continue;
            }

            let valid = if key == "auth" {
                looks_like_high_entropy_secret(value) || looks_like_base64_secret(value)
            } else {
                looks_like_token_like_secret(value) || looks_like_high_entropy_secret(value)
            };
            if !valid {
                continue;
            }

            if let Some(matched) = structured_match_from_value(document, value) {
                matches.push(matched);
            }
        }
    }

    matches
}

fn scan_kubeconfig_credentials(document: &FetchedDocument) -> Vec<StructuredMatch> {
    let Ok(yaml) = serde_yaml::from_str::<YamlValue>(&document.body) else {
        return Vec::new();
    };

    let mut matches = Vec::new();
    collect_kubeconfig_credentials(document, &yaml, &mut matches);
    matches
}

const CONTEXT_WINDOW_CHARS: usize = 80;

fn body_window_around<'a>(body: &'a str, start: usize, end: usize) -> &'a str {
    let mut window_start = start.saturating_sub(CONTEXT_WINDOW_CHARS);
    let mut window_end = end.saturating_add(CONTEXT_WINDOW_CHARS).min(body.len());
    while window_start > 0 && !body.is_char_boundary(window_start) {
        window_start -= 1;
    }
    while window_end < body.len() && !body.is_char_boundary(window_end) {
        window_end += 1;
    }
    &body[window_start..window_end]
}

fn scan_contextual_token_matches<'a>(
    document: &'a FetchedDocument,
    regex: &Regex,
    context_keywords: &[&str],
) -> Vec<StructuredMatch> {
    let mut matches = Vec::new();
    let body = document.body.as_str();
    for matched in regex.find_iter(body) {
        let window = body_window_around(body, matched.start(), matched.end());
        let lowered_window = window.to_ascii_lowercase();
        let has_context = context_keywords
            .iter()
            .any(|keyword| lowered_window.contains(&keyword.to_ascii_lowercase()));
        if !has_context {
            continue;
        }
        let token = matched.as_str();
        if looks_like_placeholder_secret(token) {
            continue;
        }
        matches.push(StructuredMatch {
            start: matched.start(),
            end: matched.end(),
            evidence_value: token.to_string(),
            secret_value: token.to_string(),
        });
    }
    matches
}

fn scan_cloudflare_api_tokens(document: &FetchedDocument) -> Vec<StructuredMatch> {
    scan_contextual_token_matches(
        document,
        &CLOUDFLARE_API_TOKEN_RE,
        &["cloudflare", "cf_api_token", "x-auth-email"],
    )
}

fn scan_datadog_api_keys(document: &FetchedDocument) -> Vec<StructuredMatch> {
    scan_contextual_token_matches(
        document,
        &DATADOG_API_KEY_RE,
        &["datadog", "dd_api_key", "dd_app_key", "dd-agent"],
    )
}

fn scan_jwt_alg_none_tokens(document: &FetchedDocument) -> Vec<StructuredMatch> {
    let mut matches = Vec::new();
    for matched in JWT_TOKEN_RE.find_iter(&document.body) {
        let token = matched.as_str();
        let Some(header_b64) = token.split('.').next() else {
            continue;
        };
        let Ok(header_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header_b64)
        else {
            continue;
        };
        let Ok(header_json) = serde_json::from_slice::<JsonValue>(&header_bytes) else {
            continue;
        };
        let alg_is_none = header_json
            .get("alg")
            .and_then(|value| value.as_str())
            .map(|alg| alg.eq_ignore_ascii_case("none"))
            .unwrap_or(false);
        if !alg_is_none {
            continue;
        }
        matches.push(StructuredMatch {
            start: matched.start(),
            end: matched.end(),
            evidence_value: token.to_string(),
            secret_value: token.to_string(),
        });
    }
    matches
}

fn collect_kubeconfig_credentials(
    document: &FetchedDocument,
    value: &YamlValue,
    matches: &mut Vec<StructuredMatch>,
) {
    match value {
        YamlValue::Mapping(map) => {
            for (key, value) in map {
                if let Some(key_str) = key.as_str() {
                    maybe_push_kubeconfig_credential(document, key_str, value, matches);
                }
                collect_kubeconfig_credentials(document, value, matches);
            }
        }
        YamlValue::Sequence(values) => {
            for value in values {
                collect_kubeconfig_credentials(document, value, matches);
            }
        }
        _ => {}
    }
}

fn maybe_push_kubeconfig_credential(
    document: &FetchedDocument,
    key: &str,
    value: &YamlValue,
    matches: &mut Vec<StructuredMatch>,
) {
    let Some(secret_value) = value.as_str() else {
        return;
    };
    if looks_like_placeholder_secret(secret_value) {
        return;
    }

    let normalized_key = key.to_ascii_lowercase();
    let valid = match normalized_key.as_str() {
        "token" | "access-token" | "refresh-token" | "client-secret" => {
            looks_like_token_like_secret(secret_value)
                || looks_like_high_entropy_secret(secret_value)
        }
        "password" => looks_like_secretish_password(secret_value),
        "client-key-data" | "client-certificate-data" => {
            looks_like_high_entropy_secret(secret_value) || looks_like_base64_secret(secret_value)
        }
        _ => false,
    };
    if !valid {
        return;
    }

    if let Some(matched) = structured_match_from_value(document, secret_value) {
        matches.push(matched);
    }
}

fn structured_match_from_value(
    document: &FetchedDocument,
    secret_value: &str,
) -> Option<StructuredMatch> {
    let (start, end, evidence_value) = resolve_match_span(&document.body, secret_value)?;
    Some(StructuredMatch {
        start,
        end,
        evidence_value,
        secret_value: secret_value.to_string(),
    })
}

fn structured_body_match_from_value(
    document: &FetchedDocument,
    secret_value: &str,
) -> Option<StructuredMatch> {
    let (start, end, evidence_value) = resolve_match_span(&document.body, secret_value)?;
    Some(StructuredMatch {
        start,
        end,
        secret_value: evidence_value.clone(),
        evidence_value,
    })
}

fn resolve_match_span(body: &str, secret_value: &str) -> Option<(usize, usize, String)> {
    let normalized = normalize_contextual_value(secret_value);
    let mut candidates = Vec::new();
    if !normalized.is_empty() {
        candidates.push(normalized);
    }

    if let Ok(json_encoded) = serde_json::to_string(secret_value) {
        let encoded = json_encoded.trim_matches('"').to_string();
        if !encoded.is_empty() && !candidates.iter().any(|candidate| candidate == &encoded) {
            candidates.push(encoded);
        }
    }

    for candidate in candidates {
        if let Some(start) = body.find(&candidate) {
            return Some((start, start + candidate.len(), candidate));
        }
    }

    None
}

fn push_finding_candidate(
    findings: &mut Vec<FindingCandidate>,
    seen: &mut HashSet<String>,
    document: &FetchedDocument,
    detector_name: &str,
    severity: &Severity,
    start: usize,
    end: usize,
    evidence_value: &str,
    secret_value: &str,
) {
    let secret_value = secret_value.trim();
    if secret_value.is_empty() {
        return;
    }

    let fingerprint = fingerprint(secret_value);
    let dedupe_key = format!("{}:{fingerprint}", document.path);
    if !seen.insert(dedupe_key) {
        return;
    }

    findings.push(FindingCandidate {
        detector: detector_name.to_string(),
        severity: severity.clone(),
        path: document.path.clone(),
        redacted_value: redact_secret(secret_value),
        evidence: build_evidence(document, start, end, evidence_value),
        fingerprint,
        confidence: None,
        matched_signals: Vec::new(),
        review_labels: Vec::new(),
        plugin_metadata: None,
    });
}

fn push_plugin_finding_candidate(
    findings: &mut Vec<FindingCandidate>,
    seen: &mut HashSet<String>,
    document: &FetchedDocument,
    plugin_id: &str,
    detector_name: &str,
    severity: Severity,
    redacted_value: &str,
    evidence: &str,
    product_name: Option<&str>,
    product_version: Option<&str>,
    cpe: Option<&str>,
    cve_ids: &[&str],
    kev_matched: Option<bool>,
    service_protocol: Option<&str>,
    service_port: Option<u16>,
) {
    push_plugin_finding_candidate_with_signals(
        findings,
        seen,
        document,
        plugin_id,
        detector_name,
        severity,
        redacted_value,
        evidence,
        product_name,
        product_version,
        cpe,
        cve_ids,
        kev_matched,
        service_protocol,
        service_port,
        Vec::new(),
    );
}

#[allow(clippy::too_many_arguments)]
fn push_plugin_finding_candidate_with_signals(
    findings: &mut Vec<FindingCandidate>,
    seen: &mut HashSet<String>,
    document: &FetchedDocument,
    plugin_id: &str,
    detector_name: &str,
    severity: Severity,
    redacted_value: &str,
    evidence: &str,
    product_name: Option<&str>,
    product_version: Option<&str>,
    cpe: Option<&str>,
    cve_ids: &[&str],
    kev_matched: Option<bool>,
    service_protocol: Option<&str>,
    service_port: Option<u16>,
    matched_signals: Vec<String>,
) {
    let redacted_value = redacted_value.trim();
    if redacted_value.is_empty() {
        return;
    }

    let fingerprint_source = format!(
        "{plugin_id}:{detector_name}:{}:{redacted_value}",
        document.path
    );
    let fingerprint = fingerprint(&fingerprint_source);
    let dedupe_key = format!("{}:{fingerprint}", document.path);
    if !seen.insert(dedupe_key) {
        return;
    }

    findings.push(FindingCandidate {
        detector: detector_name.to_string(),
        severity,
        path: document.path.clone(),
        redacted_value: redacted_value.to_string(),
        evidence: evidence.trim().to_string(),
        fingerprint,
        confidence: None,
        matched_signals,
        review_labels: Vec::new(),
        plugin_metadata: build_plugin_metadata(
            plugin_id,
            product_name,
            product_version,
            cpe,
            cve_ids,
            kev_matched,
            service_protocol,
            service_port,
        ),
    });
}

fn scan_phase_one_plugin_findings(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    scan_phase_one_passive_http_plugins(document, seen, findings);
    scan_phase_one_version_correlations(document, seen, findings);
}

fn scan_phase_one_passive_http_plugins(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    let lowered_path = document.path.to_ascii_lowercase();
    let lowered_body = document.body.to_ascii_lowercase();
    let trimmed_body = document.body.trim();

    if lowered_path.contains("server-status")
        && (lowered_body.contains("scoreboard:")
            || lowered_body.contains("server version:")
            || lowered_body.contains("server mpm:"))
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "ApacheStatusPlugin",
            "apache_server_status_public",
            Severity::Medium,
            "apache server-status page",
            "Apache server-status markers were observed in a public response.",
            Some("Apache HTTP Server"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if (lowered_path.contains("/check_mk") || lowered_path.contains("/checkmk"))
        && (lowered_body.contains("checkmk")
            || lowered_body.contains("check_mk")
            || lowered_body.contains("monitoring"))
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "CheckMkPlugin",
            "checkmk_monitoring_endpoint_public",
            Severity::Medium,
            "checkmk endpoint",
            "Checkmk monitoring markers were observed in a public response.",
            Some("Checkmk"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if looks_like_config_json_path(&lowered_path) && looks_like_json_object(trimmed_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "ConfigJsonHttp",
            "json_config_file_exposed",
            Severity::Medium,
            "json configuration file",
            "A JSON configuration-style document was fetched from a public path.",
            None,
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if lowered_path.ends_with(".ds_store") || lowered_path.contains("/.ds_store") {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "DotDsStoreOpenPlugin",
            "ds_store_listing_exposed",
            Severity::Medium,
            ".DS_Store file",
            "A .DS_Store artifact was fetched from a public path.",
            None,
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if (looks_like_dotenv_path(&lowered_path))
        && (document.body.contains('=')
            && (lowered_body.contains("app_")
                || lowered_body.contains("database_url=")
                || lowered_body.contains("secret_key=")
                || lowered_body.contains("api_key=")
                || lowered_body.contains("token=")
                || lowered_body.contains("password=")))
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "DotEnvConfigPlugin",
            "dotenv_file_exposed",
            Severity::High,
            "dotenv configuration",
            "A dotenv-style configuration file was observed on a public path.",
            None,
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if lowered_path.contains(".git/config")
        && (lowered_body.contains("[core]") || lowered_body.contains("[remote"))
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "GitConfigHttpPlugin",
            "git_config_history_exposed",
            Severity::High,
            "git configuration file",
            "A .git/config file was observed on a public path.",
            Some("Git"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if (lowered_path.contains("/graphql") || lowered_body.contains("__schema"))
        && (lowered_body.contains("__schema")
            || lowered_body.contains("\"querytype\"")
            || lowered_body.contains("\"mutationtype\"")
            || lowered_body.contains("introspectionquery"))
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "GraphQLIntrospectionPlugin",
            "graphql_introspection_enabled",
            Severity::Medium,
            "graphql introspection response",
            "GraphQL introspection markers were observed in a public response.",
            Some("GraphQL"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_chrome_devtools_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "ChromeDevToolsPlugin",
            "chrome_devtools_public",
            Severity::High,
            "chrome devtools protocol",
            "Chrome DevTools Protocol markers were observed in a public response.",
            Some("Chrome DevTools"),
            extract_first_json_string_field(&document.body, &["Browser"]).as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_jenkins_surface(&lowered_body, document) {
        let version = extract_header_value(document, "x-jenkins")
            .or_else(|| extract_header_value(document, "x-hudson"));
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "JenkinsOpenPlugin",
            "jenkins_public_instance",
            Severity::Medium,
            "jenkins instance",
            "Jenkins headers or page markers were observed on a public HTTP response.",
            Some("Jenkins"),
            version.as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_grafana_surface(&lowered_path, &lowered_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "GrafanaOpenPlugin",
            "grafana_public_instance",
            Severity::Medium,
            "grafana instance",
            "Grafana UI or API markers were observed in a public response.",
            Some("Grafana"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_goanywhere_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "GoAnywhereMFT",
            "goanywhere_admin_public",
            Severity::Medium,
            "goanywhere mft admin",
            "GoAnywhere MFT administration markers were observed in a public response.",
            Some("GoAnywhere MFT"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_vicibox_recordings_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "ViciboxPlugin",
            "vicibox_recordings_public",
            Severity::Medium,
            "vicibox recordings",
            "Vicidial/ViciBox recordings exposure markers were observed in a public response.",
            Some("Vicidial / ViciBox"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_deadbolt_ransom_note(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "DeadMon",
            "deadbolt_ransom_note",
            Severity::High,
            "deadbolt ransom note",
            "DeadBolt ransomware note markers were observed in a public response.",
            Some("DeadBolt"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_attu_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "AttuPlugin",
            "attu_public_instance",
            Severity::Medium,
            "attu ui",
            "Attu (Milvus GUI) markers were observed in a public response.",
            Some("Attu"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_cadvisor_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "CAdvisorPlugin",
            "cadvisor_public_instance",
            Severity::Medium,
            "cadvisor dashboard",
            "cAdvisor markers were observed in a public response.",
            Some("cAdvisor"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_chroma_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "ChromaPlugin",
            "chroma_public_instance",
            Severity::Medium,
            "chroma api",
            "Chroma markers were observed in a public response.",
            Some("Chroma"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_cockroachdb_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "CockroachDBPlugin",
            "cockroachdb_console_public",
            Severity::Medium,
            "cockroachdb console",
            "CockroachDB console markers were observed in a public response.",
            Some("CockroachDB"),
            extract_first_json_string_field(&document.body, &["build", "tag", "version"])
                .as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_druid_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "DruidPlugin",
            "druid_public_instance",
            Severity::Medium,
            "druid console",
            "Apache Druid console markers were observed in a public response.",
            Some("Apache Druid"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_dagster_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "DagsterPlugin",
            "dagster_ui_public",
            Severity::Medium,
            "dagster ui",
            "Dagster UI markers were observed in a public response.",
            Some("Dagster"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if (lowered_path.contains("/telescope") || lowered_body.contains("laravel telescope"))
        && lowered_body.contains("telescope")
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "LaravelTelescopeHttpPlugin",
            "laravel_telescope_enabled",
            Severity::Medium,
            "laravel telescope panel",
            "Laravel Telescope UI markers were observed in a public response.",
            Some("Laravel Telescope"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_flink_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "FlinkPlugin",
            "flink_dashboard_public",
            Severity::Medium,
            "flink dashboard",
            "Apache Flink dashboard markers were observed in a public response.",
            Some("Apache Flink"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_h2_console_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "H2ConsolePlugin",
            "h2_console_public",
            Severity::Medium,
            "h2 console",
            "H2 Console markers were observed in a public response.",
            Some("H2 Console"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_harbor_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "HarborPlugin",
            "harbor_public_instance",
            Severity::Medium,
            "harbor ui",
            "Harbor UI markers were observed in a public response.",
            Some("Harbor"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_hdfs_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "HdfsOpenPlugin",
            "hdfs_namenode_public",
            Severity::Medium,
            "hdfs namenode",
            "Hadoop HDFS NameNode markers were observed in a public response.",
            Some("Hadoop HDFS"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_localai_surface(&lowered_path, &lowered_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "LocalAIPlugin",
            "localai_public_instance",
            Severity::Medium,
            "localai api surface",
            "LocalAI markers were observed in a public response.",
            Some("LocalAI"),
            extract_first_json_string_field(&document.body, &["version"]).as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_marqo_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "MarqoPlugin",
            "marqo_public_instance",
            Severity::Medium,
            "marqo api",
            "Marqo markers were observed in a public response.",
            Some("Marqo"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_mlflow_surface(&lowered_path, &lowered_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "MLflowPlugin",
            "mlflow_tracking_server_public",
            Severity::Medium,
            "mlflow tracking ui",
            "MLflow UI or tracking API markers were observed in a public response.",
            Some("MLflow"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_meilisearch_surface(&lowered_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "MeilisearchPlugin",
            "meilisearch_public_instance",
            Severity::Medium,
            "meilisearch api",
            "Meilisearch markers were observed in a public response.",
            Some("Meilisearch"),
            extract_first_json_string_field(&document.body, &["pkgVersion", "version"]).as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_milvus_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "MilvusPlugin",
            "milvus_public_instance",
            Severity::Medium,
            "milvus api",
            "Milvus markers were observed in a public response.",
            Some("Milvus"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_mongo_express_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "MongoExpressPlugin",
            "mongo_express_public",
            Severity::Medium,
            "mongo express ui",
            "Mongo Express markers were observed in a public response.",
            Some("Mongo Express"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_neo4j_surface(&lowered_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "Neo4jOpenPlugin",
            "neo4j_http_public",
            Severity::Medium,
            "neo4j http api",
            "Neo4j Browser or HTTP API markers were observed in a public response.",
            Some("Neo4j"),
            extract_first_json_string_field(&document.body, &["neo4j_version", "version"])
                .as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if (lowered_path.contains("/api/tags") || lowered_body.contains("\"ollama_version\""))
        && lowered_body.contains("\"models\"")
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "OllamaPlugin",
            "ollama_server_exposed",
            Severity::Medium,
            "ollama model catalog",
            "Ollama API model-list markers were observed without authentication.",
            Some("Ollama"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_postgrest_surface(&lowered_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "PostgRESTPlugin",
            "postgrest_public_instance",
            Severity::Medium,
            "postgrest api",
            "PostgREST markers were observed in a public response.",
            Some("PostgREST"),
            extract_first_json_string_field(&document.body, &["version"]).as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_prefect_surface(&lowered_path, &lowered_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "PrefectPlugin",
            "prefect_server_public",
            Severity::Medium,
            "prefect ui",
            "Prefect UI or API markers were observed in a public response.",
            Some("Prefect"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_rails_debug_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "RailsPlugin",
            "rails_debug_public",
            Severity::Medium,
            "rails debug page",
            "Ruby on Rails debug page markers were observed in a public response.",
            Some("Ruby on Rails"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_redis_commander_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "RedisCommanderPlugin",
            "redis_commander_public",
            Severity::Medium,
            "redis commander ui",
            "Redis Commander markers were observed in a public response.",
            Some("Redis Commander"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_solr_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "SolrOpenPlugin",
            "solr_admin_public",
            Severity::Medium,
            "solr admin console",
            "Apache Solr administration markers were observed in a public response.",
            Some("Apache Solr"),
            extract_first_json_string_field(
                &document.body,
                &["solr-spec-version", "lucene-spec-version"],
            )
            .as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_selenium_grid_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "SeleniumGridPlugin",
            "selenium_grid_public",
            Severity::Medium,
            "selenium grid",
            "Selenium Grid console markers were observed in a public response.",
            Some("Selenium Grid"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_splash_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "SplashPlugin",
            "splash_public_instance",
            Severity::Medium,
            "splash rendering service",
            "Splash rendering service markers were observed in a public response.",
            Some("Splash"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_qdrant_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "QdrantPlugin",
            "qdrant_public_instance",
            Severity::Medium,
            "qdrant api",
            "Qdrant markers were observed in a public response.",
            Some("Qdrant"),
            extract_first_json_string_field(&document.body, &["version"]).as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_jupyter_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "JupyterPlugin",
            "jupyter_public_instance",
            Severity::Medium,
            "jupyter notebook or lab",
            "Jupyter Notebook or Lab markers were observed in a public response.",
            Some("Jupyter"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_questdb_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "QuestDBPlugin",
            "questdb_public_instance",
            Severity::Medium,
            "questdb console",
            "QuestDB markers were observed in a public response.",
            Some("QuestDB"),
            extract_first_json_string_field(&document.body, &["version"]).as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_yarn_resourcemanager_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "YarnOpenPlugin",
            "yarn_resourcemanager_public",
            Severity::Medium,
            "yarn resourcemanager",
            "Hadoop YARN ResourceManager markers were observed in a public response.",
            Some("Hadoop YARN"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if lowered_path.contains("phpinfo")
        || lowered_body.contains("<title>phpinfo()</title>")
        || lowered_body.contains("php version ")
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "PhpInfoHttpPlugin",
            "phpinfo_file_exposed",
            Severity::Medium,
            "phpinfo page",
            "PHP info page markers were observed in a public response.",
            Some("PHP"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_ray_dashboard_surface(&lowered_path, &lowered_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "RayDashboardPlugin",
            "ray_dashboard_public",
            Severity::Medium,
            "ray dashboard",
            "Ray Dashboard markers were observed in a public response.",
            Some("Ray Dashboard"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_weaviate_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "WeaviatePlugin",
            "weaviate_public_instance",
            Severity::Medium,
            "weaviate api",
            "Weaviate markers were observed in a public response.",
            Some("Weaviate"),
            extract_first_json_string_field(&document.body, &["version"]).as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_vespa_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "VespaPlugin",
            "vespa_public_instance",
            Severity::Medium,
            "vespa application status",
            "Vespa application status markers were observed in a public response.",
            Some("Vespa"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if lowered_path.ends_with("/metrics")
        && lowered_body.contains("# help")
        && lowered_body.contains("# type")
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "PrometheusPlugin",
            "prometheus_metrics_public",
            Severity::Medium,
            "prometheus metrics endpoint",
            "Prometheus metrics markers were observed in a public response.",
            Some("Prometheus"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_couchdb_surface(&lowered_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "CouchDbOpenPlugin",
            "couchdb_public_instance",
            Severity::Medium,
            "couchdb welcome response",
            "CouchDB welcome or Fauxton markers were observed in a public response.",
            Some("CouchDB"),
            extract_json_string_field(&document.body, "version").as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_elasticsearch_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "ElasticSearchOpenPlugin",
            "elasticsearch_public_instance",
            Severity::Medium,
            "elasticsearch api root",
            "ElasticSearch root API markers were observed in a public response.",
            Some("ElasticSearch"),
            extract_first_json_string_field(&document.body, &["number"]).as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_consul_surface(&lowered_path, &lowered_body, trimmed_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "Consul",
            "consul_public_server",
            Severity::Medium,
            "consul ui/api surface",
            "Consul UI or API markers were observed in a public response.",
            Some("Consul"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_docker_registry_surface(&lowered_path, trimmed_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "DockerRegistryHttpPlugin",
            "docker_registry_public",
            Severity::Medium,
            "docker registry api",
            "Docker Registry v2 API markers were observed in a public response.",
            Some("Docker Registry"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_nsq_admin_surface(&lowered_path, &lowered_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "NsqAdminPlugin",
            "nsq_admin_public",
            Severity::Medium,
            "nsqadmin panel",
            "NSQ Admin markers were observed in a public response.",
            Some("NSQ Admin"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if advertises_ntlm_auth(document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "HttpNTLM",
            "http_ntlm_advertised",
            Severity::Medium,
            "ntlm challenge",
            "HTTP response headers advertised NTLM authentication.",
            Some("NTLM"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_nginx_ui_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "NginxUIPlugin",
            "nginx_ui_public",
            Severity::Medium,
            "nginx ui",
            "Nginx UI markers were observed in a public response.",
            Some("Nginx UI"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_nats_monitoring_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "NATSPlugin",
            "nats_monitoring_public",
            Severity::Medium,
            "nats monitoring api",
            "NATS monitoring markers were observed in a public response.",
            Some("NATS"),
            extract_first_json_string_field(&document.body, &["version"]).as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_nomad_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "NomadPlugin",
            "nomad_public_instance",
            Severity::Medium,
            "nomad ui",
            "HashiCorp Nomad UI markers were observed in a public response.",
            Some("Nomad"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_novnc_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "NoVncPlugin",
            "novnc_public_instance",
            Severity::Medium,
            "novnc client",
            "noVNC markers were observed in a public response.",
            Some("noVNC"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if lowered_body.contains("import.meta.env")
        || lowered_body.contains("window.env")
        || lowered_body.contains("window.__env")
        || lowered_body.contains("process.env")
        || lowered_body.contains("next_public_")
        || lowered_body.contains("vite_")
        || lowered_body.contains("react_app_")
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "PublicEnvPlugin",
            "public_environment_variables_exposed",
            Severity::Medium,
            "public environment variable bundle",
            "Client-side environment variable markers were observed in a public response.",
            None,
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_sonarqube_surface(&lowered_path, &lowered_body, document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "SonarQubePlugin",
            "sonarqube_public_instance",
            Severity::Medium,
            "sonarqube instance",
            "SonarQube UI or API markers were observed in a public response.",
            Some("SonarQube"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_spring_boot_actuator_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "SpringBootActuatorPlugin",
            "spring_boot_actuator_public",
            Severity::Medium,
            "spring boot actuator",
            "Sensitive Spring Boot actuator markers were observed in a public response.",
            Some("Spring Boot"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_tidb_status_surface(&lowered_path, &lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "TiDBPlugin",
            "tidb_status_public",
            Severity::Medium,
            "tidb status server",
            "TiDB status server markers were observed in a public response.",
            Some("TiDB"),
            extract_first_json_string_field(&document.body, &["version"]).as_deref(),
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if lowered_path.contains("security.txt") {
        if let Some(expires_at) = extract_security_txt_expiry(&document.body) {
            if expires_at < Utc::now() {
                push_plugin_finding_candidate(
                    findings,
                    seen,
                    document,
                    "SecurityTxtPlugin",
                    "expired_security_txt",
                    Severity::Low,
                    "expired security.txt",
                    "security.txt Expires value is in the past.",
                    Some("security.txt"),
                    Some(&expires_at.to_rfc3339()),
                    None,
                    &[],
                    None,
                    Some("http"),
                    infer_service_port(document),
                );
            }
        }
    }

    if let Some(swagger_match) = match_swagger_ui_signal(document) {
        let evidence = build_plugin_evidence(
            document,
            swagger_match.start,
            swagger_match.end,
            &swagger_match.matched,
        );
        push_plugin_finding_candidate_with_signals(
            findings,
            seen,
            document,
            "SwaggerUIPlugin",
            "swagger_api_description_public",
            Severity::Medium,
            "swagger/openapi description",
            &evidence,
            Some("OpenAPI"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
            vec![swagger_match.matched],
        );
    }

    if lowered_path.contains("_profiler")
        || extract_header_value(document, "x-debug-token").is_some()
        || extract_header_value(document, "x-debug-token-link").is_some()
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "SymfonyProfilerPlugin",
            "symfony_profiler_enabled",
            Severity::Medium,
            "symfony profiler panel",
            "Symfony profiler markers were observed in a public response.",
            Some("Symfony"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if lowered_body.contains("symfony exception")
        || (lowered_body.contains("whoops, looks like something went wrong")
            && lowered_body.contains("symfony"))
        || lowered_body.contains("symfony\\\\component\\\\")
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "SymfonyVerbosePlugin",
            "symfony_verbose_error_leak",
            Severity::Medium,
            "symfony verbose error page",
            "Symfony verbose exception markers were observed in a public response.",
            Some("Symfony"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if lowered_path.contains("trace.axd")
        || (lowered_body.contains("trace.axd") && lowered_body.contains("application trace"))
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "TraceAxdPlugin",
            "aspnet_trace_axd_exposed",
            Severity::Medium,
            "trace.axd endpoint",
            "ASP.NET trace.axd markers were observed in a public response.",
            Some("ASP.NET"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_vite_fs_raw_env_exposure(&lowered_path, &document.body) {
        let (redacted_value, evidence) = if lowered_path.contains("/proc/self/environ")
            || lowered_path.contains("/proc/1/environ")
        {
            (
                "vite @fs raw process environment",
                "A Vite /@fs/ raw file read exposed a process environment dump.",
            )
        } else {
            (
                "vite @fs raw dotenv file",
                "A Vite /@fs/ raw file read exposed a local dotenv-style file.",
            )
        };
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "ViteJSPlugin",
            "vite_fs_raw_file_read_exposed",
            Severity::High,
            redacted_value,
            evidence,
            Some("Vite"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_vscode_sftp_surface(&lowered_path, trimmed_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "VsCodeSFTPPlugin",
            "vscode_sftp_config_exposed",
            Severity::Medium,
            "vscode sftp configuration",
            "VSCode SFTP configuration markers were observed in a public response.",
            Some("VSCode SFTP"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if lowered_body.contains("/@vite/client")
        || lowered_body.contains("__vite_ping")
        || lowered_body.contains("import.meta.hot")
        || lowered_body.contains("vite/client")
    {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "ViteJSPlugin",
            "vite_development_environment_exposed",
            Severity::Medium,
            "vite development client",
            "Vite development environment markers were observed in a public response.",
            Some("Vite"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_webdav_surface(document) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "WebDAVPlugin",
            "webdav_public_instance",
            Severity::Medium,
            "webdav capability",
            "WebDAV capability headers were observed in a public response.",
            Some("WebDAV"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_django_debug_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "DjangoPlugin",
            "django_debug_public",
            Severity::Medium,
            "django debug page",
            "Django debug page markers were observed in a public response.",
            Some("Django"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_flask_debug_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "FlaskPlugin",
            "flask_debug_public",
            Severity::Medium,
            "flask debugger",
            "Flask/Werkzeug debugger markers were observed in a public response.",
            Some("Flask"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }

    if is_yii_debug_surface(&lowered_body) {
        push_plugin_finding_candidate(
            findings,
            seen,
            document,
            "YiiDebugPlugin",
            "yii_debug_public",
            Severity::Medium,
            "yii debug toolbar",
            "Yii debug toolbar markers were observed in a public response.",
            Some("Yii"),
            None,
            None,
            &[],
            None,
            Some("http"),
            infer_service_port(document),
        );
    }
}

fn scan_phase_one_version_correlations(
    document: &FetchedDocument,
    seen: &mut HashSet<String>,
    findings: &mut Vec<FindingCandidate>,
) {
    if let Some(version) = extract_screenconnect_version(document) {
        if is_screenconnect_vulnerable_version(&version) {
            push_plugin_finding_candidate(
                findings,
                seen,
                document,
                "ConnectWiseScreenConnect",
                "screenconnect_vulnerable_version",
                Severity::High,
                "screenconnect vulnerable version",
                "ConnectWise ScreenConnect vulnerable-version markers were observed in a public response.",
                Some("ConnectWise ScreenConnect"),
                Some(&version),
                None,
                &[],
                None,
                Some("http"),
                infer_service_port(document),
            );
        }
    }

    if let Some(version) = extract_goanywhere_version(document) {
        if compare_numeric_versions(&version, "7.4.1").is_lt() {
            push_plugin_finding_candidate(
                findings,
                seen,
                document,
                "GoAnywhereMFT202501",
                "goanywhere_vulnerable_version",
                Severity::High,
                "goanywhere vulnerable version",
                "GoAnywhere MFT vulnerable-version markers were observed in a public response.",
                Some("GoAnywhere MFT"),
                Some(&version),
                None,
                &[],
                None,
                Some("http"),
                infer_service_port(document),
            );
        }
    }

    if let Some(version) = extract_solr_version(document) {
        if compare_numeric_versions(&version, "9.8.0").is_lt() {
            push_plugin_finding_candidate(
                findings,
                seen,
                document,
                "SolrVersionPlugin",
                "solr_vulnerable_version",
                Severity::High,
                "solr vulnerable version",
                "Apache Solr version markers were observed below the current patched threshold for published 2024-2025 security fixes.",
                Some("Apache Solr"),
                Some(&version),
                None,
                &[],
                None,
                Some("http"),
                infer_service_port(document),
            );
        }
    }

    if let Some(version) = extract_header_value(document, "x-jenkins")
        .or_else(|| extract_header_value(document, "x-hudson"))
    {
        if compare_numeric_versions(&version, "2.426.3").is_lt() {
            push_plugin_finding_candidate(
                findings,
                seen,
                document,
                "JenkinsVersionPlugin",
                "jenkins_version_outdated",
                Severity::High,
                "jenkins version disclosure",
                "Jenkins version disclosure matched the initial phase-1 static outdated-version floor.",
                Some("Jenkins"),
                Some(&version),
                None,
                &[],
                None,
                Some("http"),
                infer_service_port(document),
            );
        }
    }
}

fn looks_like_config_json_path(lowered_path: &str) -> bool {
    lowered_path.ends_with("/config.json")
        || lowered_path.ends_with("/runtime-config.json")
        || lowered_path.ends_with("/settings.json")
        || lowered_path.ends_with("/manifest.json")
}

fn looks_like_json_object(trimmed_body: &str) -> bool {
    trimmed_body.starts_with('{') && trimmed_body.ends_with('}') && trimmed_body.contains(':')
}

fn is_chrome_devtools_surface(lowered_path: &str, lowered_body: &str) -> bool {
    (lowered_path.contains("/json/version") || lowered_path.contains("/json/list"))
        && lowered_body.contains("websocketdebuggerurl")
        && (lowered_body.contains("\"browser\"") || lowered_body.contains("\"protocol-version\""))
}

fn is_attu_surface(lowered_body: &str) -> bool {
    lowered_body.contains("<title>attu")
        || lowered_body.contains("milvus gui")
        || (lowered_body.contains("attu") && lowered_body.contains("milvus"))
}

fn is_cadvisor_surface(lowered_body: &str) -> bool {
    lowered_body.contains("<title>cadvisor")
        || lowered_body.contains("cadvisor -")
        || lowered_body.contains("container advisor")
}

fn is_chroma_surface(lowered_path: &str, lowered_body: &str) -> bool {
    (lowered_path.contains("/api/v1/heartbeat") || lowered_path.contains("/api/v2/heartbeat"))
        && (lowered_body.contains("chroma") || lowered_body.contains("heartbeat"))
}

fn is_cockroachdb_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_body.contains("cockroach")
        && (lowered_body.contains("db console")
            || lowered_body.contains("cockroachlabs")
            || lowered_body.contains("cockroach labs")
            || lowered_path.contains("/_admin"))
}

fn is_dagster_surface(lowered_body: &str) -> bool {
    lowered_body.contains("dagster ui") || lowered_body.contains("dagit")
}

fn is_deadbolt_ransom_note(lowered_body: &str) -> bool {
    lowered_body.contains("deadbolt")
        && (lowered_body.contains("bitcoin")
            || lowered_body.contains("files have been encrypted")
            || lowered_body.contains("unlock"))
}

fn is_django_debug_surface(lowered_body: &str) -> bool {
    lowered_body.contains("you’re seeing this error because you have <code>debug = true</code>")
        || lowered_body
            .contains("you're seeing this error because you have <code>debug = true</code>")
        || (lowered_body.contains("django version")
            && lowered_body.contains("exception type:")
            && lowered_body.contains("request method:"))
}

fn is_druid_surface(lowered_body: &str) -> bool {
    lowered_body.contains("apache druid console")
        || lowered_body.contains("druid console")
        || lowered_body.contains("druid coordinator")
}

fn is_elasticsearch_surface(lowered_body: &str) -> bool {
    lowered_body.contains("\"tagline\":\"you know, for search\"")
        || (lowered_body.contains("\"cluster_name\"")
            && lowered_body.contains("\"version\"")
            && lowered_body.contains("\"lucene_version\""))
}

fn is_grafana_surface(lowered_path: &str, lowered_body: &str, document: &FetchedDocument) -> bool {
    lowered_body.contains("window.grafanabootdata")
        || lowered_body.contains("<title>grafana")
        || lowered_body.contains("grafana-app")
        || (lowered_path.contains("/api/health")
            && lowered_body.contains("\"database\"")
            && lowered_body.contains("\"version\""))
        || extract_header_value(document, "x-grafana-org-id").is_some()
}

fn is_flink_surface(lowered_body: &str) -> bool {
    lowered_body.contains("apache flink dashboard")
        || lowered_body.contains("flink web dashboard")
        || lowered_body.contains("flink-dashboard")
}

fn is_flask_debug_surface(lowered_body: &str) -> bool {
    lowered_body.contains("werkzeug debugger")
        || lowered_body.contains("the debugger caught an exception in your wsgi application")
}

fn is_h2_console_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("h2-console") || lowered_body.contains("<title>h2 console")
}

fn is_harbor_surface(lowered_body: &str) -> bool {
    lowered_body.contains("<title>harbor")
        || lowered_body.contains("harbor-ui")
        || lowered_body.contains("project harbor")
}

fn is_hdfs_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("dfshealth")
        || (lowered_body.contains("namenode")
            && (lowered_body.contains("hadoop") || lowered_body.contains("dfs health")))
}

fn is_goanywhere_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("goanywhere")
        || (lowered_body.contains("goanywhere") && lowered_body.contains("mft"))
}

fn is_vicibox_recordings_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("/recordings/")
        && (lowered_body.contains("vicidial")
            || lowered_body.contains("vicibox")
            || lowered_body.contains(".wav")
            || lowered_body.contains(".mp3"))
}

fn is_jenkins_surface(lowered_body: &str, document: &FetchedDocument) -> bool {
    extract_header_value(document, "x-jenkins").is_some()
        || extract_header_value(document, "x-hudson").is_some()
        || lowered_body.contains("dashboard [jenkins]")
        || lowered_body.contains("jenkins.instanceidentity")
        || lowered_body.contains("welcome to jenkins")
}

fn is_jupyter_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("/tree")
        || lowered_path.contains("/lab")
        || lowered_body.contains("jupyter notebook")
        || lowered_body.contains("jupyterlab")
        || lowered_body.contains("jupyter server")
}

fn is_localai_surface(lowered_path: &str, lowered_body: &str, document: &FetchedDocument) -> bool {
    lowered_body.contains("localai")
        || extract_header_value(document, "server")
            .is_some_and(|value| value.to_ascii_lowercase().contains("localai"))
        || (lowered_path.contains("/v1/models") && lowered_body.contains("\"data\""))
        || (lowered_path.contains("/readyz") && lowered_body.contains("localai"))
}

fn is_marqo_surface(lowered_path: &str, lowered_body: &str) -> bool {
    (lowered_path.contains("/indexes") || lowered_path.contains("/api"))
        && lowered_body.contains("marqo")
}

fn is_mlflow_surface(lowered_path: &str, lowered_body: &str, document: &FetchedDocument) -> bool {
    lowered_body.contains("<title>mlflow")
        || lowered_body.contains("mlflow ui")
        || lowered_body.contains("mlflow tracking")
        || lowered_body.contains("__mlflow")
        || lowered_path.contains("/ajax-api/2.0/mlflow")
        || extract_header_value(document, "x-mlflow-server-version").is_some()
}

fn is_meilisearch_surface(lowered_body: &str, document: &FetchedDocument) -> bool {
    lowered_body.contains("meilisearch")
        || extract_header_value(document, "x-meilisearch-instance-uid").is_some()
        || extract_header_value(document, "server")
            .is_some_and(|value| value.to_ascii_lowercase().contains("meilisearch"))
}

fn is_milvus_surface(lowered_path: &str, lowered_body: &str) -> bool {
    (lowered_path.contains("/api/v1") || lowered_path.contains("/api/v2"))
        && lowered_body.contains("milvus")
}

fn is_mongo_express_surface(lowered_body: &str) -> bool {
    lowered_body.contains("mongo express") || lowered_body.contains("<title>mongo-express")
}

fn is_nats_monitoring_surface(lowered_path: &str, lowered_body: &str) -> bool {
    (lowered_path.contains("/varz")
        || lowered_path.contains("/connz")
        || lowered_path.contains("/routez"))
        && lowered_body.contains("server_id")
        && lowered_body.contains("max_connections")
}

fn is_neo4j_surface(lowered_body: &str, document: &FetchedDocument) -> bool {
    lowered_body.contains("neo4j browser")
        || lowered_body.contains("neo4j_version")
        || lowered_body.contains("bolt_routing")
        || extract_header_value(document, "server")
            .is_some_and(|value| value.to_ascii_lowercase().contains("neo4j"))
}

fn is_nomad_surface(lowered_body: &str) -> bool {
    lowered_body.contains("<title>nomad")
        || lowered_body.contains("nomad ui")
        || lowered_body.contains("hashicorp nomad")
}

fn is_novnc_surface(lowered_body: &str) -> bool {
    lowered_body.contains("novnc")
        && (lowered_body.contains("connect") || lowered_body.contains("remote desktop"))
}

fn is_nginx_ui_surface(lowered_body: &str) -> bool {
    lowered_body.contains("<title>nginx ui")
        || lowered_body.contains("nginx-ui")
        || lowered_body.contains("nginx ui")
}

fn is_postgrest_surface(lowered_body: &str, document: &FetchedDocument) -> bool {
    lowered_body.contains("postgrest")
        || extract_header_value(document, "server")
            .is_some_and(|value| value.to_ascii_lowercase().contains("postgrest"))
}

fn is_prefect_surface(lowered_path: &str, lowered_body: &str, _document: &FetchedDocument) -> bool {
    lowered_body.contains("prefect ui")
        || lowered_body.contains("__prefect2_ui_api_url")
        || lowered_body.contains("prefect server")
        || lowered_body.contains("\"prefect\"")
        || lowered_path.contains("/api/health")
            && lowered_body.contains("\"status\"")
            && lowered_body.contains("prefect")
}

fn is_rails_debug_surface(lowered_body: &str) -> bool {
    lowered_body.contains("application trace")
        && lowered_body.contains("framework trace")
        && lowered_body.contains("full trace")
        && (lowered_body.contains("web console") || lowered_body.contains("action dispatch"))
}

fn is_qdrant_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_body.contains("qdrant")
        && (lowered_path.contains("/collections")
            || lowered_path.contains("/dashboard")
            || lowered_path.contains("/api"))
}

fn is_questdb_surface(lowered_body: &str) -> bool {
    lowered_body.contains("questdb")
        || (lowered_body.contains("web console") && lowered_body.contains("quest"))
}

fn is_ray_dashboard_surface(
    lowered_path: &str,
    lowered_body: &str,
    _document: &FetchedDocument,
) -> bool {
    lowered_body.contains("ray dashboard")
        || lowered_body.contains("ray cluster")
        || lowered_body.contains("\"ray_version\"")
        || lowered_path.contains("/api/version")
            && lowered_body.contains("\"version\"")
            && lowered_body.contains("ray")
}

fn is_redis_commander_surface(lowered_body: &str) -> bool {
    lowered_body.contains("redis commander") || lowered_body.contains("<title>redis-commander")
}

fn is_solr_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("/solr")
        && (lowered_body.contains("solr admin")
            || lowered_body.contains("apache solr")
            || lowered_body.contains("lucene-spec-version")
            || lowered_body.contains("solr-spec-version"))
}

fn is_selenium_grid_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("/grid/console")
        || lowered_body.contains("selenium grid")
        || lowered_body.contains("grid console")
}

fn is_splash_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("/render.html")
        && (lowered_body.contains("splash")
            || lowered_body.contains("lua scripting")
            || lowered_body.contains("javascript rendering service"))
}

fn is_spring_boot_actuator_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("/actuator/")
        && (lowered_body.contains("propertysources")
            || lowered_body.contains("activeprofiles")
            || lowered_body.contains("beans")
            || lowered_body.contains("contexts")
            || lowered_body.contains("\"status\""))
}

fn is_tidb_status_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("/status")
        && lowered_body.contains("tidb")
        && lowered_body.contains("status")
}

fn is_weaviate_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_body.contains("weaviate")
        && (lowered_path.contains("/v1/meta")
            || lowered_path.contains("/v1/")
            || lowered_path.contains("/meta"))
}

fn is_vespa_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("/applicationstatus")
        && (lowered_body.contains("vespa") || lowered_body.contains("application status"))
}

fn is_vscode_sftp_surface(lowered_path: &str, trimmed_body: &str) -> bool {
    lowered_path.ends_with("/.vscode/sftp.json")
        && trimmed_body.starts_with('{')
        && trimmed_body.contains("\"host\"")
        && trimmed_body.contains("\"username\"")
}

fn is_webdav_surface(document: &FetchedDocument) -> bool {
    header_contains_token(document, "dav", "1")
        || header_contains_token(document, "allow", "PROPFIND")
        || header_contains_token(document, "allow", "MKCOL")
}

fn is_yarn_resourcemanager_surface(lowered_path: &str, lowered_body: &str) -> bool {
    lowered_path.contains("/cluster")
        || ((lowered_body.contains("yarn resourcemanager")
            || lowered_body.contains("resourcemanager"))
            && lowered_body.contains("hadoop"))
}

fn is_yii_debug_surface(lowered_body: &str) -> bool {
    lowered_body.contains("yii debug toolbar")
        || lowered_body.contains("yii debug")
        || lowered_body.contains("yii\\debug")
}

fn is_couchdb_surface(lowered_body: &str, document: &FetchedDocument) -> bool {
    lowered_body.contains("\"couchdb\":\"welcome\"")
        || lowered_body.contains("fauxton")
        || extract_header_value(document, "server")
            .is_some_and(|value| value.to_ascii_lowercase().contains("couchdb"))
}

fn is_consul_surface(
    lowered_path: &str,
    lowered_body: &str,
    trimmed_body: &str,
    _document: &FetchedDocument,
) -> bool {
    lowered_body.contains("consul ui")
        || lowered_body.contains("consul-ui")
        || lowered_body.contains("\"consul_version\"")
        || (lowered_path.contains("/v1/status/leader")
            && trimmed_body.starts_with('"')
            && trimmed_body.ends_with('"')
            && trimmed_body.contains(':'))
        || (lowered_path.contains("/ui/") && lowered_body.contains("consul"))
}

fn is_docker_registry_surface(
    lowered_path: &str,
    trimmed_body: &str,
    document: &FetchedDocument,
) -> bool {
    extract_header_value(document, "docker-distribution-api-version")
        .is_some_and(|value| value.to_ascii_lowercase().contains("registry/2.0"))
        && document.status == 200
        || (lowered_path.contains("/v2/")
            && document.status == 200
            && (trimmed_body == "{}"
                || trimmed_body.contains("\"repositories\"")
                || trimmed_body.contains("\"errors\"") == false))
}

fn is_nsq_admin_surface(
    lowered_path: &str,
    lowered_body: &str,
    _document: &FetchedDocument,
) -> bool {
    lowered_body.contains("<title>nsq admin")
        || lowered_body.contains("nsqadmin")
        || lowered_path.contains("/nsqadmin")
}

fn is_sonarqube_surface(
    lowered_path: &str,
    lowered_body: &str,
    document: &FetchedDocument,
) -> bool {
    lowered_body.contains("sonarqube")
        || lowered_body.contains("sonarcloud")
        || lowered_path.contains("/api/system/status")
            && lowered_body.contains("\"status\"")
            && lowered_body.contains("up")
        || extract_header_value(document, "server")
            .is_some_and(|value| value.to_ascii_lowercase().contains("sonarqube"))
}

fn extract_json_string_field(body: &str, field_name: &str) -> Option<String> {
    let value = serde_json::from_str::<JsonValue>(body).ok()?;
    value.get(field_name)?.as_str().map(str::to_string)
}

fn extract_first_json_string_field(body: &str, field_names: &[&str]) -> Option<String> {
    for field_name in field_names {
        if let Some(value) = extract_json_string_field(body, field_name) {
            return Some(value);
        }
    }
    None
}

fn extract_header_value(document: &FetchedDocument, name: &str) -> Option<String> {
    document
        .headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn extract_header_value_by_name_fragment(
    document: &FetchedDocument,
    fragment: &str,
) -> Option<String> {
    let lowered_fragment = fragment.to_ascii_lowercase();
    document
        .headers
        .iter()
        .find(|(header_name, _)| header_name.to_ascii_lowercase().contains(&lowered_fragment))
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn extract_version_token(value: &str) -> Option<String> {
    let regex = Regex::new(r"\d+\.\d+\.\d+(?:\.\d+)?").ok()?;
    regex
        .find(value)
        .map(|matched| matched.as_str().to_string())
}

fn extract_screenconnect_version(document: &FetchedDocument) -> Option<String> {
    if let Some(value) = extract_header_value_by_name_fragment(document, "screenconnect") {
        if let Some(version) = extract_version_token(&value) {
            return Some(version);
        }
    }
    SCREENCONNECT_VERSION_RE
        .captures(&document.body)
        .and_then(|captures| captures.name("version"))
        .map(|matched| matched.as_str().to_string())
}

fn is_screenconnect_vulnerable_version(version: &str) -> bool {
    let parts = numeric_version_parts(version);
    let Some(major) = parts.first().copied() else {
        return false;
    };
    let minor = parts.get(1).copied().unwrap_or_default();

    if major < 22 {
        return true;
    }

    if major == 22 {
        return compare_numeric_versions(version, "22.4.20001").is_lt();
    }

    if major == 23 {
        if minor < 9 {
            return true;
        }
        if minor == 9 {
            return compare_numeric_versions(version, "23.9.8").is_lt();
        }
        return false;
    }

    false
}

fn extract_goanywhere_version(document: &FetchedDocument) -> Option<String> {
    GOANYWHERE_VERSION_RE
        .captures(&document.body)
        .and_then(|captures| captures.name("version"))
        .map(|matched| matched.as_str().to_string())
}

fn extract_solr_version(document: &FetchedDocument) -> Option<String> {
    SOLR_SPEC_VERSION_RE
        .captures(&document.body)
        .and_then(|captures| captures.name("version"))
        .map(|matched| matched.as_str().to_string())
        .or_else(|| {
            extract_first_json_string_field(&document.body, &["solr-spec-version", "version"])
        })
}

fn header_contains_token(document: &FetchedDocument, name: &str, token: &str) -> bool {
    extract_header_value(document, name).is_some_and(|value| {
        value
            .to_ascii_lowercase()
            .contains(&token.to_ascii_lowercase())
    })
}

fn advertises_ntlm_auth(document: &FetchedDocument) -> bool {
    header_contains_token(document, "www-authenticate", "NTLM")
}

fn extract_security_txt_expiry(body: &str) -> Option<DateTime<Utc>> {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.len() < "expires:".len() || !trimmed[..8].eq_ignore_ascii_case("expires:") {
            continue;
        }
        let value = trimmed[8..].trim();
        if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
            return Some(parsed.with_timezone(&Utc));
        }
    }
    None
}

fn infer_service_port(document: &FetchedDocument) -> Option<u16> {
    Url::parse(&document.url)
        .ok()
        .and_then(|url| url.port_or_known_default())
}

fn compare_numeric_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let mut left_parts = numeric_version_parts(left);
    let mut right_parts = numeric_version_parts(right);
    let target_len = left_parts.len().max(right_parts.len()).max(3);
    left_parts.resize(target_len, 0);
    right_parts.resize(target_len, 0);
    left_parts.cmp(&right_parts)
}

fn numeric_version_parts(value: &str) -> Vec<u64> {
    value
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .find(|segment| segment.chars().any(|ch| ch.is_ascii_digit()))
        .unwrap_or_default()
        .split('.')
        .filter_map(|segment| segment.parse::<u64>().ok())
        .collect()
}

fn candidate_detectors(document: &FetchedDocument) -> Vec<&'static DetectorDefinition> {
    DETECTORS
        .iter()
        .filter(|detector| detector.prefilter.matches(document))
        .collect()
}

fn contextual_assignment_rule(key: &str) -> Option<&'static ContextualAssignmentRule> {
    if key_is_identifier_field(key) {
        return None;
    }
    CONTEXTUAL_ASSIGNMENT_RULES.iter().find(|rule| {
        rule.keywords
            .iter()
            .any(|keyword| key_matches_keyword(key, keyword))
    })
}

fn key_matches_keyword(key: &str, keyword: &str) -> bool {
    key == keyword
        || key.starts_with(&format!("{keyword}_"))
        || key.ends_with(&format!("_{keyword}"))
        || key.contains(&format!("_{keyword}_"))
}

// Field names ending in an identifier suffix (e.g. `private_key_id`, `client_uuid`)
// describe a public reference to a credential, not the credential itself, and so
// must not be matched by the generic secret/key/token assignment rules.
fn key_is_identifier_field(key: &str) -> bool {
    const IDENTIFIER_SUFFIXES: &[&str] = &["_id", "_uuid", "_arn", "_urn"];
    IDENTIFIER_SUFFIXES
        .iter()
        .any(|suffix| key.ends_with(suffix) && key.len() > suffix.len())
}

impl DetectorPrefilter {
    fn matches(&self, document: &FetchedDocument) -> bool {
        let lowered_path = document.path.to_ascii_lowercase();

        match self {
            Self::BodyContainsAny(literals) => literals
                .iter()
                .any(|literal| document.body.contains(literal)),
            Self::PathContainsAny(hints) => hints.iter().any(|hint| lowered_path.contains(hint)),
            Self::PathOrBodyContainsAny {
                path_hints,
                body_literals,
            } => {
                path_hints.iter().any(|hint| lowered_path.contains(hint))
                    || body_literals
                        .iter()
                        .any(|literal| document.body.contains(literal))
            }
        }
    }
}

fn normalize_contextual_key(value: &str) -> String {
    value
        .trim()
        .trim_matches(&['"', '\''][..])
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace('.', "_")
}

fn normalize_contextual_value(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(|ch| ch == ',' || ch == ';')
        .trim_matches(&['"', '\'', '`'][..])
        .trim()
        .to_string()
}

fn validate_contextual_value(
    document: &FetchedDocument,
    key: &str,
    value: &str,
    rule: &ContextualAssignmentRule,
    source: ContextualValueSource,
) -> bool {
    if value.len() < rule.min_value_len || looks_like_placeholder_secret(value) {
        return false;
    }

    match rule.value_kind {
        ContextValueKind::BroadSecret => {
            if matches!(key, "token" | "secret" | "key" | "auth")
                && !is_contextual_secret_path(&document.path)
                && matches!(
                    source,
                    ContextualValueSource::BodyAssignment | ContextualValueSource::StructuredField
                )
            {
                let candidate = strip_auth_scheme(value).unwrap_or(value);
                return looks_like_jwt(candidate);
            }
            looks_like_broad_secret(value)
        }
        ContextValueKind::Password => looks_like_secretish_password(value),
        ContextValueKind::ConnectionString => looks_like_connection_string(value),
    }
}

fn push_metadata_secret_finding_candidate(
    findings: &mut Vec<FindingCandidate>,
    seen: &mut HashSet<String>,
    document: &FetchedDocument,
    detector_name: &str,
    severity: &Severity,
    secret_value: &str,
    evidence: &str,
    confidence: Option<FindingConfidence>,
    matched_signals: Vec<String>,
    review_labels: Vec<String>,
) {
    let secret_value = secret_value.trim();
    if secret_value.is_empty() {
        return;
    }

    let fingerprint = fingerprint(secret_value);
    let dedupe_key = format!("{}:{detector_name}:{fingerprint}", document.path);
    if !seen.insert(dedupe_key) {
        return;
    }

    findings.push(FindingCandidate {
        detector: detector_name.to_string(),
        severity: severity.clone(),
        path: document.path.clone(),
        redacted_value: redact_secret(secret_value),
        evidence: evidence.trim().to_string(),
        fingerprint,
        confidence,
        matched_signals,
        review_labels,
        plugin_metadata: None,
    });
}

fn looks_like_placeholder_secret(value: &str) -> bool {
    let candidate = strip_auth_scheme(value).unwrap_or(value).trim();
    if candidate.is_empty() {
        return true;
    }

    let lowered = candidate.to_ascii_lowercase();
    let exact_placeholders = [
        "example",
        "placeholder",
        "changeme",
        "dummy",
        "sample",
        "test",
        "testing",
        "secret",
        "password",
        "token",
        "api_key",
        "apikey",
        "null",
        "undefined",
        "none",
        "redacted",
        "masked",
    ];
    if exact_placeholders.contains(&lowered.as_str()) {
        return true;
    }

    if lowered.starts_with("${")
        || lowered.starts_with("{{")
        || lowered.starts_with('<')
        || lowered.starts_with("your_")
        || lowered.starts_with("your-")
        || lowered.starts_with("replace_")
        || lowered.starts_with("replace-")
        || lowered.ends_with("_here")
        || lowered.ends_with("-here")
        || lowered.contains("changeme")
        || lowered.contains("placeholder")
        || lowered.contains("<redacted>")
    {
        return true;
    }

    unique_char_count(candidate) <= 2 && candidate.len() >= 8
}

fn looks_like_connection_string(value: &str) -> bool {
    if AZURE_STORAGE_CONNECTION_STRING.is_match(value) {
        let lowered = value.to_ascii_lowercase();
        return !(lowered.contains("<redacted>")
            || lowered.contains("changeme")
            || lowered.contains("placeholder")
            || lowered.contains("accountname=example"));
    }

    if !DATABASE_URL_WITH_CREDS.is_match(value) {
        let lowered = value.to_ascii_lowercase();
        return lowered.starts_with("jdbc:")
            && lowered.contains("user=")
            && lowered.contains("password=")
            && !lowered.contains("example");
    }

    let Ok(parsed) = Url::parse(value) else {
        return true;
    };

    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    if host == "example.com"
        || host == "example.org"
        || host == "example.net"
        || host == "example.test"
        || host.starts_with("example.")
    {
        return false;
    }

    !parsed.username().is_empty()
        && parsed
            .password()
            .map(|password| !looks_like_placeholder_secret(password))
            .unwrap_or(false)
}

fn looks_like_token_like_secret(value: &str) -> bool {
    let candidate = strip_auth_scheme(value).unwrap_or(value).trim();
    looks_like_jwt(candidate) || looks_like_high_entropy_secret(candidate)
}

fn looks_like_broad_secret(value: &str) -> bool {
    let candidate = strip_auth_scheme(value).unwrap_or(value).trim();
    if candidate.len() < 12
        || candidate.contains("://")
        || candidate.chars().any(|ch| ch.is_whitespace())
    {
        return false;
    }

    looks_like_token_like_secret(candidate)
        || looks_like_base64_secret(candidate)
        || looks_like_hex_secret(candidate)
        || looks_like_secretish_password(candidate)
        || has_secretish_prefix(candidate)
}

fn looks_like_hex_secret(value: &str) -> bool {
    let candidate = value.trim();
    candidate.len() >= 16
        && unique_char_count(candidate) >= 6
        && candidate.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn has_secretish_prefix(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "sk_", "sk-", "pk_", "pk-", "key_", "key-", "tok_", "tok-", "pat_", "pat-", "ghp_",
        "glpat-", "xox", "hf_", "sg.", "npm_", "pypi-", "bearer ", "basic ",
    ]
    .iter()
    .any(|prefix| lowered.starts_with(prefix))
}

fn looks_like_high_entropy_secret(value: &str) -> bool {
    let candidate = strip_auth_scheme(value).unwrap_or(value).trim();
    if candidate.len() < 16
        || candidate.contains("://")
        || candidate.chars().any(|ch| ch.is_whitespace())
    {
        return false;
    }

    let class_count = char_class_count(candidate);
    let unique_count = unique_char_count(candidate);
    let has_separator = candidate.contains('_')
        || candidate.contains('-')
        || candidate.contains('/')
        || candidate.contains('+')
        || candidate.contains('=');

    (class_count >= 3 && unique_count >= 8)
        || (class_count >= 2 && unique_count >= 10 && has_separator && candidate.len() >= 20)
        || looks_like_jwt(candidate)
}

fn looks_like_base64_secret(value: &str) -> bool {
    let candidate = value.trim();
    candidate.len() >= 12
        && candidate.len() % 4 == 0
        && unique_char_count(candidate) >= 6
        && candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_'))
}

fn looks_like_jwt(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };

    value.starts_with("eyJ")
        && header.len() >= 8
        && payload.len() >= 8
        && signature.len() >= 8
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn looks_like_secretish_password(value: &str) -> bool {
    if value.len() < 10 || value.contains("://") || value.chars().any(|ch| ch.is_whitespace()) {
        return false;
    }

    let class_count = char_class_count(value);
    let unique_count = unique_char_count(value);
    (class_count >= 2 && unique_count >= 6)
        || (class_count >= 1 && unique_count >= 10 && value.len() >= 16)
}

fn is_contextual_secret_path(path: &str) -> bool {
    let lowered = path.trim().to_ascii_lowercase();
    looks_like_dotenv_path(&lowered)
        || lowered.contains(".env.")
        || lowered.ends_with(".json")
        || lowered.ends_with(".yaml")
        || lowered.ends_with(".yml")
        || lowered.ends_with(".toml")
        || lowered.ends_with(".ini")
        || lowered.ends_with(".conf")
        || lowered.ends_with(".config")
        || lowered.ends_with(".js")
        || lowered.ends_with(".cjs")
        || lowered.ends_with(".mjs")
        || lowered.ends_with(".ts")
        || lowered.ends_with(".tsx")
        || lowered.ends_with(".npmrc")
        || lowered.ends_with(".pypirc")
        || lowered.ends_with(".netrc")
        || lowered.ends_with("kubeconfig")
        || lowered.ends_with("/config")
        || lowered.contains("/settings")
}

fn looks_like_dotenv_path(lowered_path: &str) -> bool {
    lowered_path.ends_with(".env")
        || lowered_path.contains("/.env")
        || lowered_path.contains(".env?")
}

fn is_vite_fs_raw_env_exposure(lowered_path: &str, body: &str) -> bool {
    if !lowered_path.starts_with("/@fs/") || !lowered_path.contains("?raw") {
        return false;
    }

    if lowered_path.contains(".env") {
        return looks_like_env_assignment_blob(body, 2);
    }

    if lowered_path.contains("/proc/self/environ") || lowered_path.contains("/proc/1/environ") {
        return body.contains('\0') && looks_like_env_assignment_blob(body, 3);
    }

    false
}

fn looks_like_env_assignment_blob(body: &str, minimum_assignments: usize) -> bool {
    body.split(|ch| matches!(ch, '\0' | '\n' | '\r'))
        .filter_map(|segment| {
            let trimmed = segment.trim();
            let (key, value) = trimmed.split_once('=')?;
            if key.len() < 2
                || value.trim().is_empty()
                || !key
                    .chars()
                    .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
            {
                return None;
            }
            Some(())
        })
        .take(minimum_assignments)
        .count()
        >= minimum_assignments
}

fn strip_auth_scheme(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    strip_ascii_case_prefix(trimmed, "Bearer ")
        .or_else(|| strip_ascii_case_prefix(trimmed, "Basic "))
        .map(str::trim)
}

fn strip_ascii_case_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    if value.len() >= prefix.len() && value[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&value[prefix.len()..])
    } else {
        None
    }
}

fn char_class_count(value: &str) -> usize {
    let has_lower = value.chars().any(|ch| ch.is_ascii_lowercase());
    let has_upper = value.chars().any(|ch| ch.is_ascii_uppercase());
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = value.chars().any(|ch| !ch.is_ascii_alphanumeric());
    [has_lower, has_upper, has_digit, has_symbol]
        .into_iter()
        .filter(|present| *present)
        .count()
}

fn unique_char_count(value: &str) -> usize {
    value.chars().collect::<HashSet<_>>().len()
}

struct SwaggerSignal {
    matched: String,
    start: usize,
    end: usize,
}

static SWAGGER_JSON_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#""(?:openapi|swagger)"\s*:"#).expect("valid regex")
});

fn match_swagger_ui_signal(document: &FetchedDocument) -> Option<SwaggerSignal> {
    if !(200..300).contains(&document.status) {
        return None;
    }

    let body = &document.body;
    if body.len() < 50 {
        return None;
    }

    let lowered_path = document.path.to_ascii_lowercase();
    let normalized_path = lowered_path.trim_end_matches('/');
    let content_type = document
        .content_type
        .as_deref()
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    let json_spec_path = matches_path_suffix(
        normalized_path,
        &[
            "/openapi.json",
            "/swagger.json",
            "/v2/api-docs",
            "/v3/api-docs",
            "/api-docs.json",
        ],
    );
    let yaml_spec_path = matches_path_suffix(
        normalized_path,
        &[
            "/openapi.yml",
            "/openapi.yaml",
            "/swagger.yml",
            "/swagger.yaml",
        ],
    );
    let ui_path = lowered_path.contains("/swagger-ui")
        || matches_path_suffix(normalized_path, &["/swagger", "/api-docs"]);

    if json_spec_path && content_type_compatible(&content_type, &["json"]) {
        if let Some(signal) = validate_swagger_json_spec(body) {
            return Some(signal);
        }
    }

    if yaml_spec_path && content_type_compatible(&content_type, &["yaml", "yml", "text/plain"]) {
        if let Some(signal) = validate_swagger_yaml_spec(body) {
            return Some(signal);
        }
    }

    if ui_path && content_type_compatible(&content_type, &["html"]) {
        if let Some(signal) = validate_swagger_ui_html(body) {
            return Some(signal);
        }
    }

    if !json_spec_path
        && !yaml_spec_path
        && !ui_path
        && content_type_compatible(&content_type, &["html"])
    {
        if let Some(signal) = validate_swagger_ui_html(body) {
            return Some(signal);
        }
    }

    None
}

fn matches_path_suffix(normalized_path: &str, suffixes: &[&str]) -> bool {
    suffixes
        .iter()
        .any(|candidate| normalized_path == *candidate || normalized_path.ends_with(*candidate))
}

fn content_type_compatible(content_type: &str, expected_fragments: &[&str]) -> bool {
    if content_type.is_empty() {
        return true;
    }
    expected_fragments
        .iter()
        .any(|fragment| content_type.contains(fragment))
}

fn validate_swagger_json_spec(body: &str) -> Option<SwaggerSignal> {
    let trimmed = body.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }

    let scan_len = clamp_to_char_boundary(body, 4096);
    let lowered = body[..scan_len].to_ascii_lowercase();

    let mat = SWAGGER_JSON_KEY_RE.find(&lowered)?;
    let start = mat.start();
    let end = mat.end();
    Some(SwaggerSignal {
        matched: body[start..end].to_string(),
        start,
        end,
    })
}

fn validate_swagger_yaml_spec(body: &str) -> Option<SwaggerSignal> {
    let trimmed = body.trim_start();
    let lowered_trim = trimmed.to_ascii_lowercase();
    let leading = body.len().saturating_sub(trimmed.len());

    for prefix in ["openapi:", "swagger:"] {
        if lowered_trim.starts_with(prefix) {
            let start = leading;
            let end = leading + prefix.len();
            return Some(SwaggerSignal {
                matched: body[start..end].to_string(),
                start,
                end,
            });
        }
    }
    None
}

fn validate_swagger_ui_html(body: &str) -> Option<SwaggerSignal> {
    let scan_len = clamp_to_char_boundary(body, 16_384);
    let lowered = body[..scan_len].to_ascii_lowercase();

    for candidate in [
        "swagger-ui-bundle.js",
        "swagger-ui-standalone-preset",
        "swagger-ui-dist",
        "swagger-ui.css",
    ] {
        if let Some(start) = lowered.find(candidate) {
            let end = start + candidate.len();
            return Some(SwaggerSignal {
                matched: body[start..end].to_string(),
                start,
                end,
            });
        }
    }
    None
}

fn clamp_to_char_boundary(body: &str, max_bytes: usize) -> usize {
    if body.len() <= max_bytes {
        return body.len();
    }
    let mut idx = max_bytes;
    while idx > 0 && !body.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn build_evidence(document: &FetchedDocument, start: usize, end: usize, matched: &str) -> String {
    build_evidence_with_render(document, start, end, matched, &redact_secret(matched))
}

fn build_plugin_evidence(
    document: &FetchedDocument,
    start: usize,
    end: usize,
    matched: &str,
) -> String {
    build_evidence_with_render(document, start, end, matched, matched)
}

fn build_evidence_with_render(
    document: &FetchedDocument,
    start: usize,
    end: usize,
    matched: &str,
    rendered_match: &str,
) -> String {
    let line_number = document.body[..start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let line_start = document.body[..start]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let line_end = document.body[end..]
        .find('\n')
        .map(|offset| end + offset)
        .unwrap_or(document.body.len());
    let line = &document.body[line_start..line_end];
    let match_start_in_line = start.saturating_sub(line_start);
    let match_end_in_line = match_start_in_line + matched.len();

    let prefix = abbreviate_suffix(&line[..match_start_in_line], 48);
    let suffix = abbreviate_prefix(&line[match_end_in_line..], 48);
    let excerpt = format!("{prefix}{rendered_match}{suffix}");
    let content_type = document.content_type.as_deref().unwrap_or("unknown");
    let truncated = if document.truncated {
        ", truncated"
    } else {
        ""
    };

    format!(
        "status={} type={} line={}{} :: {}",
        document.status,
        content_type,
        line_number,
        truncated,
        excerpt.trim()
    )
}

fn abbreviate_prefix(value: &str, keep: usize) -> String {
    if value.chars().count() <= keep {
        return value.to_string();
    }

    let prefix = value.chars().take(keep).collect::<String>();
    format!("{prefix}…")
}

fn abbreviate_suffix(value: &str, keep: usize) -> String {
    let total = value.chars().count();
    if total <= keep {
        return value.to_string();
    }

    let suffix = value
        .chars()
        .skip(total.saturating_sub(keep))
        .collect::<String>();
    format!("…{suffix}")
}

fn fingerprint(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::core::{FindingCandidate, FindingConfidence, Severity};
    use crate::fetcher::FetchedDocument;

    use super::{DetectorEngine, candidate_detectors, compare_numeric_versions};

    fn document(path: &str, body: &str) -> FetchedDocument {
        document_with_headers(
            path,
            body,
            &[("Strict-Transport-Security", "max-age=31536000")],
        )
    }

    fn document_with_headers(path: &str, body: &str, headers: &[(&str, &str)]) -> FetchedDocument {
        FetchedDocument {
            path: path.to_string(),
            url: format!("https://example.test{path}"),
            status: 200,
            content_type: Some("text/plain".to_string()),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            body: body.to_string(),
            truncated: false,
            coverage_source: "test-seed".to_string(),
        }
    }

    #[test]
    fn detector_engine_redacts_matches() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/.env",
            "OPENAI_API_KEY=sk-proj-1234567890abcdefghijklmnopqrstuv",
        ));
        // The path-exposure detector \`dotenv_file_exposed\` co-fires on any
        // \`/.env\` body containing \`api_key=\` regardless of the secret value,
        // so this test asserts only on the secret detector it is checking
        // for redaction behavior on.
        let openai = findings
            .iter()
            .find(|finding| finding.detector == "openai_api_key")
            .expect("openai_api_key finding for sk-proj credential");
        assert!(openai.redacted_value.contains("****"));
        assert_eq!(openai.path, "/.env");
    }

    #[test]
    fn detector_engine_tags_phase_one_passive_plugins_with_catalog_metadata() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/.env",
            "APP_KEY=base64:1234567890\nDATABASE_URL=postgres://scanner:secret@example.test/db\n",
        ));

        let dotenv = findings
            .iter()
            .find(|finding| {
                finding
                    .plugin_metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.plugin_id == "DotEnvConfigPlugin")
            })
            .expect("dotenv plugin finding");

        let metadata = dotenv.plugin_metadata.as_ref().expect("plugin metadata");
        assert_eq!(metadata.plugin_id, "DotEnvConfigPlugin");
        assert_eq!(metadata.plugin_family.as_str(), "leakage_debug_config");
        assert_eq!(metadata.execution_mode.as_str(), "passive_http");
        assert_eq!(metadata.leakix_label.as_str(), "trusted_pro");
    }

    #[test]
    fn detector_engine_flags_vite_fs_raw_dotenv_reads() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/@fs/..%2f..%2f..%2f..%2f.env?raw",
            "VITE_API_BASE_URL=https://api.example.test\nDATABASE_URL=postgres://scanner:secret@example.test/db\n",
        ));

        let vite = findings
            .iter()
            .find(|finding| {
                finding.detector == "vite_fs_raw_file_read_exposed"
                    && finding
                        .plugin_metadata
                        .as_ref()
                        .is_some_and(|metadata| metadata.plugin_id == "ViteJSPlugin")
            })
            .expect("vite @fs raw dotenv finding");
        assert_eq!(vite.severity, Severity::High);

        assert!(findings.iter().any(|finding| {
            finding
                .plugin_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.plugin_id == "DotEnvConfigPlugin")
        }));
    }

    #[test]
    fn detector_engine_flags_vite_fs_raw_process_environment_reads() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/@fs//proc/self/environ?raw",
            "PWD=/workspace\0HOME=/root\0DATABASE_URL=postgres://scanner:secret@example.test/db\0",
        ));

        let vite = findings
            .iter()
            .find(|finding| {
                finding.detector == "vite_fs_raw_file_read_exposed"
                    && finding
                        .plugin_metadata
                        .as_ref()
                        .is_some_and(|metadata| metadata.plugin_id == "ViteJSPlugin")
            })
            .expect("vite @fs raw environ finding");
        assert_eq!(vite.severity, Severity::High);
    }

    #[test]
    fn detector_engine_emits_version_correlation_finding_for_old_jenkins_header() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/",
            "<html><title>Dashboard [Jenkins]</title></html>",
            &[("X-Jenkins", "2.401.3")],
        ));

        let version_finding = findings
            .iter()
            .find(|finding| {
                finding
                    .plugin_metadata
                    .as_ref()
                    .is_some_and(|metadata| metadata.plugin_id == "JenkinsVersionPlugin")
            })
            .expect("jenkins version correlation finding");
        let metadata = version_finding
            .plugin_metadata
            .as_ref()
            .expect("plugin metadata");
        assert_eq!(metadata.execution_mode.as_str(), "version_correlation");
        assert_eq!(metadata.product_name.as_deref(), Some("Jenkins"));
        assert_eq!(metadata.product_version.as_deref(), Some("2.401.3"));
    }

    #[test]
    fn detector_engine_emits_screenconnect_vulnerability_only_for_affected_versions() {
        let engine = DetectorEngine::new();
        let vulnerable = engine.scan_document(&document_with_headers(
            "/login",
            "<html><title>ConnectWise Control</title></html>",
            &[("X-ScreenConnect-Version", "23.9.7.8817")],
        ));
        let vulnerable_ids = vulnerable
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();
        assert!(vulnerable_ids.contains("ConnectWiseScreenConnect"));

        let patched = engine.scan_document(&document_with_headers(
            "/login",
            "<html><title>ConnectWise Control</title></html>",
            &[("X-ScreenConnect-Version", "23.9.8.9000")],
        ));
        let patched_ids = patched
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();
        assert!(!patched_ids.contains("ConnectWiseScreenConnect"));
    }

    #[test]
    fn detector_engine_emits_goanywhere_vulnerability_only_for_affected_versions() {
        let engine = DetectorEngine::new();
        let vulnerable = engine.scan_document(&document(
            "/goanywhere/login.xhtml",
            "<html><title>GoAnywhere MFT</title><div>GoAnywhere MFT 7.4.0</div></html>",
        ));
        let vulnerable_ids = vulnerable
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();
        assert!(vulnerable_ids.contains("GoAnywhereMFT202501"));

        let patched = engine.scan_document(&document(
            "/goanywhere/login.xhtml",
            "<html><title>GoAnywhere MFT</title><div>GoAnywhere MFT 7.4.1</div></html>",
        ));
        let patched_ids = patched
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();
        assert!(!patched_ids.contains("GoAnywhereMFT202501"));
    }

    #[test]
    fn detector_engine_emits_solr_vulnerability_only_for_affected_versions() {
        let engine = DetectorEngine::new();
        let vulnerable = engine.scan_document(&document(
            "/solr/admin/info/system",
            "{\"lucene\":{\"solr-spec-version\":\"9.7.0\"},\"mode\":\"solrcloud\"}",
        ));
        let vulnerable_ids = vulnerable
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();
        assert!(vulnerable_ids.contains("SolrVersionPlugin"));

        let patched = engine.scan_document(&document(
            "/solr/admin/info/system",
            "{\"lucene\":{\"solr-spec-version\":\"9.8.0\"},\"mode\":\"solrcloud\"}",
        ));
        let patched_ids = patched
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();
        assert!(!patched_ids.contains("SolrVersionPlugin"));
    }

    #[test]
    fn detector_engine_emits_bundled_http_pack_findings_for_promoted_plugins() {
        let config = crate::config::AppConfig::default();
        let manifest = config
            .load_extension_manifests()
            .expect("bundled manifests should load")
            .into_iter()
            .find(|manifest| manifest.name == "bundled-http-plugin-pack")
            .expect("bundled http plugin pack manifest");

        let craft = super::run_external_detector_pack(
            &document(
                "/admin/login",
                "<html><title>Craft CMS</title><body>Craft CMS Control Panel</body></html>",
            ),
            &manifest,
        )
        .expect("craft rule should execute");
        let moodle = super::run_external_detector_pack(
            &document(
                "/login/index.php",
                "<html><title>Moodle</title><body>Moodle login</body></html>",
            ),
            &manifest,
        )
        .expect("moodle rule should execute");
        let mirth = super::run_external_detector_pack(
            &document(
            "/",
            "<html><title>NextGen Connect</title><body>Mirth Connect Administrator</body></html>",
            ),
            &manifest,
        )
        .expect("mirth rule should execute");
        let sap = super::run_external_detector_pack(
            &document(
            "/irj/portal",
            "<html><title>SAP NetWeaver Portal</title><body>SAP Enterprise Portal</body></html>",
            ),
            &manifest,
        )
        .expect("sap rule should execute");

        let all = [craft, moodle, mirth, sap]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let plugin_ids = all
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();

        assert!(plugin_ids.contains("CraftCMSPlugin"));
        assert!(plugin_ids.contains("MoodlePlugin"));
        assert!(plugin_ids.contains("MirthPlugin"));
        assert!(plugin_ids.contains("SAPNetWeaverPlugin"));
        assert!(all.iter().all(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.implementation_source.as_str() == "bundled_detector_pack"
            })
        }));
    }

    #[test]
    fn detector_engine_emits_bundled_version_pack_findings_for_promoted_plugins() {
        let config = crate::config::AppConfig::default();
        let manifest = config
            .load_extension_manifests()
            .expect("bundled manifests should load")
            .into_iter()
            .find(|manifest| manifest.name == "bundled-version-rule-pack")
            .expect("bundled version rule pack manifest");

        let litellm = super::run_external_detector_pack(
            &document(
                "/",
                "<html><title>LiteLLM</title><body>LiteLLM version 1.82.8</body></html>",
            ),
            &manifest,
        )
        .expect("litellm version rule should execute");
        let flowise = super::run_external_detector_pack(
            &document(
                "/",
                "<html><title>Flowise</title><body>Flowise version 3.0.1</body></html>",
            ),
            &manifest,
        )
        .expect("flowise version rule should execute");

        let all = [litellm, flowise].into_iter().flatten().collect::<Vec<_>>();
        let plugin_ids = all
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();

        assert!(plugin_ids.contains("LiteLLMPlugin"));
        assert!(plugin_ids.contains("FlowiseVersionPlugin"));
        assert!(all.iter().all(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.implementation_source.as_str() == "bundled_version_rule"
            })
        }));
        assert!(all.iter().all(|finding| finding.confidence.is_some()));
        assert!(all.iter().any(|finding| {
            finding.evidence.contains("version 1.82.8")
                || finding.evidence.contains("version 3.0.1")
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "LiteLLMPlugin"
                    && metadata.cve_ids.iter().any(|cve| cve == "CVE-2026-35029")
                    && metadata.cve_ids.iter().any(|cve| cve == "CVE-2026-35030")
                    && metadata.kev_matched == Some(false)
            })
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "FlowiseVersionPlugin"
                    && metadata.cve_ids.iter().any(|cve| cve == "CVE-2025-50538")
                    && metadata.cve_ids.iter().any(|cve| cve == "CVE-2025-8943")
                    && metadata.kev_matched == Some(false)
            })
        }));
    }

    #[test]
    fn detector_engine_emits_bundled_version_pack_findings_for_best_effort_promotions() {
        let config = crate::config::AppConfig::default();
        let manifest = config
            .load_extension_manifests()
            .expect("bundled manifests should load")
            .into_iter()
            .find(|manifest| manifest.name == "bundled-version-rule-pack")
            .expect("bundled version rule pack manifest");

        let appsmith = super::run_external_detector_pack(
            &document(
                "/",
                "<html><title>Appsmith</title><body>Appsmith Community Edition version 1.50.9</body></html>",
            ),
            &manifest,
        )
        .expect("appsmith version rule should execute");
        let zimbra = super::run_external_detector_pack(
            &document(
                "/",
                "<html><title>Zimbra</title><body>Zimbra Collaboration Suite 10.0.3</body></html>",
            ),
            &manifest,
        )
        .expect("zimbra version rule should execute");
        let sharepoint = super::run_external_detector_pack(
            &document(
                "/_layouts/15/start.aspx",
                "<html><title>Microsoft SharePoint</title><body>SharePoint Server Version 16.0.10396.20017</body></html>",
            ),
            &manifest,
        )
        .expect("sharepoint version rule should execute");
        let n8n = super::run_external_detector_pack(
            &document_with_headers(
                "/rest/settings",
                "{\"data\":{}}",
                &[("X-N8N-Version", "1.120.3")],
            ),
            &manifest,
        )
        .expect("n8n version rule should execute");
        let metabase = super::run_external_detector_pack(
            &document_with_headers(
                "/api/health",
                "{\"status\":\"ok\",\"product\":\"metabase\"}",
                &[("X-Metabase-Version", "v0.56.2")],
            ),
            &manifest,
        )
        .expect("metabase version rule should execute");
        let appsmith_header = super::run_external_detector_pack(
            &document_with_headers(
                "/api/v1/health",
                "{\"appsmith\":\"ok\"}",
                &[("X-Appsmith-Version", "1.50.9")],
            ),
            &manifest,
        )
        .expect("appsmith version rule should execute");
        let bitbucket = super::run_external_detector_pack(
            &document(
                "/users/sign_in",
                "<html><title>Bitbucket</title><body>Bitbucket version 8.3.0</body></html>",
            ),
            &manifest,
        )
        .expect("bitbucket version rule should execute");
        let confluence = super::run_external_detector_pack(
            &document(
                "/login.action",
                "<html><title>Confluence</title><body>Confluence version 8.5.1</body></html>",
            ),
            &manifest,
        )
        .expect("confluence version rule should execute");
        let gitlab = super::run_external_detector_pack(
            &document(
                "/users/sign_in",
                "<html><title>GitLab</title><body>GitLab version 16.7.1</body></html>",
            ),
            &manifest,
        )
        .expect("gitlab version rule should execute");
        let jira = super::run_external_detector_pack(
            &document(
                "/login.jsp",
                "<html><title>Jira</title><body>Jira version 8.16.0</body></html>",
            ),
            &manifest,
        )
        .expect("jira version rule should execute");
        let teamcity = super::run_external_detector_pack(
            &document(
                "/login.html",
                "<html><title>TeamCity</title><body>TeamCity version 2023.11.3</body></html>",
            ),
            &manifest,
        )
        .expect("teamcity version rule should execute");
        let wazuh = super::run_external_detector_pack(
            &document(
                "/app/login",
                "<html><title>Wazuh</title><body>Wazuh version 4.8.2</body></html>",
            ),
            &manifest,
        )
        .expect("wazuh version rule should execute");
        let zoneminder = super::run_external_detector_pack(
            &document(
                "/zm/index.php",
                "<html><title>ZoneMinder</title><body>ZoneMinder version 1.36.32</body></html>",
            ),
            &manifest,
        )
        .expect("zoneminder version rule should execute");

        let all = [
            appsmith,
            zimbra,
            sharepoint,
            n8n,
            metabase,
            appsmith_header,
            bitbucket,
            confluence,
            gitlab,
            jira,
            teamcity,
            wazuh,
            zoneminder,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let plugin_ids = all
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();

        assert!(plugin_ids.contains("AppsmithPlugin"));
        assert!(plugin_ids.contains("BitbucketPlugin"));
        assert!(plugin_ids.contains("ConfluenceVersionIssue"));
        assert!(plugin_ids.contains("GitlabPlugin"));
        assert!(plugin_ids.contains("JiraPlugin"));
        assert!(plugin_ids.contains("N8nPlugin"));
        assert!(plugin_ids.contains("MetabaseHttpPlugin"));
        assert!(plugin_ids.contains("ZimbraPlugin"));
        assert!(plugin_ids.contains("SharePointPlugin"));
        assert!(plugin_ids.contains("TeamCityPlugin"));
        assert!(plugin_ids.contains("WazuhPlugin"));
        assert!(plugin_ids.contains("ZoneMinderPlugin"));
        assert!(all.iter().all(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.implementation_source.as_str() == "bundled_version_rule"
            })
        }));
        assert!(all.iter().all(|finding| finding.confidence.is_some()));
        assert!(
            all.iter()
                .all(|finding| !finding.matched_signals.is_empty())
        );
        assert!(all.iter().all(|finding| !finding.review_labels.is_empty()));
        assert!(all.iter().any(|finding| {
            finding
                .matched_signals
                .iter()
                .any(|signal| signal == "version")
        }));
        assert!(all.iter().any(|finding| {
            finding
                .review_labels
                .iter()
                .any(|label| label == "version_rule")
        }));
        assert!(all.iter().any(|finding| {
            finding.evidence.contains("version 1.50.9")
                || finding.evidence.contains("version 1.120.3")
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "AppsmithPlugin"
                    && metadata.cve_ids == vec!["CVE-2024-55965".to_string()]
                    && metadata.kev_matched == Some(false)
            })
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "N8nPlugin"
                    && metadata.cve_ids.iter().any(|cve| cve == "CVE-2025-68613")
                    && metadata.kev_matched == Some(true)
            })
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "BitbucketPlugin"
                    && metadata.cve_ids == vec!["CVE-2022-36804".to_string()]
                    && metadata.kev_matched == Some(true)
            })
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "ConfluenceVersionIssue"
                    && metadata.cve_ids == vec!["CVE-2023-22515".to_string()]
                    && metadata.kev_matched == Some(true)
            })
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "GitlabPlugin"
                    && metadata.cve_ids == vec!["CVE-2023-7028".to_string()]
                    && metadata.kev_matched == Some(true)
            })
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "JiraPlugin"
                    && metadata.cve_ids == vec!["CVE-2021-26086".to_string()]
                    && metadata.kev_matched == Some(true)
            })
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "SharePointPlugin"
                    && metadata.cve_ids
                        == vec![
                            "CVE-2025-49704".to_string(),
                            "CVE-2025-49706".to_string(),
                            "CVE-2025-53770".to_string(),
                            "CVE-2025-53771".to_string(),
                        ]
                    && metadata.kev_matched == Some(true)
            })
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "TeamCityPlugin"
                    && metadata.cve_ids == vec!["CVE-2024-27198".to_string()]
                    && metadata.kev_matched == Some(true)
            })
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "WazuhPlugin"
                    && metadata.cve_ids == vec!["CVE-2025-24016".to_string()]
                    && metadata.kev_matched == Some(false)
            })
        }));
        assert!(all.iter().any(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.plugin_id == "ZoneMinderPlugin"
                    && metadata.cve_ids
                        == vec![
                            "CVE-2023-25825".to_string(),
                            "CVE-2023-26032".to_string(),
                            "CVE-2023-26034".to_string(),
                            "CVE-2023-26035".to_string(),
                            "CVE-2023-26036".to_string(),
                            "CVE-2023-26037".to_string(),
                            "CVE-2023-26039".to_string(),
                        ]
                    && metadata.kev_matched == Some(false)
            })
        }));
    }

    #[test]
    fn detector_engine_version_rules_skip_patched_versions_for_curated_cve_ranges() {
        let config = crate::config::AppConfig::default();
        let manifest = config
            .load_extension_manifests()
            .expect("bundled manifests should load")
            .into_iter()
            .find(|manifest| manifest.name == "bundled-version-rule-pack")
            .expect("bundled version rule pack manifest");

        let appsmith = super::run_external_detector_pack(
            &document(
                "/",
                "<html><title>Appsmith</title><body>Appsmith Community Edition version 1.51.0</body></html>",
            ),
            &manifest,
        )
        .expect("appsmith version rule should execute");
        let gitlab = super::run_external_detector_pack(
            &document(
                "/users/sign_in",
                "<html><title>GitLab</title><body>GitLab version 16.7.2</body></html>",
            ),
            &manifest,
        )
        .expect("gitlab version rule should execute");
        let teamcity = super::run_external_detector_pack(
            &document(
                "/login.html",
                "<html><title>TeamCity</title><body>TeamCity version 2023.11.4</body></html>",
            ),
            &manifest,
        )
        .expect("teamcity version rule should execute");

        let plugin_ids = [appsmith, gitlab, teamcity]
            .into_iter()
            .flatten()
            .filter_map(|finding| finding.plugin_metadata)
            .map(|metadata| metadata.plugin_id)
            .collect::<HashSet<_>>();

        assert!(!plugin_ids.contains("AppsmithPlugin"));
        assert!(!plugin_ids.contains("GitlabPlugin"));
        assert!(!plugin_ids.contains("TeamCityPlugin"));
    }

    #[test]
    fn detector_engine_emits_bundled_http_pack_findings_for_best_effort_promotions() {
        let config = crate::config::AppConfig::default();
        let manifest = config
            .load_extension_manifests()
            .expect("bundled manifests should load")
            .into_iter()
            .find(|manifest| manifest.name == "bundled-http-plugin-pack")
            .expect("bundled http rule pack manifest");

        let browserless = super::run_external_detector_pack(
            &document(
                "/json/version",
                "<html><title>Browserless</title><body>browserless chrome service</body></html>",
            ),
            &manifest,
        )
        .expect("browserless rule should execute");
        let node_red = super::run_external_detector_pack(
            &document(
                "/red/settings",
                "<html><title>Node-RED</title><body>Welcome to Node-RED</body></html>",
            ),
            &manifest,
        )
        .expect("node-red rule should execute");
        let traversal = super::run_external_detector_pack(
            &document("/../../../../etc/passwd", "root:x:0:0:root:/root:/bin/sh"),
            &manifest,
        )
        .expect("traversal rule should execute");

        let all = [browserless, node_red, traversal]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let plugin_ids = all
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();

        assert!(plugin_ids.contains("BrowserlessPlugin"));
        assert!(plugin_ids.contains("NodeREDPlugin"));
        assert!(plugin_ids.contains("TraversalHttpPlugin"));
        assert!(all.iter().all(|finding| {
            finding.plugin_metadata.as_ref().is_some_and(|metadata| {
                metadata.implementation_source.as_str() == "bundled_detector_pack"
            })
        }));
        assert!(all.iter().all(|finding| finding.confidence.is_some()));
        assert!(
            all.iter()
                .any(|finding| finding.evidence.contains("/json/version"))
        );
        assert!(
            all.iter()
                .all(|finding| !finding.matched_signals.is_empty())
        );
        assert!(all.iter().all(|finding| !finding.review_labels.is_empty()));
        assert!(all.iter().any(|finding| {
            finding
                .matched_signals
                .iter()
                .any(|signal| signal == "path_hint")
        }));
        assert!(all.iter().any(|finding| {
            finding
                .review_labels
                .iter()
                .any(|label| label == "http_rule")
        }));
    }

    #[test]
    fn detector_engine_best_effort_http_rules_respect_negative_path_filters() {
        let config = crate::config::AppConfig::default();
        let manifest = config
            .load_extension_manifests()
            .expect("bundled manifests should load")
            .into_iter()
            .find(|manifest| manifest.name == "bundled-http-plugin-pack")
            .expect("bundled http rule pack manifest");

        let findings = super::run_external_detector_pack(
            &document(
                "/docs/browserless/overview",
                "<html><title>Browserless Docs</title><body>browserless version 2.30.1</body></html>",
            ),
            &manifest,
        )
        .expect("browserless docs rule should execute");

        let plugin_ids = findings
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();
        assert!(!plugin_ids.contains("BrowserlessPlugin"));
    }

    #[test]
    fn detector_engine_best_effort_version_rules_respect_negative_path_filters() {
        let config = crate::config::AppConfig::default();
        let manifest = config
            .load_extension_manifests()
            .expect("bundled manifests should load")
            .into_iter()
            .find(|manifest| manifest.name == "bundled-version-rule-pack")
            .expect("bundled version rule pack manifest");

        let findings = super::run_external_detector_pack(
            &document_with_headers(
                "/docs/appsmith/getting-started",
                "<html><title>Appsmith docs</title><body>Appsmith version 1.51.0</body></html>",
                &[("X-Appsmith-Version", "1.51.0")],
            ),
            &manifest,
        )
        .expect("appsmith docs rule should execute");

        let plugin_ids = findings
            .iter()
            .filter_map(|finding| finding.plugin_metadata.as_ref())
            .map(|metadata| metadata.plugin_id.as_str())
            .collect::<HashSet<_>>();
        assert!(!plugin_ids.contains("AppsmithPlugin"));
    }

    #[test]
    fn detector_engine_tags_additional_phase_one_public_surfaces() {
        let engine = DetectorEngine::new();
        let cases = vec![
            (
                document(
                    "/login",
                    "<html><script>window.grafanaBootData = {\"user\":null};</script></html>",
                ),
                "GrafanaOpenPlugin",
            ),
            (
                document(
                    "/",
                    "<html><title>MLflow</title><div>MLflow Tracking</div></html>",
                ),
                "MLflowPlugin",
            ),
            (
                document(
                    "/api/health",
                    "{\"status\":\"READY\",\"prefect\":\"server\"}",
                ),
                "PrefectPlugin",
            ),
            (
                document(
                    "/api/version",
                    "{\"version\":\"2.9.0\",\"ray\":\"dashboard\"}",
                ),
                "RayDashboardPlugin",
            ),
            (
                document("/", "<html><title>SonarQube</title></html>"),
                "SonarQubePlugin",
            ),
            (
                document("/", "<html><title>NSQ Admin</title></html>"),
                "NsqAdminPlugin",
            ),
            (
                document_with_headers(
                    "/v2/",
                    "{}",
                    &[("Docker-Distribution-Api-Version", "registry/2.0")],
                ),
                "DockerRegistryHttpPlugin",
            ),
            (document("/v1/status/leader", "\"10.0.0.1:8300\""), "Consul"),
            (
                document("/", "{\"couchdb\":\"Welcome\",\"version\":\"3.4.2\"}"),
                "CouchDbOpenPlugin",
            ),
        ];

        for (document, expected_plugin_id) in cases {
            let findings = engine.scan_document(&document);
            let plugin_ids = findings
                .iter()
                .filter_map(|finding| finding.plugin_metadata.as_ref())
                .map(|metadata| metadata.plugin_id.as_str())
                .collect::<HashSet<_>>();
            assert!(
                plugin_ids.contains(expected_plugin_id),
                "expected {expected_plugin_id} for {} but saw {:?}",
                document.path,
                plugin_ids
            );
        }
    }

    #[test]
    fn detector_engine_tags_vector_data_and_admin_public_surfaces() {
        let engine = DetectorEngine::new();
        let cases = vec![
            (
                document("/", "<html><title>Attu</title><div>Milvus GUI</div></html>"),
                "AttuPlugin",
            ),
            (
                document("/", "<html><title>cAdvisor - /</title></html>"),
                "CAdvisorPlugin",
            ),
            (
                document(
                    "/_admin/v1/health",
                    "<html>Cockroach Labs DB Console</html>",
                ),
                "CockroachDBPlugin",
            ),
            (
                document("/", "<html><title>Dagster UI</title></html>"),
                "DagsterPlugin",
            ),
            (
                document("/", "<html><title>Apache Flink Dashboard</title></html>"),
                "FlinkPlugin",
            ),
            (
                document_with_headers(
                    "/version",
                    "{\"pkgVersion\":\"1.8.0\"}",
                    &[("X-MeiliSearch-Instance-Uid", "test-instance")],
                ),
                "MeilisearchPlugin",
            ),
            (
                document(
                    "/",
                    "{\"neo4j_version\":\"5.24.0\",\"bolt_routing\":\"/db/{databaseName}/cluster\"}",
                ),
                "Neo4jOpenPlugin",
            ),
            (
                document_with_headers(
                    "/",
                    "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"Example API\"},\"postgrest\":\"12.0\"}",
                    &[("Server", "postgrest/12.0")],
                ),
                "PostgRESTPlugin",
            ),
            (
                document(
                    "/collections",
                    "{\"title\":\"qdrant - vector search engine\",\"version\":\"1.13.0\"}",
                ),
                "QdrantPlugin",
            ),
            (
                document("/", "<html><title>QuestDB Web Console</title></html>"),
                "QuestDBPlugin",
            ),
            (
                document(
                    "/v1/meta",
                    "{\"hostname\":\"vector-1\",\"version\":\"1.26.0\",\"weaviate\":\"ok\"}",
                ),
                "WeaviatePlugin",
            ),
            (
                document_with_headers(
                    "/v1/models",
                    "{\"data\":[],\"version\":\"2.15.0\",\"localai\":\"ok\"}",
                    &[("Server", "LocalAI/2.15.0")],
                ),
                "LocalAIPlugin",
            ),
        ];

        for (document, expected_plugin_id) in cases {
            let findings = engine.scan_document(&document);
            let plugin_ids = findings
                .iter()
                .filter_map(|finding| finding.plugin_metadata.as_ref())
                .map(|metadata| metadata.plugin_id.as_str())
                .collect::<HashSet<_>>();
            assert!(
                plugin_ids.contains(expected_plugin_id),
                "expected {expected_plugin_id} for {} but saw {:?}",
                document.path,
                plugin_ids
            );
        }
    }

    #[test]
    fn detector_engine_tags_more_phase_one_admin_surfaces() {
        let engine = DetectorEngine::new();
        let cases = vec![
            (
                document(
                    "/api/v1/heartbeat",
                    "{\"nanosecond heartbeat\":true,\"chroma\":\"ok\"}",
                ),
                "ChromaPlugin",
            ),
            (
                document("/", "<html><title>Apache Druid Console</title></html>"),
                "DruidPlugin",
            ),
            (
                document("/h2-console", "<html><title>H2 Console</title></html>"),
                "H2ConsolePlugin",
            ),
            (
                document(
                    "/",
                    "<html><title>Harbor</title><div>harbor-ui</div></html>",
                ),
                "HarborPlugin",
            ),
            (
                document(
                    "/dfshealth.html",
                    "<html><title>NameNode</title><div>Hadoop DFS Health</div></html>",
                ),
                "HdfsOpenPlugin",
            ),
            (
                document("/lab", "<html><title>JupyterLab</title></html>"),
                "JupyterPlugin",
            ),
            (
                document("/indexes", "{\"marqo\":\"ok\",\"results\":[]}"),
                "MarqoPlugin",
            ),
            (
                document(
                    "/api/v1/health",
                    "{\"milvus\":\"ok\",\"status\":\"healthy\"}",
                ),
                "MilvusPlugin",
            ),
            (
                document("/", "<html><title>Mongo Express</title></html>"),
                "MongoExpressPlugin",
            ),
            (
                document(
                    "/varz",
                    "{\"server_id\":\"abc\",\"max_connections\":65536,\"version\":\"2.10.0\"}",
                ),
                "NATSPlugin",
            ),
            (
                document(
                    "/",
                    "<html><title>Nomad</title><div>HashiCorp Nomad</div></html>",
                ),
                "NomadPlugin",
            ),
            (
                document(
                    "/",
                    "<html><title>noVNC</title><button>Connect</button></html>",
                ),
                "NoVncPlugin",
            ),
            (
                document("/", "<html><title>redis-commander</title></html>"),
                "RedisCommanderPlugin",
            ),
            (
                document(
                    "/grid/console",
                    "<html><title>Grid Console</title><div>Selenium Grid</div></html>",
                ),
                "SeleniumGridPlugin",
            ),
            (
                document(
                    "/cluster",
                    "<html><title>YARN ResourceManager</title><div>Hadoop</div></html>",
                ),
                "YarnOpenPlugin",
            ),
        ];

        for (document, expected_plugin_id) in cases {
            let findings = engine.scan_document(&document);
            let plugin_ids = findings
                .iter()
                .filter_map(|finding| finding.plugin_metadata.as_ref())
                .map(|metadata| metadata.plugin_id.as_str())
                .collect::<HashSet<_>>();
            assert!(
                plugin_ids.contains(expected_plugin_id),
                "expected {expected_plugin_id} for {} but saw {:?}",
                document.path,
                plugin_ids
            );
        }
    }

    #[test]
    fn detector_engine_tags_framework_debug_and_misc_http_surfaces() {
        let engine = DetectorEngine::new();
        let cases = vec![
            (
                document(
                    "/json/version",
                    "{\"Browser\":\"Chrome/123.0.0.0\",\"webSocketDebuggerUrl\":\"ws://127.0.0.1/devtools/browser/abc\"}",
                ),
                "ChromeDevToolsPlugin",
            ),
            (
                document(
                    "/",
                    "<html>You’re seeing this error because you have <code>DEBUG = True</code> in your Django settings file. Django version 5.1 Exception Type:</html>",
                ),
                "DjangoPlugin",
            ),
            (
                document(
                    "/",
                    "{\"name\":\"node-a\",\"cluster_name\":\"elastic\",\"version\":{\"number\":\"8.15.0\",\"lucene_version\":\"9.11.1\"},\"tagline\":\"You Know, for Search\"}",
                ),
                "ElasticSearchOpenPlugin",
            ),
            (
                document(
                    "/",
                    "<html><title>Werkzeug Debugger</title><div>The debugger caught an exception in your WSGI application</div></html>",
                ),
                "FlaskPlugin",
            ),
            (
                document(
                    "/goanywhere/login.xhtml",
                    "<html><title>GoAnywhere MFT</title><div>GoAnywhere MFT Administration</div></html>",
                ),
                "GoAnywhereMFT",
            ),
            (
                document_with_headers(
                    "/",
                    "<html>Unauthorized</html>",
                    &[("WWW-Authenticate", "NTLM")],
                ),
                "HttpNTLM",
            ),
            (
                document(
                    "/",
                    "<html><title>Nginx UI</title><div>nginx-ui</div></html>",
                ),
                "NginxUIPlugin",
            ),
            (
                document(
                    "/solr/admin/info/system",
                    "{\"lucene\":{\"solr-spec-version\":\"9.7.0\"},\"mode\":\"solrcloud\"}",
                ),
                "SolrOpenPlugin",
            ),
            (
                document(
                    "/actuator/env",
                    "{\"activeProfiles\":[\"prod\"],\"propertySources\":[{\"name\":\"systemProperties\"}]}",
                ),
                "SpringBootActuatorPlugin",
            ),
            (
                document(
                    "/.vscode/sftp.json",
                    "{\"host\":\"example.test\",\"username\":\"deploy\",\"protocol\":\"sftp\"}",
                ),
                "VsCodeSFTPPlugin",
            ),
            (
                document_with_headers(
                    "/",
                    "<html>Index</html>",
                    &[("DAV", "1,2"), ("Allow", "OPTIONS, GET, PROPFIND, MKCOL")],
                ),
                "WebDAVPlugin",
            ),
            (
                document(
                    "/",
                    "<html><div>Yii Debug Toolbar</div><div>yii\\\\debug</div></html>",
                ),
                "YiiDebugPlugin",
            ),
        ];

        for (document, expected_plugin_id) in cases {
            let findings = engine.scan_document(&document);
            let plugin_ids = findings
                .iter()
                .filter_map(|finding| finding.plugin_metadata.as_ref())
                .map(|metadata| metadata.plugin_id.as_str())
                .collect::<HashSet<_>>();
            assert!(
                plugin_ids.contains(expected_plugin_id),
                "expected {expected_plugin_id} for {} but saw {:?}",
                document.path,
                plugin_ids
            );
        }
    }

    #[test]
    fn detector_engine_tags_more_status_and_ransom_surfaces() {
        let engine = DetectorEngine::new();
        let cases = vec![
            (
                document(
                    "/",
                    "<html><h1>DeadBolt</h1><p>Your files have been encrypted. Send Bitcoin to unlock.</p></html>",
                ),
                "DeadMon",
            ),
            (
                document(
                    "/",
                    "<html><h1>Application Trace</h1><h2>Framework Trace</h2><h3>Full Trace</h3><div>Web Console</div></html>",
                ),
                "RailsPlugin",
            ),
            (
                document(
                    "/render.html",
                    "<html><title>Splash</title><p>JavaScript rendering service with Lua scripting</p></html>",
                ),
                "SplashPlugin",
            ),
            (
                document(
                    "/status",
                    "<html><title>TiDB Status</title><div>TiDB status server</div></html>",
                ),
                "TiDBPlugin",
            ),
            (
                document(
                    "/ApplicationStatus",
                    "<html><title>Application Status</title><div>Vespa</div></html>",
                ),
                "VespaPlugin",
            ),
            (
                document(
                    "/RECORDINGS/",
                    "<html><title>Recordings</title><div>Vicidial recordings archive</div><a href=\"agent-001.wav\">agent-001.wav</a></html>",
                ),
                "ViciboxPlugin",
            ),
        ];

        for (document, expected_plugin_id) in cases {
            let findings = engine.scan_document(&document);
            let plugin_ids = findings
                .iter()
                .filter_map(|finding| finding.plugin_metadata.as_ref())
                .map(|metadata| metadata.plugin_id.as_str())
                .collect::<HashSet<_>>();
            assert!(
                plugin_ids.contains(expected_plugin_id),
                "expected {expected_plugin_id} for {} but saw {:?}",
                document.path,
                plugin_ids
            );
        }
    }

    #[test]
    fn compare_numeric_versions_handles_suffixes_and_segment_length() {
        assert!(compare_numeric_versions("2.401.3", "2.426.3").is_lt());
        assert!(compare_numeric_versions("2.426.3-lts", "2.426.3").is_eq());
        assert!(compare_numeric_versions("2.500", "2.426.3").is_gt());
    }

    #[test]
    fn detector_engine_finds_expanded_provider_catalog() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/config.js",
            concat!(
                "const anthropic='sk-ant-1234567890abcdefghijklmnopqrstuv';\n",
                "const stripe='sk", "_live_1234567890abcdefghijklmnopqrst';\n",
                "const openrouter='sk-or-v1-1234567890abcdefghijklmnopqrstuv';\n",
                "const google='AIza12345678901234567890123456789012345';\n",
                "const googleOauth='ya29.a0AfH6SMBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';\n",
                "const gitlab='glpat-1234567890abcdefghijklmnopqrstuv';\n",
                "const huggingface='hf_1234567890abcdefghijklmnopqrstuv';\n",
                "const sendgrid='SG.qwertyuiopasdfghjklzxcvbnm1234.asdfghjklqwertyuiopzxcvbnm1234';\n",
                "const pypi='pypi-AgEIcHlwaS5vcmcCJDEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY';\n",
                "const npm='npm_1234567890abcdefghijklmnopqrstuvwxyz';\n",
                "const shopify='shpat_1234567890abcdefghijklmnopqrstuv';\n",
                "const slack='xox", "b-123456789012-abcdefghijklmnopqrstuvwx';\n",
                "const slackApp='xap", "p-1-123456789012-abcdefghijklmnopqrstuvwx';\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("anthropic_api_key"));
        assert!(detectors.contains("stripe_live_api_key"));
        assert!(detectors.contains("openrouter_api_key"));
        assert!(detectors.contains("google_api_key"));
        assert!(detectors.contains("google_oauth_access_token"));
        assert!(detectors.contains("gitlab_personal_access_token"));
        assert!(detectors.contains("huggingface_access_token"));
        assert!(detectors.contains("sendgrid_api_key"));
        assert!(detectors.contains("pypi_api_token"));
        assert!(detectors.contains("npm_access_token"));
        assert!(detectors.contains("shopify_admin_api_token"));
        assert!(detectors.contains("slack_access_token"));
        assert!(detectors.contains("slack_app_token"));
    }

    #[test]
    fn detector_engine_finds_contextual_assignments_without_provider_prefixes() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/application.json",
            concat!(
                "AWS_SECRET_ACCESS_KEY=Zx9wVb3qRt7yLm2Nf8KpQ4sJd6Hc1XvB0mNeUaYw\n",
                "DATABASE_URL=postgres://svcuser:S3cr3tPassw0rd!@db.internal.local:5432/app\n",
                "AUTHORIZATION=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.c2lnbmF0dXJld2l0aGVudHJvcHkxMjM0NTY\n",
                "DB_PASSWORD=Sup3rS3cretPass!\n",
                "AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=prodstore;AccountKey=QWxhZGRpbjpPcGVuU2VzYW1lL0xvbmdLZXlWYWx1ZVN0cmluZw==;EndpointSuffix=core.windows.net\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_connection_string"));
        assert!(detectors.contains("generic_authorization_header"));
        assert!(detectors.contains("generic_password"));
    }

    #[test]
    fn detector_engine_finds_structured_artifact_credentials() {
        let engine = DetectorEngine::new();

        let npm_findings = engine.scan_document(&document(
            "/.npmrc",
            "//registry.npmjs.org/:_auth=QWxhZGRpbjpPcGVuU2VzYW1lMTIzNDU2\n",
        ));
        assert_eq!(npm_findings.len(), 1);
        assert_eq!(npm_findings[0].detector, "npm_registry_auth");

        let pypirc_findings = engine.scan_document(&document(
            "/.pypirc",
            "[pypi]\nusername = __token__\npassword = Sup3rPypiPassw0rd!\n",
        ));
        assert_eq!(pypirc_findings.len(), 1);
        assert_eq!(pypirc_findings[0].detector, "pypirc_password");

        let netrc_findings = engine.scan_document(&document(
            "/.netrc",
            "machine api.example.test login svc password Sup3rS3cretPass!\n",
        ));
        assert_eq!(netrc_findings.len(), 1);
        assert_eq!(netrc_findings[0].detector, "netrc_machine_password");

        let docker_findings = engine.scan_document(&document(
            "/.docker/config.json",
            r#"{"auths":{"registry.example.test":{"auth":"QWxhZGRpbjpPcGVuU2VzYW1lMTIzNDU2"}}}"#,
        ));
        // The path-exposure detector \`json_config_file_exposed\` co-fires on
        // \`/.docker/config.json\` whenever the body is a JSON object. Assert
        // only on the specific structured-credential detector under test.
        assert!(
            docker_findings
                .iter()
                .any(|finding| finding.detector == "docker_registry_auth"),
            "expected docker_registry_auth finding, got {docker_findings:?}",
        );

        let kube_findings = engine.scan_document(&document(
            "/.kube/config",
            concat!(
                "apiVersion: v1\n",
                "kind: Config\n",
                "current-context: prod\n",
                "users:\n",
                "  - name: prod\n",
                "    user:\n",
                "      token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwcm9kIiwicm9sZSI6ImFkbWluIn0.c2lnbmF0dXJlYm9keXdpdGhzdWZmaWNpZW50ZW50cm9weQ\n"
            ),
        ));
        assert_eq!(kube_findings.len(), 1);
        assert_eq!(kube_findings[0].detector, "kubeconfig_embedded_credential");
    }

    #[test]
    fn detector_engine_finds_service_account_credential_artifacts() {
        let engine = DetectorEngine::new();

        let google_service_account_findings = engine.scan_document(&document(
            "/google/service-account.json",
            concat!(
                "{\n",
                "  \"type\": \"service_account\",\n",
                "  \"project_id\": \"sample-project\",\n",
                "  \"private_key_id\": \"1234567890abcdef1234567890abcdef12345678\",\n",
                "  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCAbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=\\n-----END PRIVATE KEY-----\\n\",\n",
                "  \"client_email\": \"svc-account@sample-project.iam.gserviceaccount.com\",\n",
                "  \"client_id\": \"123456789012345678901\",\n",
                "  \"token_uri\": \"https://oauth2.googleapis.com/token\"\n",
                "}\n"
            ),
        ));
        assert_eq!(google_service_account_findings.len(), 1);
        assert_eq!(
            google_service_account_findings[0].detector,
            "google_service_account_private_key"
        );

        let firebase_service_account_findings = engine.scan_document(&document(
            "/firebase/firebase-adminsdk.json",
            concat!(
                "{\n",
                "  \"type\": \"service_account\",\n",
                "  \"project_id\": \"sample-project\",\n",
                "  \"private_key_id\": \"abcdef1234567890abcdef1234567890abcdef12\",\n",
                "  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nQWERTYUIOPLKJHGFDSAZXCVBNM0123456789+/=abcd\\n-----END PRIVATE KEY-----\\n\",\n",
                "  \"client_email\": \"firebase-adminsdk-abc12@sample-project.iam.gserviceaccount.com\",\n",
                "  \"client_id\": \"109876543210987654321\",\n",
                "  \"token_uri\": \"https://oauth2.googleapis.com/token\"\n",
                "}\n"
            ),
        ));
        assert_eq!(firebase_service_account_findings.len(), 1);
        assert_eq!(
            firebase_service_account_findings[0].detector,
            "firebase_admin_service_account_private_key"
        );

        let authorized_user_findings = engine.scan_document(&document(
            "/config/application_default_credentials.json",
            concat!(
                "{\n",
                "  \"type\": \"authorized_user\",\n",
                "  \"client_id\": \"123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com\",\n",
                "  \"client_secret\": \"your_client_secret_here\",\n",
                "  \"refresh_token\": \"1//0gAbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFGHIJKLMN\"\n",
                "}\n"
            ),
        ));
        assert_eq!(authorized_user_findings.len(), 1);
        assert_eq!(
            authorized_user_findings[0].detector,
            "google_authorized_user_refresh_token"
        );
    }

    #[test]
    fn detector_engine_ignores_placeholder_service_account_artifacts() {
        let engine = DetectorEngine::new();

        let google_service_account_findings = engine.scan_document(&document(
            "/google/service-account.json",
            concat!(
                "{\n",
                "  \"type\": \"service_account\",\n",
                "  \"project_id\": \"sample-project\",\n",
                "  \"private_key_id\": \"1234567890abcdef1234567890abcdef12345678\",\n",
                "  \"private_key\": \"<redacted>\",\n",
                "  \"client_email\": \"svc-account@sample-project.iam.gserviceaccount.com\",\n",
                "  \"client_id\": \"123456789012345678901\",\n",
                "  \"token_uri\": \"https://oauth2.googleapis.com/token\"\n",
                "}\n"
            ),
        ));
        assert!(google_service_account_findings.is_empty());

        let firebase_service_account_findings = engine.scan_document(&document(
            "/firebase/firebase-adminsdk.json",
            concat!(
                "{\n",
                "  \"type\": \"service_account\",\n",
                "  \"project_id\": \"sample-project\",\n",
                "  \"private_key_id\": \"abcdef1234567890abcdef1234567890abcdef12\",\n",
                "  \"private_key\": \"your_private_key_here\",\n",
                "  \"client_email\": \"firebase-adminsdk-abc12@sample-project.iam.gserviceaccount.com\",\n",
                "  \"client_id\": \"109876543210987654321\",\n",
                "  \"token_uri\": \"https://oauth2.googleapis.com/token\"\n",
                "}\n"
            ),
        ));
        assert!(firebase_service_account_findings.is_empty());

        let authorized_user_findings = engine.scan_document(&document(
            "/config/application_default_credentials.json",
            concat!(
                "{\n",
                "  \"type\": \"authorized_user\",\n",
                "  \"client_id\": \"123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com\",\n",
                "  \"client_secret\": \"your_client_secret_here\",\n",
                "  \"refresh_token\": \"${GOOGLE_REFRESH_TOKEN}\"\n",
                "}\n"
            ),
        ));
        assert!(authorized_user_findings.is_empty());
    }

    #[test]
    fn detector_engine_finds_cloud_credential_artifacts() {
        let engine = DetectorEngine::new();

        let aws_findings = engine.scan_document(&document(
            "/.aws/credentials",
            concat!(
                "[default]\n",
                "aws_access_key_id = AKIA1234567890ABCDEF\n",
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG+bPxRfiCYzEXAMPLEKEY99\n",
                "aws_session_token = FwoGZXIvYXdzEO7//////////wEaDK2v8nB5dHjK9LmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoP\n"
            ),
        ));
        let aws_detectors = aws_findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(aws_detectors.contains("aws_access_key_id"));
        assert!(aws_detectors.contains("aws_shared_credentials_secret_access_key"));
        assert!(aws_detectors.contains("aws_shared_credentials_session_token"));

        let azure_findings = engine.scan_document(&document(
            "/azure/service-principal.json",
            concat!(
                "{\n",
                "  \"tenantId\": \"11111111-2222-3333-4444-555555555555\",\n",
                "  \"clientId\": \"66666666-7777-8888-9999-000000000000\",\n",
                "  \"subscriptionId\": \"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\",\n",
                "  \"clientSecret\": \"Azur3SpnClientSecretValueQwErTy123456789!\"\n",
                "}\n"
            ),
        ));
        assert_eq!(azure_findings.len(), 1);
        assert_eq!(
            azure_findings[0].detector,
            "azure_service_principal_client_secret"
        );

        let google_findings = engine.scan_document(&document(
            "/google/oauth-client.json",
            concat!(
                "{\n",
                "  \"installed\": {\n",
                "    \"client_id\": \"123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com\",\n",
                "    \"project_id\": \"sample-project\",\n",
                "    \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n",
                "    \"token_uri\": \"https://oauth2.googleapis.com/token\",\n",
                "    \"client_secret\": \"GOCSPX-1234567890abcdefghijklmnopqrstuv\"\n",
                "  }\n",
                "}\n"
            ),
        ));
        assert_eq!(google_findings.len(), 1);
        assert_eq!(google_findings[0].detector, "google_oauth_client_secret");
    }

    #[test]
    fn detector_engine_ignores_placeholder_cloud_credential_artifacts() {
        let engine = DetectorEngine::new();

        let aws_findings = engine.scan_document(&document(
            "/.aws/credentials",
            concat!(
                "[default]\n",
                "aws_access_key_id = AKIA1234567890ABCDEF\n",
                "aws_secret_access_key = ${AWS_SECRET_ACCESS_KEY}\n",
                "aws_session_token = <redacted>\n"
            ),
        ));
        let aws_detectors = aws_findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(aws_detectors.contains("aws_access_key_id"));
        assert!(!aws_detectors.contains("aws_shared_credentials_secret_access_key"));
        assert!(!aws_detectors.contains("aws_shared_credentials_session_token"));

        let azure_findings = engine.scan_document(&document(
            "/azure/service-principal.json",
            concat!(
                "{\n",
                "  \"tenantId\": \"11111111-2222-3333-4444-555555555555\",\n",
                "  \"clientId\": \"66666666-7777-8888-9999-000000000000\",\n",
                "  \"clientSecret\": \"your_client_secret_here\"\n",
                "}\n"
            ),
        ));
        assert!(azure_findings.is_empty());

        let google_findings = engine.scan_document(&document(
            "/google/oauth-client.json",
            concat!(
                "{\n",
                "  \"installed\": {\n",
                "    \"client_id\": \"123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com\",\n",
                "    \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n",
                "    \"token_uri\": \"https://oauth2.googleapis.com/token\",\n",
                "    \"client_secret\": \"your_client_secret_here\"\n",
                "  }\n",
                "}\n"
            ),
        ));
        assert!(google_findings.is_empty());
    }

    #[test]
    fn detector_engine_finds_nested_structured_secret_fields_in_json() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/config/app.json",
            concat!(
                "{\n",
                "  \"integrations\": {\n",
                "    \"vendor\": {\n",
                "      \"api\": { \"key\": \"Zx9wVb3qRt7yLm2Nf8KpQ4sJd6Hc1XvB0mNeUaYw\" },\n",
                "      \"oauth\": { \"client\": { \"secret\": \"Cli3ntS3cretValu3Z9y8x7w6v5u4t3s2AaBb\" } },\n",
                "      \"database\": { \"url\": \"postgres://svcuser:Sup3rS3cretPassw0rd!@db.internal.local:5432/app\" }\n",
                "    }\n",
                "  }\n",
                "}\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_client_secret"));
        assert!(detectors.contains("generic_connection_string"));
    }

    #[test]
    fn detector_engine_finds_nested_structured_secret_fields_in_yaml_and_toml() {
        let engine = DetectorEngine::new();

        let yaml_findings = engine.scan_document(&document(
            "/settings/runtime.yaml",
            concat!(
                "integrations:\n",
                "  payments:\n",
                "    client:\n",
                "      secret: Paym3ntSecretValueAbCdEfGhIjKlMnOpQr\n",
                "  cache:\n",
                "    redis:\n",
                "      url: redis://svcuser:Sup3rRedisPassw0rd!@redis.internal.local:6379/0\n"
            ),
        ));
        let yaml_detectors = yaml_findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(yaml_detectors.contains("generic_client_secret"));
        assert!(yaml_detectors.contains("generic_connection_string"));

        let toml_findings = engine.scan_document(&document(
            "/config/runtime.toml",
            concat!(
                "[oauth.client]\n",
                "secret = \"TomlClientSecretValue9QwErTyUiOpAsDfGhJkLz\"\n\n",
                "[database]\n",
                "url = \"mysql://svcuser:Sup3rMySqlPassw0rd!@mysql.internal.local:3306/app\"\n"
            ),
        ));
        let toml_detectors = toml_findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(toml_detectors.contains("generic_client_secret"));
        assert!(toml_detectors.contains("generic_connection_string"));
    }

    #[test]
    fn detector_engine_ignores_nested_structured_placeholders() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/config/app.json",
            concat!(
                "{\n",
                "  \"integrations\": {\n",
                "    \"vendor\": {\n",
                "      \"api\": { \"key\": \"${API_KEY}\" },\n",
                "      \"oauth\": { \"client\": { \"secret\": \"your_client_secret_here\" } },\n",
                "      \"database\": { \"url\": \"postgres://user:password@example.com:5432/app\" }\n",
                "    }\n",
                "  }\n",
                "}\n"
            ),
        ));

        assert!(findings.is_empty());
    }

    #[test]
    fn detector_engine_ignores_placeholder_structured_credentials() {
        let engine = DetectorEngine::new();

        let npm_findings = engine.scan_document(&document(
            "/.npmrc",
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
        ));
        assert!(npm_findings.is_empty());

        let pypirc_findings = engine.scan_document(&document(
            "/.pypirc",
            "[pypi]\nusername = __token__\npassword = changeme123\n",
        ));
        assert!(pypirc_findings.is_empty());

        let docker_findings = engine.scan_document(&document(
            "/.docker/config.json",
            r#"{"auths":{"registry.example.test":{"auth":"<redacted>"}}}"#,
        ));
        // The path-exposure detector \`json_config_file_exposed\` co-fires on
        // any JSON body at \`/.docker/config.json\` independently of the
        // \`auth\` value. The contract under test is that the structured
        // \`docker_registry_auth\` detector recognizes the placeholder and
        // does not fire, so assert only on that detector being absent.
        assert!(
            docker_findings
                .iter()
                .all(|finding| finding.detector != "docker_registry_auth"),
            "docker_registry_auth must not fire on placeholder \"<redacted>\", got {docker_findings:?}",
        );
    }

    #[test]
    fn detector_engine_ignores_placeholders_and_examples() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/application.yml",
            concat!(
                "API_KEY=your_api_key_here\n",
                "ACCESS_TOKEN=${ACCESS_TOKEN}\n",
                "PASSWORD=changeme123\n",
                "DATABASE_URL=postgres://user:password@example.com:5432/app\n",
                "AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=example;AccountKey=<redacted>;EndpointSuffix=core.windows.net\n"
            ),
        ));

        assert!(findings.is_empty());
    }

    #[test]
    fn detector_engine_prefers_specific_detectors_over_generic_matches() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/.env",
            "OPENAI_API_KEY=sk-proj-1234567890abcdefghijklmnopqrstuv",
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        // The specific OpenAI detector must fire and crowd out any generic
        // \`generic_api_key\`/\`generic_access_token\` match for the same value.
        // The path-exposure detector \`dotenv_file_exposed\` is allowed to
        // co-fire because it reports a different concern (file on a public
        // path) and is not a generic-secret detector.
        assert!(detectors.contains("openai_api_key"));
        assert!(!detectors.contains("generic_api_key"));
        assert!(!detectors.contains("generic_access_token"));
    }

    #[test]
    fn detector_engine_prefers_specific_registry_detectors_over_structured_fallbacks() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/.npmrc",
            "//registry.npmjs.org/:_authToken=npm_1234567890abcdefghijklmnopqrstuvwxyz\n",
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "npm_access_token");
    }

    #[test]
    fn detector_engine_broadly_finds_generic_key_and_token_shapes() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/runtime-config.json",
            concat!(
                "X_API_KEY=key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2\n",
                "PRIVATE_TOKEN=tok_AbCdEfGhIjKlMnOpQrStUvWxYz123456\n",
                "SESSION_SECRET=shh_9z8y7x6w5v4u3t2s1r0qPONMLKJIHG\n",
                "LICENSE_KEY=lic-1234-ABCDEFGHijklmnopQRSTuvwxYZ\n",
                "AUTHORIZATION=Bearer pat_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6\n",
                "PASSPHRASE=VaultDoorPassphrase2026!\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_client_secret"));
        assert!(detectors.contains("generic_authorization_header"));
        assert!(detectors.contains("generic_password"));
    }

    #[test]
    fn detector_engine_finds_broad_structured_secret_fields() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/settings/runtime.yaml",
            concat!(
                "integrations:\n",
                "  upstream:\n",
                "    serviceKey: key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2\n",
                "    privateToken: tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654\n",
                "    sessionSecret: Sup3rSess10nSecretValueAlphaBeta\n",
                "    credentials: CredValueAbCdEfGhIjKlMnOpQrSt\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_client_secret"));
        assert!(detectors.contains("generic_credential"));
    }

    #[test]
    fn detector_engine_avoids_generic_key_outside_secret_contexts() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/public/index.html",
            concat!(
                "token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJwdWJsaWMifQ.signaturevalue123456\n",
                "key = key_1234567890ABCDEFGHIJKLMNOPQRST\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(!detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
    }

    #[test]
    fn detector_engine_finds_generic_response_header_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/status",
            "",
            &[
                ("X-Api-Key", "key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2"),
                (
                    "Authorization",
                    "Bearer pat_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
                ),
                ("X-Auth-Token", "tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654"),
            ],
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_authorization_header"));
        assert!(detectors.contains("generic_access_token"));
        assert!(findings.iter().any(|finding| {
            finding
                .review_labels
                .iter()
                .any(|label| label == "response_header_secret")
        }));
    }

    #[test]
    fn detector_engine_finds_generic_query_parameter_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&FetchedDocument {
            path: "/download".to_string(),
            url: "https://example.test/download?api_key=key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2&private_token=tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654&session_secret=Sup3rSess10nSecretValueAlphaBeta".to_string(),
            status: 200,
            content_type: Some("text/plain".to_string()),
            headers: Vec::new(),
            body: String::new(),
            truncated: false,
            coverage_source: "test-seed".to_string(),
        });

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_client_secret"));
        assert!(findings.iter().any(|finding| {
            finding
                .review_labels
                .iter()
                .any(|label| label == "query_secret")
        }));
    }

    #[test]
    fn detector_engine_ignores_placeholder_header_and_query_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&FetchedDocument {
            path: "/public".to_string(),
            url:
                "https://example.test/public?api_key=your_api_key_here&private_token=%24%7BTOKEN%7D"
                    .to_string(),
            status: 200,
            content_type: Some("text/plain".to_string()),
            headers: vec![
                ("X-Api-Key".to_string(), "your_api_key_here".to_string()),
                ("Authorization".to_string(), "Bearer ${TOKEN}".to_string()),
                (
                    "Strict-Transport-Security".to_string(),
                    "max-age=31536000".to_string(),
                ),
            ],
            body: String::new(),
            truncated: false,
            coverage_source: "test-seed".to_string(),
        });

        assert!(findings.is_empty());
    }

    #[test]
    fn detector_engine_finds_generic_cookie_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/login",
            "",
            &[
                (
                    "Set-Cookie",
                    "sessionid=4f8c2d1a7b9e6f0c3d5a8b1c7e9f2a4d; Path=/; HttpOnly",
                ),
                (
                    "Set-Cookie",
                    "remember_me=tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654; Path=/; Secure",
                ),
            ],
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_session_cookie"));
        assert!(findings.iter().any(|finding| {
            finding
                .review_labels
                .iter()
                .any(|label| label == "cookie_secret")
        }));
    }

    #[test]
    fn detector_engine_finds_cookie_header_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/debug",
            "",
            &[(
                "Cookie",
                "session_token=tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654; private_token=pat_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
            )],
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_session_cookie"));
        assert!(detectors.contains("generic_access_token"));
    }

    #[test]
    fn detector_engine_ignores_placeholder_cookie_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/public",
            "",
            &[
                ("Set-Cookie", "sessionid=changeme123; Path=/"),
                (
                    "Cookie",
                    "remember_me=${TOKEN}; private_token=your_api_key_here",
                ),
                ("Strict-Transport-Security", "max-age=31536000"),
            ],
        ));

        assert!(findings.is_empty());
    }

    #[test]
    fn detector_engine_finds_generic_html_attribute_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<html><head>",
                "<meta name=\"api-key\" content=\"key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2\">",
                "<meta property=\"private-token\" content=\"tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654\">",
                "</head><body>",
                "<div data-session-secret=\"Sup3rSess10nSecretValueAlphaBeta\"></div>",
                "<input type=\"hidden\" name=\"service_key\" value=\"key_AbCdEfGhIjKlMnOpQrStUvWxYz123456\">",
                "</body></html>"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_client_secret"));
        assert!(findings.iter().any(|finding| {
            finding
                .review_labels
                .iter()
                .any(|label| label == "html_attribute_secret")
        }));
    }

    #[test]
    fn detector_engine_ignores_placeholder_html_attribute_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<html><head>",
                "<meta name=\"api-key\" content=\"your_api_key_here\">",
                "</head><body>",
                "<div data-session-secret=\"${SESSION_SECRET}\"></div>",
                "<input type=\"hidden\" name=\"service_key\" value=\"changeme123\">",
                "</body></html>"
            ),
        ));

        assert!(findings.is_empty());
    }

    #[test]
    fn detector_engine_finds_script_tag_bootstrap_json_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script id=\"__NEXT_DATA__\" type=\"application/json\">",
                "{\"props\":{\"pageProps\":{\"api_key\":\"key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2\",\"private_token\":\"tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654\",\"session_secret\":\"Sup3rSess10nSecretValueAlphaBeta\"}}}",
                "</script>"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_client_secret"));
    }

    #[test]
    fn detector_engine_finds_serialized_html_attribute_blob_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<div data-state='{\"api_key\":\"key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2\",\"private_token\":\"tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654\"}'></div>",
                "<div x-data=\"{ session_secret: 'Sup3rSess10nSecretValueAlphaBeta' }\"></div>"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_client_secret"));
        assert!(findings.iter().any(|finding| {
            finding
                .matched_signals
                .iter()
                .any(|signal| signal == "html_attribute_blob")
        }));
    }

    #[test]
    fn detector_engine_finds_html_entity_encoded_attribute_blob_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            "<div data-state=\"{&quot;api_key&quot;:&quot;key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2&quot;,&quot;private_token&quot;:&quot;tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654&quot;}\"></div>",
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
    }

    #[test]
    fn detector_engine_finds_generic_inline_script_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "window.__ENV__ = {\n",
                "  token: `tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654`,\n",
                "  key: 'key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2',\n",
                "  secret: \"Sup3rSess10nSecretValueAlphaBeta\"\n",
                "};\n",
                "</script>\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_client_secret"));
        assert!(findings.iter().any(|finding| {
            finding
                .review_labels
                .iter()
                .any(|label| label == "inline_script_secret")
        }));
    }

    #[test]
    fn detector_engine_ignores_placeholder_inline_script_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "window.__ENV__ = {\n",
                "  token: `${TOKEN}`,\n",
                "  key: 'your_api_key_here',\n",
                "  secret: \"changeme123\"\n",
                "};\n",
                "</script>\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(!detectors.contains("generic_access_token"));
        assert!(!detectors.contains("generic_api_key"));
        assert!(!detectors.contains("generic_client_secret"));
    }

    #[test]
    fn detector_engine_finds_escaped_inline_script_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "window.__ENV__ = {\n",
                "  token: `tok_\\x5aYXWVUTSRQPONMLKJIHGFEDCBA987654`,\n",
                "  key: 'key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e\\u0032',\n",
                "  secret: \"Sup3rSess10nSecretValueAlpha\\u0042eta\"\n",
                "};\n",
                "</script>\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_client_secret"));
    }

    #[test]
    fn detector_engine_finds_decoded_json_parse_inline_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "window.runtimeConfig = JSON.parse(\"{\\\"api_key\\\":\\\"key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2\\\",\\\"private_token\\\":\\\"tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654\\\",\\\"session_secret\\\":\\\"Sup3rSess10nSecretValueAlphaBeta\\\"}\");\n",
                "</script>\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_client_secret"));
        assert!(findings.iter().any(|finding| {
            finding
                .matched_signals
                .iter()
                .any(|signal| signal == "inline_script_decoded")
        }));
    }

    #[test]
    fn detector_engine_finds_decode_uri_inline_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "window.__ENV__ = decodeURI('%7B%22api_key%22%3A%22key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2%22%2C%22private_token%22%3A%22tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654%22%7D');\n",
                "</script>\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
    }

    #[test]
    fn detector_engine_finds_decoded_atob_inline_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "window.__BOOTSTRAP__ = atob(\"eyJhcGlfa2V5Ijoia2V5X0Y3czhROWIwVDF1MlYzdzRYNXk2WjdhOEI5YzBEMWUyIiwicHJpdmF0ZV90b2tlbiI6InRva19aWVhXVlVUU1JRUE9OTUxLSklIR0ZFRENCQTk4NzY1NCJ9\");\n",
                "</script>\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
    }

    #[test]
    fn detector_engine_ignores_placeholder_decoded_inline_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "window.runtimeConfig = JSON.parse(\"{\\\"api_key\\\":\\\"your_api_key_here\\\",\\\"private_token\\\":\\\"${TOKEN}\\\",\\\"session_secret\\\":\\\"changeme123\\\"}\");\n",
                "</script>\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(!detectors.contains("generic_api_key"));
        assert!(!detectors.contains("generic_access_token"));
        assert!(!detectors.contains("generic_client_secret"));
    }

    #[test]
    fn detector_engine_finds_unescape_inline_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "window.runtimeConfig = unescape('%7B%22session_secret%22%3A%22Sup3rSess10nSecretValueAlphaBeta%22%2C%22api_key%22%3A%22key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2%22%7D');\n",
                "</script>\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_client_secret"));
        assert!(detectors.contains("generic_api_key"));
    }

    #[test]
    fn detector_engine_finds_inline_storage_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "localStorage.setItem('api_key', 'key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2');\n",
                "sessionStorage.setItem(\"private_token\", \"tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654\");\n",
                "document.cookie = \"sessionid=4f8c2d1a7b9e6f0c3d5a8b1c7e9f2a4d; path=/\";\n",
                "</script>\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_session_cookie"));
        assert!(findings.iter().any(|finding| {
            finding
                .review_labels
                .iter()
                .any(|label| label == "browser_storage_secret")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .matched_signals
                .iter()
                .any(|signal| signal == "inline_storage")
        }));
    }

    #[test]
    fn detector_engine_ignores_placeholder_inline_storage_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "localStorage.setItem('api_key', 'your_api_key_here');\n",
                "sessionStorage.setItem(\"private_token\", \"${TOKEN}\");\n",
                "document.cookie = \"sessionid=changeme123; path=/\";\n",
                "</script>\n"
            ),
        ));

        assert!(findings.is_empty());
    }

    #[test]
    fn detector_engine_finds_inline_storage_property_and_cookie_helper_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "localStorage.api_key = 'key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2';\n",
                "sessionStorage['private_token'] = \"tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654\";\n",
                "Cookies.set('sessionid', '4f8c2d1a7b9e6f0c3d5a8b1c7e9f2a4d');\n",
                "</script>\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_session_cookie"));
    }

    #[test]
    fn detector_engine_ignores_placeholder_inline_storage_property_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<script>\n",
                "localStorage.api_key = 'your_api_key_here';\n",
                "sessionStorage['private_token'] = \"${TOKEN}\";\n",
                "Cookies.set('sessionid', 'changeme123');\n",
                "</script>\n"
            ),
        ));

        assert!(findings.is_empty());
    }

    #[test]
    fn detector_engine_finds_generic_fragment_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<a href=\"https://example.test/callback#access_token=tok_ZYXWVUTSRQPONMLKJIHGFEDCBA987654&id_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdGEifQ.signaturevalue123456\">continue</a>\n",
                "<script>window.location.hash = '#api_key=key_F7s8Q9r0T1u2V3w4X5y6Z7a8B9c0D1e2&session_secret=Sup3rSess10nSecretValueAlphaBeta';</script>\n"
            ),
        ));

        let detectors = findings
            .iter()
            .map(|finding| finding.detector.as_str())
            .collect::<HashSet<_>>();
        assert!(detectors.contains("generic_access_token"));
        assert!(detectors.contains("generic_api_key"));
        assert!(detectors.contains("generic_client_secret"));
        assert!(findings.iter().any(|finding| {
            finding
                .review_labels
                .iter()
                .any(|label| label == "fragment_secret")
        }));
    }

    #[test]
    fn detector_engine_ignores_placeholder_fragment_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document(
            "/index.html",
            concat!(
                "<a href=\"https://example.test/callback#access_token=${TOKEN}&api_key=your_api_key_here\">continue</a>\n",
                "<script>window.location.hash = '#session_secret=changeme123';</script>\n"
            ),
        ));

        assert!(findings.is_empty());
    }

    #[test]
    fn detector_prefilter_targets_only_relevant_families() {
        let candidates = candidate_detectors(&document(
            "/config.js",
            concat!(
                "const token='github_pat_example'; ",
                "const hook='https://hooks.slack.com/services/T/B/C'; ",
                "const gitlab='glpat-example';"
            ),
        ))
        .into_iter()
        .map(|detector| detector.name)
        .collect::<HashSet<_>>();

        assert!(candidates.contains("github_personal_access_token"));
        assert!(candidates.contains("slack_webhook"));
        assert!(candidates.contains("gitlab_personal_access_token"));
        assert!(!candidates.contains("google_api_key"));
        assert!(!candidates.contains("aws_access_key_id"));
    }

    #[test]
    fn detector_prefilter_uses_path_hints_for_structured_detectors() {
        let candidates = candidate_detectors(&document(
            "/.npmrc",
            "registry=https://registry.npmjs.org/\n_authToken=${NPM_TOKEN}\n",
        ))
        .into_iter()
        .map(|detector| detector.name)
        .collect::<HashSet<_>>();

        assert!(candidates.contains("npm_registry_auth"));
        assert!(!candidates.contains("kubeconfig_embedded_credential"));
    }

    const PYTHON_TRACEBACK: &str = concat!(
        "Traceback (most recent call last):\n",
        "  File \"/srv/app/views.py\", line 42, in handle_request\n",
        "    user = User.objects.get(pk=request.GET['id'])\n",
        "  File \"/srv/app/.venv/lib/python3.11/site-packages/django/db/models/manager.py\", line 85, in manager_method\n",
        "    return getattr(self.get_queryset(), name)(*args, **kwargs)\n",
        "django.core.exceptions.ObjectDoesNotExist: User matching query does not exist.\n"
    );

    const JAVA_STACK_TRACE: &str = concat!(
        "java.lang.NullPointerException: Cannot invoke \"User.getId()\" because \"user\" is null\n",
        "\tat com.example.app.UserController.show(UserController.java:128)\n",
        "\tat org.springframework.web.method.support.InvocableHandlerMethod.doInvoke(InvocableHandlerMethod.java:205)\n",
        "\tat io.netty.handler.codec.http.HttpServerCodec.callDecode(HttpServerCodec.java:64)\n"
    );

    const DOTNET_YSOD: &str = concat!(
        "<html>\n",
        "  <head>\n",
        "    <title>Server Error in '/' Application.</title>\n",
        "  </head>\n",
        "  <body bgcolor=\"white\">\n",
        "    <span><h1>Server Error in '/' Application.<hr width=100% size=1 color=silver></h1>\n",
        "    <h2>[NullReferenceException: Object reference not set to an instance of an object.]</h2>\n",
        "  </body>\n",
        "</html>\n"
    );

    const RAILS_DIAGNOSTIC: &str = concat!(
        "<!DOCTYPE html>\n",
        "<html>\n",
        "<head>\n",
        "  <title>Action Controller: Exception caught</title>\n",
        "</head>\n",
        "<body>\n",
        "  <h1>ActiveRecord::RecordNotFound in UsersController#show</h1>\n",
        "  <p>Couldn't find User with 'id'=99</p>\n",
        "</body>\n",
        "</html>\n"
    );

    const NODE_JS_ERROR: &str = concat!(
        "TypeError: Cannot read properties of undefined (reading 'name')\n",
        "    at Object.handle (/srv/api/handlers/user.js:42:18)\n",
        "    at processTicksAndRejections (node:internal/process/task_queues:96:5)\n"
    );

    fn verbose_stack_trace_findings(body: &str) -> Vec<FindingCandidate> {
        let engine = DetectorEngine::new();
        engine
            .scan_document(&document("/error", body))
            .into_iter()
            .filter(|finding| finding.detector == "verbose_stack_trace_disclosure")
            .collect()
    }

    #[test]
    fn verbose_stack_trace_detector_fires_on_python_traceback() {
        let findings = verbose_stack_trace_findings(PYTHON_TRACEBACK);
        let finding = findings
            .first()
            .expect("python traceback should fire detector");
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.confidence, Some(FindingConfidence::High));
        assert!(finding.evidence.starts_with("Traceback (most recent call last):"));
        assert!(finding.evidence.chars().count() <= 201, "evidence over budget: {}", finding.evidence);
    }

    #[test]
    fn verbose_stack_trace_detector_fires_on_java_stack_trace() {
        let findings = verbose_stack_trace_findings(JAVA_STACK_TRACE);
        assert!(
            findings.len() >= 2,
            "expected multiple Java frames to fire, got {}",
            findings.len()
        );
        for finding in &findings {
            assert_eq!(finding.severity, Severity::Low);
            assert_eq!(finding.confidence, Some(FindingConfidence::High));
        }
    }

    #[test]
    fn verbose_stack_trace_detector_fires_on_dotnet_ysod() {
        let findings = verbose_stack_trace_findings(DOTNET_YSOD);
        assert!(
            findings
                .iter()
                .any(|finding| finding.evidence.contains("Server Error in")
                    || finding.evidence.contains("NullReferenceException")),
            "expected .NET YSOD finding, got {findings:?}"
        );
    }

    #[test]
    fn verbose_stack_trace_detector_fires_on_rails_diagnostic_page() {
        let findings = verbose_stack_trace_findings(RAILS_DIAGNOSTIC);
        assert!(
            findings
                .iter()
                .any(|finding| finding.evidence.contains("Action Controller")
                    || finding.evidence.contains("ActiveRecord::RecordNotFound")),
            "expected Rails finding, got {findings:?}"
        );
    }

    #[test]
    fn verbose_stack_trace_detector_fires_on_node_type_error() {
        let findings = verbose_stack_trace_findings(NODE_JS_ERROR);
        let finding = findings
            .first()
            .expect("node TypeError should fire detector");
        assert!(
            finding.evidence.starts_with("TypeError:"),
            "expected TypeError prefix, got {:?}",
            finding.evidence
        );
        assert_eq!(finding.confidence, Some(FindingConfidence::High));
    }

    #[test]
    fn verbose_stack_trace_detector_does_not_fire_on_benign_html() {
        let benign = concat!(
            "<!DOCTYPE html>\n",
            "<html>\n",
            "  <head><title>Welcome</title></head>\n",
            "  <body>\n",
            "    <h1>Hello, world!</h1>\n",
            "    <p>This is a normal landing page describing our company at example.com.</p>\n",
            "    <p>We use Java for our backend (compiled at com pile time) but no traces here.</p>\n",
            "  </body>\n",
            "</html>\n"
        );
        let findings = verbose_stack_trace_findings(benign);
        assert!(
            findings.is_empty(),
            "benign HTML should not produce findings: {findings:?}"
        );
    }

    #[test]
    fn verbose_stack_trace_evidence_is_truncated_to_two_hundred_characters() {
        // The Node.js alternation matches a span that includes the error
        // message, so a long message lets us exercise truncation.
        let long_message = "x".repeat(400);
        let body = format!(
            "TypeError: {long_message}\n    at handler (/srv/api/handler.js:42:18)\n",
        );
        let findings = verbose_stack_trace_findings(&body);
        let finding = findings
            .first()
            .expect("long type error should still fire detector");
        assert!(
            finding.evidence.ends_with('…'),
            "expected truncation marker, evidence={}",
            finding.evidence
        );
        // 200 ASCII bytes + 1 ellipsis char = 201 chars maximum.
        assert!(
            finding.evidence.chars().count() <= 201,
            "evidence over budget: {} chars",
            finding.evidence.chars().count()
        );
    }

    #[test]
    fn modern_token_detector_fires_on_github_pat_fine_grained_format() {
        let engine = DetectorEngine::new();
        // 11 chars `github_pat_` + 82 alnum/_ chars
        let token = format!(
            "github_pat_{}",
            "A1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY3zABCDE_FGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"
        );
        assert_eq!(token.len() - "github_pat_".len(), 82);
        let body = format!("const gh='{token}';\n");
        let findings = engine.scan_document(&document("/config.js", &body));

        let detectors: HashSet<_> = findings.iter().map(|f| f.detector.as_str()).collect();
        assert!(detectors.contains("github_pat_fine_grained"));

        // Near-miss: 81-char body must not fire the fine-grained detector.
        let short = format!(
            "github_pat_{}",
            "A1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY3zABCDE_FGHIJKLMNOPQRSTUVWXYZabcdefghijklmno"
        );
        assert_eq!(short.len() - "github_pat_".len(), 81);
        let findings_short = engine.scan_document(&document(
            "/config.js",
            &format!("const gh='{short}';\n"),
        ));
        assert!(
            !findings_short
                .iter()
                .any(|f| f.detector == "github_pat_fine_grained")
        );
    }

    #[test]
    fn modern_token_detector_fires_on_cloudflare_api_token_with_context() {
        let engine = DetectorEngine::new();
        // 40-char [A-Za-z0-9_-] token (must end in word char so \b matches).
        let token = "A1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2x-Y3z";
        assert_eq!(token.len(), 40);

        let with_context = format!("# Cloudflare API token\nCF_API_TOKEN={token}\n");
        let findings = engine.scan_document(&document("/cloudflare.env", &with_context));
        let detectors: HashSet<_> = findings.iter().map(|f| f.detector.as_str()).collect();
        assert!(detectors.contains("cloudflare_api_token"));

        // Near-miss: same token without any cloudflare/CF/X-Auth-Email context.
        let without_context = format!("API_TOKEN={token}\n");
        let findings_bare = engine.scan_document(&document("/notes.txt", &without_context));
        assert!(
            !findings_bare
                .iter()
                .any(|f| f.detector == "cloudflare_api_token"),
            "cloudflare_api_token must require contextual keyword"
        );
    }

    #[test]
    fn modern_token_detector_fires_on_datadog_api_key_with_context() {
        let engine = DetectorEngine::new();
        let token = "0123456789abcdef0123456789abcdef";
        assert_eq!(token.len(), 32);

        let with_context = format!("# datadog agent config\nDD_API_KEY={token}\n");
        let findings = engine.scan_document(&document("/datadog.yaml", &with_context));
        let detectors: HashSet<_> = findings.iter().map(|f| f.detector.as_str()).collect();
        assert!(detectors.contains("datadog_api_key"));

        // Near-miss: a generic 32-char hex string with no datadog/DD_/dd-agent context.
        let without_context = format!("checksum={token}\n");
        let findings_bare = engine.scan_document(&document("/checksums.txt", &without_context));
        assert!(
            !findings_bare
                .iter()
                .any(|f| f.detector == "datadog_api_key")
        );
    }

    #[test]
    fn modern_token_detector_fires_on_jwt_alg_none_only() {
        let engine = DetectorEngine::new();
        // Header is `{"alg":"none","typ":"JWT"}` base64url-encoded; payload `{"sub":"1"}`; empty signature.
        let alg_none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.";
        let body_alg_none = format!("token={alg_none}\n");
        let findings = engine.scan_document(&document("/login.html", &body_alg_none));
        let detectors: HashSet<_> = findings.iter().map(|f| f.detector.as_str()).collect();
        assert!(detectors.contains("jwt_alg_none"));

        // Near-miss: alg:HS256 must NOT fire jwt_alg_none.
        let alg_hs256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlYWJjZGVmZw";
        let body_hs256 = format!("token={alg_hs256}\n");
        let findings_hs = engine.scan_document(&document("/login.html", &body_hs256));
        assert!(!findings_hs.iter().any(|f| f.detector == "jwt_alg_none"));
    }

    #[test]
    fn modern_token_detectors_redact_secret_values() {
        let engine = DetectorEngine::new();
        let alg_none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.";
        let findings = engine.scan_document(&document(
            "/login.html",
            &format!("token={alg_none}\n"),
        ));
        let jwt = findings
            .iter()
            .find(|f| f.detector == "jwt_alg_none")
            .expect("jwt_alg_none finding");
        // redact_secret should mask the middle of the token.
        assert!(jwt.redacted_value.contains("****"));
        // The full token must not appear verbatim in redacted_value.
        assert!(!jwt.redacted_value.contains(alg_none));
    }

    #[test]
    fn header_policy_open_cors_with_credentials_fires_on_wildcard_with_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/api/data",
            "{}",
            &[
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        ));

        let finding = findings
            .iter()
            .find(|finding| finding.detector == "open_cors_with_credentials")
            .expect("open_cors_with_credentials finding");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(
            finding.confidence,
            Some(crate::core::FindingConfidence::High)
        );
        assert_eq!(finding.redacted_value, "*");
        assert!(finding.evidence.contains("status=200"));
    }

    #[test]
    fn header_policy_open_cors_with_credentials_does_not_fire_without_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/api/data",
            "{}",
            &[("Access-Control-Allow-Origin", "*")],
        ));
        assert!(
            !findings
                .iter()
                .any(|finding| finding.detector == "open_cors_with_credentials")
        );
    }

    #[test]
    fn header_policy_open_cors_with_credentials_does_not_fire_when_safe() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/api/data",
            "{}",
            &[
                ("Access-Control-Allow-Origin", "https://trusted.example"),
                ("Access-Control-Allow-Credentials", "false"),
            ],
        ));
        assert!(
            !findings
                .iter()
                .any(|finding| finding.detector == "open_cors_with_credentials")
        );
    }

    #[test]
    fn header_policy_open_cors_reflective_origin_fires_on_specific_origin_with_credentials() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/api/data",
            "{}",
            &[
                ("Access-Control-Allow-Origin", "https://attacker.example"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        ));

        let finding = findings
            .iter()
            .find(|finding| finding.detector == "open_cors_reflective_origin")
            .expect("open_cors_reflective_origin finding");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(
            finding.confidence,
            Some(crate::core::FindingConfidence::Medium)
        );
        assert_eq!(finding.redacted_value, "https://attacker.example");
    }

    #[test]
    fn header_policy_open_cors_reflective_origin_does_not_fire_on_null_origin() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/api/data",
            "{}",
            &[
                ("Access-Control-Allow-Origin", "null"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
        ));
        assert!(
            !findings
                .iter()
                .any(|finding| finding.detector == "open_cors_reflective_origin")
        );
    }

    #[test]
    fn header_policy_missing_hsts_fires_on_https_without_header() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers("/", "<html></html>", &[]));

        let finding = findings
            .iter()
            .find(|finding| finding.detector == "missing_hsts_on_https")
            .expect("missing_hsts_on_https finding");
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(
            finding.confidence,
            Some(crate::core::FindingConfidence::High)
        );
    }

    #[test]
    fn header_policy_missing_hsts_does_not_fire_when_header_is_present() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/",
            "<html></html>",
            &[("Strict-Transport-Security", "max-age=63072000")],
        ));
        assert!(
            !findings
                .iter()
                .any(|finding| finding.detector == "missing_hsts_on_https")
        );
    }

    #[test]
    fn header_policy_missing_hsts_does_not_fire_on_http() {
        let mut doc = document_with_headers("/", "<html></html>", &[]);
        doc.url = "http://insecure.test/".to_string();
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&doc);
        assert!(
            !findings
                .iter()
                .any(|finding| finding.detector == "missing_hsts_on_https")
        );
    }

    #[test]
    fn header_policy_weak_csp_fires_on_unsafe_inline_in_script_src() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/",
            "<html></html>",
            &[(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'",
            )],
        ));

        let finding = findings
            .iter()
            .find(|finding| finding.detector == "weak_csp_unsafe_directives")
            .expect("weak_csp_unsafe_directives finding");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(
            finding.confidence,
            Some(crate::core::FindingConfidence::High)
        );
        assert!(finding.evidence.contains("script-src"));
    }

    #[test]
    fn header_policy_weak_csp_fires_on_unsafe_eval_in_default_src() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/",
            "<html></html>",
            &[(
                "Content-Security-Policy",
                "default-src 'self' 'unsafe-eval'",
            )],
        ));
        let finding = findings
            .iter()
            .find(|finding| finding.detector == "weak_csp_unsafe_directives")
            .expect("weak_csp_unsafe_directives finding");
        assert!(finding.evidence.contains("default-src"));
    }

    #[test]
    fn header_policy_weak_csp_does_not_fire_on_strict_policy() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/",
            "<html></html>",
            &[(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'nonce-abc123'",
            )],
        ));
        assert!(
            !findings
                .iter()
                .any(|finding| finding.detector == "weak_csp_unsafe_directives")
        );
    }

    #[test]
    fn header_policy_weak_csp_ignores_unsafe_in_other_directives() {
        let engine = DetectorEngine::new();
        let findings = engine.scan_document(&document_with_headers(
            "/",
            "<html></html>",
            &[(
                "Content-Security-Policy",
                "style-src 'self' 'unsafe-inline'; script-src 'self'",
            )],
        ));
        assert!(
            !findings
                .iter()
                .any(|finding| finding.detector == "weak_csp_unsafe_directives")
        );
    }

    fn swagger_document(
        path: &str,
        status: u16,
        content_type: Option<&str>,
        body: &str,
    ) -> FetchedDocument {
        FetchedDocument {
            path: path.to_string(),
            url: format!("https://example.test{path}"),
            status,
            content_type: content_type.map(|value| value.to_string()),
            headers: vec![("Strict-Transport-Security".to_string(), "max-age=31536000".to_string())],
            body: body.to_string(),
            truncated: false,
            coverage_source: "test-seed".to_string(),
        }
    }

    fn has_swagger_ui_finding(findings: &[FindingCandidate]) -> bool {
        findings.iter().any(|finding| {
            finding
                .plugin_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.plugin_id == "SwaggerUIPlugin")
        })
    }

    fn find_swagger_ui_finding(findings: &[FindingCandidate]) -> Option<&FindingCandidate> {
        findings.iter().find(|finding| {
            finding
                .plugin_metadata
                .as_ref()
                .is_some_and(|metadata| metadata.plugin_id == "SwaggerUIPlugin")
        })
    }

    #[test]
    fn swagger_ui_plugin_skips_non_2xx_spec_paths() {
        let engine = DetectorEngine::new();
        let body = "<html><title>403 Forbidden</title>nothing here</html>";
        for status in [400_u16, 403, 404, 500, 502] {
            let findings = engine.scan_document(&swagger_document(
                "/openapi.json",
                status,
                Some("text/html"),
                body,
            ));
            assert!(
                !has_swagger_ui_finding(&findings),
                "SwaggerUIPlugin should not fire on HTTP {status} response"
            );
        }
    }

    #[test]
    fn swagger_ui_plugin_skips_html_without_swagger_ui_keywords() {
        let engine = DetectorEngine::new();
        let body = "<html><body>Welcome to a parked domain.</body></html>";
        let findings = engine.scan_document(&swagger_document(
            "/openapi.json",
            200,
            Some("text/html"),
            body,
        ));
        assert!(
            !has_swagger_ui_finding(&findings),
            "SwaggerUIPlugin must require swagger/openapi structural evidence on JSON spec paths"
        );
    }

    #[test]
    fn swagger_ui_plugin_skips_json_lacking_openapi_or_swagger_keys() {
        let engine = DetectorEngine::new();
        let body = "{\"hello\":\"world\",\"items\":[1,2,3,4,5,6,7,8,9,10,11,12]}";
        let findings = engine.scan_document(&swagger_document(
            "/openapi.json",
            200,
            Some("application/json"),
            body,
        ));
        assert!(
            !has_swagger_ui_finding(&findings),
            "SwaggerUIPlugin must require an openapi/swagger top-level key on JSON spec paths"
        );
    }

    #[test]
    fn swagger_ui_plugin_skips_tiny_bodies() {
        let engine = DetectorEngine::new();
        let body = "{}";
        let findings = engine.scan_document(&swagger_document(
            "/openapi.json",
            200,
            Some("application/json"),
            body,
        ));
        assert!(
            !has_swagger_ui_finding(&findings),
            "SwaggerUIPlugin must ignore bodies under 50 bytes"
        );
    }

    #[test]
    fn swagger_ui_plugin_matches_openapi_3_json_spec() {
        let engine = DetectorEngine::new();
        let body = r#"{
  "openapi": "3.0.3",
  "info": { "title": "Example API", "version": "1.0.0" },
  "paths": { "/widgets": { "get": { "summary": "List widgets" } } }
}"#;
        let findings = engine.scan_document(&swagger_document(
            "/openapi.json",
            200,
            Some("application/json"),
            body,
        ));
        let finding =
            find_swagger_ui_finding(&findings).expect("OpenAPI 3.x JSON spec should match");
        let signal = finding
            .matched_signals
            .iter()
            .find(|s| s.contains("openapi"))
            .unwrap_or_else(|| {
                panic!(
                    "matched_signals must record the matched substring, got {:?}",
                    finding.matched_signals
                )
            });
        assert!(
            signal.contains(':'),
            "matched_signal must include the JSON key colon, got {signal:?}"
        );
        assert!(
            finding.evidence.contains("status=200"),
            "evidence should include status code, got {:?}",
            finding.evidence
        );
        assert!(
            !finding.evidence.contains("****"),
            "evidence must not redact non-secret swagger markers, got {:?}",
            finding.evidence
        );
    }

    #[test]
    fn swagger_ui_plugin_matches_swagger_2_json_spec() {
        let engine = DetectorEngine::new();
        let body = r#"{
  "swagger": "2.0",
  "info": { "title": "Legacy API", "version": "0.0.1" },
  "host": "example.test",
  "basePath": "/v1",
  "paths": {}
}"#;
        let findings = engine.scan_document(&swagger_document(
            "/v2/api-docs",
            200,
            Some("application/json"),
            body,
        ));
        let finding =
            find_swagger_ui_finding(&findings).expect("Swagger 2.0 JSON spec should match");
        assert!(
            finding
                .matched_signals
                .iter()
                .any(|signal| signal.contains("swagger")),
            "matched_signals must record the matched substring, got {:?}",
            finding.matched_signals
        );
    }

    #[test]
    fn swagger_ui_plugin_matches_swagger_ui_html() {
        let engine = DetectorEngine::new();
        let body = r#"<!doctype html>
<html>
  <head><title>Swagger UI</title></head>
  <body>
    <div id="swagger-ui"></div>
    <script src="./swagger-ui-bundle.js"></script>
  </body>
</html>"#;
        let findings = engine.scan_document(&swagger_document(
            "/swagger-ui/",
            200,
            Some("text/html"),
            body,
        ));
        let finding =
            find_swagger_ui_finding(&findings).expect("swagger-ui HTML page should match");
        assert!(
            finding
                .matched_signals
                .iter()
                .any(|signal| signal == "swagger-ui-bundle.js"),
            "matched_signals must capture the swagger-ui bundle reference, got {:?}",
            finding.matched_signals
        );
    }

    #[test]
    fn swagger_ui_plugin_skips_yaml_spec_without_openapi_prefix() {
        let engine = DetectorEngine::new();
        let body = "title: Some Document\nversion: 1.0\ndescription: not actually a spec\n";
        let findings = engine.scan_document(&swagger_document(
            "/openapi.yaml",
            200,
            Some("text/yaml"),
            body,
        ));
        assert!(
            !has_swagger_ui_finding(&findings),
            "YAML spec path requires the body to start with openapi: or swagger:"
        );
    }

    #[test]
    fn swagger_ui_plugin_skips_json_with_swagger_only_in_string_value() {
        let engine = DetectorEngine::new();
        let body = r#"{"message":"swagger is great","detail":"this is not an openapi spec at all, just a regular response payload"}"#;
        let findings = engine.scan_document(&swagger_document(
            "/openapi.json",
            200,
            Some("application/json"),
            body,
        ));
        assert!(
            !has_swagger_ui_finding(&findings),
            "JSON value containing the word `swagger` is not a key and must not match"
        );
    }

    #[test]
    fn swagger_ui_plugin_skips_json_spec_path_with_html_content_type() {
        let engine = DetectorEngine::new();
        let body = r#"{
  "openapi": "3.0.3",
  "info": { "title": "Example API", "version": "1.0.0" },
  "paths": {}
}"#;
        let findings = engine.scan_document(&swagger_document(
            "/openapi.json",
            200,
            Some("text/html; charset=utf-8"),
            body,
        ));
        assert!(
            !has_swagger_ui_finding(&findings),
            "JSON spec path with text/html content-type must not match (content-type gate)"
        );
    }

    #[test]
    fn swagger_ui_plugin_skips_yaml_spec_path_with_json_content_type() {
        let engine = DetectorEngine::new();
        let body =
            "openapi: 3.0.3\ninfo:\n  title: Example API\n  version: 1.0.0\npaths: {}\n";
        let findings = engine.scan_document(&swagger_document(
            "/openapi.yaml",
            200,
            Some("application/json"),
            body,
        ));
        assert!(
            !has_swagger_ui_finding(&findings),
            "YAML spec path with application/json content-type must not match (content-type gate)"
        );
    }

    #[test]
    fn swagger_ui_plugin_captures_exact_case_of_matched_substring() {
        let engine = DetectorEngine::new();
        let body = r#"{
  "OpenAPI": "3.0.3",
  "info": { "title": "Example API", "version": "1.0.0" },
  "paths": {}
}"#;
        let findings = engine.scan_document(&swagger_document(
            "/openapi.json",
            200,
            Some("application/json"),
            body,
        ));
        let finding = find_swagger_ui_finding(&findings)
            .expect("mixed-case OpenAPI key should still match");
        let signal = finding
            .matched_signals
            .first()
            .expect("matched_signals must be populated");
        assert!(
            signal.contains("OpenAPI"),
            "matched_signal must preserve the original body casing, got {signal:?}"
        );
        assert!(
            finding.evidence.contains("OpenAPI"),
            "evidence snippet must preserve original casing, got {:?}",
            finding.evidence
        );
    }
}
