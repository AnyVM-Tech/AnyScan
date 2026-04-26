//! Per-host pipelined HEAD probe over a single TCP / TLS connection.
//!
//! This module exists to replace the per-request connect+TLS+request+graceful-close
//! cycle (which tops out at ~62-700 RPS depending on graceful-close stalls) with a
//! pipelined HEAD scan that opens ONE TCP+TLS handshake per host, writes all paths
//! back-to-back, reads responses in order, and closes via TCP RST (SO_LINGER=0).
//!
//! Reference Python prototype: `path_scan_reuse.py` from the AnyScan benchmark
//! suite. Reference numbers on c6in.xlarge for 30-path fuzzing:
//!
//! | variant                                  | successful RPS |
//! | ---------------------------------------- | -------------- |
//! | per-request, graceful close (baseline)   | 47             |
//! | per-request, RST close (SO_LINGER=0)     | 716            |
//! | + 8192 conns, fd ulimit 1M               | 1,711          |
//! | + keep-alive, 1 conn / host              | 3,105          |
//! | + HTTP/1.1 pipelining                    | 3,364          |
//! | sustained 8k hosts × 30 paths            | 9,646          |
//!
//! The graceful-FIN -> RST switch is the single biggest fix: ~50% of hosts on the
//! open internet stall ~30 s on `wait_closed()`.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// Default User-Agent advertised by the probe.
pub const DEFAULT_USER_AGENT: &str = "anyscan-probe/1";

/// Configuration shared across all probes.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// TCP connect timeout (per address).
    pub connect_timeout: Duration,
    /// TLS handshake timeout.
    pub tls_handshake_timeout: Duration,
    /// Time budget for writing all queued bytes.
    pub write_timeout: Duration,
    /// Time budget for reading a single status line + headers block.
    pub read_timeout: Duration,
    /// Total budget across all paths on a single connection.
    pub per_connection_timeout: Duration,
    /// User-Agent header value.
    pub user_agent: String,
    /// Skip TLS certificate verification (lab / pentest only).
    pub allow_invalid_tls: bool,
    /// Extra request headers (e.g. `Authorization`, custom `Cookie`).
    pub extra_headers: Vec<(String, String)>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            tls_handshake_timeout: Duration::from_secs(3),
            write_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
            per_connection_timeout: Duration::from_secs(8),
            user_agent: DEFAULT_USER_AGENT.to_string(),
            allow_invalid_tls: false,
            extra_headers: Vec::new(),
        }
    }
}

/// One HEAD response, parsed up to (but not including) any body.
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// `Connection: close` was advertised by the server.
    pub server_closed: bool,
}

impl ProbeResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Outcome of a `probe_host_paths` call.
#[derive(Debug)]
pub struct PathProbeOutcome {
    /// One result per input path, **in input order**.
    pub responses: Vec<Result<ProbeResponse, ProbeError>>,
    /// `Some(idx)` when the server signalled `Connection: close` at response `idx`.
    /// Slots after `idx` will be `Err(ProbeError::ServerClosedEarly { .. })`.
    pub server_closed_early: Option<usize>,
}

impl PathProbeOutcome {
    pub fn ok_count(&self) -> usize {
        self.responses.iter().filter(|r| r.is_ok()).count()
    }
}

/// Bucketed probe failures.
///
/// Matches the failure categories the bench harness reports: `tls_handshake`,
/// `connect_timeout`, `read_timeout`, `connection_reset`, `malformed_response`.
#[derive(Debug, Clone, Error)]
pub enum ProbeError {
    #[error("connect timeout to {host}:{port}")]
    ConnectTimeout { host: String, port: u16 },
    #[error("connect to {host}:{port} failed: {message}")]
    ConnectError {
        host: String,
        port: u16,
        message: String,
    },
    #[error("TLS handshake timeout to {host}")]
    TlsHandshakeTimeout { host: String },
    #[error("TLS handshake to {host} failed: {message}")]
    TlsHandshake { host: String, message: String },
    #[error("invalid SNI / hostname: {host}")]
    InvalidHost { host: String },
    #[error("write timeout")]
    WriteTimeout,
    #[error("write error: {0}")]
    WriteError(String),
    #[error("read timeout")]
    ReadTimeout,
    #[error("connection reset")]
    ConnectionReset,
    #[error("malformed response: {0}")]
    MalformedResponse(String),
    /// Returned for slots after `server_closed_early`.
    #[error("server closed connection before response {index}")]
    ServerClosedEarly { index: usize },
    #[error("per-connection time budget exhausted before response {index}")]
    BudgetExhausted { index: usize },
    #[error("response too large (header section exceeded {limit} bytes)")]
    HeadersTooLarge { limit: usize },
}

impl ProbeError {
    /// Bucket name suitable for a stats counter (see bench binary).
    pub fn bucket(&self) -> &'static str {
        match self {
            ProbeError::ConnectTimeout { .. } => "connect_timeout",
            ProbeError::ConnectError { .. } => "connect_error",
            ProbeError::TlsHandshakeTimeout { .. } | ProbeError::TlsHandshake { .. } => {
                "tls_handshake"
            }
            ProbeError::InvalidHost { .. } => "invalid_host",
            ProbeError::WriteTimeout => "write_timeout",
            ProbeError::WriteError(_) => "write_error",
            ProbeError::ReadTimeout => "read_timeout",
            ProbeError::ConnectionReset => "connection_reset",
            ProbeError::MalformedResponse(_) => "malformed_response",
            ProbeError::ServerClosedEarly { .. } => "server_closed_early",
            ProbeError::BudgetExhausted { .. } => "budget_exhausted",
            ProbeError::HeadersTooLarge { .. } => "headers_too_large",
        }
    }
}

const HEADERS_BYTE_LIMIT: usize = 64 * 1024;

/// Probe a single URL with one HEAD request. Use this for ad-hoc one-shot
/// callers (e.g. verification flows). For batches against the same host,
/// prefer [`probe_host_paths`].
pub async fn probe_url(
    host: &str,
    port: u16,
    is_https: bool,
    path: &str,
    config: &ProbeConfig,
) -> Result<ProbeResponse, ProbeError> {
    let outcome = probe_host_paths(host, port, is_https, &[path], config).await?;
    match outcome.responses.into_iter().next() {
        Some(Ok(resp)) => Ok(resp),
        Some(Err(err)) => Err(err),
        None => Err(ProbeError::MalformedResponse(
            "no responses returned".into(),
        )),
    }
}

/// Pipelined HEAD probe of `paths.len()` requests against a single host.
///
/// Behavior:
/// * One TCP (and, when `is_https`, TLS) handshake.
/// * All paths written in a single buffer; the last carries `Connection: close`.
/// * Responses parsed in order; HEAD bodies are absent so we only read up to `\r\n\r\n`.
/// * If the server signals `Connection: close`, remaining slots fail with
///   `ServerClosedEarly` and `server_closed_early` is set.
/// * After the last response (or early stop) the stream is closed via TCP RST
///   (`SO_LINGER=0` then drop), avoiding 30 s graceful-FIN stalls.
pub async fn probe_host_paths(
    host: &str,
    port: u16,
    is_https: bool,
    paths: &[&str],
    config: &ProbeConfig,
) -> Result<PathProbeOutcome, ProbeError> {
    if paths.is_empty() {
        return Ok(PathProbeOutcome {
            responses: Vec::new(),
            server_closed_early: None,
        });
    }

    // --- 1. TCP connect with bucketed timeout ---
    let tcp = match timeout(config.connect_timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            return Err(ProbeError::ConnectError {
                host: host.to_string(),
                port,
                message: err.to_string(),
            });
        }
        Err(_) => {
            return Err(ProbeError::ConnectTimeout {
                host: host.to_string(),
                port,
            });
        }
    };

    // RST close: arm SO_LINGER=0 BEFORE we know if anything will go wrong, so
    // an early drop on any error path also sends RST instead of FIN. Tokio's
    // wrapper is `#[deprecated]` for Windows reasons; on the Linux scanners
    // we target this is a non-blocking RST and exactly what we want.
    #[allow(deprecated)]
    {
        let _ = tcp.set_linger(Some(Duration::from_secs(0)));
    }
    // Latency-sensitive: small writes should go on the wire immediately.
    let _ = tcp.set_nodelay(true);

    let deadline = tokio::time::Instant::now() + config.per_connection_timeout;

    if is_https {
        let connector = build_tls_connector(config.allow_invalid_tls)?;
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| ProbeError::InvalidHost {
                host: host.to_string(),
            })?;
        let tls = match timeout(
            config.tls_handshake_timeout,
            connector.connect(server_name, tcp),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(err)) => {
                return Err(ProbeError::TlsHandshake {
                    host: host.to_string(),
                    message: err.to_string(),
                });
            }
            Err(_) => {
                return Err(ProbeError::TlsHandshakeTimeout {
                    host: host.to_string(),
                });
            }
        };
        run_pipeline(tls, host, paths, config, deadline).await
    } else {
        run_pipeline(tcp, host, paths, config, deadline).await
    }
}

async fn run_pipeline<S>(
    stream: S,
    host: &str,
    paths: &[&str],
    config: &ProbeConfig,
    deadline: tokio::time::Instant,
) -> Result<PathProbeOutcome, ProbeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(paths.len() * 256);
    for (idx, path) in paths.iter().enumerate() {
        let last = idx + 1 == paths.len();
        let connection = if last { "close" } else { "keep-alive" };
        // HEAD — no body. We only ever read header bytes.
        buf.extend_from_slice(b"HEAD ");
        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        buf.extend_from_slice(host.as_bytes());
        buf.extend_from_slice(b"\r\nUser-Agent: ");
        buf.extend_from_slice(config.user_agent.as_bytes());
        buf.extend_from_slice(b"\r\nAccept: */*\r\nConnection: ");
        buf.extend_from_slice(connection.as_bytes());
        buf.extend_from_slice(b"\r\n");
        for (name, value) in &config.extra_headers {
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(b"\r\n");
    }

    let (read_half, mut write_half) = tokio::io::split(stream);

    // Pipeline write: one syscall-ish flush, no per-path round-trips.
    match timeout(config.write_timeout, async {
        write_half.write_all(&buf).await?;
        write_half.flush().await
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            if matches!(err.kind(), std::io::ErrorKind::ConnectionReset) {
                return Err(ProbeError::ConnectionReset);
            }
            return Err(ProbeError::WriteError(err.to_string()));
        }
        Err(_) => return Err(ProbeError::WriteTimeout),
    }

    let mut reader = BufReader::with_capacity(16 * 1024, read_half);
    let mut responses: Vec<Result<ProbeResponse, ProbeError>> = Vec::with_capacity(paths.len());
    let mut server_closed_early: Option<usize> = None;

    for idx in 0..paths.len() {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            for filler in idx..paths.len() {
                responses.push(Err(ProbeError::BudgetExhausted { index: filler }));
            }
            break;
        }
        let read_budget = (deadline - now).min(config.read_timeout);

        let parsed = match timeout(read_budget, read_one_response(&mut reader)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(err)) => {
                let propagating = matches!(
                    err,
                    ProbeError::ConnectionReset | ProbeError::MalformedResponse(_)
                );
                responses.push(Err(err));
                if propagating {
                    for filler in (idx + 1)..paths.len() {
                        responses.push(Err(ProbeError::ServerClosedEarly { index: filler }));
                    }
                    server_closed_early.get_or_insert(idx);
                    break;
                } else {
                    continue;
                }
            }
            Err(_) => {
                responses.push(Err(ProbeError::ReadTimeout));
                // A read timeout on a pipelined connection means subsequent
                // responses are also lost — we can't safely resync.
                for filler in (idx + 1)..paths.len() {
                    responses.push(Err(ProbeError::ServerClosedEarly { index: filler }));
                }
                server_closed_early.get_or_insert(idx);
                break;
            }
        };

        let server_closed = parsed.server_closed;
        responses.push(Ok(parsed));
        if server_closed {
            server_closed_early.get_or_insert(idx);
            for filler in (idx + 1)..paths.len() {
                responses.push(Err(ProbeError::ServerClosedEarly { index: filler }));
            }
            break;
        }
    }

    // Drop occurs at scope exit; `read_half` and `write_half` go away, and
    // because SO_LINGER=0 was set on the underlying TcpStream the kernel
    // sends RST instead of FIN. For TLS we deliberately do NOT call shutdown
    // — graceful close is exactly what we're avoiding.
    Ok(PathProbeOutcome {
        responses,
        server_closed_early,
    })
}

async fn read_one_response<R>(reader: &mut BufReader<R>) -> Result<ProbeResponse, ProbeError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    // Read status line.
    let mut line = Vec::with_capacity(128);
    let n = read_line(reader, &mut line, HEADERS_BYTE_LIMIT).await?;
    if n == 0 {
        return Err(ProbeError::ConnectionReset);
    }
    let status = parse_status_line(&line)?;
    let mut headers = Vec::with_capacity(8);
    let mut server_closed = false;
    let mut consumed = n;
    loop {
        line.clear();
        let n = read_line(reader, &mut line, HEADERS_BYTE_LIMIT - consumed).await?;
        if n == 0 {
            return Err(ProbeError::ConnectionReset);
        }
        consumed += n;
        // Trailing \r\n on a line of its own (or just \n) terminates headers.
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        if let Some((name, value)) = parse_header(&line) {
            if name.eq_ignore_ascii_case("connection")
                && value.split(',').any(|tok| tok.trim().eq_ignore_ascii_case("close"))
            {
                server_closed = true;
            }
            headers.push((name, value));
        }
        if consumed >= HEADERS_BYTE_LIMIT {
            return Err(ProbeError::HeadersTooLarge {
                limit: HEADERS_BYTE_LIMIT,
            });
        }
    }
    Ok(ProbeResponse {
        status,
        headers,
        server_closed,
    })
}

async fn read_line<R>(
    reader: &mut BufReader<R>,
    out: &mut Vec<u8>,
    limit: usize,
) -> Result<usize, ProbeError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut total = 0usize;
    loop {
        let mut byte = [0u8; 1];
        match reader.read_exact(&mut byte).await {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                if total == 0 {
                    return Ok(0);
                }
                return Err(ProbeError::ConnectionReset);
            }
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {
                return Err(ProbeError::ConnectionReset);
            }
            Err(err) => {
                return Err(ProbeError::MalformedResponse(err.to_string()));
            }
        }
        out.push(byte[0]);
        total += 1;
        if byte[0] == b'\n' {
            return Ok(total);
        }
        if total >= limit {
            return Err(ProbeError::HeadersTooLarge { limit });
        }
    }
}

fn parse_status_line(line: &[u8]) -> Result<u16, ProbeError> {
    if !line.starts_with(b"HTTP/") {
        return Err(ProbeError::MalformedResponse(format!(
            "status line missing HTTP/ prefix: {:?}",
            String::from_utf8_lossy(line)
        )));
    }
    // HTTP/1.1 200 OK\r\n
    let mut parts = line.splitn(3, |b| *b == b' ');
    parts.next();
    let code = parts
        .next()
        .ok_or_else(|| ProbeError::MalformedResponse("missing status code".into()))?;
    let code_str = std::str::from_utf8(code)
        .map_err(|_| ProbeError::MalformedResponse("status code not utf-8".into()))?;
    code_str
        .parse::<u16>()
        .map_err(|_| ProbeError::MalformedResponse(format!("bad status code: {code_str}")))
}

fn parse_header(line: &[u8]) -> Option<(String, String)> {
    let mut parts = line.splitn(2, |b| *b == b':');
    let name = parts.next()?;
    let value = parts.next()?;
    let name = std::str::from_utf8(name).ok()?.trim();
    let value = std::str::from_utf8(value).ok()?.trim_matches(|c: char| {
        c == ' ' || c == '\t' || c == '\r' || c == '\n'
    });
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), value.to_string()))
}

fn build_tls_connector(allow_invalid: bool) -> Result<TlsConnector, ProbeError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = if allow_invalid {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    Ok(TlsConnector::from(Arc::new(config)))
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    /// Spawns a tiny loopback HTTP/1.1 server that answers HEAD requests with the
    /// status code keyed by path in `routes`. Returns `(host, port, shutdown_tx)`.
    async fn spawn_test_server(
        routes: HashMap<String, u16>,
    ) -> (String, u16, oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, mut rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept = listener.accept() => {
                        let Ok((mut sock, _)) = accept else { continue };
                        let routes = routes.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 8192];
                            let mut written = 0usize;
                            loop {
                                let n = match sock.read(&mut buf[written..]).await {
                                    Ok(0) => break,
                                    Ok(n) => n,
                                    Err(_) => break,
                                };
                                written += n;
                                while let Some(end) = find_double_crlf(&buf[..written]) {
                                    let req = &buf[..end];
                                    let path = parse_request_path(req).unwrap_or("/").to_string();
                                    let status = *routes.get(&path).unwrap_or(&404);
                                    let response = format!(
                                        "HTTP/1.1 {} OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                                        status
                                    );
                                    if sock.write_all(response.as_bytes()).await.is_err() {
                                        return;
                                    }
                                    buf.copy_within(end..written, 0);
                                    written -= end;
                                }
                                if written >= buf.len() {
                                    break;
                                }
                            }
                        });
                    }
                }
            }
        });
        ("127.0.0.1".to_string(), port, tx)
    }

    fn find_double_crlf(buf: &[u8]) -> Option<usize> {
        buf.windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
    }

    fn parse_request_path(req: &[u8]) -> Option<&str> {
        let line = req.split(|b| *b == b'\n').next()?;
        let mut parts = line.split(|b| *b == b' ');
        parts.next()?; // method
        let path = parts.next()?;
        std::str::from_utf8(path).ok().map(|s| s.trim_end_matches('\r'))
    }

    fn cfg() -> ProbeConfig {
        ProbeConfig {
            connect_timeout: Duration::from_secs(2),
            tls_handshake_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
            per_connection_timeout: Duration::from_secs(8),
            user_agent: "anyscan-test/1".into(),
            allow_invalid_tls: true,
            extra_headers: Vec::new(),
        }
    }

    #[tokio::test]
    async fn pipelined_thirty_paths_all_return_status() {
        let paths_30: Vec<&str> = vec![
            "/", "/admin", "/login", "/wp-login.php", "/wp-admin", "/.env", "/.git/config",
            "/.git/HEAD", "/robots.txt", "/sitemap.xml", "/api", "/api/v1", "/health", "/status",
            "/server-status", "/phpinfo.php", "/phpmyadmin", "/admin.php", "/index.php",
            "/config.php", "/config.json", "/.well-known/security.txt", "/backup", "/backup.zip",
            "/dump.sql", "/swagger", "/swagger.json", "/openapi.json", "/graphql", "/dashboard",
        ];
        // Map each path to a unique status code so a swap or out-of-order parse fails the test.
        let mut routes = HashMap::new();
        for (i, p) in paths_30.iter().enumerate() {
            routes.insert((*p).to_string(), 200u16 + i as u16);
        }
        let (host, port, _shutdown) = spawn_test_server(routes.clone()).await;
        let outcome = probe_host_paths(&host, port, false, &paths_30, &cfg())
            .await
            .expect("probe_host_paths returns outcome");
        assert_eq!(outcome.responses.len(), paths_30.len());
        assert!(outcome.server_closed_early.is_none());
        for (i, resp) in outcome.responses.iter().enumerate() {
            let resp = resp.as_ref().expect("path response is ok");
            assert_eq!(
                resp.status, 200 + i as u16,
                "path {}: expected status {}, got {}",
                paths_30[i],
                200 + i as u16,
                resp.status
            );
        }
    }

    /// Server that sends one response with `Connection: close` then drops.
    async fn spawn_close_after_one(close_at: usize) -> (String, u16, oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, mut rx) = oneshot::channel::<()>();
        let counter = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept = listener.accept() => {
                        let Ok((mut sock, _)) = accept else { continue };
                        let counter = counter.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 8192];
                            let mut written = 0usize;
                            loop {
                                let n = match sock.read(&mut buf[written..]).await {
                                    Ok(0) => return,
                                    Ok(n) => n,
                                    Err(_) => return,
                                };
                                written += n;
                                while let Some(end) = find_double_crlf(&buf[..written]) {
                                    let idx = counter.fetch_add(1, Ordering::SeqCst);
                                    let advertise_close = idx == close_at;
                                    let response = format!(
                                        "HTTP/1.1 {} OK\r\nContent-Length: 0\r\nConnection: {}\r\n\r\n",
                                        200,
                                        if advertise_close { "close" } else { "keep-alive" }
                                    );
                                    if sock.write_all(response.as_bytes()).await.is_err() {
                                        return;
                                    }
                                    buf.copy_within(end..written, 0);
                                    written -= end;
                                    if advertise_close {
                                        return;
                                    }
                                }
                            }
                        });
                    }
                }
            }
        });
        ("127.0.0.1".to_string(), port, tx)
    }

    #[tokio::test]
    async fn server_connection_close_marks_remaining_slots_as_errors() {
        let (host, port, _shutdown) = spawn_close_after_one(0).await;
        let paths: Vec<&str> = vec!["/a", "/b", "/c", "/d", "/e"];
        let outcome = probe_host_paths(&host, port, false, &paths, &cfg())
            .await
            .expect("probe_host_paths returns outcome");
        assert_eq!(outcome.responses.len(), paths.len());
        assert_eq!(outcome.server_closed_early, Some(0));
        // First slot is the response with Connection: close header.
        let first = outcome.responses[0].as_ref().expect("first slot ok");
        assert_eq!(first.status, 200);
        assert!(first.server_closed);
        // Remaining slots must be ServerClosedEarly errors.
        for (i, resp) in outcome.responses.iter().enumerate().skip(1) {
            match resp {
                Err(ProbeError::ServerClosedEarly { index }) => assert_eq!(*index, i),
                other => panic!("slot {}: expected ServerClosedEarly, got {:?}", i, other),
            }
        }
    }

    #[tokio::test]
    async fn https_against_plain_tcp_listener_yields_tls_handshake_error() {
        // Plaintext server that immediately closes the socket — TLS handshake
        // should classify cleanly into the `tls_handshake` bucket.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                drop(sock);
            }
        });
        let mut config = cfg();
        config.tls_handshake_timeout = Duration::from_secs(2);
        let err = probe_host_paths("127.0.0.1", port, true, &["/"], &config).await;
        match err {
            Err(ProbeError::TlsHandshake { .. }) | Err(ProbeError::TlsHandshakeTimeout { .. }) => {}
            other => panic!("expected TlsHandshake error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn connect_refused_falls_into_connect_error_bucket() {
        // 127.0.0.1:1 should refuse on most kernels.
        let outcome = probe_host_paths("127.0.0.1", 1, false, &["/"], &cfg()).await;
        match outcome {
            Err(e) => {
                let bucket = e.bucket();
                assert!(
                    bucket == "connect_error" || bucket == "connect_timeout",
                    "expected connect_error or connect_timeout, got {bucket}"
                );
            }
            Ok(_) => panic!("expected connect failure"),
        }
    }
}
