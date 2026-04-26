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

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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
    /// When true (default), write all path requests up-front then drain
    /// responses (HTTP/1.1 pipelining). When false, write one request at a
    /// time, read its response, then move to the next — still on a single
    /// keep-alive connection. The bench binary's `--pipeline` flag flips
    /// this so A/B comparisons of pipelined-vs-sequential are meaningful.
    pub pipeline: bool,
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
            pipeline: true,
        }
    }
}

/// One HEAD response, parsed up to (but not including) any body.
///
/// Header storage is *raw bytes* — the response section between the status
/// line and the terminating CRLF, with each line newline-terminated. Callers
/// access header pairs through [`ProbeResponse::headers`] (zero-allocation
/// iterator) or [`ProbeResponse::header`] (early-exit lookup). To keep an
/// owned `Vec<(String, String)>` for downstream storage (e.g. fetcher's
/// `FetchedDocument`), use [`ProbeResponse::headers_owned`].
///
/// Why raw bytes: profiling showed `parse_header`'s `to_string()` calls were
/// 6 small allocations per response × 1.6 M responses = ~10 M heap ops on a
/// loopback bench run. Most callers (the bench, the fetcher's content-type
/// lookup) only need a handful of headers; deferring the allocation lets
/// them skip the rest entirely.
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub status: u16,
    /// Raw header bytes — every line ends with `\n` (preceded optionally by
    /// `\r`). Access via [`headers`] / [`header`] / [`headers_owned`].
    raw_headers: Vec<u8>,
    /// `Connection: close` was advertised by the server.
    pub server_closed: bool,
}

impl ProbeResponse {
    /// Construct from an owned list of (name, value) pairs. Used by callers
    /// that source headers from a different parser (e.g. the fetcher's proxy
    /// path which gets a `reqwest::HeaderMap`).
    pub fn from_owned(
        status: u16,
        headers: Vec<(String, String)>,
        server_closed: bool,
    ) -> Self {
        let mut raw_headers = Vec::with_capacity(headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum());
        for (name, value) in &headers {
            raw_headers.extend_from_slice(name.as_bytes());
            raw_headers.extend_from_slice(b": ");
            raw_headers.extend_from_slice(value.as_bytes());
            raw_headers.extend_from_slice(b"\r\n");
        }
        Self {
            status,
            raw_headers,
            server_closed,
        }
    }

    /// Iterate `(name, value)` pairs without per-call heap allocation.
    /// Returned slices borrow from the response's raw header bytes; trailing
    /// CR/LF/SP/TAB are trimmed. Lines that don't parse as a `name: value`
    /// pair are skipped.
    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.raw_headers.split(|b| *b == b'\n').filter_map(parse_header_borrowed)
    }

    /// Look up a single header by case-insensitive name. Early-exits as soon
    /// as the first match is found; no allocation.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Materialize all headers into an owned `Vec<(String, String)>`. Used
    /// by callers that need to store the headers past the lifetime of the
    /// `ProbeResponse` (e.g. the fetcher's `FetchedDocument`).
    pub fn headers_owned(&self) -> Vec<(String, String)> {
        self.headers()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    /// Borrow the raw header bytes (everything between the status line and
    /// the terminating empty line). For advanced callers that want to do
    /// their own parsing.
    pub fn raw_headers(&self) -> &[u8] {
        &self.raw_headers
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
    /// Returned when the request would smuggle additional bytes through
    /// CR/LF/NUL injection in host, path, user-agent, or header values.
    #[error("invalid request input: {reason}")]
    InvalidRequest { reason: String },
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
    /// Returned for slots after a local write to the upstream connection
    /// failed in sequential mode. The connection is unusable but the cause
    /// is local (timeout / write error), not a server-signalled close.
    #[error("request {index} aborted: prior write to upstream failed")]
    WriteAborted { index: usize },
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
            ProbeError::InvalidRequest { .. } => "invalid_request",
            ProbeError::WriteTimeout => "write_timeout",
            ProbeError::WriteError(_) => "write_error",
            ProbeError::ReadTimeout => "read_timeout",
            ProbeError::ConnectionReset => "connection_reset",
            ProbeError::MalformedResponse(_) => "malformed_response",
            ProbeError::ServerClosedEarly { .. } => "server_closed_early",
            ProbeError::WriteAborted { .. } => "write_aborted",
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

    // --- 0. Reject CR/LF/NUL in any field that lands directly in the request
    // bytes. Without this, a path or header value containing "\r\n" would let
    // a caller smuggle additional headers or whole requests, and the response
    // parser would happily desync. We bucket as `invalid_request` so the
    // bench / fetcher can count and surface them without confusing them with
    // real network failures.
    validate_request_token("host", host)?;
    validate_request_token("user_agent", &config.user_agent)?;
    for (idx, path) in paths.iter().enumerate() {
        validate_request_token(&format!("path[{idx}]"), path)?;
    }
    for (name, value) in &config.extra_headers {
        validate_header_name(name)?;
        validate_request_token(&format!("header value for {name}"), value)?;
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

    let host_header = format_host_header(host, port, is_https);

    if is_https {
        let connector = tls_connector(config.allow_invalid_tls)?;
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
        run_pipeline(tls, &host_header, paths, config, deadline).await
    } else {
        run_pipeline(tcp, &host_header, paths, config, deadline).await
    }
}

/// Per-RFC-7230 §5.4 the `Host` header MUST include the port when it differs
/// from the scheme default. Some virtual-host configurations route requests
/// differently (or 400) when the authority is missing the port.
///
/// IPv6 literals are bracketed per RFC 3986 §3.2.2 / RFC 7230 §2.7.1 — without
/// brackets, a value like `::1:8080` is ambiguous (and rejected by compliant
/// servers).
fn format_host_header(host: &str, port: u16, is_https: bool) -> String {
    let default = if is_https { 443 } else { 80 };
    let needs_brackets = host.contains(':') && !host.starts_with('[');
    let bracketed: String;
    let host_for_header: &str = if needs_brackets {
        bracketed = format!("[{host}]");
        &bracketed
    } else {
        host
    };
    if port == default {
        host_for_header.to_string()
    } else {
        format!("{host_for_header}:{port}")
    }
}

fn write_request_into(
    buf: &mut Vec<u8>,
    host_header: &str,
    path: &str,
    is_last: bool,
    config: &ProbeConfig,
) {
    let connection = if is_last { "close" } else { "keep-alive" };
    // HEAD — no body. We only ever read header bytes.
    buf.extend_from_slice(b"HEAD ");
    buf.extend_from_slice(path.as_bytes());
    buf.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    buf.extend_from_slice(host_header.as_bytes());
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

async fn run_pipeline<S>(
    stream: S,
    host_header: &str,
    paths: &[&str],
    config: &ProbeConfig,
    deadline: tokio::time::Instant,
) -> Result<PathProbeOutcome, ProbeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::with_capacity(16 * 1024, read_half);
    let mut responses: Vec<Result<ProbeResponse, ProbeError>> = Vec::with_capacity(paths.len());
    let mut server_closed_early: Option<usize> = None;

    if config.pipeline {
        // Write all requests in one buffered flush, then drain responses.
        let mut buf: Vec<u8> = Vec::with_capacity(paths.len() * 256);
        for (idx, path) in paths.iter().enumerate() {
            let last = idx + 1 == paths.len();
            write_request_into(&mut buf, host_header, path, last, config);
        }
        write_with_timeout(&mut write_half, &buf, config.write_timeout).await?;
    }

    for idx in 0..paths.len() {
        // Sequential mode writes the request *before* each read.
        if !config.pipeline {
            let mut buf: Vec<u8> = Vec::with_capacity(256);
            let last = idx + 1 == paths.len();
            write_request_into(&mut buf, host_header, paths[idx], last, config);
            if let Err(e) = write_with_timeout(&mut write_half, &buf, config.write_timeout).await {
                // Local write failure: the connection is unusable but the
                // cause is local (timeout / write error). Do NOT set
                // `server_closed_early` — that field is reserved for cases
                // where the server signalled `Connection: close`. Fill the
                // remaining slots with `WriteAborted` so callers can tell
                // these apart from server-side closes.
                responses.push(Err(e));
                for filler in (idx + 1)..paths.len() {
                    responses.push(Err(ProbeError::WriteAborted { index: filler }));
                }
                break;
            }
        }

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
                // Any framing-level error desyncs the byte stream — we can't
                // safely parse subsequent responses on the same connection.
                let propagating = matches!(
                    err,
                    ProbeError::ConnectionReset
                        | ProbeError::MalformedResponse(_)
                        | ProbeError::HeadersTooLarge { .. }
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

async fn write_with_timeout<W>(
    writer: &mut W,
    buf: &[u8],
    write_timeout: Duration,
) -> Result<(), ProbeError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    match timeout(write_timeout, async {
        writer.write_all(buf).await?;
        writer.flush().await
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            if matches!(err.kind(), std::io::ErrorKind::ConnectionReset) {
                Err(ProbeError::ConnectionReset)
            } else {
                Err(ProbeError::WriteError(err.to_string()))
            }
        }
        Err(_) => Err(ProbeError::WriteTimeout),
    }
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
    // Raw header bytes accumulator — one allocation per response, replacing
    // the previous `Vec<(String, String)>` (1 Vec alloc + 2 String allocs per
    // header). Capacity 256 covers a typical short HEAD response in one go.
    let mut raw_headers: Vec<u8> = Vec::with_capacity(256);
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
        // Detect Connection: close on the raw bytes — avoids the per-header
        // String allocation that `parse_header` used to do.
        if let Some(value) = header_value_if_name(&line, b"connection") {
            for tok in value.split(|b| *b == b',') {
                let tok = trim_ascii_ws(tok);
                if tok.eq_ignore_ascii_case(b"close") {
                    server_closed = true;
                    break;
                }
            }
        }
        raw_headers.extend_from_slice(&line);
        if consumed >= HEADERS_BYTE_LIMIT {
            return Err(ProbeError::HeadersTooLarge {
                limit: HEADERS_BYTE_LIMIT,
            });
        }
    }
    Ok(ProbeResponse {
        status,
        raw_headers,
        server_closed,
    })
}

/// If `line` is a `name: value\r?\n?` header whose name matches
/// `expected_name` case-insensitively, return the (untrimmed) value bytes.
fn header_value_if_name<'a>(line: &'a [u8], expected_name: &[u8]) -> Option<&'a [u8]> {
    let colon = line.iter().position(|b| *b == b':')?;
    if colon != expected_name.len() {
        return None;
    }
    if !line[..colon].eq_ignore_ascii_case(expected_name) {
        return None;
    }
    Some(&line[colon + 1..])
}

/// Trim leading & trailing ASCII whitespace (SP, HT, CR, LF) from a byte slice.
fn trim_ascii_ws(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'));
    let Some(start) = start else { return &[]; };
    let end = s.iter().rposition(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n')).unwrap();
    &s[start..=end]
}

/// Parse a single header line `name: value\r?\n?` into borrowed `&str`
/// halves. Returns `None` for blank lines, malformed lines, or non-UTF-8
/// content. Used by [`ProbeResponse::headers`].
fn parse_header_borrowed(line: &[u8]) -> Option<(&str, &str)> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() {
        return None;
    }
    let colon = line.iter().position(|b| *b == b':')?;
    let name = std::str::from_utf8(&line[..colon]).ok()?;
    let value = std::str::from_utf8(&line[colon + 1..]).ok()?;
    let name = name.trim_matches(|c: char| matches!(c, ' ' | '\t'));
    let value = value.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'));
    if name.is_empty() {
        return None;
    }
    Some((name, value))
}

/// Read up to (and including) the next `\n`, into `out`. Enforces `limit`:
/// if reached without a `\n`, returns `HeadersTooLarge` (the caller treats
/// this as fatal and tears the connection down — see `run_pipeline`).
///
/// Uses [`AsyncBufReadExt::read_until`] so the inner `BufReader` services
/// reads in 16 KiB chunks rather than one syscall per byte. This matters
/// at high RPS: per-byte was ~50× slower in profiling.
///
/// The cap is enforced *during* the read by wrapping the reader in
/// `take(limit + 1)`: a peer streaming a very long unterminated header line
/// can't grow `out` past `limit + 1` bytes before we detect overflow.
async fn read_line<R>(
    reader: &mut BufReader<R>,
    out: &mut Vec<u8>,
    limit: usize,
) -> Result<usize, ProbeError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let initial_len = out.len();
    let cap = (limit as u64).saturating_add(1);
    let mut limited = (&mut *reader).take(cap);
    match limited.read_until(b'\n', out).await {
        Ok(0) => Ok(0),
        Ok(_) => {
            let read = out.len() - initial_len;
            if read > limit {
                return Err(ProbeError::HeadersTooLarge { limit });
            }
            // No newline was seen and the inner buffer drained at EOF before
            // the cap: classify as connection reset.
            if !out.ends_with(b"\n") {
                if read == 0 {
                    return Ok(0);
                }
                return Err(ProbeError::ConnectionReset);
            }
            Ok(read)
        }
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            if out.len() == initial_len {
                Ok(0)
            } else {
                Err(ProbeError::ConnectionReset)
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {
            Err(ProbeError::ConnectionReset)
        }
        Err(err) => Err(ProbeError::MalformedResponse(err.to_string())),
    }
}

/// Reject CR/LF/NUL in any user-controlled field that lands directly in the
/// HTTP request bytes. This is the canonical CRLF-injection guard: without
/// it a path of `/foo\r\nX-Smuggle: 1` would let the caller inject extra
/// headers (or whole pipelined requests) and the response parser would
/// happily desync.
fn validate_request_token(field: &str, value: &str) -> Result<(), ProbeError> {
    if let Some(idx) = value
        .as_bytes()
        .iter()
        .position(|b| matches!(b, b'\r' | b'\n' | 0))
    {
        return Err(ProbeError::InvalidRequest {
            reason: format!(
                "{field} contains forbidden control byte 0x{:02x} at offset {idx}",
                value.as_bytes()[idx]
            ),
        });
    }
    Ok(())
}

/// Header field names per RFC 7230 are restricted to visible ASCII (no
/// whitespace, no separators). Be conservative here: `tchar`-only.
fn validate_header_name(name: &str) -> Result<(), ProbeError> {
    if name.is_empty() {
        return Err(ProbeError::InvalidRequest {
            reason: "empty header name".into(),
        });
    }
    for (idx, b) in name.as_bytes().iter().enumerate() {
        let allowed = matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
                | b'^' | b'_' | b'`' | b'|' | b'~'
        ) || b.is_ascii_alphanumeric();
        if !allowed {
            return Err(ProbeError::InvalidRequest {
                reason: format!(
                    "header name contains forbidden byte 0x{:02x} at offset {idx}",
                    b
                ),
            });
        }
    }
    Ok(())
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

/// Lazily initialised, process-wide TLS connectors.
///
/// `rustls::crypto::ring::default_provider().install_default()` MUST be
/// called at most once per process — subsequent calls error. And the
/// `ClientConfig` itself is heavy: building the verifier, copying the root
/// store, and wrapping in `Arc` every probe was measurable overhead at
/// thousands-of-RPS rates. Cache once, share via `Arc`.
static TLS_VERIFYING: OnceLock<TlsConnector> = OnceLock::new();
static TLS_NOVERIFY: OnceLock<TlsConnector> = OnceLock::new();
static CRYPTO_INSTALLED: OnceLock<()> = OnceLock::new();

fn tls_connector(allow_invalid: bool) -> Result<TlsConnector, ProbeError> {
    CRYPTO_INSTALLED.get_or_init(|| {
        // Idempotent: returns Err if already installed (e.g. by reqwest in
        // the same process). We only care that it ends up installed, not who
        // won the race.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    let cell = if allow_invalid {
        &TLS_NOVERIFY
    } else {
        &TLS_VERIFYING
    };
    Ok(cell
        .get_or_init(|| {
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
            TlsConnector::from(Arc::new(config))
        })
        .clone())
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
            pipeline: true,
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

    #[tokio::test]
    async fn crlf_in_path_rejected_pre_connect() {
        // The smuggle attempt: a path with embedded \r\nX-Smuggled. We don't
        // want it on the wire. Connect refused on port 1 would *also* surface
        // here, so any non-`invalid_request` bucket is a regression.
        let outcome = probe_host_paths(
            "127.0.0.1",
            1,
            false,
            &["/foo\r\nX-Smuggle: 1"],
            &cfg(),
        )
        .await;
        match outcome {
            Err(ProbeError::InvalidRequest { reason }) => {
                assert!(reason.contains("path"), "reason should mention path: {reason}");
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn crlf_in_extra_header_value_rejected() {
        let mut config = cfg();
        config.extra_headers.push(("X-Foo".into(), "bar\r\nX-Y: z".into()));
        let outcome = probe_host_paths("127.0.0.1", 1, false, &["/"], &config).await;
        assert!(matches!(outcome, Err(ProbeError::InvalidRequest { .. })));
    }

    #[tokio::test]
    async fn invalid_header_name_rejected() {
        let mut config = cfg();
        config.extra_headers.push(("X Foo".into(), "bar".into()));
        let outcome = probe_host_paths("127.0.0.1", 1, false, &["/"], &config).await;
        assert!(matches!(outcome, Err(ProbeError::InvalidRequest { .. })));
    }

    #[tokio::test]
    async fn host_header_includes_non_default_port() {
        // Capture the full request and assert the Host header contains the port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
        let captured_clone = Arc::clone(&captured);
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 4096];
            let mut written = 0usize;
            loop {
                let n = match sock.read(&mut buf[written..]).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                written += n;
                if find_double_crlf(&buf[..written]).is_some() {
                    captured_clone.lock().await.extend_from_slice(&buf[..written]);
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                    return;
                }
            }
        });
        let outcome = probe_host_paths("127.0.0.1", port, false, &["/"], &cfg())
            .await
            .expect("probe ok");
        assert!(outcome.responses[0].is_ok());
        // Give the captor a tick.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let bytes = captured.lock().await.clone();
        let request = String::from_utf8_lossy(&bytes);
        let expected = format!("Host: 127.0.0.1:{port}\r\n");
        assert!(
            request.contains(&expected),
            "expected `{expected}` in request, got:\n{request}"
        );
    }

    #[tokio::test]
    async fn host_header_omits_default_port() {
        // Default-port (443 over https / 80 over http) requests must NOT
        // include the port in the Host header. We can't easily bind 80 in a
        // test, so exercise the helper directly.
        assert_eq!(format_host_header("example.com", 80, false), "example.com");
        assert_eq!(format_host_header("example.com", 443, true), "example.com");
        assert_eq!(
            format_host_header("example.com", 8080, false),
            "example.com:8080"
        );
        assert_eq!(
            format_host_header("example.com", 8443, true),
            "example.com:8443"
        );
    }

    #[tokio::test]
    async fn sequential_mode_writes_one_request_at_a_time() {
        // Server returns a different status per path. With pipeline=false the
        // function must still return all responses in input order.
        let mut routes = HashMap::new();
        routes.insert("/a".to_string(), 201u16);
        routes.insert("/b".to_string(), 202);
        routes.insert("/c".to_string(), 203);
        let (host, port, _shutdown) = spawn_test_server(routes).await;
        let mut config = cfg();
        config.pipeline = false;
        let paths = ["/a", "/b", "/c"];
        let outcome = probe_host_paths(&host, port, false, &paths, &config)
            .await
            .expect("sequential probe ok");
        assert_eq!(outcome.responses.len(), 3);
        let codes: Vec<u16> = outcome
            .responses
            .iter()
            .map(|r| r.as_ref().unwrap().status)
            .collect();
        assert_eq!(codes, vec![201, 202, 203]);
    }

    #[tokio::test]
    async fn read_line_caps_during_read_on_unterminated_line() {
        // 70 KiB of `A`s with no `\n`: a peer that streams a long line without
        // a terminator should not be allowed to grow `out` past `limit + 1`
        // before we detect the overflow.
        let limit: usize = 64 * 1024;
        let payload = vec![b'A'; 70 * 1024];
        let mut reader = BufReader::with_capacity(16 * 1024, &payload[..]);
        let mut out: Vec<u8> = Vec::new();
        let result = read_line(&mut reader, &mut out, limit).await;
        match result {
            Err(ProbeError::HeadersTooLarge { limit: l }) => assert_eq!(l, limit),
            other => panic!("expected HeadersTooLarge, got {other:?}"),
        }
        assert!(
            out.len() <= limit + 1,
            "out grew past limit + 1: out.len()={} limit+1={}",
            out.len(),
            limit + 1
        );
    }

    #[tokio::test]
    async fn host_header_brackets_ipv6_literals() {
        // RFC 3986 §3.2.2 / RFC 7230 §2.7.1: IPv6 literals must be bracketed
        // in the Host header. The bench input parser strips brackets for
        // `[::1]:port`, so the helper has to put them back when emitting.
        assert_eq!(format_host_header("::1", 8080, false), "[::1]:8080");
        // Default port: omit the port but keep the brackets.
        assert_eq!(format_host_header("::1", 80, false), "[::1]");
        assert_eq!(format_host_header("::1", 443, true), "[::1]");
        // Idempotent for already-bracketed input.
        assert_eq!(format_host_header("[::1]", 8080, false), "[::1]:8080");
        assert_eq!(format_host_header("[::1]", 80, false), "[::1]");
        // Full-form IPv6 also handled.
        assert_eq!(
            format_host_header("2001:db8::1", 8443, true),
            "[2001:db8::1]:8443"
        );
    }

    #[tokio::test]
    async fn sequential_write_failure_does_not_set_server_closed_early() {
        // Drive run_pipeline directly with a half-dropped duplex stream so
        // the very first write returns BrokenPipe deterministically. We
        // assert two things:
        //   1. server_closed_early stays None (the failure is local, not a
        //      server-signalled close).
        //   2. Filler slots after the failure carry WriteAborted, not
        //      ServerClosedEarly.
        let (client, server) = tokio::io::duplex(8);
        drop(server);

        let mut config = cfg();
        config.pipeline = false;
        config.write_timeout = Duration::from_millis(200);
        config.read_timeout = Duration::from_millis(200);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let paths = ["/a", "/b", "/c", "/d"];
        let outcome = run_pipeline(client, "test.local", &paths, &config, deadline)
            .await
            .expect("run_pipeline returns outcome");

        assert!(
            outcome.server_closed_early.is_none(),
            "write failure should NOT set server_closed_early; got {:?}",
            outcome.server_closed_early
        );
        let first_err_idx = outcome
            .responses
            .iter()
            .position(|r| r.is_err())
            .expect("at least one slot should error after dropped peer");
        // The first error is the actual write error (WriteError / WriteTimeout
        // / ConnectionReset); subsequent slots must be WriteAborted.
        match &outcome.responses[first_err_idx] {
            Err(ProbeError::WriteError(_))
            | Err(ProbeError::WriteTimeout)
            | Err(ProbeError::ConnectionReset) => {}
            other => panic!("first error slot {first_err_idx}: expected a write-side error, got {other:?}"),
        }
        for (i, resp) in outcome.responses.iter().enumerate().skip(first_err_idx + 1) {
            match resp {
                Err(ProbeError::WriteAborted { index }) => assert_eq!(*index, i),
                other => panic!(
                    "slot {i}: expected WriteAborted (write failure should not masquerade as \
                     server close), got {other:?}"
                ),
            }
        }
    }
}
