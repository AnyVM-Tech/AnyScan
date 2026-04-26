//! Per-host pipelined HEAD path-scanner benchmark.
//!
//! Exercises [`anyscan::request_probe::probe_host_paths`] against a list of
//! hosts and a list of paths, reporting attempted/successful RPS bucketed by
//! failure reason. Mirrors the asyncio prototype `path_scan_reuse.py` but in
//! native Rust on tokio.
//!
//! Run on c6in.xlarge (4 vCPU):
//!   ulimit -n 1048576    # required, otherwise we cap out far below target
//!   sysctl -w net.ipv4.ip_local_port_range="1024 65535"
//!   sysctl -w net.ipv4.tcp_tw_reuse=1
//!   sysctl -w net.core.somaxconn=65535
//!   ./anyscan-path-bench --hosts hosts.txt --paths paths30.txt --concurrency 1024
//!
//! Expected ranges from the reference benchmark (30 paths/host):
//!   * sustained 8k hosts:    ~17,000 attempted RPS, ~9,600 successful RPS
//!   * 1k host warmup:        ~6,000 attempted RPS, ~3,300 successful RPS

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use anyscan::request_probe::{ProbeConfig, probe_host_paths};
use clap::Parser;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use url::Url;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "anyscan-path-bench",
    about = "Per-host pipelined HEAD path-scanner benchmark."
)]
struct Args {
    /// File of hosts: one per line, either a URL (https://example.com) or
    /// `host[:port]` (defaults to https / port 443).
    #[arg(long)]
    hosts: PathBuf,

    /// File of paths: one per line. Lines starting with `#` are ignored.
    #[arg(long)]
    paths: PathBuf,

    /// Maximum simultaneous host connections.
    #[arg(long, default_value_t = 1024)]
    concurrency: usize,

    /// tokio worker threads. Defaults to `num_cpus`.
    #[arg(long, default_value_t = 0)]
    workers: usize,

    /// Pipeline all path requests up-front (HTTP/1.1 pipelining). Default true.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pipeline: bool,

    /// Per-request read/write timeout in milliseconds.
    #[arg(long, default_value_t = 3000)]
    timeout_ms: u64,

    /// Total per-host budget in milliseconds (across all paths).
    #[arg(long, default_value_t = 10_000)]
    per_host_budget_ms: u64,

    /// Skip TLS certificate verification.
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    allow_invalid_tls: bool,

    /// Override default scheme when input is `host[:port]` (`http` or `https`).
    #[arg(long, default_value = "https")]
    default_scheme: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let (cur, max) = raise_fd_limit();
    if cur > 0 {
        eprintln!("RLIMIT_NOFILE: cur={cur} max={max}");
    }

    let workers = if args.workers == 0 {
        num_cpus::get().max(1)
    } else {
        args.workers
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;
    runtime.block_on(run(args))
}

/// Raise `RLIMIT_NOFILE` to `1<<20` (1,048,576) on Unix. No-op on Windows
/// (which has no equivalent) so the bench still builds cross-platform.
///
/// Returns `(cur, max)` after the call as `(u64, u64)` so `main()` doesn't
/// need its own cfg cascade. `libc::rlim_t` is `u64` on most modern Unix
/// targets but `u32` on some 32-bit ones; we cast unconditionally so the
/// signature stays portable. `(0, 0)` means we couldn't query (Windows path
/// or `getrlimit` failure) so the caller can suppress the log.
// `libc::rlim_t` is `u64` on 64-bit Unix targets but `u32` on some 32-bit
// ones; the casts below are no-ops on the former and load-bearing on the
// latter. Suppress the lint here so the function compiles cleanly on both.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn raise_fd_limit() -> (u64, u64) {
    const TARGET: libc::rlim_t = 1 << 20;
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) != 0 {
            eprintln!(
                "getrlimit(RLIMIT_NOFILE) failed: {}",
                std::io::Error::last_os_error()
            );
            return (0, 0);
        }
    }
    let want = TARGET.min(current.rlim_max);
    let new = libc::rlimit {
        rlim_cur: want,
        rlim_max: current.rlim_max,
    };
    let setres = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new) };
    if setres != 0 {
        eprintln!(
            "setrlimit(RLIMIT_NOFILE, {want}) failed: {} — continuing with cur={}",
            std::io::Error::last_os_error(),
            current.rlim_cur
        );
        return (current.rlim_cur as u64, current.rlim_max as u64);
    }
    let mut after = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        let _ = libc::getrlimit(libc::RLIMIT_NOFILE, &mut after);
    }
    (after.rlim_cur as u64, after.rlim_max as u64)
}

#[cfg(not(unix))]
fn raise_fd_limit() -> (u64, u64) {
    // Windows has no RLIMIT_NOFILE; the default per-process handle limit is
    // already in the millions. Nothing to do, and we suppress the log.
    (0, 0)
}

/// Every probe-error bucket we know about, mirroring `ProbeError::bucket()`.
/// The bench pre-populates an `AtomicU64` for each so `record_failure` can
/// resolve the bucket → counter without taking a lock. If `ProbeError` ever
/// adds a bucket and this list isn't updated, the increment falls through
/// to `failure_other` (still counted, surfaced as `unknown_bucket`).
const ALL_FAILURE_BUCKETS: &[&str] = &[
    "connect_timeout",
    "connect_error",
    "tls_handshake",
    "invalid_host",
    "invalid_request",
    "write_timeout",
    "write_error",
    "read_timeout",
    "connection_reset",
    "malformed_response",
    "server_closed_early",
    "write_aborted",
    "budget_exhausted",
    "headers_too_large",
];

/// Number of slots in the per-status counter array. HTTP status is `u16`, so
/// every possible value indexes directly without a hash. `65536 × 8 B = 512 KiB`
/// — a one-time allocation per process, 0.0% of any realistic scanner's RSS.
const STATUS_CODE_SLOTS: usize = u16::MAX as usize + 1;

#[derive(Debug)]
struct BenchStats {
    hosts_completed: AtomicU64,
    paths_attempted: AtomicU64,
    paths_succeeded: AtomicU64,
    paths_failed: AtomicU64,
    /// Per-status-code counter, indexed by HTTP status. Replaces the previous
    /// `Mutex<HashMap<u16, u64>>` that was the dominant contention point in
    /// the per-response hot path: profiling against an in-process loopback
    /// server (16 384 hosts × 100 paths, 8 worker threads) showed the lock
    /// alone cost 43–83 % of attempt RPS depending on `--concurrency`.
    statuses: Box<[AtomicU64]>,
    /// Pre-populated mapping of failure bucket → atomic counter. Read-only
    /// after `BenchStats::new`, so `HashMap::get` does no synchronization.
    failure_buckets: HashMap<&'static str, AtomicU64>,
    /// Catch-all for any bucket not present in `ALL_FAILURE_BUCKETS`. Should
    /// stay at 0 in practice — non-zero means `ProbeError` added a new bucket
    /// and this file wasn't updated.
    failure_other: AtomicU64,
}

impl Default for BenchStats {
    fn default() -> Self {
        let statuses: Box<[AtomicU64]> = (0..STATUS_CODE_SLOTS)
            .map(|_| AtomicU64::new(0))
            .collect();
        let mut failure_buckets =
            HashMap::with_capacity(ALL_FAILURE_BUCKETS.len());
        for &b in ALL_FAILURE_BUCKETS {
            failure_buckets.insert(b, AtomicU64::new(0));
        }
        BenchStats {
            hosts_completed: AtomicU64::new(0),
            paths_attempted: AtomicU64::new(0),
            paths_succeeded: AtomicU64::new(0),
            paths_failed: AtomicU64::new(0),
            statuses,
            failure_buckets,
            failure_other: AtomicU64::new(0),
        }
    }
}

impl BenchStats {
    fn record_failure(&self, bucket: &'static str) {
        self.paths_attempted.fetch_add(1, Ordering::Relaxed);
        self.paths_failed.fetch_add(1, Ordering::Relaxed);
        if let Some(counter) = self.failure_buckets.get(bucket) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failure_other.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_success(&self, status: u16) {
        self.paths_attempted.fetch_add(1, Ordering::Relaxed);
        self.paths_succeeded.fetch_add(1, Ordering::Relaxed);
        // Bound check is elided: `status as usize` is always < STATUS_CODE_SLOTS.
        self.statuses[status as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u64, u64, u64, u64, Vec<(String, u64)>) {
        let attempted = self.paths_attempted.load(Ordering::Relaxed);
        let succeeded = self.paths_succeeded.load(Ordering::Relaxed);
        let failed = self.paths_failed.load(Ordering::Relaxed);
        let hosts = self.hosts_completed.load(Ordering::Relaxed);
        let mut top: Vec<(String, u64)> = self
            .failure_buckets
            .iter()
            .map(|(k, c)| ((*k).to_string(), c.load(Ordering::Relaxed)))
            .filter(|(_, v)| *v > 0)
            .collect();
        let other = self.failure_other.load(Ordering::Relaxed);
        if other > 0 {
            top.push(("unknown_bucket".to_string(), other));
        }
        top.sort_by(|a, b| b.1.cmp(&a.1));
        top.truncate(5);
        (attempted, succeeded, failed, hosts, top)
    }

    /// Snapshot the per-status counter array into a `HashMap<u16, u64>` of
    /// non-zero entries. Called once at the end of the run for the JSON
    /// summary; iterates 65 536 atomics (~tens of µs).
    fn statuses_snapshot(&self) -> HashMap<u16, u64> {
        let mut out = HashMap::new();
        for (code, atomic) in self.statuses.iter().enumerate() {
            let v = atomic.load(Ordering::Relaxed);
            if v > 0 {
                out.insert(code as u16, v);
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
struct Host {
    host: String,
    port: u16,
    is_https: bool,
}

async fn run(args: Args) -> Result<()> {
    let hosts = parse_hosts(&args.hosts, &args.default_scheme)?;
    let paths = parse_paths(&args.paths)?;
    if hosts.is_empty() {
        return Err(anyhow!("no hosts loaded from {}", args.hosts.display()));
    }
    if paths.is_empty() {
        return Err(anyhow!("no paths loaded from {}", args.paths.display()));
    }

    eprintln!(
        "anyscan-path-bench: {} hosts × {} paths = {} requests, concurrency={}, workers={}",
        hosts.len(),
        paths.len(),
        hosts.len() * paths.len(),
        args.concurrency,
        if args.workers == 0 {
            num_cpus::get().max(1)
        } else {
            args.workers
        }
    );

    run_bench(hosts, paths, args).await?;
    Ok(())
}

/// Final summary returned from [`run_bench`]. Mirrors the JSON line printed
/// to stdout but is also useful for in-process consumers (the smoke test
/// asserts on `paths_attempted` / `statuses`).
#[derive(Debug, Clone)]
pub struct BenchSummary {
    pub hosts_completed: u64,
    pub paths_attempted: u64,
    pub paths_succeeded: u64,
    pub paths_failed: u64,
    pub elapsed_seconds: f64,
    pub attempt_rps: f64,
    pub success_rps: f64,
    pub top_failures: Vec<(String, u64)>,
    pub statuses: HashMap<u16, u64>,
}

async fn run_bench(hosts: Vec<Host>, paths: Vec<String>, args: Args) -> Result<BenchSummary> {
    let stats = Arc::new(BenchStats::default());
    let started = Instant::now();
    let total_paths = (hosts.len() * paths.len()) as u64;

    let probe_config = Arc::new(ProbeConfig {
        connect_timeout: Duration::from_millis(args.timeout_ms),
        tls_handshake_timeout: Duration::from_millis(args.timeout_ms.saturating_mul(2)),
        write_timeout: Duration::from_millis(args.timeout_ms),
        read_timeout: Duration::from_millis(args.timeout_ms),
        per_connection_timeout: Duration::from_millis(args.per_host_budget_ms),
        user_agent: "anyscan-path-bench/1".to_string(),
        allow_invalid_tls: args.allow_invalid_tls,
        extra_headers: Vec::new(),
        pipeline: args.pipeline,
    });

    let sem = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let stats_clone = Arc::clone(&stats);
    let reporter = tokio::spawn(async move {
        let mut last_attempted = 0u64;
        let mut last_succeeded = 0u64;
        let mut last_at = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let (attempted, succeeded, _failed, hosts_done, top) = stats_clone.snapshot();
            if attempted >= total_paths {
                break;
            }
            let now = Instant::now();
            let elapsed = (now - last_at).as_secs_f64();
            let attempt_rps = (attempted - last_attempted) as f64 / elapsed.max(1e-6);
            let success_rps = (succeeded - last_succeeded) as f64 / elapsed.max(1e-6);
            last_at = now;
            last_attempted = attempted;
            last_succeeded = succeeded;
            let top_str = if top.is_empty() {
                "-".to_string()
            } else {
                top.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            eprintln!(
                "[t+{:>5.1}s] hosts={} attempted={} succeeded={} attempt_rps={:.0} success_rps={:.0} top_err={}",
                started.elapsed().as_secs_f64(),
                hosts_done,
                attempted,
                succeeded,
                attempt_rps,
                success_rps,
                top_str
            );
        }
    });

    // JoinSet drops finished handles as they complete, so memory is bounded
    // by the semaphore (currently in-flight tasks) rather than total host
    // count. That matters at 8k+ hosts.
    let path_count = paths.len();
    let paths_arc: Arc<[String]> = paths.into();
    let mut set: JoinSet<()> = JoinSet::new();
    for host in hosts {
        let permit = Arc::clone(&sem).acquire_owned().await?;
        let stats = Arc::clone(&stats);
        let probe_config = Arc::clone(&probe_config);
        let paths = Arc::clone(&paths_arc);
        set.spawn(async move {
            let _permit = permit;
            let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
            let outcome =
                probe_host_paths(&host.host, host.port, host.is_https, &path_refs, &probe_config)
                    .await;
            match outcome {
                Ok(outcome) => {
                    for resp in outcome.responses.into_iter() {
                        match resp {
                            Ok(r) => stats.record_success(r.status),
                            Err(e) => stats.record_failure(e.bucket()),
                        }
                    }
                }
                Err(e) => {
                    // Whole-connection failure (connect/TLS) — count one failure per path.
                    let bucket = e.bucket();
                    for _ in 0..path_count {
                        stats.record_failure(bucket);
                    }
                }
            }
            stats.hosts_completed.fetch_add(1, Ordering::Relaxed);
        });
    }
    while set.join_next().await.is_some() {}
    // Tickle reporter so it picks up final state and exits.
    reporter.abort();
    let _ = reporter.await;

    let elapsed = started.elapsed().as_secs_f64();
    let (attempted, succeeded, failed, hosts_done, top) = stats.snapshot();
    let statuses_snapshot: HashMap<u16, u64> = stats.statuses_snapshot();
    let summary = BenchSummary {
        hosts_completed: hosts_done,
        paths_attempted: attempted,
        paths_succeeded: succeeded,
        paths_failed: failed,
        elapsed_seconds: elapsed,
        attempt_rps: attempted as f64 / elapsed.max(1e-9),
        success_rps: succeeded as f64 / elapsed.max(1e-9),
        top_failures: top,
        statuses: statuses_snapshot,
    };
    println!("{}", serde_summary(&summary));
    Ok(summary)
}

fn serde_summary(s: &BenchSummary) -> String {
    let mut status_pairs: Vec<(u16, u64)> = s.statuses.iter().map(|(k, v)| (*k, *v)).collect();
    status_pairs.sort_by(|a, b| b.1.cmp(&a.1));
    let status_obj = status_pairs
        .iter()
        .map(|(code, c)| format!("\"{code}\": {c}"))
        .collect::<Vec<_>>()
        .join(", ");
    let top_obj = s
        .top_failures
        .iter()
        .map(|(k, v)| format!("\"{k}\": {v}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"{{"hosts_completed": {hd}, "paths_attempted": {pa}, "paths_succeeded": {ps}, "paths_failed": {pf}, "elapsed_seconds": {es:.3}, "attempt_rps": {ar:.1}, "success_rps": {sr:.1}, "top_failures": {{{top_obj}}}, "statuses": {{{status_obj}}}}}"#,
        hd = s.hosts_completed,
        pa = s.paths_attempted,
        ps = s.paths_succeeded,
        pf = s.paths_failed,
        es = s.elapsed_seconds,
        ar = s.attempt_rps,
        sr = s.success_rps,
    )
}

fn parse_hosts(path: &PathBuf, default_scheme: &str) -> Result<Vec<Host>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading hosts file {}", path.display()))?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(parse_host_line(line, default_scheme)?);
    }
    Ok(out)
}

fn parse_paths(path: &PathBuf) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading paths file {}", path.display()))?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(line.to_string());
    }
    Ok(out)
}

fn parse_host_line(line: &str, default_scheme: &str) -> Result<Host> {
    if line.contains("://") {
        let url = Url::parse(line).with_context(|| format!("parsing url {line}"))?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("no host in url {line}"))?
            .to_string();
        let is_https = url.scheme() == "https";
        let port = url.port().unwrap_or(if is_https { 443 } else { 80 });
        Ok(Host {
            host,
            port,
            is_https,
        })
    } else if let Some((h, p)) = line.rsplit_once(':') {
        // Watch out for IPv6 literals like `[::1]:8080`.
        if h.starts_with('[') && h.ends_with(']') {
            let host = h[1..h.len() - 1].to_string();
            let port: u16 = p.parse().with_context(|| format!("bad port in {line}"))?;
            Ok(Host {
                host,
                port,
                is_https: default_scheme == "https",
            })
        } else if h.contains(':') && !h.contains('[') {
            // Probably an IPv6 literal without explicit port — treat whole line as host.
            Ok(Host {
                host: line.to_string(),
                port: if default_scheme == "https" { 443 } else { 80 },
                is_https: default_scheme == "https",
            })
        } else {
            let port: u16 = p.parse().with_context(|| format!("bad port in {line}"))?;
            Ok(Host {
                host: h.to_string(),
                port,
                is_https: default_scheme == "https",
            })
        }
    } else {
        Ok(Host {
            host: line.to_string(),
            port: if default_scheme == "https" { 443 } else { 80 },
            is_https: default_scheme == "https",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Smoke test: bench against a loopback hyper-style server with 30 known paths,
    /// ensure attempted == 30 × hosts and successful matches.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn smoke_test_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let routes: Arc<HashMap<String, u16>> = Arc::new(
            [
                ("/", 200u16),
                ("/admin", 401),
                ("/login", 200),
                ("/wp-login.php", 200),
                ("/wp-admin", 302),
                ("/.env", 404),
                ("/.git/config", 404),
                ("/.git/HEAD", 404),
                ("/robots.txt", 200),
                ("/sitemap.xml", 404),
                ("/api", 200),
                ("/api/v1", 200),
                ("/health", 200),
                ("/status", 200),
                ("/server-status", 403),
                ("/phpinfo.php", 404),
                ("/phpmyadmin", 404),
                ("/admin.php", 404),
                ("/index.php", 200),
                ("/config.php", 404),
                ("/config.json", 404),
                ("/.well-known/security.txt", 404),
                ("/backup", 404),
                ("/backup.zip", 404),
                ("/dump.sql", 404),
                ("/swagger", 404),
                ("/swagger.json", 404),
                ("/openapi.json", 404),
                ("/graphql", 405),
                ("/dashboard", 302),
            ]
            .iter()
            .map(|(p, s)| ((*p).to_string(), *s))
            .collect(),
        );
        let routes_clone = Arc::clone(&routes);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let routes = Arc::clone(&routes_clone);
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
                        while let Some(end) = buf[..written]
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .map(|p| p + 4)
                        {
                            let req = &buf[..end];
                            let line =
                                req.split(|b| *b == b'\n').next().unwrap_or(b"");
                            let mut parts = line.split(|b| *b == b' ');
                            parts.next();
                            let path = parts
                                .next()
                                .and_then(|p| std::str::from_utf8(p).ok())
                                .unwrap_or("/")
                                .trim_end_matches('\r')
                                .to_string();
                            let status = *routes.get(&path).unwrap_or(&404);
                            let response = format!(
                                "HTTP/1.1 {status} OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                            );
                            if sock.write_all(response.as_bytes()).await.is_err() {
                                return;
                            }
                            buf.copy_within(end..written, 0);
                            written -= end;
                        }
                    }
                });
            }
        });

        let hosts = vec![Host {
            host: "127.0.0.1".to_string(),
            port,
            is_https: false,
        }];
        let paths: Vec<String> = routes.keys().cloned().collect();
        let path_count = paths.len() as u64;
        let args = Args {
            hosts: PathBuf::from("/dev/null"),
            paths: PathBuf::from("/dev/null"),
            concurrency: 4,
            workers: 0,
            pipeline: true,
            timeout_ms: 2000,
            per_host_budget_ms: 5000,
            allow_invalid_tls: false,
            default_scheme: "http".to_string(),
        };
        let summary = run_bench(hosts, paths, args).await.unwrap();
        assert_eq!(summary.hosts_completed, 1);
        assert_eq!(
            summary.paths_attempted, path_count,
            "every path should land in the counters"
        );
        assert_eq!(
            summary.paths_succeeded, path_count,
            "loopback server should answer every request"
        );
        assert_eq!(summary.paths_failed, 0);
        assert!(summary.statuses.contains_key(&200));
        let total_status: u64 = summary.statuses.values().sum();
        assert_eq!(total_status, path_count);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn smoke_test_sequential_mode_matches_pipelined_counts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
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
                        while let Some(end) = buf[..written]
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .map(|p| p + 4)
                        {
                            if sock
                                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
                                .await
                                .is_err()
                            {
                                return;
                            }
                            buf.copy_within(end..written, 0);
                            written -= end;
                        }
                    }
                });
            }
        });
        let hosts = vec![Host {
            host: "127.0.0.1".to_string(),
            port,
            is_https: false,
        }];
        let paths: Vec<String> = (0..5).map(|i| format!("/p{i}")).collect();
        let args = Args {
            hosts: PathBuf::from("/dev/null"),
            paths: PathBuf::from("/dev/null"),
            concurrency: 4,
            workers: 0,
            pipeline: false, // <-- the flag now actually flips the path
            timeout_ms: 2000,
            per_host_budget_ms: 5000,
            allow_invalid_tls: false,
            default_scheme: "http".to_string(),
        };
        let summary = run_bench(hosts, paths, args).await.unwrap();
        assert_eq!(summary.paths_attempted, 5);
        assert_eq!(summary.paths_succeeded, 5);
    }
}
