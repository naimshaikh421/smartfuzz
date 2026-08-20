//! CLI argument parsing and scan configuration.

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ScanMode {
    /// Top ~500 entries, depth 2
    Fast,
    /// Top ~5000 entries, depth 4
    Balanced,
    /// Top 50000+, full recursive analysis
    Deep,
}

impl ScanMode {
    pub fn max_depth(self) -> u32 {
        match self {
            ScanMode::Fast => 2,
            ScanMode::Balanced => 4,
            ScanMode::Deep => 8,
        }
    }

    pub fn wordlist_limit(self) -> usize {
        match self {
            ScanMode::Fast => 500,
            ScanMode::Balanced => 5_000,
            ScanMode::Deep => 50_000,
        }
    }

    pub fn default_threads(self) -> usize {
        match self {
            ScanMode::Fast => 80,
            ScanMode::Balanced => 40,
            ScanMode::Deep => 20,
        }
    }
}

#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
#[command(
    name = "smartfuzz",
    about = "Intelligent adaptive web content discovery for authorized testing",
    long_about = "SmartFuzz fingerprints targets, generates technology-aware wordlists, \
recursively discovers endpoints, analyzes JavaScript/APIs, and filters soft-404s. \
Use only on systems you are authorized to test.\n\n\
FUZZ keyword: -u https://target.com/FUZZ or -u https://target.com/api/FUZZ.json"
)]
pub struct Args {
    /// Target URL. Supports FUZZ keyword (e.g. https://t.com/FUZZ or https://t.com/api/FUZZ.php)
    #[arg(short = 'u', long)]
    pub url: String,

    /// Scan mode: fast | balanced | deep
    #[arg(short = 'm', long, value_enum, default_value = "balanced")]
    pub mode: ScanMode,

    /// Enable recursive discovery (default: true)
    #[arg(short = 'r', long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
    pub recursive: bool,

    /// Disable recursive discovery
    #[arg(long = "no-recursive")]
    pub no_recursive: bool,

    /// Maximum recursion depth (overrides mode default)
    #[arg(long)]
    pub depth: Option<u32>,

    /// Concurrent workers
    #[arg(short = 't', long)]
    pub threads: Option<usize>,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

    /// Resume from previous scan state file
    #[arg(long)]
    pub resume: Option<PathBuf>,

    /// Save resume state to this path
    #[arg(long, default_value = ".smartfuzz_state.json")]
    pub state_file: PathBuf,

    /// Max requests per second (0 = unlimited, adaptive still applies)
    #[arg(long, default_value_t = 0)]
    pub rate_limit: u32,

    /// Fixed delay between requests in milliseconds
    #[arg(short = 'p', long, default_value_t = 0)]
    pub delay: u64,

    /// Random jitter added to delay (ms). Default: 25% of `-p` when delay > 0
    #[arg(long)]
    pub delay_jitter: Option<u64>,

    /// Maximum total HTTP requests (0 = unlimited)
    #[arg(long = "scan-limit", default_value_t = 0)]
    pub scan_limit: u64,

    /// Follow redirects (default: true)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
    pub follow_redirects: bool,

    /// Show soft-404 and duplicate filtered results
    #[arg(long, default_value_t = false)]
    pub show_filtered: bool,

    /// Auto-calibrate soft-404 / wildcard filters (like ffuf -ac)
    #[arg(long = "auto-calibrate", short = 'a', default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
    pub auto_calibrate: bool,

    /// Disable auto-calibration
    #[arg(long = "no-auto-calibrate")]
    pub no_auto_calibrate: bool,

    /// Extract links from HTML responses and add to queue
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
    pub spider: bool,

    /// Disable HTML link spidering
    #[arg(long = "no-spider")]
    pub no_spider: bool,

    /// File extensions to append (comma-separated), e.g. php,bak,old,env
    #[arg(short = 'e', long, value_delimiter = ',')]
    pub extensions: Vec<String>,

    /// POST/PUT body data (FUZZ keyword supported)
    #[arg(short = 'd', long)]
    pub data: Option<String>,

    /// Read raw HTTP request from file (supports FUZZ)
    #[arg(long)]
    pub request: Option<PathBuf>,

    /// Match response body regex
    #[arg(long = "match-regex")]
    pub match_regex: Option<String>,

    /// Filter (exclude) response body regex
    #[arg(long = "filter-regex")]
    pub filter_regex: Option<String>,

    /// Filter responses similar to soft-404 baseline (0.0–1.0 threshold)
    #[arg(long = "filter-similar", default_value_t = 0.95)]
    pub filter_similar: f64,

    /// Disable similarity filtering
    #[arg(long = "no-similarity")]
    pub no_similarity: bool,

    /// Match response time <= ms
    #[arg(long)]
    pub match_time: Option<u64>,

    /// Filter response time >= ms
    #[arg(long)]
    pub filter_time: Option<u64>,

    /// Maximum scan duration in seconds (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    pub maxtime: u64,

    /// Maximum response body bytes to buffer (default 2MB)
    #[arg(long, default_value_t = 2_097_152)]
    pub max_body: usize,

    /// Load config from JSON/YAML file
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Write JSON report to path
    #[arg(long)]
    pub json: Option<PathBuf>,

    /// Write HTML report to path
    #[arg(long)]
    pub html: Option<PathBuf>,

    /// Write Markdown report to path
    #[arg(long)]
    pub markdown: Option<PathBuf>,

    /// Write CSV report to path
    #[arg(long)]
    pub csv: Option<PathBuf>,

    /// Write NDJSON event stream for UI / automation (full scan transparency)
    #[arg(long)]
    pub json_events: Option<PathBuf>,

    /// Write ffuf-compatible JSON report (free format, import into ffuf tooling)
    #[arg(long)]
    pub ffuf_json: Option<PathBuf>,

    /// VHost discovery — fuzz Host header (no external services)
    #[arg(long)]
    pub vhost: bool,

    /// Base domain for vhost entries (default: URL host)
    #[arg(long)]
    pub vhost_domain: Option<String>,

    /// Connect to this IP while fuzzing Host header (e.g. CDN/origin IP)
    #[arg(long)]
    pub vhost_ip: Option<String>,

    /// VHost wordlist path (defaults to first `-w` or built-in list)
    #[arg(long)]
    pub vhost_wordlist: Option<PathBuf>,

    /// Verbose logging
    #[arg(short = 'v', long, default_value_t = false)]
    pub verbose: bool,

    /// Suppress non-result output
    #[arg(long, default_value_t = false)]
    pub silent: bool,

    /// Include status codes (comma-separated). Empty = smart defaults
    #[arg(long, value_delimiter = ',')]
    pub status_codes: Option<Vec<u16>>,

    /// Exclude status codes (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub exclude_status: Option<Vec<u16>>,

    /// Match response sizes (comma-separated bytes)
    #[arg(long, value_delimiter = ',')]
    pub match_size: Option<Vec<u64>>,

    /// Filter (exclude) response sizes
    #[arg(long, value_delimiter = ',')]
    pub filter_size: Option<Vec<u64>>,

    /// Match line counts
    #[arg(long, value_delimiter = ',')]
    pub match_lines: Option<Vec<usize>>,

    /// Filter line counts
    #[arg(long, value_delimiter = ',')]
    pub filter_lines: Option<Vec<usize>>,

    /// Match word counts
    #[arg(long, value_delimiter = ',')]
    pub match_words: Option<Vec<usize>>,

    /// Filter word counts
    #[arg(long, value_delimiter = ',')]
    pub filter_words: Option<Vec<usize>>,

    /// Custom wordlist path(s)
    #[arg(short = 'w', long)]
    pub wordlist: Vec<PathBuf>,

    /// Extra headers (Header: Value)
    #[arg(short = 'H', long)]
    pub header: Vec<String>,

    /// HTTP method
    #[arg(long, default_value = "GET")]
    pub method: String,

    /// User-Agent
    #[arg(long, default_value = "SmartFuzz/0.1 (+authorized-testing)")]
    pub user_agent: String,

    /// Enable HTTP/2 (ALPN negotiation). Set false to force HTTP/1.1
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
    pub http2: bool,

    /// Force HTTP/1.1 only
    #[arg(long = "http1")]
    pub http1: bool,

    /// Skip fingerprinting stage
    #[arg(long, default_value_t = false)]
    pub skip_fingerprint: bool,

    /// Skip JavaScript analysis
    #[arg(long, default_value_t = false)]
    pub skip_js: bool,

    /// Skip GraphQL introspection
    #[arg(long, default_value_t = false)]
    pub skip_graphql: bool,

    /// Plugin directory
    #[arg(long)]
    pub plugins: Option<PathBuf>,

    /// Cookies string
    #[arg(long)]
    pub cookies: Option<String>,

    /// Proxy URL
    #[arg(long)]
    pub proxy: Option<String>,

    /// Insecure TLS (skip cert verification)
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// Collect discovered file extensions and fuzz them
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
    pub collect_extensions: bool,

    /// After fingerprinting, auto-select wordlists based on detected tech (default: true)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
    pub auto_wordlist: bool,

    /// Disable tech-based wordlist selection
    #[arg(long = "no-auto-wordlist")]
    pub no_auto_wordlist: bool,

    /// Download missing wordlists from free SecLists (GitHub) into cache
    #[arg(long)]
    pub download_wordlists: bool,

    /// Never download wordlists — local/cache/embedded only
    #[arg(long)]
    pub no_download: bool,

    /// Local SecLists root (e.g. /path/to/SecLists/Discovery/Web-Content)
    #[arg(long)]
    pub wordlist_dir: Option<PathBuf>,

    /// Cache directory for downloaded wordlists
    #[arg(long, default_value = "wordlists/cache")]
    pub wordlist_cache: PathBuf,

    /// Fingerprint + show wordlist recommendations only (no fuzzing)
    #[arg(long)]
    pub recommend_only: bool,
}

impl Args {
    /// Merge optional JSON config file over defaults (CLI still wins for set values).
    pub fn apply_config_file(&mut self) -> anyhow::Result<()> {
        let Some(path) = self.config.clone() else {
            return Ok(());
        };
        let data = std::fs::read_to_string(&path)?;
        let cfg: ConfigFile = if path.extension().and_then(|e| e.to_str()) == Some("yaml")
            || path.extension().and_then(|e| e.to_str()) == Some("yml")
        {
            serde_yaml::from_str(&data)?
        } else {
            serde_json::from_str(&data)?
        };
        cfg.merge_into(self);
        Ok(())
    }

    pub fn effective_depth(&self) -> u32 {
        self.depth.unwrap_or_else(|| self.mode.max_depth())
    }

    pub fn effective_threads(&self) -> usize {
        self.threads
            .unwrap_or_else(|| self.mode.default_threads())
            .max(1)
    }

    pub fn wordlist_cap(&self) -> usize {
        self.mode.wordlist_limit()
    }

    pub fn is_recursive(&self) -> bool {
        if self.no_recursive {
            false
        } else {
            self.recursive
        }
    }

    pub fn is_auto_calibrate(&self) -> bool {
        if self.no_auto_calibrate {
            false
        } else {
            self.auto_calibrate
        }
    }

    pub fn is_spider(&self) -> bool {
        if self.no_spider {
            false
        } else {
            self.spider
        }
    }

    pub fn use_http2(&self) -> bool {
        if self.http1 {
            false
        } else {
            self.http2
        }
    }

    pub fn use_similarity(&self) -> bool {
        !self.no_similarity && self.filter_similar > 0.0
    }

    pub fn is_auto_wordlist(&self) -> bool {
        if self.no_auto_wordlist {
            false
        } else {
            self.auto_wordlist
        }
    }

    pub fn allow_wordlist_download(&self) -> bool {
        self.download_wordlists && !self.no_download
    }

    pub fn effective_delay_jitter(&self) -> u64 {
        if let Some(j) = self.delay_jitter {
            return j;
        }
        if self.delay > 0 {
            self.delay / 4
        } else {
            0
        }
    }

    pub fn has_fuzz(&self) -> bool {
        crate::http::has_fuzz(&self.url)
            || self
                .data
                .as_ref()
                .map(|d| crate::http::has_fuzz(d))
                .unwrap_or(false)
            || self.request.is_some()
    }

    pub fn effective_method(&self) -> &str {
        if self.data.is_some() && self.method.eq_ignore_ascii_case("GET") {
            "POST"
        } else {
            &self.method
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfigFile {
    pub url: Option<String>,
    pub mode: Option<ScanMode>,
    pub threads: Option<usize>,
    pub depth: Option<u32>,
    pub wordlist: Option<Vec<PathBuf>>,
    pub extensions: Option<Vec<String>>,
    pub rate_limit: Option<u32>,
    pub timeout: Option<u64>,
    pub headers: Option<Vec<String>>,
    pub cookies: Option<String>,
    pub proxy: Option<String>,
    pub method: Option<String>,
    pub data: Option<String>,
    pub status_codes: Option<Vec<u16>>,
    pub exclude_status: Option<Vec<u16>>,
    pub plugins: Option<PathBuf>,
    pub insecure: Option<bool>,
    pub recursive: Option<bool>,
    pub maxtime: Option<u64>,
    pub scan_limit: Option<u64>,
}

impl ConfigFile {
    fn merge_into(self, args: &mut Args) {
        if let Some(u) = self.url {
            if args.url.is_empty() {
                args.url = u;
            }
        }
        if args.threads.is_none() {
            if let Some(t) = self.threads {
                args.threads = Some(t);
            }
        }
        if args.depth.is_none() {
            if let Some(d) = self.depth {
                args.depth = Some(d);
            }
        }
        if let Some(m) = self.mode {
            args.mode = m;
        }
        if args.wordlist.is_empty() {
            if let Some(w) = self.wordlist {
                args.wordlist = w;
            }
        }
        if args.extensions.is_empty() {
            if let Some(e) = self.extensions {
                args.extensions = e;
            }
        }
        if let Some(r) = self.rate_limit {
            if args.rate_limit == 0 {
                args.rate_limit = r;
            }
        }
        if let Some(t) = self.timeout {
            args.timeout = t;
        }
        if args.header.is_empty() {
            if let Some(h) = self.headers {
                args.header = h;
            }
        }
        if args.cookies.is_none() {
            args.cookies = self.cookies;
        }
        if args.proxy.is_none() {
            args.proxy = self.proxy;
        }
        if let Some(m) = self.method {
            args.method = m;
        }
        if args.data.is_none() {
            args.data = self.data;
        }
        if args.status_codes.is_none() {
            args.status_codes = self.status_codes;
        }
        if args.exclude_status.is_none() {
            args.exclude_status = self.exclude_status;
        }
        if args.plugins.is_none() {
            args.plugins = self.plugins;
        }
        if let Some(i) = self.insecure {
            args.insecure = i;
        }
        if let Some(r) = self.recursive {
            args.recursive = r;
        }
        if let Some(m) = self.maxtime {
            if args.maxtime == 0 {
                args.maxtime = m;
            }
        }
        if let Some(s) = self.scan_limit {
            if args.scan_limit == 0 {
                args.scan_limit = s;
            }
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_full_scan_limit_no_calibrate() {
        let args = Args::try_parse_from([
            "smartfuzz",
            "-u",
            "http://127.0.0.1:8765",
            "--scan-limit",
            "5",
            "--skip-fingerprint",
            "--no-auto-wordlist",
            "--no-auto-calibrate",
            "-w",
            "/tmp/sf-local-wl.txt",
            "--no-download",
            "--no-recursive",
        ])
        .unwrap();
        assert_eq!(args.scan_limit, 5);
        assert!(!args.is_auto_calibrate());
    }
}
