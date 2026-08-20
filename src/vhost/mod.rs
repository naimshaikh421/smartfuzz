//! VHost discovery via Host-header fuzzing (100% free, no external services).

use crate::cli::Args;
use crate::http::{load_wordlist_file, HttpEngine};
use crate::response::{AnalyzedResponse, DiscoverySource, ResponseAnalyzer, ScanStage};

#[derive(Debug, Clone)]
pub struct VhostConfig {
    pub target_url: String,
    pub base_domain: String,
    pub ip_override: Option<String>,
}

/// Baseline response for the default Host header (used to filter false positives).
#[derive(Debug, Clone)]
pub struct VhostBaseline {
    pub status: u16,
    pub size: u64,
    pub hash: String,
    pub words: usize,
    pub lines: usize,
}

impl VhostConfig {
    pub fn from_url(
        url: &str,
        base_domain: Option<&str>,
        ip: Option<&str>,
    ) -> anyhow::Result<Self> {
        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().unwrap_or("localhost").to_string();
        let base = base_domain
            .map(|s| s.to_string())
            .unwrap_or_else(|| strip_www(&host));
        Ok(Self {
            target_url: url.to_string(),
            base_domain: base,
            ip_override: ip.map(|s| s.to_string()),
        })
    }

    pub fn host_for_entry(&self, entry: &str) -> String {
        let entry = entry.trim();
        if entry.contains('.') {
            entry.to_string()
        } else {
            format!("{}.{}", entry, self.base_domain)
        }
    }

    fn request_url(&self) -> Option<String> {
        if let Some(ip) = &self.ip_override {
            let mut base = url::Url::parse(&self.target_url).ok()?;
            base.set_host(Some(ip.as_str())).ok()?;
            Some(base.to_string())
        } else {
            Some(self.target_url.clone())
        }
    }
}

fn strip_www(host: &str) -> String {
    host.strip_prefix("www.").unwrap_or(host).to_string()
}

const BUILTIN_VHOSTS: &[&str] = &[
    "www",
    "admin",
    "api",
    "dev",
    "staging",
    "test",
    "beta",
    "mail",
    "webmail",
    "portal",
    "internal",
    "intranet",
    "vpn",
    "remote",
    "secure",
    "login",
    "dashboard",
    "app",
    "mobile",
    "m",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "media",
    "blog",
    "shop",
    "store",
    "jenkins",
    "gitlab",
    "jira",
    "confluence",
    "grafana",
    "kibana",
    "prometheus",
    "status",
    "monitor",
    "backup",
    "old",
    "new",
    "legacy",
    "demo",
    "sandbox",
    "uat",
    "qa",
    "preprod",
    "prod",
    "production",
    "cms",
    "wiki",
    "docs",
    "help",
    "support",
    "ftp",
    "sftp",
    "db",
    "mysql",
    "postgres",
    "redis",
    "elastic",
    "search",
    "graphql",
    "ws",
    "socket",
    "auth",
    "sso",
    "oauth",
    "id",
    "accounts",
    "account",
    "billing",
    "pay",
    "payment",
    "checkout",
];

pub fn load_vhost_wordlist(args: &Args) -> anyhow::Result<Vec<String>> {
    if let Some(path) = &args.vhost_wordlist {
        return load_wordlist_file(path);
    }
    if let Some(path) = args.wordlist.first() {
        return load_wordlist_file(path);
    }
    Ok(BUILTIN_VHOSTS.iter().map(|s| s.to_string()).collect())
}

/// Capture baseline response using the default Host header (no vhost override).
pub async fn capture_baseline(
    http: &HttpEngine,
    cfg: &VhostConfig,
    default_host: &str,
    extra_headers: &[(String, String)],
) -> Option<VhostBaseline> {
    let url = cfg.request_url()?;
    let mut headers: Vec<(String, String)> = extra_headers.to_vec();
    headers.push(("Host".into(), default_host.to_string()));

    let resp = http.get(&url, &headers).await.ok()?;
    Some(VhostBaseline {
        status: resp.status,
        size: resp.size(),
        hash: crate::fingerprint::hash_body(&resp.body),
        words: resp.word_count(),
        lines: resp.line_count(),
    })
}

/// Returns true when the vhost response is indistinguishable from the default Host baseline.
pub fn matches_baseline(item: &AnalyzedResponse, baseline: &VhostBaseline, threshold: f64) -> bool {
    if item.hash == baseline.hash {
        return true;
    }
    if item.status != baseline.status {
        return false;
    }
    let size_sim = if item.size.max(baseline.size) == 0 {
        1.0
    } else {
        1.0 - ((item.size as f64 - baseline.size as f64).abs()
            / item.size.max(baseline.size) as f64)
    };
    let word_sim = if item.words.max(baseline.words) == 0 {
        1.0
    } else {
        1.0 - ((item.words as f64 - baseline.words as f64).abs()
            / item.words.max(baseline.words) as f64)
    };
    let line_sim = if item.lines.max(baseline.lines) == 0 {
        1.0
    } else {
        1.0 - ((item.lines as f64 - baseline.lines as f64).abs()
            / item.lines.max(baseline.lines) as f64)
    };
    let sim = (size_sim * 0.5) + (word_sim * 0.3) + (line_sim * 0.2);
    sim >= threshold
}

pub async fn probe_vhost(
    http: &HttpEngine,
    cfg: &VhostConfig,
    entry: &str,
    analyzer: &ResponseAnalyzer,
    extra_headers: &[(String, String)],
    baseline: Option<&VhostBaseline>,
    similarity_threshold: f64,
) -> Option<AnalyzedResponse> {
    let hostname = cfg.host_for_entry(entry);
    let url = cfg.request_url()?;

    let mut headers: Vec<(String, String)> = extra_headers.to_vec();
    headers.push(("Host".into(), hostname.clone()));

    let resp = http.get(&url, &headers).await.ok()?;
    let path = format!("vhost:{}", hostname);
    let mut analyzed = analyzer.analyze_staged(
        &resp,
        &path,
        0,
        DiscoverySource::Wordlist,
        ScanStage::Fingerprint,
    );

    if let Some(base) = baseline {
        if matches_baseline(&analyzed, base, similarity_threshold) {
            analyzed.filtered = true;
            analyzed.filter_reason = Some("vhost-same-as-baseline".into());
            return Some(analyzed);
        }
    }

    Some(analyzed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_entry_expansion() {
        let cfg = VhostConfig {
            target_url: "https://example.com".into(),
            base_domain: "example.com".into(),
            ip_override: None,
        };
        assert_eq!(cfg.host_for_entry("admin"), "admin.example.com");
        assert_eq!(cfg.host_for_entry("dev.example.com"), "dev.example.com");
    }

    #[test]
    fn baseline_match_by_hash() {
        let base = VhostBaseline {
            status: 200,
            size: 1000,
            hash: "abc".into(),
            words: 50,
            lines: 10,
        };
        let item = AnalyzedResponse {
            url: String::new(),
            path: "/test".into(),
            status: 200,
            size: 1000,
            hash: "abc".into(),
            words: 50,
            lines: 10,
            elapsed_ms: 0,
            redirected: false,
            redirect_target: None,
            soft_404: false,
            duplicate: false,
            filtered: false,
            filter_reason: None,
            depth: 0,
            source: DiscoverySource::Wordlist,
            content_type: None,
            stage: ScanStage::Fingerprint,
        };
        assert!(matches_baseline(&item, &base, 0.95));
    }

    #[test]
    fn builtin_list_not_empty() {
        assert!(!BUILTIN_VHOSTS.is_empty());
    }
}
