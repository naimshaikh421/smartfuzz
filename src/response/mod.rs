//! Response analysis, soft-404, similarity, directory heuristics.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fingerprint::Soft404Baseline;
use crate::http::HttpResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzedResponse {
    pub url: String,
    pub path: String,
    pub status: u16,
    pub size: u64,
    pub words: usize,
    pub lines: usize,
    pub elapsed_ms: u64,
    pub hash: String,
    pub redirected: bool,
    pub redirect_target: Option<String>,
    pub soft_404: bool,
    pub duplicate: bool,
    pub filtered: bool,
    pub filter_reason: Option<String>,
    pub depth: u32,
    pub source: DiscoverySource,
    pub content_type: Option<String>,
    #[serde(default)]
    pub stage: ScanStage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ScanStage {
    #[default]
    Fingerprint,
    Directory,
    File,
    Api,
    Recursive,
    Spider,
}

impl ScanStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fingerprint => "fingerprint",
            Self::Directory => "directory",
            Self::File => "file",
            Self::Api => "api",
            Self::Recursive => "recursive",
            Self::Spider => "spider",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoverySource {
    Fingerprint,
    Wordlist,
    Recursive,
    JavaScript,
    Api,
    Robots,
    Sitemap,
    Plugin,
    Spider,
    Extension,
    OpenApi,
    Graphql,
    SourceMap,
}

impl DiscoverySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fingerprint => "fingerprint",
            Self::Wordlist => "wordlist",
            Self::Recursive => "recursive",
            Self::JavaScript => "javascript",
            Self::Api => "api",
            Self::Robots => "robots",
            Self::Sitemap => "sitemap",
            Self::Plugin => "plugin",
            Self::Spider => "spider",
            Self::Extension => "extension",
            Self::OpenApi => "openapi",
            Self::Graphql => "graphql",
            Self::SourceMap => "sourcemap",
        }
    }
}

pub struct ResponseAnalyzer {
    soft404: Option<Soft404Baseline>,
    extras: Vec<Soft404Baseline>,
    similarity_threshold: f64,
}

impl ResponseAnalyzer {
    pub fn new(soft404: Option<Soft404Baseline>) -> Self {
        Self {
            soft404,
            extras: Vec::new(),
            similarity_threshold: 0.95,
        }
    }

    pub fn with_extras(mut self, extras: Vec<Soft404Baseline>) -> Self {
        self.extras = extras;
        self
    }

    pub fn set_threshold(&mut self, t: f64) {
        self.similarity_threshold = t;
    }

    pub fn get_soft404(&self) -> Option<Soft404Baseline> {
        self.soft404.clone()
    }

    pub fn with_same_baseline(&self) -> Self {
        Self {
            soft404: self.soft404.clone(),
            extras: self.extras.clone(),
            similarity_threshold: self.similarity_threshold,
        }
    }

    pub fn analyze(
        &self,
        resp: &HttpResponse,
        path: &str,
        depth: u32,
        source: DiscoverySource,
    ) -> AnalyzedResponse {
        self.analyze_staged(resp, path, depth, source, ScanStage::Directory)
    }

    pub fn analyze_staged(
        &self,
        resp: &HttpResponse,
        path: &str,
        depth: u32,
        source: DiscoverySource,
        stage: ScanStage,
    ) -> AnalyzedResponse {
        let hash = hash_bytes(&resp.body);
        let mut soft_404 = false;
        let mut filter_reason = None;

        let candidates: Vec<&Soft404Baseline> =
            self.soft404.iter().chain(self.extras.iter()).collect();

        for b in candidates {
            if is_soft404_match(resp, &hash, b) {
                soft_404 = true;
                filter_reason = Some("soft-404".into());
                break;
            }
        }

        AnalyzedResponse {
            url: resp.url.clone(),
            path: path.to_string(),
            status: resp.status,
            size: resp.size(),
            words: resp.word_count(),
            lines: resp.line_count(),
            elapsed_ms: resp.elapsed_ms,
            hash,
            redirected: resp.redirected,
            redirect_target: resp.redirect_target.clone(),
            soft_404,
            duplicate: false,
            filtered: soft_404,
            filter_reason,
            depth,
            source,
            content_type: resp.content_type().map(|s| s.to_string()),
            stage,
        }
    }

    pub fn similarity(&self, a: &AnalyzedResponse, b: &AnalyzedResponse) -> f64 {
        if a.hash == b.hash {
            return 1.0;
        }
        let size_sim = if a.size.max(b.size) == 0 {
            1.0
        } else {
            1.0 - ((a.size as f64 - b.size as f64).abs() / a.size.max(b.size) as f64)
        };
        let word_sim = if a.words.max(b.words) == 0 {
            1.0
        } else {
            1.0 - ((a.words as f64 - b.words as f64).abs() / a.words.max(b.words) as f64)
        };
        let line_sim = if a.lines.max(b.lines) == 0 {
            1.0
        } else {
            1.0 - ((a.lines as f64 - b.lines as f64).abs() / a.lines.max(b.lines) as f64)
        };
        (size_sim * 0.5) + (word_sim * 0.3) + (line_sim * 0.2)
    }

    pub fn is_similar(&self, a: &AnalyzedResponse, b: &AnalyzedResponse) -> bool {
        a.status == b.status && self.similarity(a, b) >= self.similarity_threshold
    }

    pub fn is_similar_to_baseline(
        &self,
        item: &AnalyzedResponse,
        baseline: &Soft404Baseline,
        threshold: f64,
    ) -> bool {
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
        let word_sim = if item.words.max(baseline.word_count) == 0 {
            1.0
        } else {
            1.0 - ((item.words as f64 - baseline.word_count as f64).abs()
                / item.words.max(baseline.word_count) as f64)
        };
        ((size_sim + word_sim) / 2.0) >= threshold
    }
}

fn is_soft404_match(resp: &HttpResponse, hash: &str, b: &Soft404Baseline) -> bool {
    // Exact hash match with same-ish status family
    if hash == b.hash {
        return true;
    }
    // Same status + near-identical size + near word count
    if resp.status == b.status {
        let size_close = sizes_similar(resp.size(), b.size, 0.05);
        let words = resp.word_count();
        let word_close = if b.word_count == 0 {
            words == 0
        } else {
            ((words as f64 - b.word_count as f64).abs() / b.word_count as f64) <= 0.08
        };
        if size_close && word_close {
            return true;
        }
    }
    false
}

fn hash_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn sizes_similar(a: u64, b: u64, tol: f64) -> bool {
    let max = a.max(b) as f64;
    if max == 0.0 {
        return true;
    }
    ((a as f64 - b as f64).abs() / max) <= tol
}

/// Detect whether a path looks like a directory (for recursion).
pub fn looks_like_directory(analyzed: &AnalyzedResponse) -> bool {
    if analyzed.soft_404 || analyzed.filtered {
        return false;
    }
    if !matches!(analyzed.status, 200 | 301 | 302 | 307 | 308 | 401 | 403) {
        return false;
    }

    // JSON API leaves shouldn't recurse as directories
    if let Some(ct) = &analyzed.content_type {
        let c = ct.to_ascii_lowercase();
        if c.contains("json")
            || c.contains("javascript")
            || c.contains("image/")
            || c.contains("font")
        {
            // Still recurse /api style paths
            let p = analyzed.path.to_ascii_lowercase();
            if !(p.contains("/api") || p.ends_with("/api") || p.contains("graphql")) {
                return false;
            }
        }
    }

    let p = analyzed.path.trim_end_matches('/');
    if let Some(last) = p.rsplit('/').next() {
        if last.contains('.') {
            let ext = last.rsplit('.').next().unwrap_or("");
            let file_exts = [
                "js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf",
                "map", "pdf", "zip", "xml", "txt", "html", "htm", "wasm", "mp4", "webm",
            ];
            if file_exts.contains(&ext) {
                return false;
            }
            // .json might be API leaf
            if ext == "json" || ext == "yaml" || ext == "yml" {
                return false;
            }
        }
    }
    true
}

pub fn looks_like_file(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .map(|last| last.contains('.'))
        .unwrap_or(false)
}

pub fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
