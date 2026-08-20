//! Smart filters: status/size/words/lines/regex/similarity/time + auto-calibration.

use crate::cli::Args;
use crate::fingerprint::Soft404Baseline;
use crate::http::HttpResponse;
use crate::response::{AnalyzedResponse, ResponseAnalyzer};
use dashmap::DashMap;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Clone)]
pub struct SmartFilters {
    include_status: Option<HashSet<u16>>,
    exclude_status: HashSet<u16>,
    match_size: Option<HashSet<u64>>,
    filter_size: HashSet<u64>,
    match_lines: Option<HashSet<usize>>,
    filter_lines: HashSet<usize>,
    match_words: Option<HashSet<usize>>,
    filter_words: HashSet<usize>,
    match_regex: Option<Regex>,
    filter_regex: Option<Regex>,
    match_time: Option<u64>,
    filter_time: Option<u64>,
    show_filtered: bool,
    default_interesting: HashSet<u16>,
    similarity_threshold: f64,
    use_similarity: bool,
    /// Auto-calibrated sizes to filter (wildcard)
    calibrated_sizes: HashSet<u64>,
    calibrated_hashes: HashSet<String>,
}

impl SmartFilters {
    pub fn from_args(args: &Args) -> Self {
        let include_status = args
            .status_codes
            .as_ref()
            .map(|v| v.iter().copied().collect());
        let exclude_status = args
            .exclude_status
            .as_ref()
            .map(|v| v.iter().copied().collect())
            .unwrap_or_default();
        let match_size = args
            .match_size
            .as_ref()
            .map(|v| v.iter().copied().collect());
        let filter_size = args
            .filter_size
            .as_ref()
            .map(|v| v.iter().copied().collect())
            .unwrap_or_default();
        let match_lines = args
            .match_lines
            .as_ref()
            .map(|v| v.iter().copied().collect());
        let filter_lines = args
            .filter_lines
            .as_ref()
            .map(|v| v.iter().copied().collect())
            .unwrap_or_default();
        let match_words = args
            .match_words
            .as_ref()
            .map(|v| v.iter().copied().collect());
        let filter_words = args
            .filter_words
            .as_ref()
            .map(|v| v.iter().copied().collect())
            .unwrap_or_default();

        let match_regex = args.match_regex.as_ref().and_then(|p| Regex::new(p).ok());
        let filter_regex = args.filter_regex.as_ref().and_then(|p| Regex::new(p).ok());

        let default_interesting = [
            200, 201, 202, 204, 301, 302, 307, 308, 400, 401, 403, 405, 500, 502, 503, 504,
        ]
        .into_iter()
        .collect();

        Self {
            include_status,
            exclude_status,
            match_size,
            filter_size,
            match_lines,
            filter_lines,
            match_words,
            filter_words,
            match_regex,
            filter_regex,
            match_time: args.match_time,
            filter_time: args.filter_time,
            show_filtered: args.show_filtered,
            default_interesting,
            similarity_threshold: args.filter_similar,
            use_similarity: args.use_similarity(),
            calibrated_sizes: HashSet::new(),
            calibrated_hashes: HashSet::new(),
        }
    }

    pub fn ingest_calibration(&mut self, baselines: &[Soft404Baseline]) {
        for b in baselines {
            self.calibrated_sizes.insert(b.size);
            self.calibrated_hashes.insert(b.hash.clone());
            // Also filter near sizes (±2%)
            let delta = ((b.size as f64) * 0.02) as u64;
            for s in b.size.saturating_sub(delta)..=b.size.saturating_add(delta) {
                self.calibrated_sizes.insert(s);
            }
        }
    }

    pub fn apply_with_body(
        &self,
        item: &mut AnalyzedResponse,
        body: Option<&str>,
        analyzer: Option<&ResponseAnalyzer>,
        baseline: Option<&Soft404Baseline>,
    ) -> FilterDecision {
        // Similarity vs soft-404 baseline
        if self.use_similarity {
            if let (Some(a), Some(b)) = (analyzer, baseline) {
                if a.is_similar_to_baseline(item, b, self.similarity_threshold) {
                    item.soft_404 = true;
                    item.filtered = true;
                    item.filter_reason = Some("similar-soft-404".into());
                    return self.filtered_decision();
                }
            }
        }

        // Auto-calibrated wildcards
        if self.calibrated_hashes.contains(&item.hash) || self.calibrated_sizes.contains(&item.size)
        {
            // Only treat as wildcard if status looks like success/soft
            if matches!(item.status, 200 | 301 | 302 | 307 | 308) {
                item.soft_404 = true;
                item.filtered = true;
                item.filter_reason = Some("wildcard-calibrated".into());
                return self.filtered_decision();
            }
        }

        if item.soft_404 {
            item.filtered = true;
            if item.filter_reason.is_none() {
                item.filter_reason = Some("soft-404".into());
            }
            return self.filtered_decision();
        }

        if self.exclude_status.contains(&item.status) {
            item.filtered = true;
            item.filter_reason = Some("exclude-status".into());
            return FilterDecision::Hide;
        }

        if item.status == 404 {
            let keep = self
                .include_status
                .as_ref()
                .map(|s| s.contains(&404))
                .unwrap_or(false);
            if !keep {
                item.filtered = true;
                item.filter_reason = Some("404".into());
                return FilterDecision::Hide;
            }
        }

        if let Some(inc) = &self.include_status {
            if !inc.contains(&item.status) {
                item.filtered = true;
                item.filter_reason = Some("status-mismatch".into());
                return FilterDecision::Hide;
            }
        } else if !self.default_interesting.contains(&item.status) {
            if item.status == 429 {
                item.filtered = true;
                item.filter_reason = Some("rate-limited".into());
                return self.filtered_decision();
            }
            item.filtered = true;
            item.filter_reason = Some("uninteresting-status".into());
            return FilterDecision::Hide;
        }

        if let Some(ms) = &self.match_size {
            if !ms.contains(&item.size) {
                item.filtered = true;
                item.filter_reason = Some("size-mismatch".into());
                return FilterDecision::Hide;
            }
        }
        if self.filter_size.contains(&item.size) {
            item.filtered = true;
            item.filter_reason = Some("filter-size".into());
            return FilterDecision::Hide;
        }

        if let Some(ml) = &self.match_lines {
            if !ml.contains(&item.lines) {
                item.filtered = true;
                item.filter_reason = Some("lines-mismatch".into());
                return FilterDecision::Hide;
            }
        }
        if self.filter_lines.contains(&item.lines) {
            item.filtered = true;
            item.filter_reason = Some("filter-lines".into());
            return FilterDecision::Hide;
        }

        if let Some(mw) = &self.match_words {
            if !mw.contains(&item.words) {
                item.filtered = true;
                item.filter_reason = Some("words-mismatch".into());
                return FilterDecision::Hide;
            }
        }
        if self.filter_words.contains(&item.words) {
            item.filtered = true;
            item.filter_reason = Some("filter-words".into());
            return FilterDecision::Hide;
        }

        if let Some(mt) = self.match_time {
            if item.elapsed_ms > mt {
                item.filtered = true;
                item.filter_reason = Some("time-mismatch".into());
                return FilterDecision::Hide;
            }
        }
        if let Some(ft) = self.filter_time {
            if item.elapsed_ms >= ft {
                item.filtered = true;
                item.filter_reason = Some("filter-time".into());
                return FilterDecision::Hide;
            }
        }

        if let Some(body) = body {
            if let Some(re) = &self.match_regex {
                if !re.is_match(body) {
                    item.filtered = true;
                    item.filter_reason = Some("regex-mismatch".into());
                    return FilterDecision::Hide;
                }
            }
            if let Some(re) = &self.filter_regex {
                if re.is_match(body) {
                    item.filtered = true;
                    item.filter_reason = Some("filter-regex".into());
                    return FilterDecision::Hide;
                }
            }
        }

        FilterDecision::Keep
    }

    pub fn apply(&self, item: &mut AnalyzedResponse) -> FilterDecision {
        self.apply_with_body(item, None, None, None)
    }

    fn filtered_decision(&self) -> FilterDecision {
        if self.show_filtered {
            FilterDecision::ShowFiltered
        } else {
            FilterDecision::Hide
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    Keep,
    ShowFiltered,
    Hide,
}

#[derive(Debug, Clone)]
struct SimilaritySample {
    path: String,
    status: u16,
    size: u64,
    hash: String,
    words: usize,
    lines: usize,
}

/// Tracks response hashes / redirect targets / attempted paths / fuzzy similarity.
#[derive(Clone, Default)]
pub struct DuplicateDetector {
    hashes: Arc<DashMap<String, String>>,
    redirects: Arc<DashMap<String, String>>,
    paths: Arc<DashMap<String, ()>>,
    /// Recent discoveries for fuzzy similarity dedup.
    similarity_samples: Arc<DashMap<String, SimilaritySample>>,
}

impl DuplicateDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seen_path(&self, path: &str) -> bool {
        self.paths.contains_key(path)
    }

    pub fn mark_path(&self, path: &str) {
        self.paths.insert(path.to_string(), ());
    }

    pub fn all_paths(&self) -> Vec<String> {
        self.paths.iter().map(|e| e.key().clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Returns true if duplicate and should be filtered.
    pub fn check_duplicate(
        &self,
        item: &mut AnalyzedResponse,
        analyzer: Option<&ResponseAnalyzer>,
    ) -> bool {
        // Dedup identical bodies for any "interesting" status
        if matches!(
            item.status,
            200 | 201 | 204 | 301 | 302 | 307 | 308 | 401 | 403
        ) && !item.hash.is_empty()
        {
            if let Some(first) = self.hashes.get(&item.hash) {
                if first.as_str() != item.path.as_str() {
                    item.duplicate = true;
                    item.filtered = true;
                    item.filter_reason = Some(format!("duplicate-of:{}", first.value()));
                    return true;
                }
            } else {
                self.hashes.insert(item.hash.clone(), item.path.clone());
            }
        }

        // Fuzzy similarity vs prior discoveries (wildcard / soft-404 pages)
        if let Some(a) = analyzer {
            if matches!(
                item.status,
                200 | 201 | 204 | 301 | 302 | 307 | 308 | 401 | 403
            ) {
                for sample in self.similarity_samples.iter() {
                    if sample.path == item.path {
                        continue;
                    }
                    let probe = AnalyzedResponse {
                        url: String::new(),
                        path: sample.path.clone(),
                        status: sample.status,
                        size: sample.size,
                        hash: sample.hash.clone(),
                        words: sample.words,
                        lines: sample.lines,
                        elapsed_ms: 0,
                        redirected: false,
                        redirect_target: None,
                        soft_404: false,
                        duplicate: false,
                        filtered: false,
                        filter_reason: None,
                        depth: 0,
                        source: crate::response::DiscoverySource::Wordlist,
                        content_type: None,
                        stage: crate::response::ScanStage::Directory,
                    };
                    if a.is_similar(item, &probe) {
                        item.duplicate = true;
                        item.filtered = true;
                        item.filter_reason = Some(format!("similar-to:{}", sample.path));
                        return true;
                    }
                }
            }
        }

        if let Some(target) = &item.redirect_target {
            if let Some(first) = self.redirects.get(target) {
                if first.as_str() != item.path.as_str() {
                    item.duplicate = true;
                    item.filtered = true;
                    item.filter_reason = Some(format!("duplicate-redirect:{}", first.value()));
                    return true;
                }
            } else {
                self.redirects.insert(target.clone(), item.path.clone());
            }
        }

        // Record for future fuzzy dedup
        if matches!(
            item.status,
            200 | 201 | 204 | 301 | 302 | 307 | 308 | 401 | 403
        ) {
            self.similarity_samples.insert(
                item.path.clone(),
                SimilaritySample {
                    path: item.path.clone(),
                    status: item.status,
                    size: item.size,
                    hash: item.hash.clone(),
                    words: item.words,
                    lines: item.lines,
                },
            );
        }

        false
    }
}

/// Auto-calibrate using random probes (ffuf -ac style).
pub async fn auto_calibrate(
    http: &crate::http::HttpEngine,
    headers: &[(String, String)],
) -> (Vec<Soft404Baseline>, u64) {
    use crate::fingerprint::hash_body;
    use rand::Rng;

    let mut baselines = Vec::new();
    let mut rng = rand::thread_rng();
    let mut requests = 0u64;

    for _ in 0..3 {
        let rand_path: String = (0..10)
            .map(|_| {
                let idx = rng.gen_range(0..36);
                b"abcdefghijklmnopqrstuvwxyz0123456789"[idx] as char
            })
            .collect();
        let probes = [
            format!("/{}", rand_path),
            format!("/{}.php", rand_path),
            format!("/{}.json", rand_path),
        ];
        for p in probes {
            if let Ok(url) = http.resolve(&p) {
                if let Ok(resp) = http.get(&url, headers).await {
                    requests += 1;
                    if matches!(resp.status, 200 | 301 | 302 | 307 | 308 | 403 | 404) {
                        baselines.push(Soft404Baseline {
                            status: resp.status,
                            size: resp.size(),
                            hash: hash_body(&resp.body),
                            word_count: resp.word_count(),
                            line_count: resp.line_count(),
                        });
                    }
                }
            }
        }
    }

    let mut size_counts: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
    let mut hash_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for b in &baselines {
        *size_counts.entry(b.size).or_default() += 1;
        *hash_counts.entry(b.hash.clone()).or_default() += 1;
    }

    let filtered = baselines
        .into_iter()
        .filter(|b| {
            size_counts.get(&b.size).copied().unwrap_or(0) >= 2
                || hash_counts.get(&b.hash).copied().unwrap_or(0) >= 2
        })
        .collect();
    (filtered, requests)
}

/// Helper: store body snippet for regex filtering without keeping full body forever.
pub fn body_for_filter(resp: &HttpResponse) -> String {
    let s = resp.body_str();
    if s.len() > 64_000 {
        s[..64_000].to_string()
    } else {
        s
    }
}
