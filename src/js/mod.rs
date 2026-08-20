//! JavaScript download, endpoint extraction, source map analysis.

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

use crate::http::HttpEngine;
use crate::wordlist::{expand_parents, normalize_path};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsAnalysis {
    pub files_analyzed: usize,
    pub urls: Vec<String>,
    pub endpoints: Vec<String>,
    pub apis: Vec<String>,
    pub parameters: Vec<String>,
    pub versions: Vec<String>,
    pub source_maps: Vec<String>,
}

pub struct JsAnalyzer {
    http: HttpEngine,
    headers: Vec<(String, String)>,
    max_files: usize,
    max_bytes: usize,
}

impl JsAnalyzer {
    pub fn new(http: HttpEngine, headers: Vec<(String, String)>) -> Self {
        Self {
            http,
            headers,
            max_files: 60,
            max_bytes: 2_000_000,
        }
    }

    pub async fn analyze(&self, js_urls: &[String]) -> Result<JsAnalysis> {
        let mut analysis = JsAnalysis::default();
        let mut seen_files = HashSet::new();
        let mut queue: Vec<String> = js_urls.to_vec();
        let mut processed = 0usize;
        let map_re = Regex::new(r#"//[#@]\s*sourceMappingURL\s*=\s*(\S+)"#).unwrap();

        while let Some(raw) = queue.pop() {
            if processed >= self.max_files {
                break;
            }
            let Some(url) = resolve_js_url(&self.http, &raw) else {
                continue;
            };
            if !seen_files.insert(url.clone()) {
                continue;
            }
            let Ok(resp) = self.http.get(&url, &self.headers).await else {
                continue;
            };
            if resp.status != 200 || resp.body.len() > self.max_bytes {
                continue;
            }
            let body = resp.body_str();
            processed += 1;
            analysis.files_analyzed += 1;

            let mut nested = Vec::new();
            extract_from_js(&body, &mut analysis, &mut nested);

            // Queue nested JS discovered inside this file
            for n in nested {
                if let Some(u) = resolve_js_url(&self.http, &n) {
                    if !seen_files.contains(&u) {
                        queue.push(u);
                    }
                }
            }

            // Source maps
            for cap in map_re.captures_iter(&body) {
                if let Some(m) = cap.get(1) {
                    let map_ref = m.as_str().trim();
                    analysis.source_maps.push(map_ref.to_string());
                    if let Some(map_url) = resolve_js_url(&self.http, map_ref) {
                        if let Ok(map_resp) = self.http.get(&map_url, &self.headers).await {
                            if map_resp.status == 200 {
                                extract_from_sourcemap(&map_resp.body_str(), &mut analysis);
                            }
                        }
                    }
                }
            }
        }

        analysis.urls.sort();
        analysis.urls.dedup();
        analysis.endpoints.sort();
        analysis.endpoints.dedup();
        analysis.apis.sort();
        analysis.apis.dedup();
        analysis.parameters.sort();
        analysis.parameters.dedup();
        analysis.versions.sort();
        analysis.versions.dedup();
        analysis.source_maps.sort();
        analysis.source_maps.dedup();

        let mut expanded = HashSet::new();
        for ep in &analysis.endpoints {
            for p in expand_parents(ep) {
                expanded.insert(p);
            }
        }
        for p in expanded {
            if !analysis.endpoints.contains(&p) {
                analysis.endpoints.push(p);
            }
        }
        analysis.endpoints.sort();
        analysis.endpoints.dedup();

        Ok(analysis)
    }
}

fn resolve_js_url(http: &HttpEngine, raw: &str) -> Option<String> {
    if raw.starts_with("data:") || raw.starts_with("blob:") {
        return None;
    }
    if raw.starts_with("http://") || raw.starts_with("https://") {
        let base_host = http.base_url().host_str()?;
        let u = url::Url::parse(raw).ok()?;
        if u.host_str()? == base_host {
            return Some(raw.to_string());
        }
        return None;
    }
    if raw.starts_with("//") {
        let scheme = http.base_url().scheme();
        return Some(format!("{}:{}", scheme, raw));
    }
    http.resolve(raw).ok()
}

fn extract_from_js(body: &str, analysis: &mut JsAnalysis, nested_js: &mut Vec<String>) {
    let url_re = Regex::new(
        r#"(?x)
        (?:
          ["'`](/[A-Za-z0-9_\-./%{}]+)["'`]
          |
          ["'`](https?://[^"'`\s]+)["'`]
          |
          ["'`](\./[A-Za-z0-9_\-./%]+)["'`]
        )
        "#,
    )
    .unwrap();

    let api_re =
        Regex::new(r#"(?i)["'`](/?(?:api|graphql|v[0-9]+)/[A-Za-z0-9_\-./{}]*)["'`]"#).unwrap();
    let param_re = Regex::new(r#"(?i)(?:\?|&)([A-Za-z_][A-Za-z0-9_]{1,40})="#).unwrap();
    let version_re =
        Regex::new(r#"(?i)(?:version|ver|v)\s*[:=]\s*["'`]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"#)
            .unwrap();
    let fetch_re = Regex::new(
        r#"(?i)(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest|\.ajax)\s*\(\s*["'`]([^"'`]+)["'`]"#,
    )
    .unwrap();
    let import_re =
        Regex::new(r#"(?i)(?:import\s*\(|require\s*\(|from\s+)["']([^"']+\.js[^"']*)["']"#)
            .unwrap();

    for cap in url_re.captures_iter(body) {
        for i in 1..=3 {
            if let Some(m) = cap.get(i) {
                let s = m.as_str();
                if s.starts_with("http") {
                    analysis.urls.push(s.to_string());
                    if let Ok(u) = url::Url::parse(s) {
                        let path = normalize_path(u.path());
                        if path.len() > 1 {
                            analysis.endpoints.push(path);
                        }
                    }
                    if s.contains(".js") {
                        nested_js.push(s.to_string());
                    }
                } else {
                    let path = normalize_path(s);
                    if interesting_path(&path) {
                        analysis.endpoints.push(path.clone());
                    }
                    if path.ends_with(".js") {
                        nested_js.push(path);
                    }
                }
            }
        }
    }

    for cap in api_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            let path = normalize_path(m.as_str());
            analysis.apis.push(path.clone());
            analysis.endpoints.push(path);
        }
    }

    for cap in fetch_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str();
            if s.starts_with('/') || s.starts_with("./") {
                analysis.endpoints.push(normalize_path(s));
            } else if s.starts_with("http") {
                analysis.urls.push(s.to_string());
            }
        }
    }

    for cap in import_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            nested_js.push(m.as_str().to_string());
        }
    }

    for cap in param_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            analysis.parameters.push(m.as_str().to_string());
        }
    }

    for cap in version_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            analysis.versions.push(m.as_str().to_string());
        }
    }
}

fn extract_from_sourcemap(body: &str, analysis: &mut JsAnalysis) {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return;
    };
    if let Some(sources) = v.get("sources").and_then(|s| s.as_array()) {
        for s in sources {
            if let Some(path) = s.as_str() {
                let p = normalize_path(path);
                if interesting_path(&p) {
                    analysis.endpoints.push(p);
                }
                // Original source path often like webpack:///./src/api/users.js
                if let Some(idx) = path.find('/') {
                    let rest = &path[idx..];
                    if rest.contains("api") || rest.contains("route") || rest.contains("controller")
                    {
                        analysis.endpoints.push(normalize_path(rest));
                    }
                }
            }
        }
    }
    if let Some(content) = v.get("sourcesContent").and_then(|s| s.as_array()) {
        for c in content {
            if let Some(src) = c.as_str() {
                let mut nested = Vec::new();
                extract_from_js(src, analysis, &mut nested);
            }
        }
    }
}

fn interesting_path(path: &str) -> bool {
    if path.len() < 2 || path.len() > 200 {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".css")
        || lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".gif")
        || lower.ends_with(".svg")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2")
        || lower.ends_with(".ttf")
        || lower.ends_with(".ico")
    {
        return false;
    }
    true
}
