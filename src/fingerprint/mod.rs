//! Target fingerprinting and technology detection.

mod favicon_db;

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::http::{HttpEngine, HttpResponse};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetProfile {
    pub url: String,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub frameworks: Vec<String>,
    pub cms: Vec<String>,
    pub cdn: Vec<String>,
    pub waf: Vec<String>,
    pub languages: Vec<String>,
    pub compression: Vec<String>,
    pub headers: HashMap<String, String>,
    pub caching: Vec<String>,
    pub robots_paths: Vec<String>,
    pub sitemap_paths: Vec<String>,
    pub security_txt: Option<String>,
    pub favicon_hash: Option<String>,
    pub favicon_mmh3: Option<i32>,
    pub favicon_tech: Vec<String>,
    pub openapi_urls: Vec<String>,
    pub graphql_detected: bool,
    pub js_files: Vec<String>,
    pub source_maps: Vec<String>,
    pub interesting_paths: Vec<String>,
    pub soft_404_baseline: Option<Soft404Baseline>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Soft404Baseline {
    pub status: u16,
    pub size: u64,
    pub hash: String,
    pub word_count: usize,
    pub line_count: usize,
}

pub struct FingerprintEngine {
    http: HttpEngine,
    headers: Vec<(String, String)>,
}

impl FingerprintEngine {
    pub fn new(http: HttpEngine, headers: Vec<(String, String)>) -> Self {
        Self { http, headers }
    }

    pub async fn run(&self) -> Result<TargetProfile> {
        let mut profile = TargetProfile {
            url: self.http.base_url().to_string(),
            ..Default::default()
        };

        // Root response
        let root_url = self.http.base_url().to_string();
        if let Ok(resp) = self.http.get(&root_url, &self.headers).await {
            self.analyze_headers(&resp, &mut profile);
            self.detect_from_body(&resp, &mut profile);
            self.extract_js_and_assets(&resp, &mut profile);
        }

        // Soft-404 baseline from random paths
        profile.soft_404_baseline = self.build_soft404_baseline().await;

        // Probe well-known files in parallel-ish sequential for clarity
        self.probe_robots(&mut profile).await;
        self.probe_sitemap(&mut profile).await;
        self.probe_security_txt(&mut profile).await;
        self.probe_favicon(&mut profile).await;
        self.probe_api_surfaces(&mut profile).await;

        Ok(profile)
    }

    fn analyze_headers(&self, resp: &HttpResponse, profile: &mut TargetProfile) {
        profile.headers = resp.headers.clone();

        if let Some(s) = resp.header("server") {
            profile.server = Some(s.clone());
            self.classify_server(s, profile);
        }
        if let Some(p) = resp.header("x-powered-by") {
            profile.powered_by = Some(p.clone());
            self.classify_powered_by(p, profile);
        }

        // Compression
        if let Some(enc) = resp.header("content-encoding") {
            for part in enc.split(',') {
                let t = part.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    profile.compression.push(t);
                }
            }
        }

        // Caching
        for key in ["cache-control", "etag", "age", "cf-cache-status", "x-cache"] {
            if let Some(v) = resp.header(key) {
                profile.caching.push(format!("{}: {}", key, v));
            }
        }

        // CDN / WAF header signals
        self.detect_cdn_waf(resp, profile);
    }

    fn classify_server(&self, server: &str, profile: &mut TargetProfile) {
        let s = server.to_ascii_lowercase();
        if s.contains("apache") {
            push_unique(&mut profile.languages, "Apache");
        }
        if s.contains("nginx") {
            push_unique(&mut profile.languages, "Nginx");
        }
        if s.contains("microsoft-iis") || s.contains("iis") {
            push_unique(&mut profile.languages, "IIS");
            push_unique(&mut profile.languages, "ASP.NET");
        }
        if s.contains("caddy") {
            push_unique(&mut profile.languages, "Caddy");
        }
        if s.contains("cloudflare") {
            push_unique(&mut profile.cdn, "Cloudflare");
        }
    }

    fn classify_powered_by(&self, powered: &str, profile: &mut TargetProfile) {
        let p = powered.to_ascii_lowercase();
        if p.contains("php") {
            push_unique(&mut profile.languages, "PHP");
        }
        if p.contains("asp.net") {
            push_unique(&mut profile.languages, "ASP.NET");
        }
        if p.contains("express") {
            push_unique(&mut profile.frameworks, "ExpressJS");
            push_unique(&mut profile.languages, "NodeJS");
        }
        if p.contains("next.js") || p.contains("nextjs") {
            push_unique(&mut profile.frameworks, "Next.js");
            push_unique(&mut profile.languages, "NodeJS");
        }
    }

    fn detect_cdn_waf(&self, resp: &HttpResponse, profile: &mut TargetProfile) {
        let keys: HashSet<String> = resp
            .headers
            .keys()
            .map(|k| k.to_ascii_lowercase())
            .collect();

        if keys.contains("cf-ray") || keys.contains("cf-cache-status") {
            push_unique(&mut profile.cdn, "Cloudflare");
            push_unique(&mut profile.waf, "Cloudflare");
        }
        if keys.contains("x-amz-cf-id") || keys.contains("x-amz-request-id") {
            push_unique(&mut profile.cdn, "AWS CloudFront/S3");
        }
        if keys.contains("x-akamai-transformed") || keys.iter().any(|k| k.contains("akamai")) {
            push_unique(&mut profile.cdn, "Akamai");
        }
        if keys.contains("x-sucuri-id") {
            push_unique(&mut profile.waf, "Sucuri");
        }
        if keys.contains("x-cdn") {
            if let Some(v) = resp.header("x-cdn") {
                push_unique(&mut profile.cdn, v);
            }
        }
        if let Some(server) = resp.header("server") {
            let s = server.to_ascii_lowercase();
            if s.contains("cloudflare") {
                push_unique(&mut profile.waf, "Cloudflare");
                push_unique(&mut profile.cdn, "Cloudflare");
            }
        }
        if resp
            .headers
            .values()
            .any(|v| v.to_ascii_lowercase().contains("mod_security"))
        {
            push_unique(&mut profile.waf, "ModSecurity");
        }
        if keys.contains("x-iinfo") {
            push_unique(&mut profile.waf, "Imperva");
        }
    }

    fn detect_from_body(&self, resp: &HttpResponse, profile: &mut TargetProfile) {
        let body = resp.body_str();
        let lower = body.to_ascii_lowercase();

        let checks: &[(&str, &str, &str)] = &[
            ("wp-content", "WordPress", "cms"),
            ("wordpress", "WordPress", "cms"),
            ("drupal", "Drupal", "cms"),
            ("joomla", "Joomla", "cms"),
            ("laravel", "Laravel", "framework"),
            ("csrf-token", "Laravel", "framework"),
            ("django", "Django", "framework"),
            ("csrftoken", "Django", "framework"),
            ("flask", "Flask", "framework"),
            ("express", "ExpressJS", "framework"),
            ("__next", "Next.js", "framework"),
            ("spring", "Spring Boot", "framework"),
            ("aspnet", "ASP.NET", "framework"),
            ("__viewstate", "ASP.NET", "framework"),
            ("rails", "Ruby on Rails", "framework"),
            ("graphql", "GraphQL", "api"),
        ];

        for (needle, name, kind) in checks {
            if lower.contains(needle) {
                match *kind {
                    "cms" if !profile.cms.iter().any(|c| c == *name) => {
                        profile.cms.push((*name).into());
                    }
                    "framework" if !profile.frameworks.iter().any(|c| c == *name) => {
                        profile.frameworks.push((*name).into());
                    }
                    "api" if *name == "GraphQL" => profile.graphql_detected = true,
                    _ => {}
                }
            }
        }

        // Language cookies / generator meta
        if lower.contains("php") && !profile.languages.iter().any(|l| l == "PHP") {
            // weak signal — only if powered-by already hinted or .php links
            if body.contains(".php") {
                profile.languages.push("PHP".into());
            }
        }
    }

    fn extract_js_and_assets(&self, resp: &HttpResponse, profile: &mut TargetProfile) {
        let body = resp.body_str();
        let script_re = Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)["']"#).unwrap();
        let link_re = Regex::new(r#"(?i)<link[^>]+href=["']([^"']+)["']"#).unwrap();
        let map_re = Regex::new(r#"//[#@]\s*sourceMappingURL\s*=\s*(\S+)"#).unwrap();

        for cap in script_re.captures_iter(&body) {
            if let Some(m) = cap.get(1) {
                let src = m.as_str().to_string();
                if src.ends_with(".js") || src.contains(".js?") {
                    profile.js_files.push(src);
                }
            }
        }
        for cap in link_re.captures_iter(&body) {
            if let Some(m) = cap.get(1) {
                let href = m.as_str();
                if href.contains("openapi") || href.contains("swagger") {
                    profile.openapi_urls.push(href.to_string());
                }
            }
        }
        for cap in map_re.captures_iter(&body) {
            if let Some(m) = cap.get(1) {
                profile.source_maps.push(m.as_str().to_string());
            }
        }

        profile.js_files.sort();
        profile.js_files.dedup();
    }

    async fn build_soft404_baseline(&self) -> Option<Soft404Baseline> {
        let probes = ["aaaa", "bbbb", "cccc", "zzzxnonexistent999"];
        let mut samples: Vec<HttpResponse> = Vec::new();

        for p in probes {
            if let Ok(url) = self.http.resolve(p) {
                if let Ok(resp) = self.http.get(&url, &self.headers).await {
                    samples.push(resp);
                }
            }
        }

        if samples.len() < 2 {
            return None;
        }

        let hashes: Vec<String> = samples.iter().map(|r| hash_body(&r.body)).collect();
        let sizes: Vec<u64> = samples.iter().map(|r| r.size()).collect();

        // If majority share same hash/size → soft 404 pattern
        let first_hash = &hashes[0];
        let same_hash = hashes.iter().filter(|h| *h == first_hash).count();
        let first_size = sizes[0];
        let same_size = sizes.iter().filter(|&&s| s == first_size).count();

        if same_hash >= 2 || same_size >= 2 {
            let r = &samples[0];
            return Some(Soft404Baseline {
                status: r.status,
                size: r.size(),
                hash: first_hash.clone(),
                word_count: r.word_count(),
                line_count: r.line_count(),
            });
        }
        None
    }

    async fn probe_robots(&self, profile: &mut TargetProfile) {
        let Ok(url) = self.http.resolve("/robots.txt") else {
            return;
        };
        let Ok(resp) = self.http.get(&url, &self.headers).await else {
            return;
        };
        if resp.status != 200 || resp.size() > 500_000 {
            return;
        }
        let body = resp.body_str();
        if body.to_ascii_lowercase().contains("<html") {
            return;
        }
        for line in body.lines() {
            let line = line.trim();
            if let Some(rest) = line
                .strip_prefix("Disallow:")
                .or_else(|| line.strip_prefix("Allow:"))
                .or_else(|| line.strip_prefix("disallow:"))
                .or_else(|| line.strip_prefix("allow:"))
            {
                let path = rest.trim();
                if path.starts_with('/') && path.len() > 1 {
                    profile
                        .robots_paths
                        .push(path.trim_end_matches('*').to_string());
                }
            }
            if let Some(rest) = line
                .strip_prefix("Sitemap:")
                .or_else(|| line.strip_prefix("sitemap:"))
            {
                profile.sitemap_paths.push(rest.trim().to_string());
            }
        }
        profile.robots_paths.sort();
        profile.robots_paths.dedup();
        profile
            .interesting_paths
            .extend(profile.robots_paths.clone());
    }

    async fn probe_sitemap(&self, profile: &mut TargetProfile) {
        let mut urls = vec!["/sitemap.xml".to_string(), "/sitemap_index.xml".to_string()];
        urls.extend(profile.sitemap_paths.clone());

        let loc_re = Regex::new(r"<loc>\s*([^<]+)\s*</loc>").unwrap();

        for u in urls {
            let resolved = if u.starts_with("http") {
                u.clone()
            } else if let Ok(r) = self.http.resolve(&u) {
                r
            } else {
                continue;
            };
            let Ok(resp) = self.http.get(&resolved, &self.headers).await else {
                continue;
            };
            if resp.status != 200 {
                continue;
            }
            let body = resp.body_str();
            for cap in loc_re.captures_iter(&body) {
                if let Some(m) = cap.get(1) {
                    let loc = m.as_str().trim();
                    if let Ok(parsed) = url::Url::parse(loc) {
                        profile.interesting_paths.push(parsed.path().to_string());
                    } else if loc.starts_with('/') {
                        profile.interesting_paths.push(loc.to_string());
                    }
                }
            }
        }
        profile.interesting_paths.sort();
        profile.interesting_paths.dedup();
    }

    async fn probe_security_txt(&self, profile: &mut TargetProfile) {
        for path in ["/.well-known/security.txt", "/security.txt"] {
            let Ok(url) = self.http.resolve(path) else {
                continue;
            };
            if let Ok(resp) = self.http.get(&url, &self.headers).await {
                if resp.status == 200 && resp.size() < 100_000 {
                    let body = resp.body_str();
                    if !body.to_ascii_lowercase().contains("<html") {
                        profile.security_txt = Some(body);
                        profile.interesting_paths.push(path.to_string());
                        break;
                    }
                }
            }
        }
    }

    async fn probe_favicon(&self, profile: &mut TargetProfile) {
        let Ok(url) = self.http.resolve("/favicon.ico") else {
            return;
        };
        if let Ok(resp) = self.http.get(&url, &self.headers).await {
            if resp.status == 200 && !resp.body.is_empty() {
                profile.favicon_hash = Some(hash_body(&resp.body));
                let mmh3 = favicon_db::favicon_mmh3(&resp.body);
                profile.favicon_mmh3 = Some(mmh3);
                profile.favicon_tech = favicon_db::identify_favicon(&resp.body);
                for tech in &profile.favicon_tech {
                    if !profile.frameworks.iter().any(|f| f == tech)
                        && !profile.cms.iter().any(|c| c == tech)
                    {
                        if tech.contains("WordPress")
                            || tech.contains("Joomla")
                            || tech.contains("Drupal")
                        {
                            profile.cms.push(tech.clone());
                        } else {
                            profile.frameworks.push(tech.clone());
                        }
                    }
                }
            }
        }
    }

    async fn probe_api_surfaces(&self, profile: &mut TargetProfile) {
        let probes = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/graphql",
            "/swagger",
            "/swagger-ui",
            "/swagger.json",
            "/swagger-ui.html",
            "/docs",
            "/documentation",
            "/openapi.json",
            "/openapi.yaml",
            "/v1/api-docs",
            "/v2/api-docs",
            "/metrics",
            "/health",
            "/status",
            "/actuator",
            "/actuator/health",
        ];

        for p in probes {
            let Ok(url) = self.http.resolve(p) else {
                continue;
            };
            let Ok(resp) = self.http.get(&url, &self.headers).await else {
                continue;
            };
            if is_interesting_probe(&resp, profile.soft_404_baseline.as_ref()) {
                profile.interesting_paths.push(p.to_string());
                let body = resp.body_str().to_ascii_lowercase();
                if p.contains("graphql") || body.contains("graphql") {
                    profile.graphql_detected = true;
                }
                if body.contains("openapi") || body.contains("swagger") {
                    profile.openapi_urls.push(p.to_string());
                }
                // Tech hints from actuator etc.
                if p.contains("actuator") && !profile.frameworks.iter().any(|f| f == "Spring Boot")
                {
                    profile.frameworks.push("Spring Boot".into());
                }
            }
        }
        profile.interesting_paths.sort();
        profile.interesting_paths.dedup();
    }
}

fn is_interesting_probe(resp: &HttpResponse, baseline: Option<&Soft404Baseline>) -> bool {
    if matches!(resp.status, 401 | 403) {
        return true;
    }
    if !(200..400).contains(&resp.status) {
        return false;
    }
    if let Some(b) = baseline {
        let h = hash_body(&resp.body);
        if h == b.hash && resp.size() == b.size {
            return false;
        }
    }
    true
}

pub fn hash_body(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|x| x.eq_ignore_ascii_case(value)) {
        list.push(value.to_string());
    }
}

/// Deduplicate tech tags for display.
pub fn unique_techs(profile: &TargetProfile) -> Vec<String> {
    let mut all = Vec::new();
    if let Some(s) = &profile.server {
        all.push(format!("Server:{}", s));
    }
    for f in &profile.frameworks {
        push_unique(&mut all, f);
    }
    for c in &profile.cms {
        push_unique(&mut all, c);
    }
    for c in &profile.cdn {
        push_unique(&mut all, c);
    }
    for w in &profile.waf {
        let tag = format!("WAF:{}", w);
        push_unique(&mut all, &tag);
    }
    for l in &profile.languages {
        push_unique(&mut all, l);
    }
    all.sort();
    all.dedup();
    all
}
