//! Async HTTP client — pooling, FUZZ templates, raw requests, vhost.

mod fuzz;
mod request;

pub use fuzz::{
    apply_fuzz, combine_wordlists, has_fuzz, keywords_in, max_keyword_count, FUZZ_KEYWORDS,
};
pub use request::{load_wordlist_file, load_wordlist_paths, RawRequestTemplate};

use anyhow::{Context, Result};
use bytes::Bytes;
use reqwest::{Client, Method, Response};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

use crate::cli::Args;

pub const FUZZ_KEYWORD: &str = "FUZZ";

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub url: String,
    pub final_url: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
    pub elapsed_ms: u64,
    pub redirected: bool,
    pub redirect_target: Option<String>,
    pub truncated: bool,
}

impl HttpResponse {
    pub fn size(&self) -> u64 {
        self.body.len() as u64
    }

    pub fn word_count(&self) -> usize {
        String::from_utf8_lossy(&self.body)
            .split_whitespace()
            .count()
    }

    pub fn line_count(&self) -> usize {
        if self.body.is_empty() {
            return 0;
        }
        self.body.iter().filter(|&&b| b == b'\n').count() + 1
    }

    pub fn header(&self, name: &str) -> Option<&String> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type").map(|s| s.as_str())
    }

    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn is_html(&self) -> bool {
        self.content_type()
            .map(|ct| ct.to_ascii_lowercase().contains("text/html"))
            .unwrap_or_else(|| {
                let lower = self.body_str().to_ascii_lowercase();
                lower.contains("<html") || lower.contains("<!doctype")
            })
    }

    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| {
                let c = ct.to_ascii_lowercase();
                c.contains("json") || c.contains("javascript")
            })
            .unwrap_or(false)
    }
}

#[derive(Clone)]
pub struct HttpEngine {
    client: Client,
    method: Method,
    base: Url,
    template: String,
    body_template: Option<String>,
    raw_request: Option<RawRequestTemplate>,
    max_body: usize,
    extra_headers: Vec<(String, String)>,
}

impl HttpEngine {
    pub fn new(args: &Args) -> Result<Self> {
        let mut builder = Client::builder()
            .user_agent(&args.user_agent)
            .timeout(Duration::from_secs(args.timeout))
            .connect_timeout(Duration::from_secs(args.timeout.min(10)))
            .pool_max_idle_per_host(args.effective_threads())
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_nodelay(true)
            .gzip(true)
            .brotli(true)
            .deflate(true)
            .cookie_store(true)
            .redirect(if args.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            });

        if !args.use_http2() {
            builder = builder.http1_only();
        }

        if args.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(proxy) = &args.proxy {
            builder = builder.proxy(reqwest::Proxy::all(proxy).context("invalid proxy")?);
        }

        let client = builder.build().context("failed to build HTTP client")?;

        let raw_request = if let Some(path) = &args.request {
            Some(RawRequestTemplate::from_file(path)?)
        } else {
            None
        };

        let method_str = if let Some(raw) = &raw_request {
            raw.method.as_str()
        } else {
            args.effective_method()
        };
        let method = Method::from_bytes(method_str.as_bytes()).unwrap_or(Method::GET);

        let mut base_str = args.url.clone();
        for kw in FUZZ_KEYWORDS {
            base_str = base_str.replace(kw, "");
        }
        let base = Url::parse(&normalize_base_url(&base_str)).context("invalid target URL")?;

        Ok(Self {
            client,
            method,
            base,
            template: args.url.clone(),
            body_template: args.data.clone(),
            raw_request,
            max_body: args.max_body,
            extra_headers: parse_headers(&args.header, &args.cookies),
        })
    }

    pub fn base_url(&self) -> &Url {
        &self.base
    }

    pub fn template(&self) -> &str {
        &self.template
    }

    pub fn raw_request(&self) -> Option<&RawRequestTemplate> {
        self.raw_request.as_ref()
    }

    pub fn has_fuzz(&self) -> bool {
        self.fuzz_slot_count() > 0
    }

    pub fn fuzz_slot_count(&self) -> usize {
        let mut templates = vec![self.template.as_str()];
        if let Some(body) = &self.body_template {
            templates.push(body.as_str());
        }
        if let Some(raw) = &self.raw_request {
            templates.push(raw.path.as_str());
            if let Some(b) = &raw.body {
                templates.push(b.as_str());
            }
            for (_, v) in &raw.headers {
                templates.push(v.as_str());
            }
        }
        max_keyword_count(&templates)
    }

    pub fn resolve_entry(&self, entry: &str) -> Result<String> {
        self.resolve_with_values(&[entry.trim_start_matches('/')])
    }

    pub fn resolve_with_values(&self, values: &[&str]) -> Result<String> {
        if let Some(raw) = &self.raw_request {
            return raw.build_url(&self.base, values);
        }
        if has_fuzz(&self.template) {
            Ok(apply_fuzz(&self.template, values))
        } else {
            self.resolve(values.first().copied().unwrap_or(""))
        }
    }

    pub fn resolve(&self, path: &str) -> Result<String> {
        if path.starts_with("http://") || path.starts_with("https://") {
            return Ok(path.to_string());
        }
        let mut base = self.base.clone();
        let clean = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };
        base.set_path(&clean);
        base.set_query(None);
        base.set_fragment(None);
        Ok(base.to_string())
    }

    pub fn body_for_values(&self, values: &[&str]) -> Option<String> {
        if let Some(raw) = &self.raw_request {
            return raw.body_for(values);
        }
        self.body_template.as_ref().map(|t| apply_fuzz(t, values))
    }

    pub fn headers_for_values(&self, values: &[&str]) -> Vec<(String, String)> {
        if let Some(raw) = &self.raw_request {
            return raw.headers_for(values);
        }
        Vec::new()
    }

    pub async fn get(&self, url: &str, extra_headers: &[(String, String)]) -> Result<HttpResponse> {
        self.request_raw(Method::GET, url, None, extra_headers)
            .await
    }

    pub async fn fuzz_entry(
        &self,
        entry: &str,
        extra_headers: &[(String, String)],
    ) -> Result<HttpResponse> {
        self.fuzz_values(&[entry.trim_start_matches('/')], extra_headers)
            .await
    }

    pub async fn fuzz_values(
        &self,
        values: &[&str],
        extra_headers: &[(String, String)],
    ) -> Result<HttpResponse> {
        let url = self.resolve_with_values(values)?;
        let body = self.body_for_values(values);
        let mut hdrs: Vec<(String, String)> = self.headers_for_values(values);
        hdrs.extend_from_slice(extra_headers);

        let method = if let Some(raw) = &self.raw_request {
            raw.method.clone()
        } else {
            self.method.clone()
        };

        self.request_raw(method, &url, body.as_deref(), &hdrs).await
    }

    pub async fn request(
        &self,
        url: &str,
        extra_headers: &[(String, String)],
    ) -> Result<HttpResponse> {
        self.request_raw(self.method.clone(), url, None, extra_headers)
            .await
    }

    pub async fn request_raw(
        &self,
        method: Method,
        url: &str,
        body: Option<&str>,
        extra_headers: &[(String, String)],
    ) -> Result<HttpResponse> {
        let start = Instant::now();
        let mut req = self.client.request(method, url);

        for (k, v) in &self.extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        for (k, v) in extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }

        if let Some(b) = body {
            let has_ct = extra_headers
                .iter()
                .chain(self.extra_headers.iter())
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
            if !has_ct {
                req = req.header("Content-Type", "application/x-www-form-urlencoded");
            }
            req = req.body(b.to_string());
        }

        let resp = req.send().await.context("request failed")?;
        Self::from_response(url, resp, start.elapsed(), self.max_body).await
    }

    async fn from_response(
        original_url: &str,
        resp: Response,
        elapsed: Duration,
        max_body: usize,
    ) -> Result<HttpResponse> {
        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();
        let redirected = normalize_cmp(&final_url) != normalize_cmp(original_url);
        let redirect_target = if redirected {
            Some(final_url.clone())
        } else {
            None
        };

        let mut headers = HashMap::new();
        for (k, v) in resp.headers().iter() {
            if let Ok(val) = v.to_str() {
                headers.insert(k.as_str().to_string(), val.to_string());
            }
        }

        let full = resp.bytes().await.unwrap_or_default();
        let truncated = full.len() > max_body;
        let body = if truncated {
            Bytes::copy_from_slice(&full[..max_body])
        } else {
            full
        };

        Ok(HttpResponse {
            url: original_url.to_string(),
            final_url,
            status,
            headers,
            body,
            elapsed_ms: elapsed.as_millis() as u64,
            redirected,
            redirect_target,
            truncated,
        })
    }

    pub fn set_extra_headers(&mut self, headers: Vec<(String, String)>) {
        self.extra_headers = headers;
    }
}

fn normalize_cmp(u: &str) -> String {
    u.trim_end_matches('/').to_ascii_lowercase()
}

fn normalize_base_url(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() || s == "/" {
        return "http://localhost/".into();
    }
    if let Ok(u) = Url::parse(s) {
        return u.to_string();
    }
    if let Ok(u) = Url::parse(&format!("{}/", s.trim_end_matches('/'))) {
        return u.to_string();
    }
    s.to_string()
}

pub fn parse_headers(raw: &[String], cookies: &Option<String>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for h in raw {
        if let Some((k, v)) = h.split_once(':') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    if let Some(c) = cookies {
        out.push(("Cookie".into(), c.clone()));
    }
    out
}

pub fn expand_with_extensions(entry: &str, extensions: &[String]) -> Vec<String> {
    let entry = entry.trim().trim_start_matches('/');
    if entry.is_empty() {
        return Vec::new();
    }
    let mut out = vec![entry.to_string()];
    for ext in extensions {
        let ext = ext.trim().trim_start_matches('.');
        if ext.is_empty() || entry.ends_with(&format!(".{}", ext)) {
            continue;
        }
        out.push(format!("{}.{}", entry, ext));
    }
    out
}

pub type SharedHttp = Arc<HttpEngine>;
