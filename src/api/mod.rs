//! API surface discovery, OpenAPI parsing, GraphQL introspection.

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fingerprint::TargetProfile;
use crate::http::HttpEngine;
use crate::response::{AnalyzedResponse, DiscoverySource, ResponseAnalyzer, ScanStage};
use crate::wordlist::normalize_path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiDiscoveryResult {
    pub endpoints: Vec<AnalyzedResponse>,
    pub openapi_paths: Vec<String>,
    pub graphql_fields: Vec<String>,
    pub graphql: bool,
    pub openapi: Vec<String>,
}

const API_SEEDS: &[&str] = &[
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/graphql",
    "/graphiql",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/docs",
    "/documentation",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/metrics",
    "/health",
    "/healthz",
    "/status",
    "/ready",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/v1",
    "/v2",
    "/rest",
    "/rpc",
    "/redoc",
    "/rapidoc",
];

const API_EXPAND: &[&str] = &[
    "auth", "users", "user", "admin", "login", "logout", "register", "search", "me", "profile",
    "config", "settings", "upload", "uploads", "files", "health", "status", "tokens", "token",
    "orders", "products", "items",
];

pub struct ApiDiscoveryEngine {
    http: HttpEngine,
    headers: Vec<(String, String)>,
    analyzer: ResponseAnalyzer,
}

impl ApiDiscoveryEngine {
    pub fn new(
        http: HttpEngine,
        headers: Vec<(String, String)>,
        analyzer: ResponseAnalyzer,
    ) -> Self {
        Self {
            http,
            headers,
            analyzer,
        }
    }

    pub async fn discover(&self, profile: &TargetProfile) -> Result<ApiDiscoveryResult> {
        let mut result = ApiDiscoveryResult {
            graphql: profile.graphql_detected,
            openapi: profile.openapi_urls.clone(),
            ..Default::default()
        };

        let mut seeds: Vec<String> = API_SEEDS.iter().map(|s| (*s).to_string()).collect();
        for p in &profile.interesting_paths {
            if p.contains("api")
                || p.contains("swagger")
                || p.contains("graphql")
                || p.contains("openapi")
                || p.contains("actuator")
                || p.contains("health")
            {
                seeds.push(normalize_path(p));
            }
        }
        seeds.extend(profile.openapi_urls.iter().cloned());
        seeds.sort();
        seeds.dedup();

        let mut found_bases = Vec::new();

        for seed in &seeds {
            if let Some(analyzed) = self.probe(seed, 1, DiscoverySource::Api).await {
                if !analyzed.soft_404 && !analyzed.filtered {
                    if seed.contains("graphql") {
                        result.graphql = true;
                    }
                    if seed.contains("openapi")
                        || seed.contains("swagger")
                        || seed.contains("api-docs")
                    {
                        result.openapi.push(seed.clone());
                        // Parse OpenAPI/Swagger body
                        if let Ok(url) = self.http.resolve(seed) {
                            if let Ok(resp) = self.http.get(&url, &self.headers).await {
                                let paths = parse_openapi(&resp.body_str());
                                result.openapi_paths.extend(paths);
                            }
                        }
                    }
                    found_bases.push(seed.clone());
                    result.endpoints.push(analyzed);
                }
            }
        }

        // Expand discovered API bases
        for base in &found_bases {
            for child in API_EXPAND {
                let path = format!("{}/{}", base.trim_end_matches('/'), child);
                if let Some(analyzed) = self.probe(&path, 2, DiscoverySource::Api).await {
                    if !analyzed.soft_404 {
                        result.endpoints.push(analyzed);
                    }
                }
            }
        }

        // Probe OpenAPI-extracted paths
        for path in result.openapi_paths.clone() {
            if let Some(analyzed) = self.probe(&path, 2, DiscoverySource::OpenApi).await {
                if !analyzed.soft_404 {
                    result.endpoints.push(analyzed);
                }
            }
        }

        Ok(result)
    }

    pub async fn introspect_graphql(&self) -> Result<Vec<String>> {
        let query = r#"{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}"#;
        let mut fields = Vec::new();

        for path in ["/graphql", "/api/graphql", "/v1/graphql", "/query"] {
            let Ok(url) = self.http.resolve(path) else {
                continue;
            };
            let Ok(resp) = self
                .http
                .request_raw(
                    reqwest::Method::POST,
                    &url,
                    Some(query),
                    &[("Content-Type".into(), "application/json".into())],
                )
                .await
            else {
                continue;
            };
            if resp.status != 200 {
                continue;
            }
            fields.extend(parse_graphql_introspection(&resp.body_str(), path));
            if !fields.is_empty() {
                break;
            }
        }

        fields.sort();
        fields.dedup();
        Ok(fields)
    }

    async fn probe(
        &self,
        path: &str,
        depth: u32,
        source: DiscoverySource,
    ) -> Option<AnalyzedResponse> {
        let url = self.http.resolve(path).ok()?;
        let resp = self.http.get(&url, &self.headers).await.ok()?;
        Some(
            self.analyzer
                .analyze_staged(&resp, path, depth, source, ScanStage::Api),
        )
    }
}

/// Extract paths from OpenAPI 2/3 JSON or YAML (free serde parsers, no API).
pub fn parse_openapi(body: &str) -> Vec<String> {
    let trimmed = body.trim();
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
            return paths_from_openapi_value(&v);
        }
    }
    if trimmed.starts_with("openapi:")
        || trimmed.starts_with("swagger:")
        || trimmed.contains("\npaths:")
    {
        if let Ok(v) = serde_yaml::from_str::<Value>(trimmed) {
            return paths_from_openapi_value(&v);
        }
    }
    // Regex fallback for partial/malformed specs
    let mut paths = Vec::new();
    let re = Regex::new(r#"(?m)^\s*(/[A-Za-z0-9_\-{}/.]+)\s*:"#).unwrap();
    for cap in re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            let p = m.as_str();
            if p.starts_with('/') && !p.contains("http") {
                paths.push(normalize_path(p));
            }
        }
    }
    dedup_paths(paths)
}

fn paths_from_openapi_value(v: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(p) = v.get("paths").and_then(|p| p.as_object()) {
        for key in p.keys() {
            paths.push(normalize_path(key));
        }
    }
    if let Some(base) = v.get("basePath").and_then(|b| b.as_str()) {
        let base = normalize_path(base);
        let keyed: Vec<_> = paths.clone();
        for k in keyed {
            paths.push(format!("{}{}", base.trim_end_matches('/'), k));
        }
    }
    if let Some(servers) = v.get("servers").and_then(|s| s.as_array()) {
        for srv in servers {
            if let Some(url) = srv.get("url").and_then(|u| u.as_str()) {
                if let Ok(u) = url::Url::parse(url) {
                    let prefix = normalize_path(u.path());
                    if prefix.len() > 1 {
                        let keyed: Vec<_> = paths.clone();
                        for k in keyed {
                            paths.push(format!("{}{}", prefix.trim_end_matches('/'), k));
                        }
                    }
                }
            }
        }
    }
    dedup_paths(paths)
}

fn parse_graphql_introspection(body: &str, base: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return out;
    };
    let Some(types) = v.pointer("/data/__schema/types").and_then(|t| t.as_array()) else {
        // Also accept errors-free partial
        return out;
    };

    out.push(normalize_path(base));
    for t in types {
        let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if name.starts_with("__") {
            continue;
        }
        if let Some(fields) = t.get("fields").and_then(|f| f.as_array()) {
            for f in fields {
                if let Some(fname) = f.get("name").and_then(|n| n.as_str()) {
                    out.push(format!("{}/{}", base.trim_end_matches('/'), fname));
                }
            }
        }
    }
    out
}

fn dedup_paths(mut paths: Vec<String>) -> Vec<String> {
    paths.sort();
    paths.dedup();
    paths
}
