//! Dynamic prioritized wordlist generation.

mod catalog;
mod download;
mod selector;

pub use catalog::{seclists_url, CatalogEntry};
pub use download::{print_recommendations, WordlistFetcher};
pub use selector::{
    extensions_for_tech, profile_tech_tags, recommend, should_use_tech_focus,
    WordlistRecommendation,
};

use crate::fingerprint::TargetProfile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordEntry {
    pub path: String,
    pub priority: u8,
    pub source: String,
}

pub struct WordlistEngine {
    entries: HashMap<String, WordEntry>,
    cap: usize,
}

impl WordlistEngine {
    pub fn new(cap: usize) -> Self {
        Self {
            entries: HashMap::new(),
            cap,
        }
    }

    pub fn insert(&mut self, path: &str, priority: u8, source: &str) {
        let path = normalize_path(path);
        if path.is_empty() || path == "/" {
            return;
        }
        match self.entries.get(&path) {
            Some(existing) if existing.priority >= priority => {}
            _ => {
                self.entries.insert(
                    path.clone(),
                    WordEntry {
                        path,
                        priority,
                        source: source.to_string(),
                    },
                );
            }
        }
    }

    pub fn extend_paths<I: IntoIterator<Item = String>>(
        &mut self,
        paths: I,
        priority: u8,
        source: &str,
    ) {
        for p in paths {
            self.insert(&p, priority, source);
        }
    }

    pub fn from_profile(&mut self, profile: &TargetProfile) {
        self.merge_profile_seeds(profile, true);
    }

    /// Skip heavy generic lists when tech-specific wordlists are loaded.
    pub fn from_profile_focused(&mut self, profile: &TargetProfile) {
        self.merge_profile_seeds(profile, false);
    }

    fn merge_profile_seeds(&mut self, profile: &TargetProfile, include_generic: bool) {
        for p in &profile.robots_paths {
            self.insert(p, 100, "robots");
        }
        for p in &profile.interesting_paths {
            self.insert(p, 100, "fingerprint");
        }
        for p in &profile.sitemap_paths {
            if let Ok(u) = url::Url::parse(p) {
                self.insert(u.path(), 100, "sitemap");
            } else {
                self.insert(p, 100, "sitemap");
            }
        }
        for p in &profile.openapi_urls {
            self.insert(p, 100, "openapi");
        }

        // Technology-specific
        for fw in profile
            .frameworks
            .iter()
            .chain(profile.cms.iter())
            .chain(profile.languages.iter())
        {
            for p in tech_wordlist(fw) {
                self.insert(p, 90, "tech");
            }
        }
        if let Some(server) = &profile.server {
            for p in tech_wordlist(server) {
                self.insert(p, 90, "tech");
            }
        }

        // API surface
        for p in API_PATHS {
            self.insert(p, 80, "api");
        }

        if include_generic {
            // Common directories
            for p in COMMON_DIRS {
                self.insert(p, 60, "common");
            }
            // Generic
            for p in GENERIC {
                self.insert(p, 50, "generic");
            }
        }
    }

    pub fn load_file(&mut self, path: &Path, priority: u8) -> anyhow::Result<usize> {
        use std::io::{BufRead, BufReader};
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut n = 0;
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            self.insert(line, priority, "file");
            n += 1;
        }
        Ok(n)
    }

    /// Apply extensions to all current entries (file stage).
    pub fn apply_extensions(&mut self, extensions: &[String]) {
        if extensions.is_empty() {
            return;
        }
        let bases: Vec<String> = self.entries.keys().cloned().collect();
        for base in bases {
            let bare = base.trim_start_matches('/');
            for ext in extensions {
                let ext = ext.trim().trim_start_matches('.');
                if ext.is_empty() {
                    continue;
                }
                if bare.ends_with(&format!(".{}", ext)) {
                    continue;
                }
                // Skip if base already looks like a file with different ext
                let path = format!("/{}.{}", bare, ext);
                self.insert(&path, 65, "extension");
            }
        }
    }

    pub fn collect_ext_from_paths(&self) -> Vec<String> {
        let mut exts = Vec::new();
        for path in self.entries.keys() {
            if let Some(last) = path.rsplit('/').next() {
                if let Some((_, ext)) = last.rsplit_once('.') {
                    if ext.len() <= 8 && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
                        exts.push(ext.to_ascii_lowercase());
                    }
                }
            }
        }
        exts.sort();
        exts.dedup();
        exts
    }

    /// Directory-only entries (no file extension).
    pub fn directory_entries(&self) -> Vec<WordEntry> {
        self.prioritized()
            .into_iter()
            .filter(|e| !crate::response::looks_like_file(&e.path))
            .collect()
    }

    /// File-like entries (with extension) + extension-expanded.
    pub fn file_entries(&self) -> Vec<WordEntry> {
        self.prioritized()
            .into_iter()
            .filter(|e| crate::response::looks_like_file(&e.path))
            .collect()
    }

    /// API-oriented entries.
    pub fn api_entries(&self) -> Vec<WordEntry> {
        self.prioritized()
            .into_iter()
            .filter(|e| {
                let p = e.path.to_ascii_lowercase();
                p.contains("/api")
                    || p.contains("graphql")
                    || p.contains("swagger")
                    || p.contains("openapi")
                    || p.contains("actuator")
                    || e.source == "api"
                    || e.source == "openapi"
            })
            .collect()
    }

    pub fn add_js_paths(&mut self, paths: &[String]) {
        for p in paths {
            self.insert(p, 100, "javascript");
            // Expand parent segments
            for parent in expand_parents(p) {
                self.insert(&parent, 100, "javascript-expand");
            }
        }
    }

    pub fn add_recursive(&mut self, base: &str, children: &[&str]) {
        let base = normalize_path(base);
        for c in children {
            let path = if base.is_empty() {
                format!("/{}", c.trim_start_matches('/'))
            } else {
                format!(
                    "{}/{}",
                    base.trim_end_matches('/'),
                    c.trim_start_matches('/')
                )
            };
            self.insert(&path, 70, "recursive");
        }
    }

    /// Return paths sorted by priority desc, capped. Uses rayon for large lists.
    pub fn prioritized(&self) -> Vec<WordEntry> {
        use rayon::prelude::*;
        let mut v: Vec<_> = self.entries.values().cloned().collect();
        if v.len() > 2_000 {
            v.par_sort_unstable_by(|a, b| {
                b.priority
                    .cmp(&a.priority)
                    .then_with(|| a.path.cmp(&b.path))
            });
        } else {
            v.sort_by(|a, b| {
                b.priority
                    .cmp(&a.priority)
                    .then_with(|| a.path.cmp(&b.path))
            });
        }
        if v.len() > self.cap {
            v.truncate(self.cap);
        }
        v
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub fn normalize_path(path: &str) -> String {
    let mut p = path.trim().to_string();
    if p.starts_with("http://") || p.starts_with("https://") {
        if let Ok(u) = url::Url::parse(&p) {
            p = u.path().to_string();
        }
    }
    if !p.starts_with('/') {
        p = format!("/{}", p);
    }
    // Strip query/fragment
    if let Some(i) = p.find('?') {
        p.truncate(i);
    }
    if let Some(i) = p.find('#') {
        p.truncate(i);
    }
    while p.contains("//") {
        p = p.replace("//", "/");
    }
    if p.len() > 1 {
        p = p.trim_end_matches('/').to_string();
    }
    p
}

pub fn expand_parents(path: &str) -> Vec<String> {
    let path = normalize_path(path);
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    for part in &parts {
        cur.push('/');
        cur.push_str(part);
        out.push(cur.clone());
    }
    out
}

fn tech_wordlist(tech: &str) -> Vec<&'static str> {
    let t = tech.to_ascii_lowercase();
    let mut out = Vec::new();

    if t.contains("laravel") {
        out.extend_from_slice(&[
            "/vendor",
            "/storage",
            "/public",
            "/resources",
            "/routes",
            "/bootstrap",
            "/artisan",
            "/api",
            "/.env",
            "/storage/logs",
            "/storage/framework",
        ]);
    }
    if t.contains("django") {
        out.extend_from_slice(&[
            "/admin",
            "/static",
            "/media",
            "/templates",
            "/api",
            "/accounts",
            "/__debug__",
        ]);
    }
    if t.contains("node") || t.contains("express") || t.contains("next") {
        out.extend_from_slice(&[
            "/graphql",
            "/socket.io",
            "/docs",
            "/uploads",
            "/swagger",
            "/api",
            "/_next",
            "/static",
        ]);
    }
    if t.contains("spring") {
        out.extend_from_slice(&[
            "/actuator",
            "/actuator/health",
            "/actuator/env",
            "/actuator/metrics",
            "/metrics",
            "/health",
            "/swagger",
            "/swagger-ui.html",
            "/v2/api-docs",
            "/v3/api-docs",
        ]);
    }
    if t.contains("asp.net") || t.contains("iis") {
        out.extend_from_slice(&[
            "/api",
            "/dashboard",
            "/config",
            "/uploads",
            "/elmah.axd",
            "/trace.axd",
            "/web.config",
        ]);
    }
    if t.contains("php") {
        out.extend_from_slice(&[
            "/install.php",
            "/config.php",
            "/phpinfo.php",
            "/info.php",
            "/admin.php",
            "/wp-admin",
            "/wp-login.php",
        ]);
    }
    if t.contains("wordpress") {
        out.extend_from_slice(&[
            "/wp-admin",
            "/wp-login.php",
            "/wp-content",
            "/wp-includes",
            "/xmlrpc.php",
            "/wp-json",
            "/wp-json/wp/v2/users",
        ]);
    }
    if t.contains("drupal") {
        out.extend_from_slice(&["/user/login", "/admin", "/node", "/sites/default"]);
    }
    if t.contains("joomla") {
        out.extend_from_slice(&["/administrator", "/components", "/modules"]);
    }
    if t.contains("flask") {
        out.extend_from_slice(&["/admin", "/static", "/api", "/login"]);
    }
    if t.contains("ruby") || t.contains("rails") {
        out.extend_from_slice(&["/rails/info", "/admin", "/api", "/sidekiq"]);
    }
    out
}

/// Context-aware children for recursive expansion.
pub fn recursive_children(parent: &str) -> Vec<&'static str> {
    let p = parent.to_ascii_lowercase();
    if p.ends_with("/admin") || p == "/admin" {
        return vec![
            "login",
            "users",
            "dashboard",
            "api",
            "settings",
            "uploads",
            "config",
            "panel",
            "index",
            "home",
            "roles",
            "permissions",
            "logs",
            "audit",
        ];
    }
    if p.ends_with("/api") || p == "/api" {
        return vec![
            "v1",
            "v2",
            "v3",
            "auth",
            "users",
            "admin",
            "search",
            "docs",
            "health",
            "status",
            "login",
            "register",
            "swagger",
            "openapi.json",
        ];
    }
    if p.contains("/api/v") || p.ends_with("/v1") || p.ends_with("/v2") || p.ends_with("/v3") {
        return vec![
            "users", "auth", "upload", "admin", "login", "me", "search", "config", "health",
            "status", "tokens", "orders", "products", "files",
        ];
    }
    if p.ends_with("/uploads") || p.ends_with("/upload") || p.ends_with("/files") {
        return vec!["files", "images", "temp", "docs", "export", "import"];
    }
    if p.ends_with("/docs") || p.ends_with("/documentation") {
        return vec!["api", "swagger", "openapi", "index", "redoc"];
    }
    if p.ends_with("/wp-admin") || p.contains("wordpress") {
        return vec![
            "admin-ajax.php",
            "install.php",
            "setup-config.php",
            "users.php",
        ];
    }
    if p.ends_with("/actuator") {
        return vec![
            "health",
            "env",
            "metrics",
            "info",
            "beans",
            "mappings",
            "configprops",
            "heapdump",
            "threaddump",
            "loggers",
        ];
    }
    if p.ends_with("/graphql") {
        return vec![]; // leaf
    }
    // Generic directory children
    vec![
        "index",
        "login",
        "admin",
        "api",
        "config",
        "settings",
        "users",
        "dashboard",
        "test",
        "backup",
        "old",
        "new",
        "dev",
        "staging",
        "v1",
        "v2",
    ]
}

const API_PATHS: &[&str] = &[
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/swagger",
    "/swagger-ui",
    "/docs",
    "/documentation",
    "/openapi.json",
    "/metrics",
    "/health",
    "/status",
    "/actuator",
];

const COMMON_DIRS: &[&str] = &[
    "/admin",
    "/login",
    "/dashboard",
    "/api",
    "/uploads",
    "/upload",
    "/static",
    "/assets",
    "/images",
    "/img",
    "/css",
    "/js",
    "/backup",
    "/backups",
    "/config",
    "/configs",
    "/tmp",
    "/temp",
    "/test",
    "/testing",
    "/dev",
    "/development",
    "/staging",
    "/prod",
    "/private",
    "/secret",
    "/secrets",
    "/internal",
    "/portal",
    "/console",
    "/manage",
    "/manager",
    "/panel",
    "/cp",
    "/cpanel",
    "/webmail",
    "/mail",
    "/ftp",
    "/db",
    "/database",
    "/sql",
    "/mysql",
    "/phpmyadmin",
    "/adminer",
    "/server-status",
    "/server-info",
    "/.git",
    "/.svn",
    "/.env",
    "/.DS_Store",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/security.txt",
    "/.well-known",
    "/.well-known/security.txt",
    "/favicon.ico",
    "/humans.txt",
    "/readme",
    "/README.md",
    "/CHANGELOG",
    "/LICENSE",
    "/swagger-ui.html",
    "/swagger.json",
    "/v1",
    "/v2",
    "/v3",
    "/graphql",
    "/graphiql",
    "/playground",
    "/altair",
    "/wp-admin",
    "/wp-content",
    "/wp-includes",
    "/vendor",
    "/node_modules",
    "/storage",
    "/media",
    "/files",
    "/download",
    "/downloads",
    "/export",
    "/import",
    "/report",
    "/reports",
    "/stats",
    "/metrics",
    "/health",
    "/healthz",
    "/ready",
    "/readiness",
    "/liveness",
    "/status",
    "/version",
    "/info",
    "/debug",
    "/trace",
    "/actuator",
    "/prometheus",
    "/monitoring",
    "/logs",
    "/log",
    "/error",
    "/errors",
    "/404",
    "/500",
    "/cgi-bin",
    "/bin",
    "/scripts",
    "/script",
    "/include",
    "/includes",
    "/lib",
    "/libs",
    "/src",
    "/source",
    "/app",
    "/application",
    "/apps",
    "/services",
    "/service",
    "/rest",
    "/rpc",
    "/soap",
    "/ws",
    "/websocket",
    "/socket.io",
    "/auth",
    "/oauth",
    "/oauth2",
    "/sso",
    "/saml",
    "/login",
    "/logout",
    "/signin",
    "/signout",
    "/register",
    "/signup",
    "/password",
    "/reset",
    "/account",
    "/accounts",
    "/profile",
    "/profiles",
    "/user",
    "/users",
    "/member",
    "/members",
    "/customer",
    "/customers",
    "/client",
    "/clients",
    "/order",
    "/orders",
    "/cart",
    "/checkout",
    "/payment",
    "/payments",
    "/billing",
    "/invoice",
    "/invoices",
    "/search",
    "/query",
    "/find",
    "/settings",
    "/preferences",
    "/options",
    "/tools",
    "/util",
    "/utils",
    "/help",
    "/support",
    "/contact",
    "/about",
    "/home",
    "/index",
    "/main",
    "/default",
    "/old",
    "/new",
    "/bak",
    "/backup.zip",
    "/dump",
    "/dump.sql",
    "/data",
    "/dataset",
    "/export.csv",
    "/api/docs",
    "/api/swagger",
    "/redoc",
    "/rapidoc",
    "/openapi.yaml",
    "/api-docs",
];

const GENERIC: &[&str] = &[
    "/a",
    "/b",
    "/c",
    "/1",
    "/2",
    "/3",
    "/test1",
    "/test2",
    "/demo",
    "/sample",
    "/example",
    "/foo",
    "/bar",
    "/baz",
    "/xyz",
    "/abc",
    "/qwerty",
    "/asdf",
    "/admin1",
    "/admin2",
    "/administrator",
    "/root",
    "/superuser",
    "/moderator",
    "/mod",
    "/staff",
    "/employee",
    "/hr",
    "/finance",
    "/sales",
    "/marketing",
    "/ops",
    "/operations",
    "/infra",
    "/infrastructure",
    "/devops",
    "/ci",
    "/cd",
    "/jenkins",
    "/gitlab",
    "/github",
    "/bitbucket",
    "/jira",
    "/confluence",
    "/wiki",
    "/kb",
    "/knowledge",
    "/blog",
    "/news",
    "/press",
    "/careers",
    "/jobs",
    "/partners",
    "/affiliate",
    "/affiliates",
    "/reseller",
    "/shop",
    "/store",
    "/catalog",
    "/product",
    "/products",
    "/item",
    "/items",
    "/category",
    "/categories",
    "/tag",
    "/tags",
    "/comment",
    "/comments",
    "/forum",
    "/forums",
    "/board",
    "/boards",
    "/ticket",
    "/tickets",
    "/issue",
    "/issues",
    "/bug",
    "/bugs",
    "/feedback",
    "/survey",
    "/poll",
    "/vote",
    "/rating",
    "/review",
    "/reviews",
    "/gallery",
    "/albums",
    "/photo",
    "/photos",
    "/video",
    "/videos",
    "/media",
    "/stream",
    "/live",
    "/broadcast",
    "/event",
    "/events",
    "/calendar",
    "/schedule",
    "/booking",
    "/reservation",
    "/appointments",
    "/map",
    "/maps",
    "/location",
    "/locations",
    "/geo",
    "/ip",
    "/whoami",
    "/me",
    "/self",
    "/session",
    "/sessions",
    "/token",
    "/tokens",
    "/key",
    "/keys",
    "/secret",
    "/secrets",
    "/credential",
    "/credentials",
    "/password-reset",
    "/forgot",
    "/recover",
    "/activate",
    "/activation",
    "/verify",
    "/verification",
    "/confirm",
    "/confirmation",
    "/unsubscribe",
    "/subscribe",
    "/newsletter",
    "/mail",
    "/email",
    "/sms",
    "/notification",
    "/notifications",
    "/alert",
    "/alerts",
    "/message",
    "/messages",
    "/inbox",
    "/outbox",
    "/draft",
    "/drafts",
    "/archive",
    "/archives",
    "/trash",
    "/deleted",
    "/recycle",
    "/bin2",
];

/// Built-in top-N slice for fast mode — highest priority common paths.
pub fn builtin_wordlist_path() -> Option<&'static str> {
    None
}
