//! HTML link extraction (feroxbuster-style spider).

use regex::Regex;
use std::collections::HashSet;
use url::Url;

use crate::wordlist::normalize_path;

/// Extract same-host paths from an HTML body.
pub fn extract_links(body: &str, base: &Url) -> Vec<String> {
    let mut out = HashSet::new();

    let href_re =
        Regex::new(r#"(?i)(?:href|src|action|data-url|data-href)\s*=\s*["']([^"'#]+)["']"#)
            .unwrap();
    let url_re = Regex::new(r#"(?i)url\(\s*['"]?([^'")]+)['"]?\s*\)"#).unwrap();

    for cap in href_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            if let Some(p) = resolve_link(base, m.as_str()) {
                out.insert(p);
            }
        }
    }
    for cap in url_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            if let Some(p) = resolve_link(base, m.as_str()) {
                out.insert(p);
            }
        }
    }

    // Absolute paths in JS-ish strings inside HTML
    let path_re = Regex::new(r#"["'](/[A-Za-z0-9_\-./%]+)["']"#).unwrap();
    for cap in path_re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            let p = normalize_path(m.as_str());
            if interesting(&p) {
                out.insert(p);
            }
        }
    }

    let mut v: Vec<_> = out.into_iter().collect();
    v.sort();
    v
}

fn resolve_link(base: &Url, raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty()
        || raw.starts_with('#')
        || raw.starts_with("mailto:")
        || raw.starts_with("tel:")
        || raw.starts_with("javascript:")
        || raw.starts_with("data:")
    {
        return None;
    }

    let joined = if raw.starts_with("http://") || raw.starts_with("https://") {
        Url::parse(raw).ok()?
    } else if raw.starts_with("//") {
        Url::parse(&format!("{}:{}", base.scheme(), raw)).ok()?
    } else {
        base.join(raw).ok()?
    };

    if joined.host_str()? != base.host_str()? {
        return None;
    }
    let path = normalize_path(joined.path());
    if interesting(&path) {
        Some(path)
    } else {
        None
    }
}

fn interesting(path: &str) -> bool {
    if path.len() < 2 || path.len() > 250 {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    let skip = [
        ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
        ".mp4", ".webm", ".mp3", ".wav",
    ];
    !skip.iter().any(|e| lower.ends_with(e))
}
