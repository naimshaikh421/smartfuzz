//! Parse raw HTTP request files (ffuf/burp style) with FUZZ keyword support.

use anyhow::{Context, Result};
use reqwest::Method;
use std::path::Path;

use super::fuzz::{apply_fuzz, has_fuzz};

#[derive(Debug, Clone)]
pub struct RawRequestTemplate {
    pub method: Method,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl RawRequestTemplate {
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path).context("read request file")?;
        Self::parse(&data)
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let mut lines = raw.lines();
        let request_line = lines.next().context("empty request file")?.trim();
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        anyhow::ensure!(parts.len() >= 2, "invalid request line: {request_line}");

        let method = Method::from_bytes(parts[0].as_bytes()).context("invalid method")?;
        let path = parts[1].to_string();

        let mut headers = Vec::new();
        let mut body_lines = Vec::new();
        let mut in_body = false;

        for line in lines {
            if !in_body && line.trim().is_empty() {
                in_body = true;
                continue;
            }
            if in_body {
                body_lines.push(line);
            } else if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }

        let body = if body_lines.is_empty() {
            None
        } else {
            Some(body_lines.join("\n"))
        };

        Ok(Self {
            method,
            path,
            headers,
            body,
        })
    }

    pub fn has_fuzz(&self) -> bool {
        has_fuzz(&self.path)
            || self.body.as_ref().map(|b| has_fuzz(b)).unwrap_or(false)
            || self.headers.iter().any(|(_, v)| has_fuzz(v))
    }

    /// Apply FUZZ replacements and build full URL from base origin.
    pub fn build_url(&self, base: &url::Url, values: &[&str]) -> Result<String> {
        let path = apply_fuzz(&self.path, values);
        let path = if path.starts_with("http://") || path.starts_with("https://") {
            return Ok(path);
        } else if path.starts_with('/') {
            path
        } else {
            format!("/{}", path)
        };
        let mut u = base.clone();
        u.set_path(&path);
        u.set_query(None);
        u.set_fragment(None);
        Ok(u.to_string())
    }

    pub fn headers_for(&self, values: &[&str]) -> Vec<(String, String)> {
        self.headers
            .iter()
            .map(|(k, v)| (k.clone(), apply_fuzz(v, values)))
            .collect()
    }

    pub fn body_for(&self, values: &[&str]) -> Option<String> {
        self.body.as_ref().map(|b| apply_fuzz(b, values))
    }
}

pub fn load_wordlist_paths(paths: &[std::path::PathBuf]) -> Result<Vec<Vec<String>>> {
    let mut lists = Vec::new();
    for path in paths {
        lists.push(load_wordlist_file(path)?);
    }
    Ok(lists)
}

pub fn load_wordlist_file(path: &Path) -> Result<Vec<String>> {
    use std::io::{BufRead, BufReader};

    if path.as_os_str() == "-" {
        let stdin = std::io::stdin();
        let reader = BufReader::new(stdin.lock());
        let mut out = Vec::new();
        for line in reader.lines() {
            let line = line?.trim().to_string();
            if !line.is_empty() && !line.starts_with('#') {
                out.push(line);
            }
        }
        return Ok(out);
    }

    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?.trim().to_string();
        if !line.is_empty() && !line.starts_with('#') {
            out.push(line);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_get_request() {
        let raw = "GET /admin/FUZZ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req = RawRequestTemplate::parse(raw).unwrap();
        assert_eq!(req.method, Method::GET);
        assert_eq!(req.path, "/admin/FUZZ");
        assert!(req.has_fuzz());
    }

    #[test]
    fn parse_post_with_body() {
        let raw = "POST /login HTTP/1.1\nHost: t.com\nContent-Type: application/json\n\n{\"user\":\"FUZZ\"}";
        let req = RawRequestTemplate::parse(raw).unwrap();
        assert_eq!(req.method, Method::POST);
        assert!(req.body.as_ref().unwrap().contains("FUZZ"));
    }

    #[test]
    fn header_fuzz() {
        let raw = "GET / HTTP/1.1\nHost: FUZZ.example.com\n\n";
        let req = RawRequestTemplate::parse(raw).unwrap();
        let h = req.headers_for(&["admin"]);
        assert!(h
            .iter()
            .any(|(k, v)| k == "Host" && v == "admin.example.com"));
    }
}
