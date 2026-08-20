//! Download free wordlists (SecLists on GitHub) with local cache.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::wordlist::selector::WordlistRecommendation;

const DEFAULT_CACHE: &str = "wordlists/cache";

pub struct WordlistFetcher {
    cache_dir: PathBuf,
    client: reqwest::Client,
    max_age_days: u64,
}

impl WordlistFetcher {
    pub fn new(cache_dir: Option<PathBuf>) -> Result<Self> {
        let cache_dir = cache_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE));
        std::fs::create_dir_all(&cache_dir).ok();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent("SmartFuzz/0.1 (authorized-testing; +https://github.com)")
            .build()?;
        Ok(Self {
            cache_dir,
            client,
            max_age_days: 14,
        })
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Resolve path: local SecLists dir → cache → download.
    pub async fn resolve(
        &self,
        rec: &WordlistRecommendation,
        local_seclists: Option<&Path>,
        allow_download: bool,
    ) -> Result<PathBuf> {
        // 1. User-provided local SecLists clone
        if let Some(base) = local_seclists {
            let local = base.join(&rec.seclists_path);
            if local.is_file() {
                return Ok(local);
            }
        }

        // 2. Cache hit
        let cached = self.cache_path(&rec.seclists_path);
        if cached.is_file() && !self.is_stale(&cached) {
            return Ok(cached);
        }

        // 3. Download (free GitHub raw)
        if allow_download {
            self.download(&rec.url, &rec.seclists_path).await?;
            if cached.is_file() {
                return Ok(cached);
            }
        }

        anyhow::bail!(
            "wordlist '{}' not found locally. Run with --download-wordlists or clone SecLists to --wordlist-dir",
            rec.name
        )
    }

    pub fn cache_path(&self, seclists_relative: &str) -> PathBuf {
        self.cache_dir.join(seclists_relative)
    }

    async fn download(&self, url: &str, seclists_relative: &str) -> Result<()> {
        let dest = self.cache_path(seclists_relative);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .context("wordlist download failed")?;
        if !resp.status().is_success() {
            anyhow::bail!("HTTP {} for {}", resp.status(), url);
        }
        let bytes = resp.bytes().await?;
        if bytes.is_empty() {
            anyhow::bail!("empty wordlist from {}", url);
        }
        // Reject HTML error pages masquerading as wordlists
        if bytes.starts_with(b"<!DOCTYPE") || bytes.starts_with(b"<html") {
            anyhow::bail!("received HTML instead of wordlist from {}", url);
        }
        std::fs::write(&dest, &bytes)?;
        Ok(())
    }

    fn is_stale(&self, path: &Path) -> bool {
        let Ok(meta) = std::fs::metadata(path) else {
            return true;
        };
        let Ok(modified) = meta.modified() else {
            return false;
        };
        let Ok(age) = SystemTime::now().duration_since(modified) else {
            return false;
        };
        age > Duration::from_secs(self.max_age_days * 86400)
    }

    /// Pre-download all recommendations (parallel sequential for simplicity).
    pub async fn fetch_all(
        &self,
        recs: &[WordlistRecommendation],
        local_seclists: Option<&Path>,
        allow_download: bool,
    ) -> Vec<(WordlistRecommendation, Result<PathBuf>)> {
        let mut out = Vec::new();
        for rec in recs {
            let r = self.resolve(rec, local_seclists, allow_download).await;
            out.push((rec.clone(), r));
        }
        out
    }
}

/// Print human-readable recommendation table.
pub fn print_recommendations(recs: &[WordlistRecommendation], tech_tags: &[String]) {
    use colored::Colorize;
    println!("\n{}", "═══ Wordlist Recommendations ═══".cyan().bold());
    if !tech_tags.is_empty() {
        println!("  {} {}", "Detected".cyan(), tech_tags.join(", "));
    } else {
        println!(
            "  {} No strong tech signal — using baseline lists",
            "Detected".cyan()
        );
    }
    println!();
    for r in recs {
        println!(
            "  {:>3} {} {} — {}",
            r.priority,
            "▸".cyan(),
            r.name.bold(),
            r.reason
        );
        println!("      {}", r.seclists_path.dimmed());
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_path_nested() {
        let f = WordlistFetcher::new(Some(PathBuf::from("/tmp/sf-test"))).unwrap();
        let p = f.cache_path("CMS/WordPress.fuzz.txt");
        assert!(p.to_string_lossy().contains("CMS"));
    }
}
