//! JSON / HTML / Markdown reporting.

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::fingerprint::unique_techs;
use crate::recursive::ScanResult;
use crate::response::format_size;

pub struct ReportBuilder<'a> {
    result: &'a ScanResult,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    tool: &'static str,
    version: &'static str,
    generated_at: String,
    target: &'a str,
    technologies: Vec<String>,
    profile: &'a crate::fingerprint::TargetProfile,
    statistics: &'a crate::recursive::ScanStats,
    endpoints: &'a [crate::response::AnalyzedResponse],
    apis: Vec<&'a crate::response::AnalyzedResponse>,
    redirects: Vec<&'a crate::response::AnalyzedResponse>,
}

impl<'a> ReportBuilder<'a> {
    pub fn new(result: &'a ScanResult) -> Self {
        Self { result }
    }

    pub fn write_json(&self, path: &Path) -> Result<()> {
        let apis: Vec<_> = self
            .result
            .discoveries
            .iter()
            .filter(|d| d.path.contains("api") || d.path.contains("graphql"))
            .collect();
        let redirects: Vec<_> = self
            .result
            .discoveries
            .iter()
            .filter(|d| d.redirected)
            .collect();

        let report = JsonReport {
            tool: "SmartFuzz",
            version: env!("CARGO_PKG_VERSION"),
            generated_at: Utc::now().to_rfc3339(),
            target: &self.result.profile.url,
            technologies: unique_techs(&self.result.profile),
            profile: &self.result.profile,
            statistics: &self.result.stats,
            endpoints: &self.result.discoveries,
            apis,
            redirects,
        };
        let json = serde_json::to_string_pretty(&report)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn write_markdown(&self, path: &Path) -> Result<()> {
        let mut md = String::new();
        md.push_str("# SmartFuzz Report\n\n");
        md.push_str(&format!("**Target:** {}\n\n", self.result.profile.url));
        md.push_str(&format!("**Generated:** {}\n\n", Utc::now().to_rfc3339()));
        md.push_str("## Technologies\n\n");
        for t in unique_techs(&self.result.profile) {
            md.push_str(&format!("- {}\n", t));
        }
        md.push_str("\n## Statistics\n\n");
        md.push_str(&format!("- Requests: {}\n", self.result.stats.requests));
        md.push_str(&format!("- Discovered: {}\n", self.result.stats.discovered));
        md.push_str(&format!("- Filtered: {}\n", self.result.stats.filtered));
        md.push_str(&format!(
            "- Duration: {:.1}s\n\n",
            self.result.stats.duration_secs
        ));
        md.push_str("## Endpoints\n\n");
        md.push_str("| Status | Size | Time | Depth | Path | Source |\n");
        md.push_str("|--------|------|------|-------|------|--------|\n");
        for d in &self.result.discoveries {
            if d.filtered {
                continue;
            }
            md.push_str(&format!(
                "| {} | {} | {}ms | {} | `{}` | {} |\n",
                d.status,
                format_size(d.size),
                d.elapsed_ms,
                d.depth,
                d.path,
                d.source.as_str()
            ));
        }
        fs::write(path, md)?;
        Ok(())
    }

    pub fn write_html(&self, path: &Path) -> Result<()> {
        let mut rows = String::new();
        for d in &self.result.discoveries {
            if d.filtered {
                continue;
            }
            let color = match d.status {
                200..=299 => "#16a34a",
                300..=399 => "#2563eb",
                401 => "#ca8a04",
                403 => "#a855f7",
                500..=599 => "#dc2626",
                _ => "#64748b",
            };
            rows.push_str(&format!(
                "<tr><td style=\"color:{color};font-weight:600\">{}</td><td>{}</td><td>{}ms</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>\n",
                d.status,
                format_size(d.size),
                d.elapsed_ms,
                d.depth,
                html_escape(&d.path),
                d.source.as_str()
            ));
        }

        let techs = unique_techs(&self.result.profile)
            .into_iter()
            .map(|t| format!("<li>{}</li>", html_escape(&t)))
            .collect::<String>();

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>SmartFuzz Report — {target}</title>
<style>
  :root {{ --bg:#0f1419; --card:#1a2332; --text:#e7ecf3; --muted:#8b9bb4; --accent:#38bdf8; }}
  body {{ font-family: ui-sans-serif, system-ui, sans-serif; background:var(--bg); color:var(--text); margin:0; padding:2rem; }}
  h1 {{ color:var(--accent); margin-bottom:0.25rem; }}
  .meta {{ color:var(--muted); margin-bottom:2rem; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:2rem; }}
  .card {{ background:var(--card); border-radius:8px; padding:1.25rem; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card); border-radius:8px; overflow:hidden; }}
  th, td {{ text-align:left; padding:0.65rem 0.9rem; border-bottom:1px solid #243044; }}
  th {{ color:var(--muted); font-weight:600; font-size:0.85rem; }}
  code {{ color:#7dd3fc; }}
  ul {{ margin:0; padding-left:1.2rem; }}
</style>
</head>
<body>
  <h1>SmartFuzz</h1>
  <p class="meta">Target: <strong>{target}</strong> · Generated {when}</p>
  <div class="grid">
    <div class="card">
      <h3>Statistics</h3>
      <p>Requests: {requests}<br/>Discovered: {discovered}<br/>Filtered: {filtered}<br/>Duration: {duration:.1}s</p>
    </div>
    <div class="card">
      <h3>Technologies</h3>
      <ul>{techs}</ul>
    </div>
  </div>
  <div class="card">
    <h3>Endpoints</h3>
    <table>
      <thead><tr><th>Status</th><th>Size</th><th>Time</th><th>Depth</th><th>Path</th><th>Source</th></tr></thead>
      <tbody>
{rows}
      </tbody>
    </table>
  </div>
</body>
</html>"#,
            target = html_escape(&self.result.profile.url),
            when = Utc::now().to_rfc3339(),
            requests = self.result.stats.requests,
            discovered = self.result.stats.discovered,
            filtered = self.result.stats.filtered,
            duration = self.result.stats.duration_secs,
            techs = techs,
            rows = rows,
        );
        fs::write(path, html)?;
        Ok(())
    }

    pub fn write_csv(&self, path: &Path) -> Result<()> {
        let mut csv =
            String::from("status,size,words,lines,time_ms,depth,path,source,stage,redirect\n");
        for d in &self.result.discoveries {
            if d.filtered {
                continue;
            }
            csv.push_str(&format!(
                "{},{},{},{},{},{},\"{}\",{},{},\"{}\"\n",
                d.status,
                d.size,
                d.words,
                d.lines,
                d.elapsed_ms,
                d.depth,
                d.path.replace('"', "\"\""),
                d.source.as_str(),
                d.stage.as_str(),
                d.redirect_target
                    .as_deref()
                    .unwrap_or("")
                    .replace('"', "\"\"")
            ));
        }
        fs::write(path, csv)?;
        Ok(())
    }

    /// ffuf-compatible JSON output (https://github.com/ffuf/ffuf JSON schema).
    pub fn write_ffuf_json(&self, path: &Path) -> Result<()> {
        use serde_json::json;

        let results: Vec<_> = self
            .result
            .discoveries
            .iter()
            .filter(|d| !d.filtered)
            .enumerate()
            .map(|(i, d)| {
                json!({
                    "status": d.status,
                    "length": d.size,
                    "words": d.words,
                    "lines": d.lines,
                    "duration": (d.elapsed_ms as f64) / 1000.0,
                    "url": d.url,
                    "input": { "FUZZ": d.path.trim_start_matches("vhost:") },
                    "position": i + 1,
                    "redirectlocation": d.redirect_target.clone().unwrap_or_default(),
                    "content-type": d.content_type.clone().unwrap_or_default(),
                    "scraper": {},
                    "resultfile": "",
                    "host": self.result.profile.url,
                })
            })
            .collect();

        let report = json!({
            "commandline": format!("smartfuzz -u {}", self.result.profile.url),
            "time": format!("{:.2}s", self.result.stats.duration_secs),
            "results": results,
        });

        fs::write(path, serde_json::to_string_pretty(&report)?)?;
        Ok(())
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
