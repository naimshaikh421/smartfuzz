//! NDJSON event stream for UI and automation (full scan transparency).

use chrono::Utc;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

use crate::fingerprint::TargetProfile;
use crate::recursive::ScanStats;
use crate::response::AnalyzedResponse;
use crate::wordlist::WordlistRecommendation;

#[derive(Debug, Serialize)]
pub struct EventEnvelope {
    pub ts: String,
    #[serde(flatten)]
    pub event: ScanEvent,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanEvent {
    ScanStarted {
        url: String,
        mode: String,
        threads: usize,
        recursive: bool,
        scan_limit: u64,
    },
    Stage {
        stage: u32,
        name: String,
    },
    Info {
        message: String,
    },
    Warn {
        message: String,
    },
    Profile {
        profile: Box<TargetProfile>,
    },
    Wordlists {
        recommendations: Vec<WordlistRecommendation>,
        tech_tags: Vec<String>,
    },
    Calibration {
        signatures: usize,
        probes: u64,
    },
    Request {
        url: String,
        path: String,
        status: u16,
        size: u64,
        elapsed_ms: u64,
        stage: String,
        redirect_target: Option<String>,
    },
    Discovery {
        item: Box<AnalyzedResponse>,
    },
    Filtered {
        item: Box<AnalyzedResponse>,
        reason: String,
    },
    Stats {
        requests: u64,
        discovered: u64,
        filtered: u64,
        retries: u64,
        depth: u64,
        workers: u64,
        speed: f64,
        elapsed_secs: f64,
    },
    ScanComplete {
        stats: ScanStats,
        report_path: Option<String>,
    },
    ScanError {
        message: String,
    },
}

pub struct EventWriter {
    writer: Mutex<BufWriter<File>>,
}

impl EventWriter {
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn emit(&self, event: ScanEvent) {
        let envelope = EventEnvelope {
            ts: Utc::now().to_rfc3339(),
            event,
        };
        if let Ok(line) = serde_json::to_string(&envelope) {
            if let Ok(mut w) = self.writer.lock() {
                let _ = writeln!(w, "{line}");
                let _ = w.flush();
            }
        }
    }
}
