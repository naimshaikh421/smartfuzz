//! JSON path plugins with priority support.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPlugin {
    pub name: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub priority: Option<u8>,
}

pub struct PluginEngine {
    plugins: Vec<JsonPlugin>,
}

impl PluginEngine {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    pub fn load_dir(&mut self, dir: &Path) -> Result<usize> {
        if !dir.is_dir() {
            return Ok(0);
        }
        let mut n = 0;
        for entry in fs::read_dir(dir).context("read plugin dir")? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(p) = load_json_plugin(&path) {
                    self.plugins.push(p);
                    n += 1;
                }
            }
        }
        Ok(n)
    }

    pub fn all_paths(&self) -> Vec<(String, u8)> {
        let mut out = Vec::new();
        for p in &self.plugins {
            let prio = p.priority.unwrap_or(85);
            for path in &p.paths {
                out.push((path.clone(), prio));
            }
        }
        out
    }

    pub fn names(&self) -> Vec<String> {
        self.plugins.iter().map(|p| p.name.clone()).collect()
    }
}

impl Default for PluginEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn load_json_plugin(path: &Path) -> Result<JsonPlugin> {
    let data = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}

pub fn example_plugin_path() -> PathBuf {
    PathBuf::from("plugins/example.json")
}
