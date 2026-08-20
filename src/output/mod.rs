//! Colorized terminal output, progress display, and NDJSON event stream.

use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::events::{EventWriter, ScanEvent};
use crate::fingerprint::{unique_techs, TargetProfile};
use crate::recursive::ScanStats;
use crate::response::{format_size, AnalyzedResponse};
use crate::wordlist::WordlistRecommendation;

pub struct Output {
    silent: bool,
    verbose: bool,
    show_filtered: bool,
    start: Instant,
    pub stats: Arc<Stats>,
    multiprog: MultiProgress,
    bar: ProgressBar,
    events: Option<Arc<EventWriter>>,
    last_stats_emit: AtomicU64,
}

#[derive(Default)]
pub struct Stats {
    pub requests: AtomicU64,
    pub discovered: AtomicU64,
    pub filtered: AtomicU64,
    pub retries: AtomicU64,
    pub depth: AtomicU64,
    pub workers: AtomicU64,
}

impl Output {
    pub fn new(
        silent: bool,
        verbose: bool,
        show_filtered: bool,
        workers: usize,
        events: Option<Arc<EventWriter>>,
    ) -> Self {
        let multiprog = MultiProgress::new();
        let bar = multiprog.add(ProgressBar::new_spinner());
        bar.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        if silent {
            bar.set_draw_target(indicatif::ProgressDrawTarget::hidden());
        }
        let stats = Arc::new(Stats {
            workers: AtomicU64::new(workers as u64),
            ..Default::default()
        });
        let out = Self {
            silent,
            verbose,
            show_filtered,
            start: Instant::now(),
            stats,
            multiprog,
            bar,
            events,
            last_stats_emit: AtomicU64::new(0),
        };
        out.refresh_bar();
        out
    }

    pub fn emit_scan_started(
        &self,
        url: &str,
        mode: &str,
        threads: usize,
        recursive: bool,
        scan_limit: u64,
    ) {
        self.emit(ScanEvent::ScanStarted {
            url: url.to_string(),
            mode: mode.to_string(),
            threads,
            recursive,
            scan_limit,
        });
    }

    pub fn emit_profile(&self, profile: &TargetProfile) {
        self.emit(ScanEvent::Profile {
            profile: Box::new(profile.clone()),
        });
        self.print_profile(profile);
    }

    pub fn emit_wordlists(&self, recommendations: &[WordlistRecommendation], tech_tags: &[String]) {
        self.emit(ScanEvent::Wordlists {
            recommendations: recommendations.to_vec(),
            tech_tags: tech_tags.to_vec(),
        });
    }

    pub fn emit_calibration(&self, signatures: usize, probes: u64) {
        self.emit(ScanEvent::Calibration { signatures, probes });
    }

    pub fn emit_request(&self, item: &AnalyzedResponse) {
        self.emit(ScanEvent::Request {
            url: item.url.clone(),
            path: item.path.clone(),
            status: item.status,
            size: item.size,
            elapsed_ms: item.elapsed_ms,
            stage: item.stage.as_str().to_string(),
            redirect_target: item.redirect_target.clone(),
        });
    }

    pub fn emit_discovery(&self, item: &AnalyzedResponse) {
        self.emit(ScanEvent::Discovery {
            item: Box::new(item.clone()),
        });
    }

    pub fn emit_filtered(&self, item: &AnalyzedResponse, reason: &str) {
        self.emit(ScanEvent::Filtered {
            item: Box::new(item.clone()),
            reason: reason.to_string(),
        });
    }

    pub fn emit_complete(&self, stats: ScanStats, report_path: Option<String>) {
        self.emit(ScanEvent::ScanComplete { stats, report_path });
    }

    pub fn emit_error(&self, message: &str) {
        self.emit(ScanEvent::ScanError {
            message: message.to_string(),
        });
    }

    fn emit(&self, event: ScanEvent) {
        if let Some(w) = &self.events {
            w.emit(event);
        }
    }

    pub fn banner(&self) {
        if self.silent {
            return;
        }
        println!(
            "{}",
            r#"
 ____                       _   _____
/ ___| _ __ ___   __ _ _ __| |_|  ___|   _ ________
\___ \| '_ ` _ \ / _` | '__| __| |_ | | | |_  /_  /
 ___) | | | | | | (_| | |  | |_|  _|| |_| |/ / / /
|____/|_| |_| |_|\__,_|_|   \__|_|   \__,_/___/___|
"#
            .cyan()
        );
        println!(
            "  {} Intelligent adaptive web content discovery",
            "SmartFuzz".bold().cyan()
        );
        println!("  {} Authorized security testing only\n", "⚠".yellow());
    }

    pub fn print_profile(&self, profile: &TargetProfile) {
        if self.silent {
            return;
        }
        println!("{}", "═══ Target Profile ═══".cyan().bold());
        println!("  {} {}", "URL".cyan(), profile.url);
        if let Some(s) = &profile.server {
            println!("  {} {}", "Server".cyan(), s);
        }
        if let Some(p) = &profile.powered_by {
            println!("  {} {}", "Powered-By".cyan(), p);
        }
        let techs = unique_techs(profile);
        if !techs.is_empty() {
            println!("  {} {}", "Tech".cyan(), techs.join(", "));
        }
        if !profile.compression.is_empty() {
            println!(
                "  {} {}",
                "Compression".cyan(),
                profile.compression.join(", ")
            );
        }
        if !profile.cdn.is_empty() {
            println!("  {} {}", "CDN".cyan(), profile.cdn.join(", "));
        }
        if !profile.waf.is_empty() {
            println!("  {} {}", "WAF".cyan(), profile.waf.join(", "));
        }
        if profile.graphql_detected {
            println!("  {} detected", "GraphQL".cyan());
        }
        if !profile.favicon_tech.is_empty() {
            println!(
                "  {} {} (mmh3: {:?})",
                "Favicon".cyan(),
                profile.favicon_tech.join(", "),
                profile.favicon_mmh3
            );
        }
        if profile.soft_404_baseline.is_some() {
            println!("  {} baseline captured", "Soft-404".cyan());
        }
        println!(
            "  {} {} robots, {} interesting, {} JS",
            "Seeds".cyan(),
            profile.robots_paths.len(),
            profile.interesting_paths.len(),
            profile.js_files.len()
        );
        println!();
    }

    pub fn print_result(&self, item: &AnalyzedResponse) {
        if item.filtered && !self.show_filtered {
            return;
        }

        let status_str = format_status(item);
        let size = format_size(item.size);
        let mut line = format!(
            "{} {:>5} {:>5}ms Depth:{} {}",
            status_str, size, item.elapsed_ms, item.depth, item.path
        );

        if let Some(t) = &item.redirect_target {
            line.push_str(&format!(" -> {}", t));
        }
        if self.verbose {
            line.push_str(&format!(" [{}]", item.source.as_str()));
        }
        if item.filtered {
            if let Some(r) = &item.filter_reason {
                line.push_str(&format!(" ({})", r));
            }
        }

        if !self.silent {
            self.bar.println(line);
        }
    }

    pub fn info(&self, msg: &str) {
        self.emit(ScanEvent::Info {
            message: msg.to_string(),
        });
        if self.silent {
            return;
        }
        self.bar.println(format!("{} {}", "[*]".cyan(), msg));
    }

    pub fn stage(&self, n: u32, name: &str) {
        self.emit(ScanEvent::Stage {
            stage: n,
            name: name.to_string(),
        });
        if self.silent {
            return;
        }
        self.bar.println(format!(
            "\n{} Stage {} — {}",
            "▶".cyan().bold(),
            n,
            name.bold()
        ));
    }

    pub fn warn(&self, msg: &str) {
        self.emit(ScanEvent::Warn {
            message: msg.to_string(),
        });
        if self.silent {
            return;
        }
        self.bar.println(format!("{} {}", "[!]".yellow(), msg));
    }

    pub fn refresh_bar(&self) {
        let reqs = self.stats.requests.load(Ordering::Relaxed);
        let elapsed = self.start.elapsed().as_secs_f64().max(0.001);
        let speed = reqs as f64 / elapsed;

        // Throttle stats events (~4/sec) for UI performance
        let now_ms = (elapsed * 1000.0) as u64;
        let last = self.last_stats_emit.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) >= 250 {
            self.last_stats_emit.store(now_ms, Ordering::Relaxed);
            self.emit(ScanEvent::Stats {
                requests: reqs,
                discovered: self.stats.discovered.load(Ordering::Relaxed),
                filtered: self.stats.filtered.load(Ordering::Relaxed),
                retries: self.stats.retries.load(Ordering::Relaxed),
                depth: self.stats.depth.load(Ordering::Relaxed),
                workers: self.stats.workers.load(Ordering::Relaxed),
                speed,
                elapsed_secs: elapsed,
            });
        }

        if self.silent {
            return;
        }
        let msg = format!(
            "Requests: {} | Speed: {:.0} req/s | Workers: {} | Depth: {} | Discovered: {} | Filtered: {} | Retries: {}",
            reqs,
            speed,
            self.stats.workers.load(Ordering::Relaxed),
            self.stats.depth.load(Ordering::Relaxed),
            self.stats.discovered.load(Ordering::Relaxed),
            self.stats.filtered.load(Ordering::Relaxed),
            self.stats.retries.load(Ordering::Relaxed),
        );
        self.bar.set_message(msg);
        self.bar.tick();
    }

    pub fn finish(&self) {
        self.refresh_bar();
        self.bar.finish_and_clear();
        if self.silent {
            return;
        }
        let reqs = self.stats.requests.load(Ordering::Relaxed);
        let elapsed = self.start.elapsed().as_secs_f64();
        println!();
        println!("{}", "═══ Scan Complete ═══".cyan().bold());
        println!(
            "  Requests: {} | Duration: {:.1}s | Avg: {:.0} req/s",
            reqs,
            elapsed,
            reqs as f64 / elapsed.max(0.001)
        );
        println!(
            "  Discovered: {} | Filtered: {}",
            self.stats.discovered.load(Ordering::Relaxed),
            self.stats.filtered.load(Ordering::Relaxed)
        );
        let _ = io::stdout().flush();
    }

    pub fn multiprog(&self) -> &MultiProgress {
        &self.multiprog
    }
}

/// Colorize any HTTP status code for terminal output.
pub fn color_status_code(status: u16) -> String {
    match status {
        100..=199 => status.to_string().cyan().bold().to_string(),
        200..=299 => status.to_string().green().bold().to_string(),
        300..=399 => status.to_string().blue().bold().to_string(),
        401 | 407 => status.to_string().yellow().bold().to_string(),
        403 => status.to_string().magenta().bold().to_string(),
        404 | 410 => status.to_string().red().to_string(),
        400 | 405 | 408 | 429 => status.to_string().yellow().bold().to_string(),
        400..=499 => status.to_string().yellow().to_string(),
        500..=599 => status.to_string().red().bold().to_string(),
        _ => status.to_string().white().to_string(),
    }
}

fn format_status(item: &AnalyzedResponse) -> String {
    let code = color_status_code(item.status);

    if item.soft_404 {
        return format!("[{}] {}", code, "SOFT-404".truecolor(128, 128, 128));
    }
    if item.filtered {
        return format!("[{}] {}", code, "FILTERED".truecolor(128, 128, 128));
    }
    match item.status {
        200 | 201 | 202 | 204 => format!("[{}] {}", code, "VALID".green()),
        301 | 302 | 307 | 308 => format!("[{}] {}", code, "REDIRECT".blue()),
        401 => format!("[{}] {}", code, "AUTH REQUIRED".yellow()),
        403 => format!("[{}] {}", code, "RESTRICTED".magenta()),
        500 | 502 | 503 | 504 => format!("[{}] {}", code, "SERVER ERROR".red()),
        _ => format!("[{}]", code),
    }
}

/// Global cancel flag for Ctrl+C.
pub fn install_ctrlc(flag: Arc<AtomicBool>) {
    let _ = ctrlc::set_handler(move || {
        flag.store(true, Ordering::SeqCst);
        eprintln!("\n{} Interrupted — saving state…", "[!]".yellow());
    });
}
