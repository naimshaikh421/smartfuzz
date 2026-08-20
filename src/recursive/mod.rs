//! Multi-stage recursive discovery: fingerprint → dirs → files → API → recurse.

use anyhow::{Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

use crate::api::ApiDiscoveryEngine;
use crate::cli::Args;
use crate::events::EventWriter;
use crate::filter::{
    auto_calibrate, body_for_filter, DuplicateDetector, FilterDecision, SmartFilters,
};
use crate::fingerprint::{FingerprintEngine, TargetProfile};
use crate::http::{
    combine_wordlists, expand_with_extensions, load_wordlist_paths, parse_headers, HttpEngine,
};
use crate::js::JsAnalyzer;
use crate::output::{install_ctrlc, Output};
use crate::plugin::PluginEngine;
use crate::rate::AdaptiveRateLimiter;
use crate::report::ReportBuilder;
use crate::response::{
    looks_like_directory, AnalyzedResponse, DiscoverySource, ResponseAnalyzer, ScanStage,
};
use crate::spider::extract_links;
use crate::wordlist::{
    extensions_for_tech, print_recommendations, profile_tech_tags, recommend, recursive_children,
    should_use_tech_focus, WordEntry, WordlistEngine, WordlistFetcher,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanState {
    pub url: String,
    pub completed_paths: Vec<String>,
    pub discoveries: Vec<AnalyzedResponse>,
    pub queue: Vec<QueueItem>,
    pub profile: Option<TargetProfile>,
    pub stage: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueItem {
    pub path: String,
    pub depth: u32,
    pub source: String,
    pub priority: u8,
    #[serde(default = "default_stage")]
    pub stage: String,
}

fn default_stage() -> String {
    "directory".into()
}

pub struct ScanEngine {
    args: Args,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub profile: TargetProfile,
    pub discoveries: Vec<AnalyzedResponse>,
    pub stats: ScanStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub requests: u64,
    pub discovered: u64,
    pub filtered: u64,
    pub retries: u64,
    pub duration_secs: f64,
}

impl ScanEngine {
    pub fn new(args: Args) -> Self {
        Self { args }
    }

    pub async fn run(&self) -> Result<ScanResult> {
        let args = self.args.clone();
        // config applied by caller / main

        let http = HttpEngine::new(&args)?;
        let headers = parse_headers(&args.header, &args.cookies);
        let cancel = Arc::new(AtomicBool::new(false));
        install_ctrlc(cancel.clone());

        let events = args
            .json_events
            .as_ref()
            .map(|p| EventWriter::new(p).map(Arc::new))
            .transpose()
            .context("json-events file")?;

        let out = Output::new(
            args.silent,
            args.verbose,
            args.show_filtered,
            args.effective_threads(),
            events,
        );
        out.banner();
        out.emit_scan_started(
            &args.url,
            &format!("{:?}", args.mode).to_lowercase(),
            args.effective_threads(),
            args.is_recursive(),
            args.scan_limit,
        );
        if args.has_fuzz() {
            out.info(&format!("FUZZ template: {}", args.url));
        }

        let mut state = if let Some(resume) = &args.resume {
            load_state(resume).unwrap_or_else(|_| empty_state(&args.url))
        } else {
            empty_state(&args.url)
        };

        let start = Instant::now();
        let maxtime = args.maxtime;
        let scan_limit = args.scan_limit;
        if scan_limit > 0 {
            out.info(&format!("Scan request limit: {scan_limit}"));
        }

        // ── Stage 1: Fingerprint ──────────────────────────────────────
        out.stage(1, "Fingerprinting & Technology Detection");
        let mut profile = if let Some(p) = state.profile.clone() {
            out.info("Loaded profile from resume state");
            p
        } else if args.skip_fingerprint {
            TargetProfile {
                url: args.url.clone(),
                ..Default::default()
            }
        } else {
            FingerprintEngine::new(http.clone(), headers.clone())
                .run()
                .await
                .context("fingerprinting failed")?
        };
        out.emit_profile(&profile);

        // Tech-based wordlist recommendations (before fuzzing)
        let tech_tags = profile_tech_tags(&profile);
        let wordlist_recommendations = if args.is_auto_wordlist() || args.recommend_only {
            let recs = recommend(&profile, args.mode);
            out.emit_wordlists(&recs, &tech_tags);
            print_recommendations(&recs, &tech_tags);
            if args.allow_wordlist_download() {
                out.info("Downloading missing wordlists from SecLists (GitHub)…");
            } else if args.wordlist_dir.is_some() {
                out.info("Using local SecLists directory (no download)");
            } else {
                out.info(
                    "Tip: --download-wordlists to fetch SecLists, or --wordlist-dir /path/to/SecLists/Discovery/Web-Content",
                );
            }
            recs
        } else {
            Vec::new()
        };

        if args.recommend_only {
            if args.allow_wordlist_download() && !wordlist_recommendations.is_empty() {
                let fetcher = WordlistFetcher::new(Some(args.wordlist_cache.clone()))?;
                for rec in &wordlist_recommendations {
                    match fetcher
                        .resolve(rec, args.wordlist_dir.as_deref(), true)
                        .await
                    {
                        Ok(p) => out.info(&format!("Ready: {} → {}", rec.name, p.display())),
                        Err(e) => out.warn(&format!("{}: {e}", rec.name)),
                    }
                }
            }
            out.finish();
            return Ok(ScanResult {
                profile,
                discoveries: Vec::new(),
                stats: ScanStats {
                    duration_secs: start.elapsed().as_secs_f64(),
                    ..Default::default()
                },
            });
        }

        // Auto-calibrate wildcards
        let mut filters = SmartFilters::from_args(&args);
        let mut calibration = Vec::new();
        if args.is_auto_calibrate() {
            out.info("Auto-calibrating soft-404 / wildcard responses…");
            let (cal, nreq) = auto_calibrate(&http, &headers).await;
            calibration = cal;
            out.stats.requests.fetch_add(nreq, Ordering::Relaxed);
            filters.ingest_calibration(&calibration);
            if let Some(primary) = calibration.first() {
                if profile.soft_404_baseline.is_none() {
                    profile.soft_404_baseline = Some(primary.clone());
                }
            }
            out.emit_calibration(calibration.len(), nreq);
            out.info(&format!(
                "Calibration captured {} wildcard signatures ({} probes)",
                calibration.len(),
                nreq
            ));
        }

        state.profile = Some(profile.clone());
        state.stage = 1;
        save_state(&args.state_file, &state)?;

        let analyzer = ResponseAnalyzer::new(profile.soft_404_baseline.clone())
            .with_extras(calibration.clone());
        let mut analyzer = analyzer;
        analyzer.set_threshold(args.filter_similar);

        let dupes = DuplicateDetector::new();
        for p in &state.completed_paths {
            dupes.mark_path(p);
        }

        let limiter = AdaptiveRateLimiter::with_delay_jitter(
            args.effective_threads(),
            args.rate_limit,
            args.mode,
            args.delay,
            args.effective_delay_jitter(),
        );
        let discoveries = Arc::new(Mutex::new(state.discoveries.clone()));
        let collected_exts = Arc::new(Mutex::new(Vec::<String>::new()));

        // VHost discovery (free — Host header fuzzing only)
        if args.vhost {
            out.stage(1, "VHost Discovery (Host header fuzzing)");
            let cfg = crate::vhost::VhostConfig::from_url(
                &args.url,
                args.vhost_domain.as_deref(),
                args.vhost_ip.as_deref(),
            )?;
            let default_host = url::Url::parse(&args.url)
                .ok()
                .and_then(|u| u.host_str().map(|s| s.to_string()))
                .unwrap_or_else(|| cfg.base_domain.clone());

            let vhost_baseline =
                crate::vhost::capture_baseline(&http, &cfg, &default_host, &headers).await;
            if let Some(ref base) = vhost_baseline {
                out.info(&format!(
                    "VHost baseline: {} bytes, status {}",
                    base.size, base.status
                ));
                out.stats.requests.fetch_add(1, Ordering::Relaxed);
            }

            match crate::vhost::load_vhost_wordlist(&args) {
                Ok(vhosts) => {
                    out.info(&format!(
                        "Probing {} vhosts on {} (base: {})",
                        vhosts.len(),
                        cfg.base_domain,
                        if cfg.ip_override.is_some() {
                            "IP override"
                        } else {
                            "DNS"
                        }
                    ));
                    for entry in vhosts {
                        if should_stop(start, maxtime, scan_limit, &out)
                            || cancel.load(Ordering::SeqCst)
                        {
                            break;
                        }
                        let host_key = format!("vhost:{}", cfg.host_for_entry(&entry));
                        if dupes.seen_path(&host_key) {
                            continue;
                        }
                        dupes.mark_path(&host_key);
                        limiter.wait_turn().await;
                        out.stats.requests.fetch_add(1, Ordering::Relaxed);
                        if let Some(mut analyzed) = crate::vhost::probe_vhost(
                            &http,
                            &cfg,
                            &entry,
                            &analyzer,
                            &headers,
                            vhost_baseline.as_ref(),
                            args.filter_similar,
                        )
                        .await
                        {
                            handle_result(
                                &mut analyzed,
                                None,
                                &filters,
                                &analyzer,
                                profile.soft_404_baseline.as_ref(),
                                &dupes,
                                &out,
                                &discoveries,
                                args.show_filtered,
                            )
                            .await;
                        }
                    }
                }
                Err(e) => out.warn(&format!("VHost wordlist: {e}")),
            }
        }

        // Fingerprint interesting paths
        for path in &profile.interesting_paths {
            if should_stop(start, maxtime, scan_limit, &out) || cancel.load(Ordering::SeqCst) {
                break;
            }
            if dupes.seen_path(path) {
                continue;
            }
            dupes.mark_path(path);
            probe_one(
                &http,
                &headers,
                path,
                0,
                DiscoverySource::Fingerprint,
                ScanStage::Fingerprint,
                &analyzer,
                &filters,
                &dupes,
                &out,
                &discoveries,
                &limiter,
                &cancel,
                args.show_filtered,
                args.is_spider(),
                &collected_exts,
                args.collect_extensions,
            )
            .await;
        }

        // JS + source maps
        let mut js_paths = Vec::new();
        if !args.skip_js && !profile.js_files.is_empty() && !resume_skip_stages(&state) {
            out.stage(1, "JavaScript & Source Map Analysis");
            let js = JsAnalyzer::new(http.clone(), headers.clone());
            match js.analyze(&profile.js_files).await {
                Ok(analysis) => {
                    out.info(&format!(
                        "JS: {} files, {} endpoints, {} source maps",
                        analysis.files_analyzed,
                        analysis.endpoints.len(),
                        analysis.source_maps.len()
                    ));
                    js_paths = analysis.endpoints.clone();
                    for path in &analysis.endpoints {
                        if should_stop(start, maxtime, scan_limit, &out)
                            || cancel.load(Ordering::SeqCst)
                        {
                            break;
                        }
                        if dupes.seen_path(path) {
                            continue;
                        }
                        dupes.mark_path(path);
                        probe_one(
                            &http,
                            &headers,
                            path,
                            0,
                            DiscoverySource::JavaScript,
                            ScanStage::Fingerprint,
                            &analyzer,
                            &filters,
                            &dupes,
                            &out,
                            &discoveries,
                            &limiter,
                            &cancel,
                            args.show_filtered,
                            args.is_spider(),
                            &collected_exts,
                            args.collect_extensions,
                        )
                        .await;
                    }
                }
                Err(e) => out.warn(&format!("JS analysis error: {e}")),
            }
        }

        // API + OpenAPI + GraphQL
        if !resume_skip_stages(&state) {
            out.stage(1, "API / OpenAPI / GraphQL Discovery");
            let api = ApiDiscoveryEngine::new(
                http.clone(),
                headers.clone(),
                analyzer.with_same_baseline(),
            );
            if let Ok(api_result) = api.discover(&profile).await {
                out.info(&format!(
                    "API: {} hits, {} OpenAPI paths",
                    api_result.endpoints.len(),
                    api_result.openapi_paths.len()
                ));
                for mut analyzed in api_result.endpoints {
                    out.stats.requests.fetch_add(1, Ordering::Relaxed);
                    if !dupes.seen_path(&analyzed.path) {
                        dupes.mark_path(&analyzed.path);
                    }
                    handle_result(
                        &mut analyzed,
                        None,
                        &filters,
                        &analyzer,
                        profile.soft_404_baseline.as_ref(),
                        &dupes,
                        &out,
                        &discoveries,
                        args.show_filtered,
                    )
                    .await;
                }
                for path in &api_result.openapi_paths {
                    js_paths.push(path.clone());
                }
            }
            if !args.skip_graphql {
                if let Ok(fields) = api.introspect_graphql().await {
                    if !fields.is_empty() {
                        out.info(&format!("GraphQL introspection → {} fields", fields.len()));
                        for path in fields {
                            if dupes.seen_path(&path) {
                                continue;
                            }
                            dupes.mark_path(&path);
                            probe_one(
                                &http,
                                &headers,
                                &path,
                                0,
                                DiscoverySource::Graphql,
                                ScanStage::Api,
                                &analyzer,
                                &filters,
                                &dupes,
                                &out,
                                &discoveries,
                                &limiter,
                                &cancel,
                                args.show_filtered,
                                false,
                                &collected_exts,
                                false,
                            )
                            .await;
                        }
                    }
                }
            }
        }

        // Plugins
        let mut plugins = PluginEngine::new();
        if let Some(dir) = &args.plugins {
            match plugins.load_dir(dir) {
                Ok(n) if n > 0 => out.info(&format!(
                    "Loaded {} plugins: {}",
                    n,
                    plugins.names().join(", ")
                )),
                Ok(_) => {}
                Err(e) => out.warn(&format!("Plugin load error: {e}")),
            }
        }

        // Build wordlist
        let mut wl = WordlistEngine::new(args.wordlist_cap());
        let mut tech_lists_loaded = 0usize;

        if args.is_auto_wordlist() && !wordlist_recommendations.is_empty() {
            let fetcher = WordlistFetcher::new(Some(args.wordlist_cache.clone()))?;
            for rec in &wordlist_recommendations {
                match fetcher
                    .resolve(
                        rec,
                        args.wordlist_dir.as_deref(),
                        args.allow_wordlist_download(),
                    )
                    .await
                {
                    Ok(path) => match wl.load_file(&path, rec.priority) {
                        Ok(n) => {
                            tech_lists_loaded += 1;
                            out.info(&format!(
                                "Loaded {} — {} entries (priority {})",
                                rec.name, n, rec.priority
                            ));
                        }
                        Err(e) => out.warn(&format!("Load {}: {e}", rec.name)),
                    },
                    Err(e) => out.warn(&format!(
                        "{}: {e} (embedded tech paths still apply)",
                        rec.name
                    )),
                }
            }
        }

        let tech_focused =
            tech_lists_loaded > 0 && should_use_tech_focus(&profile, &wordlist_recommendations);
        if tech_focused {
            out.info("Tech-focused mode — skipping heavy embedded generic lists");
            wl.from_profile_focused(&profile);
        } else {
            wl.from_profile(&profile);
        }
        wl.add_js_paths(&js_paths);
        for (path, prio) in plugins.all_paths() {
            wl.insert(&path, prio, "plugin");
        }
        for path in &args.wordlist {
            match wl.load_file(path, 55) {
                Ok(n) => out.info(&format!("Loaded {} entries from {}", n, path.display())),
                Err(e) => out.warn(&format!("Wordlist {}: {e}", path.display())),
            }
        }

        // Extensions from CLI + tech detection + collected
        let mut exts = args.extensions.clone();
        if exts.is_empty() {
            let tech_exts = extensions_for_tech(&profile);
            if !tech_exts.is_empty() {
                out.info(&format!(
                    "Auto extensions from tech: {}",
                    tech_exts.join(",")
                ));
                exts = tech_exts;
            }
        }
        if args.collect_extensions {
            let collected = collected_exts.lock().await.clone();
            for e in collected {
                if !exts.iter().any(|x| x.eq_ignore_ascii_case(&e)) {
                    exts.push(e);
                }
            }
            for e in wl.collect_ext_from_paths() {
                if !exts.iter().any(|x| x.eq_ignore_ascii_case(&e)) {
                    exts.push(e);
                }
            }
        }
        if !exts.is_empty() {
            out.info(&format!("Extensions: {}", exts.join(",")));
            wl.apply_extensions(&exts);
        }

        let max_depth = args.effective_depth();
        let recursive = args.is_recursive();
        let fuzz_slots = http.fuzz_slot_count();

        // Multi-FUZZ template scan (FUZZ + FUZZ2 + … with multiple wordlists)
        if fuzz_slots > 1 {
            out.stage(2, "Multi-FUZZ Template Scan");
            run_multi_fuzz(
                &http,
                &headers,
                &analyzer,
                &filters,
                &dupes,
                &out,
                &discoveries,
                &limiter,
                &cancel,
                &args,
                fuzz_slots,
                &wl,
                start,
                maxtime,
                scan_limit,
                profile.soft_404_baseline.as_ref(),
            )
            .await?;
        }

        // Resume queue or build staged queues
        let mut queue: VecDeque<QueueItem> = if !state.queue.is_empty() {
            out.info(&format!("Resuming with {} queued paths", state.queue.len()));
            state.queue.clone().into()
        } else {
            VecDeque::new()
        };

        // ── Stage 2: Directory fuzzing ────────────────────────────────
        if state.stage < 2 && queue.is_empty() {
            out.stage(2, "Directory Fuzzing");
            let dirs = wl.directory_entries();
            out.info(&format!("{} directory candidates", dirs.len()));
            enqueue_entries(&mut queue, &dirs, 1, "directory", &dupes);
            state.stage = 2;
        }

        run_queue(
            &mut queue,
            &http,
            &headers,
            &analyzer,
            &filters,
            &dupes,
            &out,
            &discoveries,
            &limiter,
            &cancel,
            &args,
            &mut state,
            start,
            maxtime,
            scan_limit,
            max_depth,
            recursive,
            &collected_exts,
            profile.soft_404_baseline.as_ref(),
        )
        .await?;

        // ── Stage 3: File / extension fuzzing ─────────────────────────
        if !cancel.load(Ordering::SeqCst)
            && !should_stop(start, maxtime, scan_limit, &out)
            && state.stage < 3
        {
            out.stage(3, "File & Extension Discovery");
            let files = wl.file_entries();
            // Also expand top directory discoveries with extensions
            let disc = discoveries.lock().await.clone();
            let mut extra = Vec::new();
            for d in disc.iter().filter(|d| looks_like_directory(d)).take(100) {
                for e in expand_with_extensions(d.path.trim_start_matches('/'), &exts) {
                    extra.push(WordEntry {
                        path: format!("/{}", e.trim_start_matches('/')),
                        priority: 65,
                        source: "extension".into(),
                    });
                }
            }
            out.info(&format!(
                "{} file candidates (+ {} extension expansions)",
                files.len(),
                extra.len()
            ));
            enqueue_entries(&mut queue, &files, 1, "file", &dupes);
            enqueue_entries(&mut queue, &extra, 1, "file", &dupes);
            state.stage = 3;

            run_queue(
                &mut queue,
                &http,
                &headers,
                &analyzer,
                &filters,
                &dupes,
                &out,
                &discoveries,
                &limiter,
                &cancel,
                &args,
                &mut state,
                start,
                maxtime,
                scan_limit,
                max_depth,
                recursive,
                &collected_exts,
                profile.soft_404_baseline.as_ref(),
            )
            .await?;
        }

        // ── Stage 4: Deep API + recursive expansion ───────────────────
        if !cancel.load(Ordering::SeqCst)
            && !should_stop(start, maxtime, scan_limit, &out)
            && state.stage < 4
        {
            out.stage(4, "Deep API & Recursive Expansion");
            let apis = wl.api_entries();
            enqueue_entries(&mut queue, &apis, 1, "api", &dupes);
            state.stage = 4;

            run_queue(
                &mut queue,
                &http,
                &headers,
                &analyzer,
                &filters,
                &dupes,
                &out,
                &discoveries,
                &limiter,
                &cancel,
                &args,
                &mut state,
                start,
                maxtime,
                scan_limit,
                max_depth,
                recursive,
                &collected_exts,
                profile.soft_404_baseline.as_ref(),
            )
            .await?;
        }

        cancel.store(true, Ordering::SeqCst);

        let final_discoveries = discoveries.lock().await.clone();
        state.discoveries = final_discoveries.clone();
        state.completed_paths = dupes.all_paths();
        state.queue.clear();
        save_state(&args.state_file, &state)?;

        out.stats
            .retries
            .store(limiter.retries(), Ordering::Relaxed);
        out.finish();

        let result = ScanResult {
            profile,
            discoveries: final_discoveries,
            stats: ScanStats {
                requests: out.stats.requests.load(Ordering::Relaxed),
                discovered: out.stats.discovered.load(Ordering::Relaxed),
                filtered: out.stats.filtered.load(Ordering::Relaxed),
                retries: out.stats.retries.load(Ordering::Relaxed),
                duration_secs: start.elapsed().as_secs_f64(),
            },
        };

        let reporter = ReportBuilder::new(&result);
        let mut default_report: Option<String> = None;
        if let Some(path) = &args.json {
            reporter.write_json(path)?;
            out.info(&format!("JSON report → {}", path.display()));
        }
        if let Some(path) = &args.html {
            reporter.write_html(path)?;
            out.info(&format!("HTML report → {}", path.display()));
        }
        if let Some(path) = &args.markdown {
            reporter.write_markdown(path)?;
            out.info(&format!("Markdown report → {}", path.display()));
        }
        if let Some(path) = &args.csv {
            reporter.write_csv(path)?;
            out.info(&format!("CSV report → {}", path.display()));
        }
        if let Some(path) = &args.ffuf_json {
            reporter.write_ffuf_json(path)?;
            out.info(&format!("ffuf JSON report → {}", path.display()));
        }
        if args.json.is_none()
            && args.html.is_none()
            && args.markdown.is_none()
            && args.csv.is_none()
            && args.ffuf_json.is_none()
        {
            let default = Path::new("smartfuzz-report.json");
            reporter.write_json(default)?;
            default_report = Some(default.display().to_string());
            if !args.silent {
                println!("  Report → {}", default.display());
            }
        }

        out.emit_complete(result.stats.clone(), default_report);

        Ok(result)
    }
}

fn resume_skip_stages(state: &ScanState) -> bool {
    // If we already progressed past stage 1 with discoveries, skip re-probing JS/API
    state.stage >= 2 && !state.completed_paths.is_empty()
}

fn timed_out(start: Instant, maxtime: u64) -> bool {
    maxtime > 0 && start.elapsed().as_secs() >= maxtime
}

fn scan_limit_reached(out: &Output, scan_limit: u64) -> bool {
    scan_limit > 0 && out.stats.requests.load(Ordering::Relaxed) >= scan_limit
}

fn should_stop(start: Instant, maxtime: u64, scan_limit: u64, out: &Output) -> bool {
    timed_out(start, maxtime) || scan_limit_reached(out, scan_limit)
}

fn enqueue_entries(
    queue: &mut VecDeque<QueueItem>,
    entries: &[WordEntry],
    depth: u32,
    stage: &str,
    dupes: &DuplicateDetector,
) {
    let mut items: Vec<_> = entries
        .iter()
        .filter(|e| !dupes.seen_path(&e.path))
        .map(|e| QueueItem {
            path: e.path.clone(),
            depth,
            source: e.source.clone(),
            priority: e.priority,
            stage: stage.to_string(),
        })
        .collect();
    items.sort_by_key(|b| std::cmp::Reverse(b.priority));
    for i in items {
        queue.push_back(i);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_queue(
    queue: &mut VecDeque<QueueItem>,
    http: &HttpEngine,
    headers: &[(String, String)],
    analyzer: &ResponseAnalyzer,
    filters: &SmartFilters,
    dupes: &DuplicateDetector,
    out: &Output,
    discoveries: &Arc<Mutex<Vec<AnalyzedResponse>>>,
    limiter: &AdaptiveRateLimiter,
    cancel: &Arc<AtomicBool>,
    args: &Args,
    state: &mut ScanState,
    start: Instant,
    maxtime: u64,
    scan_limit: u64,
    max_depth: u32,
    recursive: bool,
    collected_exts: &Arc<Mutex<Vec<String>>>,
    baseline: Option<&crate::fingerprint::Soft404Baseline>,
) -> Result<()> {
    let mut save_counter = 0u64;

    while !queue.is_empty()
        && !cancel.load(Ordering::SeqCst)
        && !should_stop(start, maxtime, scan_limit, out)
    {
        let batch_size = args.effective_threads() * 2;
        let mut batch = Vec::new();
        while batch.len() < batch_size {
            if let Some(item) = queue.pop_front() {
                if dupes.seen_path(&item.path) {
                    continue;
                }
                if item.depth > max_depth {
                    continue;
                }
                dupes.mark_path(&item.path);
                batch.push(item);
            } else {
                break;
            }
        }
        if batch.is_empty() {
            break;
        }

        let mut futs = FuturesUnordered::new();
        let sem = limiter.semaphore();

        for item in batch {
            let http = http.clone();
            let headers = headers.to_vec();
            let analyzer = analyzer.with_same_baseline();
            let limiter = limiter.clone();
            let cancel = cancel.clone();
            let sem = sem.clone();
            let stats = out.stats.clone();

            futs.push(async move {
                if cancel.load(Ordering::SeqCst) {
                    return None;
                }
                let _permit = sem.acquire().await.ok()?;
                limiter.wait_turn().await;

                stats.requests.fetch_add(1, Ordering::Relaxed);
                stats.depth.fetch_max(item.depth as u64, Ordering::Relaxed);
                stats
                    .workers
                    .store(limiter.current_cap() as u64, Ordering::Relaxed);

                let result = limiter
                    .with_retry(3, || async {
                        http.fuzz_entry(&item.path, &headers)
                            .await
                            .map_err(|e| std::io::Error::other(e.to_string()))
                    })
                    .await;

                match result {
                    Ok(resp) => {
                        if resp.status == 429 {
                            limiter.on_rate_limited();
                        } else {
                            limiter.on_success();
                        }
                        let source = source_from_str(&item.source);
                        let stage = stage_from_str(&item.stage);
                        let analyzed =
                            analyzer.analyze_staged(&resp, &item.path, item.depth, source, stage);
                        let body = body_for_filter(&resp);
                        Some((item, analyzed, body, resp.is_html(), resp.url.clone()))
                    }
                    Err(_) => None,
                }
            });
        }

        let mut new_dirs = Vec::new();
        let mut spider_paths = Vec::new();

        while let Some(opt) = futs.next().await {
            let Some((item, mut analyzed, body, is_html, req_url)) = opt else {
                continue;
            };

            let kept = handle_result(
                &mut analyzed,
                Some(&body),
                filters,
                analyzer,
                baseline,
                dupes,
                out,
                discoveries,
                args.show_filtered,
            )
            .await;

            if kept {
                if args.collect_extensions {
                    if let Some(ext) = file_ext(&analyzed.path) {
                        let mut c = collected_exts.lock().await;
                        if !c.iter().any(|x| x == &ext) {
                            c.push(ext);
                        }
                    }
                }
                if recursive && looks_like_directory(&analyzed) && item.depth < max_depth {
                    new_dirs.push((analyzed.path.clone(), item.depth));
                }
                if args.is_spider() && is_html {
                    if let Ok(base) = url::Url::parse(&req_url) {
                        for p in extract_links(&body, &base) {
                            spider_paths.push(p);
                        }
                    }
                }
            }
            out.refresh_bar();
        }

        // Recursive children
        if recursive {
            for (dir, depth) in new_dirs {
                for child in recursive_children(&dir) {
                    let path = format!(
                        "{}/{}",
                        dir.trim_end_matches('/'),
                        child.trim_start_matches('/')
                    );
                    if !dupes.seen_path(&path) {
                        queue.push_back(QueueItem {
                            path,
                            depth: depth + 1,
                            source: "recursive".into(),
                            priority: 70,
                            stage: "recursive".into(),
                        });
                    }
                }
            }
        }

        // Spider links
        for path in spider_paths {
            if !dupes.seen_path(&path) {
                queue.push_back(QueueItem {
                    path,
                    depth: 1,
                    source: "spider".into(),
                    priority: 95,
                    stage: "spider".into(),
                });
            }
        }

        save_counter += 1;
        if save_counter.is_multiple_of(5) {
            state.discoveries = discoveries.lock().await.clone();
            state.queue = queue.iter().cloned().collect();
            state.completed_paths = dupes.all_paths();
            let _ = save_state(&args.state_file, state);
        }
    }

    state.discoveries = discoveries.lock().await.clone();
    state.completed_paths = dupes.all_paths();
    let _ = save_state(&args.state_file, state);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn probe_one(
    http: &HttpEngine,
    headers: &[(String, String)],
    path: &str,
    depth: u32,
    source: DiscoverySource,
    stage: ScanStage,
    analyzer: &ResponseAnalyzer,
    filters: &SmartFilters,
    dupes: &DuplicateDetector,
    out: &Output,
    discoveries: &Arc<Mutex<Vec<AnalyzedResponse>>>,
    limiter: &AdaptiveRateLimiter,
    cancel: &Arc<AtomicBool>,
    show_filtered: bool,
    spider: bool,
    collected_exts: &Arc<Mutex<Vec<String>>>,
    collect_ext: bool,
) {
    if cancel.load(Ordering::SeqCst) {
        return;
    }
    limiter.wait_turn().await;
    out.stats.requests.fetch_add(1, Ordering::Relaxed);

    let Ok(resp) = http.fuzz_entry(path, headers).await else {
        return;
    };
    if resp.status == 429 {
        limiter.on_rate_limited();
    } else {
        limiter.on_success();
    }

    let mut analyzed = analyzer.analyze_staged(&resp, path, depth, source, stage);
    out.emit_request(&analyzed);
    let body = body_for_filter(&resp);
    let kept = handle_result(
        &mut analyzed,
        Some(&body),
        filters,
        analyzer,
        analyzer.get_soft404().as_ref(),
        dupes,
        out,
        discoveries,
        show_filtered,
    )
    .await;

    if kept {
        if collect_ext {
            if let Some(ext) = file_ext(path) {
                let mut c = collected_exts.lock().await;
                if !c.iter().any(|x| x == &ext) {
                    c.push(ext);
                }
            }
        }
        if spider && resp.is_html() {
            if let Ok(base) = url::Url::parse(&resp.url) {
                for p in extract_links(&body, &base) {
                    if !dupes.seen_path(&p) {
                        // Enqueue via discoveries side-channel: probe immediately for high-prio
                        dupes.mark_path(&p);
                        // Fire and forget lightweight — schedule as discovery seed
                        if let Ok(r2) = http.fuzz_entry(&p, headers).await {
                            out.stats.requests.fetch_add(1, Ordering::Relaxed);
                            let mut a2 = analyzer.analyze_staged(
                                &r2,
                                &p,
                                depth,
                                DiscoverySource::Spider,
                                ScanStage::Spider,
                            );
                            let b2 = body_for_filter(&r2);
                            let _ = handle_result(
                                &mut a2,
                                Some(&b2),
                                filters,
                                analyzer,
                                analyzer.get_soft404().as_ref(),
                                dupes,
                                out,
                                discoveries,
                                show_filtered,
                            )
                            .await;
                        }
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_result(
    analyzed: &mut AnalyzedResponse,
    body: Option<&str>,
    filters: &SmartFilters,
    analyzer: &ResponseAnalyzer,
    baseline: Option<&crate::fingerprint::Soft404Baseline>,
    dupes: &DuplicateDetector,
    out: &Output,
    discoveries: &Arc<Mutex<Vec<AnalyzedResponse>>>,
    show_filtered: bool,
) -> bool {
    if dupes.check_duplicate(analyzed, Some(analyzer)) {
        out.stats.filtered.fetch_add(1, Ordering::Relaxed);
        analyzed.filtered = true;
        analyzed.filter_reason = Some("duplicate".into());
        out.emit_filtered(analyzed, "duplicate");
        if show_filtered {
            out.print_result(analyzed);
        }
        return false;
    }

    match filters.apply_with_body(analyzed, body, Some(analyzer), baseline) {
        FilterDecision::Keep => {
            out.stats.discovered.fetch_add(1, Ordering::Relaxed);
            out.emit_discovery(analyzed);
            out.print_result(analyzed);
            discoveries.lock().await.push(analyzed.clone());
            true
        }
        FilterDecision::ShowFiltered => {
            out.stats.filtered.fetch_add(1, Ordering::Relaxed);
            let reason = analyzed
                .filter_reason
                .clone()
                .unwrap_or_else(|| "filtered".into());
            out.emit_filtered(analyzed, &reason);
            out.print_result(analyzed);
            false
        }
        FilterDecision::Hide => {
            out.stats.filtered.fetch_add(1, Ordering::Relaxed);
            let reason = analyzed
                .filter_reason
                .clone()
                .unwrap_or_else(|| "hidden".into());
            out.emit_filtered(analyzed, &reason);
            false
        }
    }
}

fn source_from_str(s: &str) -> DiscoverySource {
    match s {
        "javascript" | "javascript-expand" => DiscoverySource::JavaScript,
        "api" => DiscoverySource::Api,
        "robots" => DiscoverySource::Robots,
        "sitemap" => DiscoverySource::Sitemap,
        "recursive" => DiscoverySource::Recursive,
        "fingerprint" => DiscoverySource::Fingerprint,
        "plugin" => DiscoverySource::Plugin,
        "spider" => DiscoverySource::Spider,
        "extension" => DiscoverySource::Extension,
        "openapi" => DiscoverySource::OpenApi,
        "graphql" => DiscoverySource::Graphql,
        "sourcemap" => DiscoverySource::SourceMap,
        _ => DiscoverySource::Wordlist,
    }
}

fn stage_from_str(s: &str) -> ScanStage {
    match s {
        "file" => ScanStage::File,
        "api" => ScanStage::Api,
        "recursive" => ScanStage::Recursive,
        "spider" => ScanStage::Spider,
        "fingerprint" => ScanStage::Fingerprint,
        _ => ScanStage::Directory,
    }
}

fn file_ext(path: &str) -> Option<String> {
    let last = path.rsplit('/').next()?;
    let (_, ext) = last.rsplit_once('.')?;
    if ext.is_empty() || ext.len() > 8 {
        return None;
    }
    if ext.chars().all(|c| c.is_ascii_alphanumeric()) {
        Some(ext.to_ascii_lowercase())
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_multi_fuzz(
    http: &HttpEngine,
    headers: &[(String, String)],
    analyzer: &ResponseAnalyzer,
    filters: &SmartFilters,
    dupes: &DuplicateDetector,
    out: &Output,
    discoveries: &Arc<Mutex<Vec<AnalyzedResponse>>>,
    limiter: &AdaptiveRateLimiter,
    cancel: &Arc<AtomicBool>,
    args: &Args,
    fuzz_slots: usize,
    wl: &WordlistEngine,
    start: Instant,
    maxtime: u64,
    scan_limit: u64,
    baseline: Option<&crate::fingerprint::Soft404Baseline>,
) -> Result<()> {
    let mut lists: Vec<Vec<String>> = Vec::new();

    if !args.wordlist.is_empty() {
        lists = load_wordlist_paths(&args.wordlist)?;
        if lists.len() < fuzz_slots {
            out.warn(&format!(
                "Multi-FUZZ: {} slots but {} wordlist(s) — reusing last list for missing slots",
                fuzz_slots,
                lists.len()
            ));
            while lists.len() < fuzz_slots {
                if let Some(last) = lists.last().cloned() {
                    lists.push(last);
                } else {
                    break;
                }
            }
        }
        lists.truncate(fuzz_slots);
    }

    if lists.is_empty() {
        let entries: Vec<String> = wl
            .prioritized()
            .iter()
            .map(|e| e.path.trim_start_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if entries.is_empty() {
            out.warn("Multi-FUZZ: no wordlist entries — skipping template scan");
            return Ok(());
        }
        let chunk = (entries.len() / fuzz_slots).max(1);
        for i in 0..fuzz_slots {
            let begin = i * chunk;
            let end = ((i + 1) * chunk).min(entries.len());
            if begin < end {
                lists.push(entries[begin..end].to_vec());
            } else {
                lists.push(entries.clone());
            }
        }
    }

    let cap = args.wordlist_cap();
    let combos = combine_wordlists(&lists, cap);
    out.info(&format!(
        "Multi-FUZZ: {} slot(s), {} combination(s) (cap {})",
        fuzz_slots,
        combos.len(),
        cap
    ));

    for combo in combos {
        if cancel.load(Ordering::SeqCst) || should_stop(start, maxtime, scan_limit, out) {
            break;
        }

        let path_key = combo.join("/");
        let display_path = format!("fuzz:{}", path_key);
        if dupes.seen_path(&display_path) {
            continue;
        }
        dupes.mark_path(&display_path);

        limiter.wait_turn().await;
        out.stats.requests.fetch_add(1, Ordering::Relaxed);

        let values: Vec<&str> = combo.iter().map(String::as_str).collect();
        let Ok(resp) = http.fuzz_values(&values, headers).await else {
            continue;
        };

        let mut analyzed = analyzer.analyze_staged(
            &resp,
            &display_path,
            0,
            DiscoverySource::Wordlist,
            ScanStage::Directory,
        );
        let body = body_for_filter(&resp);
        handle_result(
            &mut analyzed,
            Some(&body),
            filters,
            analyzer,
            baseline,
            dupes,
            out,
            discoveries,
            args.show_filtered,
        )
        .await;
        out.refresh_bar();
    }

    Ok(())
}

fn empty_state(url: &str) -> ScanState {
    ScanState {
        url: url.to_string(),
        completed_paths: Vec::new(),
        discoveries: Vec::new(),
        queue: Vec::new(),
        profile: None,
        stage: 0,
    }
}

fn save_state(path: &Path, state: &ScanState) -> Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    fs::write(path, json)?;
    Ok(())
}

fn load_state(path: &Path) -> Result<ScanState> {
    let data = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}
