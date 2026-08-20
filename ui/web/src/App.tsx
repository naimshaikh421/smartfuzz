import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  formatBytes,
  getHealth,
  startScan,
  statusClass,
  stopScan,
  subscribeEvents,
} from "./api";
import { UrlLink } from "./UrlLink";
import type {
  DiscoveryItem,
  ScanConfig,
  ScanEvent,
  ScanSummary,
  StatsEvent,
  TargetProfile,
  WordlistRec,
} from "./types";

const DEFAULT_CONFIG: ScanConfig = {
  url: "",
  mode: "balanced",
  recursive: true,
  scan_limit: 0,
  timeout: 10,
  show_filtered: true,
  auto_wordlist: true,
  recommend_only: false,
  vhost: false,
  verbose: false,
};

function useScanState() {
  const [stats, setStats] = useState<StatsEvent | null>(null);
  const [profile, setProfile] = useState<TargetProfile | null>(null);
  const [wordlists, setWordlists] = useState<WordlistRec[]>([]);
  const [techTags, setTechTags] = useState<string[]>([]);
  const [stages, setStages] = useState<{ stage: number; name: string; ts?: string }[]>([]);
  const [discoveries, setDiscoveries] = useState<DiscoveryItem[]>([]);
  const [filtered, setFiltered] = useState<(DiscoveryItem & { reason: string })[]>([]);
  const [requests, setRequests] = useState<DiscoveryItem[]>([]);
  const [log, setLog] = useState<{ level: string; message: string; ts?: string }[]>([]);
  const [calibration, setCalibration] = useState<{ signatures: number; probes: number } | null>(
    null
  );

  const reset = useCallback(() => {
    setStats(null);
    setProfile(null);
    setWordlists([]);
    setTechTags([]);
    setStages([]);
    setDiscoveries([]);
    setFiltered([]);
    setRequests([]);
    setLog([]);
    setCalibration(null);
  }, []);

  const ingest = useCallback((evt: ScanEvent) => {
    const ts = evt.ts as string | undefined;
    switch (evt.type) {
      case "stats":
        setStats(evt as unknown as StatsEvent);
        break;
      case "profile":
        setProfile((evt as unknown as { profile: TargetProfile }).profile);
        break;
      case "wordlists": {
        const w = evt as unknown as { recommendations: WordlistRec[]; tech_tags: string[] };
        setWordlists(w.recommendations ?? []);
        setTechTags(w.tech_tags ?? []);
        break;
      }
      case "calibration":
        setCalibration({
          signatures: Number(evt.signatures ?? 0),
          probes: Number(evt.probes ?? 0),
        });
        break;
      case "stage":
        setStages((prev) => [
          ...prev,
          { stage: Number(evt.stage), name: String(evt.name), ts },
        ]);
        break;
      case "info":
        setLog((prev) => [...prev.slice(-500), { level: "info", message: String(evt.message), ts }]);
        break;
      case "warn":
        setLog((prev) => [...prev.slice(-500), { level: "warn", message: String(evt.message), ts }]);
        break;
      case "request":
        setRequests((prev) => [
          ...prev.slice(-2000),
          {
            path: String(evt.path ?? ""),
            url: String(evt.url ?? ""),
            status: Number(evt.status ?? 0),
            size: Number(evt.size ?? 0),
            elapsed_ms: Number(evt.elapsed_ms ?? 0),
            stage: String(evt.stage ?? ""),
            redirect_target: (evt.redirect_target as string | null) ?? null,
            depth: 0,
            source: "",
          },
        ]);
        break;
      case "discovery":
        setDiscoveries((prev) => [...prev, (evt as unknown as { item: DiscoveryItem }).item]);
        break;
      case "filtered":
        setFiltered((prev) => [
          ...prev,
          {
            ...(evt as unknown as { item: DiscoveryItem }).item,
            reason: String((evt as unknown as { reason: string }).reason),
          },
        ]);
        break;
      default:
        break;
    }
  }, []);

  return {
    stats,
    profile,
    wordlists,
    techTags,
    stages,
    discoveries,
    filtered,
    requests,
    log,
    calibration,
    reset,
    ingest,
  };
}

export default function App() {
  const [config, setConfig] = useState<ScanConfig>(DEFAULT_CONFIG);
  const [health, setHealth] = useState<{ binary_exists?: boolean; binary?: string } | null>(null);
  const [active, setActive] = useState<ScanSummary | null>(null);
  const [status, setStatus] = useState<string>("idle");
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"discoveries" | "filtered" | "requests" | "log">("discoveries");

  const scan = useScanState();
  const unsub = useRef<(() => void) | null>(null);
  const discoveriesRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    getHealth().then(setHealth).catch(() => setHealth(null));
    return () => unsub.current?.();
  }, []);

  useEffect(() => {
    if (tab === "discoveries" && discoveriesRef.current) {
      discoveriesRef.current.scrollTop = discoveriesRef.current.scrollHeight;
    }
  }, [scan.discoveries.length, tab]);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!config.url.trim()) {
      setError("Target URL is required");
      return;
    }
    setError(null);
    scan.reset();
    unsub.current?.();
    try {
      const job = await startScan({ ...config, url: config.url.trim() });
      setActive(job);
      setStatus("running");
      unsub.current = subscribeEvents(
        job.id,
        0,
        (evt) => scan.ingest(evt),
        (endStatus) => setStatus(endStatus)
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Start failed");
    }
  };

  const onStop = async () => {
    if (!active) return;
    try {
      await stopScan(active.id);
      setStatus("cancelling");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Stop failed");
    }
  };

  const stats = scan.stats;
  const running = status === "running" || status === "cancelling";
  const targetUrl = active?.url ?? config.url.trim();

  const profileTech = useMemo(() => {
    if (!scan.profile) return [];
    const tags = new Set<string>();
    if (scan.profile.server) tags.add(scan.profile.server);
    if (scan.profile.powered_by) tags.add(scan.profile.powered_by);
    for (const t of scan.profile.favicon_tech ?? []) tags.add(t);
    if (scan.profile.graphql_detected) tags.add("GraphQL");
    for (const t of scan.techTags) tags.add(t);
    return [...tags];
  }, [scan.profile, scan.techTags]);

  return (
    <div className="app">
      <header className="hero">
        <div>
          <p className="eyebrow">Authorized testing only</p>
          <h1>SmartFuzz</h1>
          <p className="lead">
            Fully transparent adaptive fuzzing — every stage, request, filter, and discovery in real time.
          </p>
        </div>
        <div className="hero-meta">
          <span className={`pill ${health?.binary_exists ? "ok" : "bad"}`}>
            {health?.binary_exists ? "Engine ready" : "Build smartfuzz first"}
          </span>
          {active && <span className="pill status-pill">{status}</span>}
        </div>
      </header>

      <section className="panel scan-form">
        <h2>Start scan</h2>
        <form onSubmit={onSubmit} className="form-grid">
          <label className="span-2">
            Target URL
            <input
              type="url"
              placeholder="https://target.example"
              value={config.url}
              onChange={(e) => setConfig({ ...config, url: e.target.value })}
              disabled={running}
              required
            />
          </label>
          <label>
            Mode
            <select
              value={config.mode}
              onChange={(e) => setConfig({ ...config, mode: e.target.value as ScanConfig["mode"] })}
              disabled={running}
            >
              <option value="fast">Fast</option>
              <option value="balanced">Balanced</option>
              <option value="deep">Deep</option>
            </select>
          </label>
          <label>
            Threads
            <input
              type="number"
              min={1}
              max={500}
              placeholder="auto"
              value={config.threads ?? ""}
              onChange={(e) =>
                setConfig({
                  ...config,
                  threads: e.target.value ? Number(e.target.value) : undefined,
                })
              }
              disabled={running}
            />
          </label>
          <label>
            Scan limit
            <input
              type="number"
              min={0}
              value={config.scan_limit}
              onChange={(e) => setConfig({ ...config, scan_limit: Number(e.target.value) })}
              disabled={running}
            />
          </label>
          <label>
            Timeout (s)
            <input
              type="number"
              min={1}
              max={120}
              value={config.timeout}
              onChange={(e) => setConfig({ ...config, timeout: Number(e.target.value) })}
              disabled={running}
            />
          </label>
          <div className="checks span-2">
            <label><input type="checkbox" checked={config.recursive} onChange={(e) => setConfig({ ...config, recursive: e.target.checked })} disabled={running} /> Recursive</label>
            <label><input type="checkbox" checked={config.auto_wordlist} onChange={(e) => setConfig({ ...config, auto_wordlist: e.target.checked })} disabled={running} /> Auto wordlist</label>
            <label><input type="checkbox" checked={config.show_filtered} onChange={(e) => setConfig({ ...config, show_filtered: e.target.checked })} disabled={running} /> Show filtered (CLI)</label>
            <label><input type="checkbox" checked={config.recommend_only} onChange={(e) => setConfig({ ...config, recommend_only: e.target.checked })} disabled={running} /> Recommend only</label>
            <label><input type="checkbox" checked={config.vhost} onChange={(e) => setConfig({ ...config, vhost: e.target.checked })} disabled={running} /> VHost fuzz</label>
          </div>
          <div className="form-actions span-2">
            <button type="submit" className="btn primary" disabled={running || !health?.binary_exists}>
              {running ? "Scanning…" : "Start fuzzing"}
            </button>
            {running && (
              <button type="button" className="btn danger" onClick={onStop}>
                Stop
              </button>
            )}
          </div>
        </form>
        {error && <p className="error">{error}</p>}
      </section>

      {stats && (
        <section className="stats-row">
          {[
            ["Requests", stats.requests],
            ["Discovered", stats.discovered],
            ["Filtered", stats.filtered],
            ["Speed", `${stats.speed.toFixed(0)} req/s`],
            ["Depth", stats.depth],
            ["Workers", stats.workers],
            ["Elapsed", `${stats.elapsed_secs.toFixed(1)}s`],
          ].map(([label, value]) => (
            <div key={String(label)} className="stat-card">
              <span className="stat-label">{label}</span>
              <span className="stat-value">{value}</span>
            </div>
          ))}
        </section>
      )}

      <div className="grid-2">
        <section className="panel">
          <h2>Stages</h2>
          <ul className="stage-list">
            {scan.stages.length === 0 && <li className="muted">Waiting for scan…</li>}
            {scan.stages.map((s, i) => (
              <li key={`${s.stage}-${i}`}>
                <span className="stage-num">{s.stage}</span>
                <span>{s.name}</span>
                {s.ts && <time>{new Date(s.ts).toLocaleTimeString()}</time>}
              </li>
            ))}
          </ul>
          {scan.calibration && (
            <p className="hint">
              Calibration: {scan.calibration.signatures} wildcard signatures from {scan.calibration.probes} probes
            </p>
          )}
        </section>

        <section className="panel">
          <h2>Target profile</h2>
          {!scan.profile && <p className="muted">Fingerprint runs first…</p>}
          {scan.profile && (
            <dl className="profile-dl">
              <div><dt>URL</dt><dd><a href={scan.profile.url} target="_blank" rel="noreferrer">{scan.profile.url}</a></dd></div>
              {scan.profile.server && <div><dt>Server</dt><dd>{scan.profile.server}</dd></div>}
              {scan.profile.powered_by && <div><dt>Powered-By</dt><dd>{scan.profile.powered_by}</dd></div>}
              {profileTech.length > 0 && (
                <div><dt>Tech</dt><dd className="tags">{profileTech.map((t) => <span key={t} className="tag">{t}</span>)}</dd></div>
              )}
              {(scan.profile.cdn?.length ?? 0) > 0 && (
                <div><dt>CDN</dt><dd>{scan.profile.cdn!.join(", ")}</dd></div>
              )}
              {(scan.profile.waf?.length ?? 0) > 0 && (
                <div><dt>WAF</dt><dd>{scan.profile.waf!.join(", ")}</dd></div>
              )}
              <div><dt>Seeds</dt><dd>{scan.profile.robots_paths?.length ?? 0} robots · {scan.profile.interesting_paths?.length ?? 0} paths · {scan.profile.js_files?.length ?? 0} JS</dd></div>
            </dl>
          )}
        </section>
      </div>

      {scan.wordlists.length > 0 && (
        <section className="panel">
          <h2>Wordlist selection</h2>
          <table className="data-table">
            <thead>
              <tr><th>Name</th><th>Reason</th><th>Priority</th><th>Tech</th></tr>
            </thead>
            <tbody>
              {scan.wordlists.map((w) => (
                <tr key={w.id}>
                  <td>{w.name}</td>
                  <td className="muted">{w.reason}</td>
                  <td>{w.priority}</td>
                  <td>{w.tech_triggered.join(", ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="panel results-panel">
        <div className="tabs">
          <button type="button" className={tab === "discoveries" ? "active" : ""} onClick={() => setTab("discoveries")}>
            Discoveries ({scan.discoveries.length})
          </button>
          <button type="button" className={tab === "filtered" ? "active" : ""} onClick={() => setTab("filtered")}>
            Filtered ({scan.filtered.length})
          </button>
          <button type="button" className={tab === "requests" ? "active" : ""} onClick={() => setTab("requests")}>
            All requests ({scan.requests.length})
          </button>
          <button type="button" className={tab === "log" ? "active" : ""} onClick={() => setTab("log")}>
            Event log ({scan.log.length})
          </button>
        </div>

        {tab === "discoveries" && (
          <div className="table-wrap" ref={discoveriesRef}>
            <table className="data-table">
              <thead>
                <tr><th>Status</th><th>URL</th><th>Size</th><th>Time</th><th>Depth</th><th>Source</th></tr>
              </thead>
              <tbody>
                {scan.discoveries.length === 0 && (
                  <tr><td colSpan={6} className="muted">No discoveries yet</td></tr>
                )}
                {scan.discoveries.map((d, i) => (
                  <tr key={`${d.path}-${i}`}>
                    <td><span className={`badge ${statusClass(d.status)}`}>{d.status}</span></td>
                    <td className="path-cell">
                      <UrlLink base={targetUrl} url={d.url} path={d.path} redirect={d.redirect_target} />
                    </td>
                    <td>{formatBytes(d.size)}</td>
                    <td>{d.elapsed_ms}ms</td>
                    <td>{d.depth}</td>
                    <td>{d.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === "filtered" && (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr><th>Status</th><th>URL</th><th>Reason</th><th>Size</th></tr>
              </thead>
              <tbody>
                {scan.filtered.length === 0 && (
                  <tr><td colSpan={4} className="muted">No filtered responses yet</td></tr>
                )}
                {scan.filtered.map((d, i) => (
                  <tr key={`f-${d.path}-${i}`} className="row-dim">
                    <td><span className={`badge ${statusClass(d.status)}`}>{d.status}</span></td>
                    <td className="path-cell">
                      <UrlLink base={targetUrl} url={d.url} path={d.path} redirect={d.redirect_target} />
                    </td>
                    <td className="reason">{d.reason}</td>
                    <td>{formatBytes(d.size)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === "requests" && (
          <div className="table-wrap requests-wrap">
            <table className="data-table compact">
              <thead>
                <tr><th>Status</th><th>URL</th><th>Size</th><th>ms</th><th>Stage</th></tr>
              </thead>
              <tbody>
                {scan.requests.slice(-500).map((d, i) => (
                  <tr key={`r-${i}`}>
                    <td><span className={`badge ${statusClass(d.status)}`}>{d.status}</span></td>
                    <td className="path-cell">
                      <UrlLink base={targetUrl} url={d.url} path={d.path} redirect={d.redirect_target} />
                    </td>
                    <td>{formatBytes(d.size)}</td>
                    <td>{d.elapsed_ms}</td>
                    <td>{d.stage}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {scan.requests.length > 500 && (
              <p className="hint">Showing last 500 of {scan.requests.length} requests</p>
            )}
          </div>
        )}

        {tab === "log" && (
          <div className="log-wrap">
            {scan.log.map((l, i) => (
              <div key={i} className={`log-line ${l.level}`}>
                {l.ts && <time>{new Date(l.ts).toLocaleTimeString()}</time>}
                <span>{l.message}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <footer className="footer">
        SmartFuzz UI · events streamed live via NDJSON · {health?.binary ?? "binary not found"}
      </footer>
    </div>
  );
}
