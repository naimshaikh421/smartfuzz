import type { ScanConfig, ScanEvent, ScanSummary } from "./types";

const API = "/api";

export async function getHealth() {
  const r = await fetch(`${API}/health`);
  if (!r.ok) throw new Error("Health check failed");
  return r.json();
}

export async function listScans(): Promise<{ items: ScanSummary[] }> {
  const r = await fetch(`${API}/scans`);
  if (!r.ok) throw new Error("Failed to list scans");
  return r.json();
}

export async function startScan(config: ScanConfig): Promise<ScanSummary> {
  const r = await fetch(`${API}/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    throw new Error(err.detail ?? "Failed to start scan");
  }
  return r.json();
}

export async function stopScan(id: string) {
  const r = await fetch(`${API}/scans/${id}/stop`, { method: "POST" });
  if (!r.ok) throw new Error("Failed to stop scan");
  return r.json();
}

export function subscribeEvents(
  scanId: string,
  after: number,
  onEvent: (evt: ScanEvent) => void,
  onEnd: (status: string) => void
): () => void {
  const es = new EventSource(`${API}/scans/${scanId}/events?after=${after}`);
  es.onmessage = (msg) => {
    try {
      const evt = JSON.parse(msg.data) as ScanEvent;
      if (evt.type === "stream_end") {
        onEnd(String(evt.status ?? "completed"));
        es.close();
        return;
      }
      onEvent(evt);
    } catch {
      /* ignore */
    }
  };
  es.onerror = () => es.close();
  return () => es.close();
}

export function statusClass(code: number): string {
  if (code >= 200 && code < 300) return "sc-2xx";
  if (code >= 300 && code < 400) return "sc-3xx";
  if (code >= 400 && code < 500) return "sc-4xx";
  if (code >= 500) return "sc-5xx";
  return "sc-other";
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

/** Resolve a full absolute URL for display and linking. */
export function resolveUrl(
  base: string,
  url?: string | null,
  path?: string | null
): string {
  const raw = (url ?? "").trim();
  if (raw.startsWith("http://") || raw.startsWith("https://")) return raw;

  const p = (path ?? "").trim();
  if (p.startsWith("http://") || p.startsWith("https://")) return p;

  if (!base) return raw || p;

  try {
    const origin = new URL(base).origin;
    if (raw) {
      return new URL(raw.startsWith("/") ? raw : `/${raw}`, origin).href;
    }
    if (p) {
      return new URL(p.startsWith("/") ? p : `/${p}`, origin).href;
    }
    return new URL(base).href;
  } catch {
    return raw || p || base;
  }
}
