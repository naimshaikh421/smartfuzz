export type ScanMode = "fast" | "balanced" | "deep";

export interface ScanConfig {
  url: string;
  mode: ScanMode;
  threads?: number;
  recursive: boolean;
  scan_limit: number;
  timeout: number;
  show_filtered: boolean;
  auto_wordlist: boolean;
  recommend_only: boolean;
  vhost: boolean;
  verbose: boolean;
}

export interface ScanSummary {
  id: string;
  url: string;
  status: string;
  created_at: number;
  started_at?: number | null;
  finished_at?: number | null;
  error?: string | null;
  config: ScanConfig;
  events_count: number;
  report_path?: string | null;
}

export interface StatsEvent {
  type: "stats";
  requests: number;
  discovered: number;
  filtered: number;
  retries: number;
  depth: number;
  workers: number;
  speed: number;
  elapsed_secs: number;
  ts?: string;
}

export interface DiscoveryItem {
  url: string;
  path: string;
  status: number;
  size: number;
  elapsed_ms: number;
  depth: number;
  source: string;
  stage: string;
  filtered?: boolean;
  filter_reason?: string | null;
  redirect_target?: string | null;
  content_type?: string | null;
}

export interface ScanEvent {
  ts?: string;
  type: string;
  [key: string]: unknown;
}

export interface TargetProfile {
  url: string;
  server?: string | null;
  powered_by?: string | null;
  compression?: string[];
  cdn?: string[];
  waf?: string[];
  graphql_detected?: boolean;
  favicon_tech?: string[];
  favicon_mmh3?: number | null;
  robots_paths?: string[];
  interesting_paths?: string[];
  js_files?: string[];
}

export interface WordlistRec {
  id: string;
  name: string;
  reason: string;
  priority: number;
  seclists_path: string;
  tech_triggered: string[];
}
