# SmartFuzz

[![CI](https://github.com/naimshaikh421/smartfuzz/actions/workflows/ci.yml/badge.svg)](https://github.com/naimshaikh421/smartfuzz/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**100% free & open source** — MIT licensed, no paid APIs, no cloud dependencies, no telemetry. Runs entirely on your machine with free Rust crates only.

Intelligent, adaptive web content discovery for **authorized** security testing.

## Requirements

| Component | Version |
|-----------|---------|
| Rust | 1.75+ (stable) |
| Node.js | 18+ (UI only) |
| Python | 3.10+ (UI server only) |

## Quick start

```bash
git clone https://github.com/naimshaikh421/smartfuzz.git
cd smartfuzz
cargo build --release

# CLI scan
./target/release/smartfuzz -u https://target.example

# Web UI (transparent live dashboard)
./ui/start.sh
# → http://127.0.0.1:8787/
```

## Features

- **Adaptive fingerprinting** — tech-aware wordlist selection (SecLists, local cache, embedded paths)
- **Multi-FUZZ** — `FUZZ`, `FUZZ2`, `FUZZ3`, `FUZZ4` in URL/body/headers
- **Soft-404 / wildcard filtering** — auto-calibration like ffuf `-ac`
- **Recursive discovery** — dirs → files → API → JS/source maps
- **VHost fuzzing** — Host-header discovery (no external services)
- **Reports** — JSON, HTML, Markdown, CSV, ffuf-compatible JSON
- **Web UI** — full transparency: every request, filter reason, and discovery streamed live

## SmartFuzz Web UI

```bash
./ui/start.sh
```

Open **http://127.0.0.1:8787/**

The UI streams NDJSON events and shows live stats, fingerprint profile, wordlist picks, discoveries (full clickable URLs), filtered responses with reasons, and all requests.

```bash
# Automation / CI integration
./target/release/smartfuzz -u https://target.example \
  --silent --json-events events.ndjson --json report.json
```

## CLI examples

```bash
# Standard scan
./target/release/smartfuzz -u https://target.example

# ffuf-style FUZZ
./target/release/smartfuzz -u https://target.example/FUZZ -w wordlists/extra.txt

# Recommend wordlists only (no fuzz traffic)
./target/release/smartfuzz -u https://target.example --recommend-only

# VHost discovery
./target/release/smartfuzz -u https://target.example --vhost --vhost-ip 1.2.3.4

# Limit total HTTP requests
./target/release/smartfuzz -u https://target.example --scan-limit 5000
```

## Tech-based wordlists

SmartFuzz fingerprints first, then picks wordlists:

| Flag | Description |
|------|-------------|
| `--auto-wordlist` | Pick lists from detected tech (default: on) |
| `--recommend-only` | Fingerprint + show picks, no fuzz |
| `--download-wordlists` | Fetch missing lists from GitHub SecLists |
| `--wordlist-dir` | Local SecLists path |
| `--no-auto-wordlist` | Manual `-w` only |

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cd ui/web && npm ci && npm run build
```

## Production notes

- Use `--scan-limit` and `--rate-limit` on shared infrastructure
- Run with `--recommend-only` first to validate scope and wordlist picks
- UI stores scan artifacts under `ui/runs/` (gitignored)
- See [SECURITY.md](SECURITY.md) for vulnerability reporting

## Legal

Use only on systems you are **authorized** to test. Unauthorized scanning may violate computer misuse laws.

## License

MIT — see [LICENSE](LICENSE).
