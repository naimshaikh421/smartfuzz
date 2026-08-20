#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UI="$(cd "$(dirname "$0")" && pwd)"

echo "==> Building SmartFuzz engine…"
(cd "$ROOT" && cargo build --release)

echo "==> Installing UI dependencies…"
(cd "$UI/web" && npm install --silent)

echo "==> Building UI…"
(cd "$UI/web" && npm run build)

echo "==> Starting SmartFuzz UI on http://127.0.0.1:${SMARTFUZZ_UI_PORT:-8787}/"
cd "$UI"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
else
  .venv/bin/pip install -q -r requirements.txt
fi
exec .venv/bin/python server.py
