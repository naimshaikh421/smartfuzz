#!/usr/bin/env python3
"""SmartFuzz web UI server — spawns scans and streams NDJSON events via SSE."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
UI_DIR = Path(__file__).resolve().parent
WEB_DIST = UI_DIR / "web" / "dist"
RUNS_DIR = UI_DIR / "runs"
DEFAULT_BIN = ROOT / "target" / "release" / "smartfuzz"


def resolve_binary() -> Path:
    env = os.environ.get("SMARTFUZZ_BIN")
    if env:
        return Path(env)
    if DEFAULT_BIN.exists():
        return DEFAULT_BIN
    debug = ROOT / "target" / "debug" / "smartfuzz"
    if debug.exists():
        return debug
    return DEFAULT_BIN


@dataclass
class ScanJob:
    id: str
    url: str
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    process: subprocess.Popen[str] | None = None
    events_path: Path = field(default_factory=Path)
    report_path: Path = field(default_factory=Path)
    config: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "config": self.config,
            "events_count": len(self.events),
            "report_path": str(self.report_path) if self.report_path else None,
        }


class ScanStartRequest(BaseModel):
    url: str
    mode: str = Field(default="balanced", pattern="^(fast|balanced|deep)$")
    threads: int | None = Field(default=None, ge=1, le=500)
    recursive: bool = True
    scan_limit: int = Field(default=0, ge=0)
    timeout: int = Field(default=10, ge=1, le=120)
    show_filtered: bool = True
    auto_wordlist: bool = True
    recommend_only: bool = False
    vhost: bool = False
    verbose: bool = False


app = FastAPI(title="SmartFuzz UI", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scans: dict[str, ScanJob] = {}
SCANS_LOCK = asyncio.Lock()


def build_command(req: ScanStartRequest, events_path: Path, report_path: Path) -> list[str]:
    bin_path = resolve_binary()
    if not bin_path.exists():
        raise HTTPException(status_code=500, detail=f"smartfuzz binary not found at {bin_path}")

    cmd = [
        str(bin_path),
        "-u",
        req.url,
        "-m",
        req.mode,
        "--silent",
        "--json-events",
        str(events_path),
        "--json",
        str(report_path),
    ]
    if req.threads:
        cmd.extend(["-t", str(req.threads)])
    if not req.recursive:
        cmd.append("--no-recursive")
    if req.scan_limit:
        cmd.extend(["--scan-limit", str(req.scan_limit)])
    if req.timeout != 10:
        cmd.extend(["--timeout", str(req.timeout)])
    if req.show_filtered:
        cmd.append("--show-filtered")
    if not req.auto_wordlist:
        cmd.append("--no-auto-wordlist")
    if req.recommend_only:
        cmd.append("--recommend-only")
    if req.vhost:
        cmd.append("--vhost")
    if req.verbose:
        cmd.append("-v")
    return cmd


async def tail_events(job: ScanJob) -> None:
    path = job.events_path
    offset = 0
    while job.status == "running":
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            chunk = text[offset:]
            if chunk:
                for line in chunk.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                        job.events.append(evt)
                    except json.JSONDecodeError:
                        pass
                offset = len(text)
        await asyncio.sleep(0.25)

    # Final read
    if path.exists():
        text = path.read_text(encoding="utf-8", errors="replace")
        chunk = text[offset:]
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
                job.events.append(evt)
            except json.JSONDecodeError:
                pass


async def watch_process(job: ScanJob) -> None:
    assert job.process is not None
    tail_task = asyncio.create_task(tail_events(job))
    code = await asyncio.get_event_loop().run_in_executor(None, job.process.wait)
    await tail_task
    job.finished_at = time.time()
    if code == 0:
        job.status = "completed"
    elif code in (130, -2, -signal.SIGINT):
        job.status = "cancelled"
    else:
        job.status = "failed"
        job.error = f"Process exited with code {code}"


@app.get("/api/health")
def health() -> dict[str, Any]:
    bin_path = resolve_binary()
    return {
        "status": "ok",
        "service": "smartfuzz-ui",
        "binary": str(bin_path),
        "binary_exists": bin_path.exists(),
    }


@app.get("/api/scans")
async def list_scans() -> dict[str, Any]:
    async with SCANS_LOCK:
        items = sorted(scans.values(), key=lambda s: s.created_at, reverse=True)
        return {"items": [s.to_dict() for s in items]}


@app.post("/api/scans")
async def start_scan(req: ScanStartRequest) -> dict[str, Any]:
    scan_id = str(uuid.uuid4())
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_dir = RUNS_DIR / scan_id
    run_dir.mkdir(parents=True, exist_ok=True)
    events_path = run_dir / "events.ndjson"
    report_path = run_dir / "report.json"

    cmd = build_command(req, events_path, report_path)
    job = ScanJob(
        id=scan_id,
        url=req.url,
        events_path=events_path,
        report_path=report_path,
        config=req.model_dump(),
    )

    try:
        job.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(ROOT),
        )
    except OSError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    job.status = "running"
    job.started_at = time.time()
    async with SCANS_LOCK:
        scans[scan_id] = job
    asyncio.create_task(watch_process(job))
    return job.to_dict()


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    job = scans.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = job.to_dict()
    if job.report_path.exists():
        try:
            data["report"] = json.loads(job.report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data["report"] = None
    return data


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: str) -> dict[str, Any]:
    job = scans.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    if job.process and job.status == "running":
        job.process.send_signal(signal.SIGINT)
        job.status = "cancelling"
    return job.to_dict()


@app.get("/api/scans/{scan_id}/events")
async def stream_events(scan_id: str, after: int = 0) -> StreamingResponse:
    job = scans.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def gen() -> AsyncIterator[str]:
        cursor = after
        while True:
            while cursor < len(job.events):
                payload = json.dumps(job.events[cursor])
                cursor += 1
                yield f"data: {payload}\n\n"
            if job.status in {"completed", "failed", "cancelled"} and cursor >= len(job.events):
                yield f"data: {json.dumps({'type': 'stream_end', 'status': job.status})}\n\n"
                break
            await asyncio.sleep(0.25)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/scans/{scan_id}/report")
async def get_report(scan_id: str) -> Any:
    job = scans.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not job.report_path.exists():
        raise HTTPException(status_code=404, detail="Report not ready")
    return json.loads(job.report_path.read_text(encoding="utf-8"))


# Static UI
if WEB_DIST.exists():
    app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="assets")

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(WEB_DIST / "index.html")

    @app.get("/{full_path:path}")
    async def spa(full_path: str) -> FileResponse:
        candidate = WEB_DIST / full_path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(WEB_DIST / "index.html")


def main() -> None:
    import uvicorn

    port = int(os.environ.get("SMARTFUZZ_UI_PORT", "8787"))
    uvicorn.run("server:app", host="127.0.0.1", port=port, reload=False)


if __name__ == "__main__":
    main()
