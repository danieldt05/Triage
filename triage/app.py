"""Web entry point: `uvicorn triage.app:app`."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from triage import __version__, report, rules
from triage.lookup.collect import collect

STATIC = Path(__file__).parent / "static"
RATE_LIMIT = 12            # diagnoses per client...
RATE_WINDOW = 60           # ...per this many seconds
MAX_CONCURRENT = 4         # whole-server cap, so one burst can't exhaust a small instance

app = FastAPI(title="Triage", version=__version__, docs_url="/api/docs", redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")

_hits: dict[str, deque] = defaultdict(deque)
_hits_lock = threading.Lock()
_slots = threading.BoundedSemaphore(MAX_CONCURRENT)


def _client_ip(request: Request) -> str:
    # Behind a hosting proxy, X-Forwarded-For is "whatever-the-client-sent, ..., real-client".
    # The client controls the first entries, so trusting them would let anyone dodge the
    # rate limit with a fake header. The proxy appends the address it actually saw, so use
    # the LAST entry. Good enough for a rate limit; not for authentication.
    forwarded = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    return forwarded[-1] if forwarded else (request.client.host if request.client else "unknown")


def _rate_limited(ip: str) -> bool:
    now = time.monotonic()
    with _hits_lock:
        q = _hits[ip]
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return True
        q.append(now)
        return False


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    return {"ok": True, "version": __version__}


@app.get("/api/diagnose")
async def diagnose(
    request: Request,
    url: str = Query(..., max_length=2048, description="Link or domain the customer is having trouble with"),
    expected: str | None = Query(None, max_length=300, description="Where DNS should be hosted (provider or nameservers)"),
) -> dict:
    if _rate_limited(_client_ip(request)):
        raise HTTPException(429, "Too many checks from your address. Wait a minute and try again.")
    if not _slots.acquire(blocking=False):
        raise HTTPException(503, "The server is busy with other checks. Try again in a few seconds.")
    try:
        obs = await run_in_threadpool(collect, url, expected)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    finally:
        _slots.release()
    return report.build(obs, rules.run(obs))
