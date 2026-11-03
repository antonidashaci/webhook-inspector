"""Catch webhooks, look at them, replay them at your local server.

The loop you actually run while integrating Stripe or GitHub: point the provider
at a bin, see exactly what arrived, then replay that same request at
localhost:3000 as many times as it takes - no re-triggering the provider.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import string
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field, field_validator

DB_PATH = Path(os.environ.get("INSPECTOR_DB", "webhooks.db"))
MAX_BODY = int(os.environ.get("INSPECTOR_MAX_BODY", 1024 * 256))
KEEP_PER_BIN = int(os.environ.get("INSPECTOR_KEEP", 200))
ALPHABET = string.ascii_lowercase + string.digits
# Headers worth hiding in a UI someone will screenshot into a bug report.
SENSITIVE = {"authorization", "cookie", "x-api-key", "proxy-authorization"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS bins (
    id          TEXT PRIMARY KEY,
    label       TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    bin_id      TEXT NOT NULL REFERENCES bins(id) ON DELETE CASCADE,
    received_at TEXT NOT NULL,
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    query       TEXT NOT NULL,
    headers     TEXT NOT NULL,
    body        BLOB NOT NULL,
    truncated   INTEGER NOT NULL DEFAULT 0,
    source_ip   TEXT
);
CREATE INDEX IF NOT EXISTS requests_bin ON requests (bin_id, id DESC);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@asynccontextmanager
async def lifespan(app: FastAPI):
    with closing(connect()) as conn:
        conn.executescript(SCHEMA)
        conn.commit()
    yield


app = FastAPI(
    title="webhook-inspector",
    description="Catch webhooks, inspect them, replay them locally.",
    version="1.0.0",
    lifespan=lifespan,
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(n: int = 8) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(n))


def pretty(body: bytes, content_type: str) -> str:
    """Decode for display, and indent JSON so you can read it."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return f"<{len(body)} bytes of binary>"
    if "json" in content_type.lower():
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except ValueError:
            pass
    return text


def mask(headers: dict[str, str], reveal: bool) -> dict[str, str]:
    if reveal:
        return headers
    return {
        k: ("<hidden, add ?reveal=1>" if k.lower() in SENSITIVE else v)
        for k, v in headers.items()
    }


class BinIn(BaseModel):
    label: str | None = Field(default=None, max_length=120)


class ReplayIn(BaseModel):
    target: str = Field(..., description="Where to send it, e.g. http://localhost:3000/webhooks")

    @field_validator("target")
    @classmethod
    def must_be_http(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("target must be an absolute http:// or https:// URL")
        return value.strip()


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"ok": True}


@app.post("/api/bins", status_code=201, tags=["bins"])
def create_bin(payload: BinIn, request: Request) -> dict:
    bin_id = new_id()
    with closing(connect()) as conn:
        conn.execute(
            "INSERT INTO bins (id, label, created_at) VALUES (?, ?, ?)",
            (bin_id, payload.label, now_iso()),
        )
        conn.commit()
    base = str(request.base_url).rstrip("/")
    return {
        "id": bin_id,
        "label": payload.label,
        "webhook_url": f"{base}/hook/{bin_id}",
        "inspect_url": f"{base}/b/{bin_id}",
    }


@app.get("/api/bins", tags=["bins"])
def list_bins() -> list[dict]:
    with closing(connect()) as conn:
        rows = conn.execute(
            "SELECT b.id, b.label, b.created_at, COUNT(r.id) AS requests "
            "FROM bins b LEFT JOIN requests r ON r.bin_id = b.id "
            "GROUP BY b.id ORDER BY b.created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


@app.delete("/api/bins/{bin_id}", status_code=204, tags=["bins"])
def delete_bin(bin_id: str):
    with closing(connect()) as conn:
        cursor = conn.execute("DELETE FROM bins WHERE id = ?", (bin_id,))
        conn.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="No such bin")


@app.api_route(
    "/hook/{bin_id}{tail:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    tags=["capture"],
)
async def capture(bin_id: str, tail: str, request: Request):
    """Accept anything and store it. Always answers 200 - a provider that gets
    a 500 from its test endpoint will disable the webhook."""
    with closing(connect()) as conn:
        if conn.execute("SELECT 1 FROM bins WHERE id = ?", (bin_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="No such bin")

        body = await request.body()
        truncated = len(body) > MAX_BODY
        stored = body[:MAX_BODY]
        conn.execute(
            "INSERT INTO requests (bin_id, received_at, method, path, query, headers, body,"
            " truncated, source_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                bin_id,
                now_iso(),
                request.method,
                tail or "/",
                str(request.url.query),
                json.dumps(dict(request.headers)),
                stored,
                int(truncated),
                request.client.host if request.client else None,
            ),
        )
        # Keep the bin bounded; an idle webhook left on for a week fills a disk.
        conn.execute(
            "DELETE FROM requests WHERE bin_id = ? AND id NOT IN "
            "(SELECT id FROM requests WHERE bin_id = ? ORDER BY id DESC LIMIT ?)",
            (bin_id, bin_id, KEEP_PER_BIN),
        )
        conn.commit()
    return {"received": True}


@app.get("/api/bins/{bin_id}/requests", tags=["capture"])
def list_requests(bin_id: str, limit: int = 50, reveal: bool = False) -> list[dict]:
    limit = max(1, min(limit, 200))
    with closing(connect()) as conn:
        if conn.execute("SELECT 1 FROM bins WHERE id = ?", (bin_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="No such bin")
        rows = conn.execute(
            "SELECT * FROM requests WHERE bin_id = ? ORDER BY id DESC LIMIT ?", (bin_id, limit)
        ).fetchall()
    return [serialise(r, reveal) for r in rows]


def serialise(row: sqlite3.Row, reveal: bool) -> dict:
    headers = json.loads(row["headers"])
    return {
        "id": row["id"],
        "received_at": row["received_at"],
        "method": row["method"],
        "path": row["path"],
        "query": row["query"],
        "source_ip": row["source_ip"],
        "headers": mask(headers, reveal),
        "truncated": bool(row["truncated"]),
        "body": pretty(row["body"], headers.get("content-type", "")),
    }


@app.delete("/api/bins/{bin_id}/requests", status_code=204, tags=["capture"])
def clear_requests(bin_id: str):
    with closing(connect()) as conn:
        conn.execute("DELETE FROM requests WHERE bin_id = ?", (bin_id,))
        conn.commit()


@app.post("/api/requests/{request_id}/replay", tags=["replay"])
async def replay(request_id: int, payload: ReplayIn) -> dict:
    """Send a captured request at your own server, verbatim."""
    with closing(connect()) as conn:
        row = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No such request")

    headers = json.loads(row["headers"])
    # host and content-length belong to the original hop, not this one.
    headers = {k: v for k, v in headers.items() if k.lower() not in {"host", "content-length"}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            response = await client.request(
                row["method"], payload.target, content=row["body"], headers=headers
            )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Could not reach target: {exc}")

    return {
        "status": response.status_code,
        "elapsed_ms": round(response.elapsed.total_seconds() * 1000),
        "body": response.text[:4000],
    }


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bin __BIN__</title>
<style>
  :root { color-scheme: light dark; --bg:#fbfbfa; --fg:#16150f; --muted:#6b6a63;
          --line:#e3e2dc; --card:#fff; --accent:#1a6b4a; }
  @media (prefers-color-scheme: dark) { :root {
      --bg:#14140f; --fg:#f0efe8; --muted:#9a998f; --line:#2c2b24; --card:#1c1b16; --accent:#6ec49a; } }
  * { box-sizing: border-box; }
  body { margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
         font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif; }
  main { max-width: 860px; margin: 0 auto; }
  h1 { font-size:1.25rem; margin:0 0 4px; }
  code { font-family: ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.9em; }
  .url { background:var(--card); border:1px solid var(--line); border-radius:8px;
         padding:10px 12px; margin:12px 0 20px; overflow-x:auto; white-space:nowrap; }
  .req { background:var(--card); border:1px solid var(--line); border-radius:10px;
         padding:14px 16px; margin-bottom:12px; }
  .top { display:flex; gap:10px; align-items:baseline; flex-wrap:wrap; }
  .m { font-weight:600; color:var(--accent); }
  .t { color:var(--muted); font-size:.85rem; margin-left:auto; }
  pre { background:var(--bg); border:1px solid var(--line); border-radius:6px;
        padding:10px; overflow-x:auto; margin:10px 0 0; font-size:.85rem; }
  summary { cursor:pointer; color:var(--muted); font-size:.85rem; margin-top:8px; }
  .empty { color:var(--muted); text-align:center; padding:48px 0; }
</style></head><body><main>
<h1>Bin <code>__BIN__</code></h1>
<div class="url">POST to <code>__URL__</code></div>
<div id="list"><p class="empty">Waiting for the first request&hellip;</p></div>
</main><script>
const bin = "__BIN__";
const esc = s => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function tick() {
  const res = await fetch(`/api/bins/${bin}/requests?limit=50`);
  if (!res.ok) return;
  const rows = await res.json();
  const list = document.getElementById('list');
  if (!rows.length) return;
  list.innerHTML = rows.map(r => `
    <div class="req">
      <div class="top"><span class="m">${esc(r.method)}</span>
        <code>${esc(r.path)}${r.query ? '?' + esc(r.query) : ''}</code>
        <span class="t">${esc(r.received_at.slice(11, 19))} UTC &middot; ${esc(r.source_ip || '?')}</span></div>
      <pre>${esc(r.body) || '(empty body)'}</pre>
      <details><summary>${Object.keys(r.headers).length} headers</summary>
        <pre>${Object.entries(r.headers).map(([k, v]) => esc(k + ': ' + v)).join('\\n')}</pre>
      </details>
    </div>`).join('');
}
tick(); setInterval(tick, 2000);
</script></body></html>"""


@app.get("/b/{bin_id}", response_class=HTMLResponse, tags=["ui"])
def viewer(bin_id: str, request: Request) -> Response:
    with closing(connect()) as conn:
        if conn.execute("SELECT 1 FROM bins WHERE id = ?", (bin_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="No such bin")
    url = f"{str(request.base_url).rstrip('/')}/hook/{bin_id}"
    return HTMLResponse(PAGE.replace("__BIN__", bin_id).replace("__URL__", url))
