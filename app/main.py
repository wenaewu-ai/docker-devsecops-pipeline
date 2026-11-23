"""A deliberately small API. The point of this repository is the pipeline around it."""

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.config import settings
from app.db import get_conn

log = logging.getLogger(__name__)
# uvicorn only configures its own loggers. The app's log lines must carry a level so the
# daily error report can tell WARNING from ERROR (see .github/scripts/daily_error_report.py).
logging.basicConfig(level=logging.INFO, format="%(levelname)s:     [%(name)s] %(message)s")

app = FastAPI(title=settings.app_name)


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=2000)


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    # The real exception is only logged: str(exc) can carry host, table or constraint
    # names, which must not reach the browser.
    log.exception("Unhandled error: %s %s", request.method, request.url)
    return JSONResponse({"error": "internal_error", "detail": "Something went wrong."}, status_code=500)


@app.get("/healthz")
def healthz() -> dict:
    """Liveness: the process is up. It does not touch the database on purpose, so a
    database outage shows up as failing requests, not as a restart loop."""
    return {"status": "ok"}


@app.get("/api/notes")
def list_notes() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT id, body, created_at FROM notes ORDER BY id DESC LIMIT 100").fetchall()
    return [{"id": r[0], "body": r[1], "created_at": r[2].isoformat()} for r in rows]


@app.post("/api/notes", status_code=201)
def create_note(note: NoteIn) -> dict:
    with get_conn() as conn:
        row = conn.execute(
            "INSERT INTO notes (body) VALUES (%s) RETURNING id, body, created_at", (note.body,)
        ).fetchone()
    return {"id": row[0], "body": row[1], "created_at": row[2].isoformat()}


@app.get("/api/notes/{note_id}")
def get_note(note_id: int) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT id, body, created_at FROM notes WHERE id = %s", (note_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="note not found")
    return {"id": row[0], "body": row[1], "created_at": row[2].isoformat()}
