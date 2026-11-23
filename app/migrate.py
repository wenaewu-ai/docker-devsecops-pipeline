"""Apply pending SQL migrations from migrations/ to the database.

Each file is applied at most once, in file name order; applied names are tracked in the
schema_migrations table. A file and its bookkeeping row are committed together, so a
failed migration leaves nothing half-applied and the run can simply be repeated.

Run with `python -m app.migrate` (the compose `migrate` service does this on every deploy).
"""

from __future__ import annotations

from pathlib import Path

from app.db import get_conn

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
# Any constant works; it only has to be the same for every instance of this app.
ADVISORY_LOCK_ID = 727_001


def pending(files: list[Path], applied: set[str]) -> list[Path]:
    return [f for f in sorted(files, key=lambda f: f.name) if f.name not in applied]


def run() -> None:
    with get_conn() as conn:
        # Two deploys started at the same moment must not apply the same file twice.
        conn.execute("SELECT pg_advisory_lock(%s)", (ADVISORY_LOCK_ID,))
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        conn.commit()
        applied = {row[0] for row in conn.execute("SELECT filename FROM schema_migrations")}

        todo = pending(list(MIGRATIONS_DIR.glob("*.sql")), applied)
        for f in todo:
            print(f"applying migration: {f.name}", flush=True)
            conn.execute(f.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO schema_migrations (filename) VALUES (%s)", (f.name,))
            conn.commit()
        print(f"migrations up to date ({len(todo)} applied, {len(applied)} already in place)", flush=True)


if __name__ == "__main__":
    run()
