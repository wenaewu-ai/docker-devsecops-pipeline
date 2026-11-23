from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main, migrate


class _FakeConn:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        return self

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


@pytest.fixture
def client():
    return TestClient(main.app, raise_server_exceptions=False)


def test_healthz_does_not_need_the_database(client, monkeypatch):
    def boom():
        raise RuntimeError("database is down")

    monkeypatch.setattr(main, "get_conn", boom)
    assert client.get("/healthz").json() == {"status": "ok"}


def test_list_notes(client, monkeypatch):
    rows = [(2, "second", datetime(2026, 11, 5, 9, 0, tzinfo=UTC)), (1, "first", datetime(2026, 11, 4, tzinfo=UTC))]
    monkeypatch.setattr(main, "get_conn", lambda: _FakeConn(rows))
    body = client.get("/api/notes").json()
    assert [n["id"] for n in body] == [2, 1]
    assert body[0]["created_at"] == "2026-11-05T09:00:00+00:00"


def test_missing_note_is_404(client, monkeypatch):
    monkeypatch.setattr(main, "get_conn", lambda: _FakeConn([]))
    assert client.get("/api/notes/99").status_code == 404


def test_empty_note_is_rejected_before_touching_the_database(client, monkeypatch):
    monkeypatch.setattr(main, "get_conn", lambda: pytest.fail("must not connect"))
    assert client.post("/api/notes", json={"body": ""}).status_code == 422


def test_unhandled_error_is_logged_but_not_leaked(client, monkeypatch, caplog):
    def boom():
        raise RuntimeError("connection to server at 10.0.0.5 failed: password for user app")

    monkeypatch.setattr(main, "get_conn", boom)
    res = client.get("/api/notes")
    assert res.status_code == 500
    assert res.json() == {"error": "internal_error", "detail": "Something went wrong."}
    assert "10.0.0.5" not in res.text
    # The daily error report keys on this exact prefix.
    assert any(r.getMessage().startswith("Unhandled error: GET ") for r in caplog.records)


def test_pending_migrations_are_ordered_and_skip_applied():
    files = [Path("0003_c.sql"), Path("0001_a.sql"), Path("0002_b.sql")]
    assert [f.name for f in migrate.pending(files, {"0001_a.sql"})] == ["0002_b.sql", "0003_c.sql"]
