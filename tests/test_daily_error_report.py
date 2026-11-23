"""Tests for .github/scripts/daily_error_report.py."""
# ruff: noqa: E501  (log samples are kept exactly as the containers print them)

import json
from datetime import date

import daily_error_report as der
import pytest

DAY = date(2026, 11, 5)  # report day in UTC+8 = 2026-11-04 16:00 to 2026-11-05 16:00 UTC


@pytest.fixture(autouse=True)
def _utc_plus_8():
    der.set_utc_offset(8)
    yield
    der.set_utc_offset(0)


APP_LOG = """\
2026-11-05T01:12:00.100000000Z INFO:     172.18.0.5:0 - "GET /api/notes HTTP/1.0" 200 OK
2026-11-05T01:12:03.000000000Z ERROR:     [app.main] Unhandled error: GET http://10.1.1.1:8080/api/notes/123?x=1
2026-11-05T01:12:03.000000001Z Traceback (most recent call last):
2026-11-05T01:12:03.000000002Z   File "/usr/local/lib/python3.12/site-packages/starlette/routing.py", line 76, in app
2026-11-05T01:12:03.000000003Z     response = await f(request)
2026-11-05T01:12:03.000000004Z   File "/app/app/main.py", line 58, in get_note
2026-11-05T01:12:03.000000005Z     with get_conn() as conn:
2026-11-05T01:12:03.000000006Z   File "/app/app/db.py", line 9, in get_conn
2026-11-05T01:12:03.000000007Z     return psycopg.connect(settings.database_url, connect_timeout=5)
2026-11-05T01:12:03.000000008Z   File "/usr/local/lib/python3.12/site-packages/psycopg/connection.py", line 120, in connect
2026-11-05T01:12:03.000000009Z psycopg.OperationalError: connection failed: connection to server at "172.18.0.2", port 5432 failed: Connection refused
2026-11-05T01:12:03.000000010Z 	Is the server running on that host and accepting TCP/IP connections?
2026-11-05T01:12:04.000000000Z INFO:     172.18.0.5:0 - "GET /api/notes/123 HTTP/1.0" 500 Internal Server Error
2026-11-05T05:40:00.000000000Z ERROR:     [app.main] Unhandled error: GET http://10.1.1.1:8080/api/notes/456
2026-11-05T05:40:00.000000001Z Traceback (most recent call last):
2026-11-05T05:40:00.000000004Z   File "/app/app/main.py", line 58, in get_note
2026-11-05T05:40:00.000000005Z     with get_conn() as conn:
2026-11-05T05:40:00.000000006Z   File "/app/app/db.py", line 9, in get_conn
2026-11-05T05:40:00.000000009Z psycopg.OperationalError: connection failed: connection to server at "172.18.0.2", port 5432 failed: Connection refused
2026-11-05T06:00:00.000000000Z WARNING:  Invalid HTTP request received.
2026-11-03T03:00:00.000000000Z ERROR:     [app.main] Unhandled error: GET http://10.1.1.1:8080/api/notes/9
2026-11-03T03:00:00.000000001Z Traceback (most recent call last):
2026-11-03T03:00:00.000000004Z   File "/app/app/db.py", line 9, in get_conn
2026-11-03T03:00:00.000000009Z psycopg.OperationalError: connection failed: connection to server at "172.18.0.2", port 5432 failed: Connection refused
2026-11-05T17:00:00.000000000Z ERROR:     [app.main] an error from the next day must not be counted
"""

NGINX_LOG = """\
2026-11-05T01:12:04.000000000Z 172.18.0.1 - - [05/Nov/2026:01:12:04 +0000] "GET /api/notes/123 HTTP/1.1" 500 120 "-" "Mozilla"
2026-11-05T01:13:00.000000000Z 172.18.0.1 - - [05/Nov/2026:01:13:00 +0000] "GET /healthz HTTP/1.1" 200 5120 "-" "Mozilla"
2026-11-05T01:14:00.000000000Z 172.18.0.1 - - [05/Nov/2026:01:14:00 +0000] "GET /nope HTTP/1.1" 404 10 "-" "Mozilla"
2026-11-05T02:00:00.000000000Z 2026/11/05 02:00:00 [error] 29#29: *51 connect() failed (111: Connection refused) while connecting to upstream, client: 172.18.0.1, server: _, request: "GET /api/notes?page=2 HTTP/1.1", upstream: "http://172.18.0.3:8000/api/notes", host: "x"
2026-11-05T02:00:00.000000001Z 172.18.0.1 - - [05/Nov/2026:02:00:00 +0000] "GET /api/notes?page=2 HTTP/1.1" 502 157 "-" "Mozilla"
2026-11-05T02:00:01.000000000Z 2026/11/05 02:00:01 [notice] 1#1: signal process started
"""

DB_LOG = """\
2026-11-05T03:00:00.000000000Z 2026-11-05 03:00:00.123 UTC [1] LOG:  database system is ready to accept connections
2026-11-05T03:10:00.000000000Z 2026-11-05 03:10:00.456 UTC [77] FATAL:  password authentication failed for user "app"
2026-11-05T03:11:00.000000000Z 2026-11-05 03:11:00.456 UTC [78] ERROR:  relation "missing_table" does not exist at character 15
"""

BACKUP_FAILED_LOG = """\
2026-11-05T14:00:00.000000000Z [backup 2026-11-05 22:00:00] starting backup of appdb -> /backups/appdb_20261105_220000.dump
2026-11-05T14:00:05.000000000Z [backup 2026-11-05 22:00:05] backup failed: pg_dump: error: connection to server at "db" (172.18.0.2), port 5432 failed: Connection refused
"""

BACKUP_OK_LOG = """\
2026-11-05T14:00:00.000000000Z [backup 2026-11-05 22:00:00] starting backup of appdb -> /backups/appdb_20261105_220000.dump
2026-11-05T14:01:00.000000000Z [backup 2026-11-05 22:01:00] backup completed and verified: /backups/appdb_20261105_220000.dump (1.2M)
2026-11-05T14:01:01.000000000Z [backup 2026-11-05 22:01:01] removed 1 backup(s) older than 30 days
"""


def _container(service, status="running", restart=0, started="2026-11-01T00:00:00.0Z", exit_code=0, oom=False):
    return {
        "Name": f"/notes-demo-{service}-1",
        "Created": started,
        "RestartCount": restart,
        "Config": {"Image": f"notes-demo-{service}", "Labels": {"com.docker.compose.service": service}},
        "State": {"Status": status, "StartedAt": started, "ExitCode": exit_code, "OOMKilled": oom},
    }


def _healthy():
    return [_container(s) for s in ("app", "nginx", "backup", "db")] + [_container("migrate", status="exited")]


def _collect_dir(tmp_path, backup_log=BACKUP_OK_LOG, containers=None, db_log=""):
    logs = tmp_path / "logs"
    logs.mkdir(parents=True)
    (logs / "app__aaaaaaaaaaaa.log").write_text(APP_LOG)
    (logs / "nginx__bbbbbbbbbbbb.log").write_text(NGINX_LOG)
    (logs / "backup__cccccccccccc.log").write_text(backup_log)
    (logs / "db__dddddddddddd.log").write_text(db_log)
    (tmp_path / "containers.json").write_text(json.dumps(_healthy() if containers is None else containers))
    return tmp_path


def _group(report, service, contains):
    found = [g for g in report["groups"] if g["service"] == service and contains in g["title"]]
    assert found, [g["title"] for g in report["groups"]]
    return found[0]


def test_normalize_collapses_ids_and_query_but_keeps_ip():
    assert der.normalize("GET http://h:8080/api/notes/123?x=1") == "GET /api/notes/{id}"
    assert "10.0.0.5" in der.normalize("Unable to connect (10.0.0.5)")


def test_app_traceback_grouped_with_location_and_history(tmp_path):
    report = der.analyze(_collect_dir(tmp_path), DAY)
    g = _group(report, "app", "Unhandled error GET /api/notes/{id}")
    assert g["level"] == "ERROR"
    assert g["count"] == 2  # /123 and /456 are one group; the next-day line is outside the window
    assert "OperationalError" in g["title"]
    assert g["exception"].startswith("psycopg.OperationalError")
    assert g["location"] == "app/db.py:9 in get_conn"
    assert g["first_seen"].startswith("2026-11-05T09:12:03")  # local time, UTC+8
    assert g["hourly"] == {"09": 1, "13": 1}
    assert g["previous_days"] == {"2026-11-03": 1}
    assert g["new_in_last_7_days"] is False
    assert "Traceback" in g["traceback"]
    assert all("next day" not in x["title"] for x in report["groups"])


def test_own_code_frame_preferred_over_library_frame(tmp_path):
    report = der.analyze(_collect_dir(tmp_path), DAY)
    g = _group(report, "app", "Unhandled error")
    assert g["location"] == "app/db.py:9 in get_conn"
    assert g["raised_at"].startswith("/usr/local/lib/python3.12/site-packages/psycopg/connection.py:120")


def test_nginx_5xx_error_log_and_traffic(tmp_path):
    report = der.analyze(_collect_dir(tmp_path), DAY)
    assert report["traffic"] == {"source": "nginx access log", "requests": 4, "status_4xx": 1, "status_5xx": 2}
    _group(report, "nginx", "HTTP 502 GET /api/notes")
    upstream = _group(report, "nginx", "connect() failed (111: Connection refused)")
    assert upstream["requests"] == {"GET /api/notes": 1}
    assert not [g for g in report["groups"] if "signal process" in g["title"]]  # notice level is not an anomaly


def test_warning_from_uvicorn(tmp_path):
    report = der.analyze(_collect_dir(tmp_path), DAY)
    assert _group(report, "app", "Invalid HTTP request")["level"] == "WARNING"


def test_postgres_errors(tmp_path):
    report = der.analyze(_collect_dir(tmp_path, db_log=DB_LOG), DAY)
    assert _group(report, "db", "FATAL: password authentication failed")["level"] == "ERROR"
    assert _group(report, "db", 'ERROR: relation "missing_table" does not exist')["level"] == "ERROR"
    assert not [g for g in report["groups"] if "ready to accept connections" in g["title"]]


def test_backup_failure_and_missing_completion(tmp_path):
    report = der.analyze(_collect_dir(tmp_path, backup_log=BACKUP_FAILED_LOG), DAY)
    assert _group(report, "backup", "Database backup failed: pg_dump: error")["level"] == "CRITICAL"
    assert _group(report, "backup", "No completed database backup")["level"] == "CRITICAL"
    assert report["backup"]["completed_at"] == []


def test_backup_ok(tmp_path):
    report = der.analyze(_collect_dir(tmp_path), DAY)
    assert report["backup"]["completed_at"] == ["2026-11-05T22:01:00+08:00"]
    assert not [g for g in report["groups"] if g["service"] == "backup"]


def test_missing_backup_not_reported_before_it_is_due(tmp_path, monkeypatch):
    # Reporting on "today" at 10:00 local time: the 22:00 backup has not had its chance yet.
    class _Now(der.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 11, 5, 2, 0, tzinfo=der.UTC)

    monkeypatch.setattr(der, "datetime", _Now)
    report = der.analyze(_collect_dir(tmp_path, backup_log=""), DAY)
    assert not [g for g in report["groups"] if g["service"] == "backup"]
    assert "Database backup: ⏳ not due yet (scheduled 22:00)" in der.render_messages(report, "Project A")[0]


def test_container_problems(tmp_path):
    containers = [
        _container("app", restart=3, started="2026-11-05T03:00:00.0Z"),
        _container("nginx", status="exited", exit_code=1),
        _container("db", oom=True),
        _container("migrate", status="exited", exit_code=1),
        # the backup container is gone
    ]
    report = der.analyze(_collect_dir(tmp_path, containers=containers), DAY)
    assert _group(report, "app", "Container restarted unexpectedly")["level"] == "CRITICAL"
    assert _group(report, "nginx", "Container is not running")["level"] == "CRITICAL"
    assert _group(report, "db", "OOMKilled")["level"] == "CRITICAL"
    assert _group(report, "migrate", "One-shot container failed")["level"] == "ERROR"
    assert _group(report, "backup", "No container found for this service")["level"] == "CRITICAL"


def test_finished_one_shot_container_is_healthy(tmp_path):
    report = der.analyze(_collect_dir(tmp_path), DAY)
    assert not [g for g in report["groups"] if g["service"] == "migrate"]
    assert "migrate ✅ exited" in der.render_messages(report, "Project A")[0]


def test_no_logs_at_all_is_critical(tmp_path):
    (tmp_path / "logs").mkdir()
    report = der.analyze(tmp_path, DAY)
    assert _group(report, "collector", "No container logs were collected")["level"] == "CRITICAL"


def test_groups_sorted_by_severity_then_count(tmp_path):
    report = der.analyze(_collect_dir(tmp_path, backup_log=BACKUP_FAILED_LOG), DAY)
    ranks = [der.LEVEL_RANK[g["level"]] for g in report["groups"]]
    assert ranks == sorted(ranks)
    assert [g["id"] for g in report["groups"]] == list(range(1, len(report["groups"]) + 1))
    assert report["summary"]["total"] == sum(g["count"] for g in report["groups"])


def test_render_messages_summary_table_and_limits(tmp_path):
    report = der.analyze(_collect_dir(tmp_path), DAY)
    msgs = der.render_messages(report, "Project A", "https://github.com/x/y/actions/runs/1")
    assert msgs[0].startswith("📊 <b>[Project A] Daily error summary</b> (2026-11-05, UTC+8)")
    assert "Count | Anomaly" in msgs[0]
    assert "   2x | [ERROR] app: Unhandled error GET /api/notes/{id}" in der._strip_html(msgs[0])
    assert "Database backup: ✅ completed at 22:01" in msgs[0]
    assert all(len(m) <= der.TG_LIMIT for m in msgs)
    text = "\n".join(msgs)
    assert "Location: <code>app/db.py:9 in get_conn" in text


def test_render_messages_split_when_long(tmp_path):
    report = der.analyze(_collect_dir(tmp_path), DAY)
    base = report["groups"][0]
    report["groups"] = [dict(base, id=i, title=f"{base['title']} {i}" * 3) for i in range(1, 60)]
    msgs = der.render_messages(report, "Project A")
    assert len(msgs) > 1
    assert all(len(m) <= der.TG_LIMIT for m in msgs)
    # HTML tags must stay paired in every message (a block is never cut in half)
    for m in msgs:
        assert m.count("<code>") == m.count("</code>")
        assert m.count("<pre>") == m.count("</pre>")


def test_render_no_anomaly():
    start = der.datetime(2026, 11, 4, 16, tzinfo=der.UTC)
    report = der.build_report(DAY, start, start + der.timedelta(days=1), [], [], der.Stats(), der.Stats(), [])
    msgs = der.render_messages(report, "Project A")
    assert "✅ No anomalies detected" in msgs[0]
    assert "Database backup: ❌ no completion record" in msgs[0]


def test_main_writes_outputs_without_sending(tmp_path, capsys):
    d = _collect_dir(tmp_path / "in")
    rc = der.main([str(d), "--date", "2026-11-05", "--utc-offset", "8", "--out-dir", str(tmp_path / "out")])
    assert rc == 0
    report = json.loads((tmp_path / "out" / "report.json").read_text())
    assert report["schema"] == "devsecops-pipeline.daily-error-report/v1"
    assert report["window"]["timezone"] == "UTC+8"
    assert "Daily error summary" in capsys.readouterr().out


def test_expected_services_are_configurable(tmp_path):
    # A deployment that uses an external database has no db container to look for.
    containers = [_container(s) for s in ("app", "nginx", "backup")]
    d = _collect_dir(tmp_path / "in", containers=containers)
    out = tmp_path / "out"
    try:
        der.main(
            [
                str(d),
                "--date",
                "2026-11-05",
                "--utc-offset",
                "8",
                "--services",
                "app,nginx,backup",
                "--out-dir",
                str(out),
            ]
        )
        report = json.loads((out / "report.json").read_text())
        assert not [g for g in report["groups"] if g["service"] == "db"]
    finally:
        der.LONG_RUNNING, der.ONE_SHOT = ("app", "nginx", "backup", "db"), ("migrate",)


def test_recent_deploys_only_within_report_day(tmp_path):
    containers = [
        _container("app", started="2026-11-05T02:00:00.0Z"),  # 10:00 on the report day
        _container("nginx", started="2026-11-05T23:00:00.0Z"),  # 07:00 the next day
        _container("backup"),
        _container("db"),
    ]
    report = der.analyze(_collect_dir(tmp_path, containers=containers), DAY)
    assert report["recent_deploys"] == [{"service": "app", "created": "2026-11-05T10:00:00+08:00"}]
    assert "Deploys / recreated containers: app 10:00" in der.render_messages(report, "Project A")[0]


def test_send_message_falls_back_to_plain_text(monkeypatch):
    calls = []

    def fake_tg(token, method, data, content_type):
        body = json.loads(data)
        calls.append(body)
        if body.get("parse_mode") == "HTML":
            return {"ok": False, "description": "Bad Request: can't parse entities: unclosed tag"}
        return {"ok": True}

    monkeypatch.setattr(der, "_tg", fake_tg)
    der.send_message("t", "42", "<b>broken &lt;x&gt;")
    assert [c.get("parse_mode") for c in calls] == ["HTML", None]
    assert calls[1]["text"] == "broken <x>"


def test_main_send_requires_secrets(tmp_path, monkeypatch):
    monkeypatch.delenv("TELEGRAM_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    d = _collect_dir(tmp_path)
    assert der.main([str(d), "--date", "2026-11-05", "--send"]) == 1


def test_access_log_line_inside_a_traceback_does_not_cut_it_short():
    # stdout (access log) and stderr (traceback) are separate streams; docker merges them by
    # arrival time, so the access line of the failed request can land mid-traceback.
    lines = [
        der.parse_ts(x)
        for x in """\
2026-11-05T01:00:00.000000000Z ERROR:     [app.main] Unhandled error: GET http://h/api/notes
2026-11-05T01:00:00.000000001Z Traceback (most recent call last):
2026-11-05T01:00:00.000000002Z   File "/usr/local/lib/python3.12/site-packages/starlette/middleware/errors.py", line 164, in __call__
2026-11-05T01:00:00.000000003Z INFO:     172.19.0.5:36854 - "GET /api/notes HTTP/1.1" 500 Internal Server Error
2026-11-05T01:00:00.000000004Z   File "/app/app/db.py", line 9, in get_conn
2026-11-05T01:00:00.000000005Z psycopg.OperationalError: failed to resolve host 'db'
2026-11-05T01:00:00.200000000Z ERROR:    Exception in ASGI application
2026-11-05T01:00:00.200000001Z Traceback (most recent call last):
2026-11-05T01:00:00.200000002Z   File "/app/app/db.py", line 9, in get_conn
2026-11-05T01:00:00.200000003Z psycopg.OperationalError: failed to resolve host 'db'
""".splitlines()
    ]
    [event] = der.parse_python_service("app", lines, der.Stats())
    assert event.title == "Unhandled error GET /api/notes → psycopg.OperationalError: failed to resolve host 'db'"
    assert event.location == "app/db.py:9 in get_conn"


def test_uvicorn_reraise_of_handled_exception_not_double_counted():
    lines = [
        (der.parse_ts(x)[0], der.parse_ts(x)[1])
        for x in """\
2026-11-05T01:00:00.000000000Z ERROR:     [app.main] Unhandled error: GET http://h/x/5
2026-11-05T01:00:00.000000001Z Traceback (most recent call last):
2026-11-05T01:00:00.000000002Z   File "/app/app/main.py", line 9, in x
2026-11-05T01:00:00.000000003Z KeyError: 'boom'
2026-11-05T01:00:00.100000000Z INFO:     127.0.0.1:1 - "GET /x/5 HTTP/1.1" 500 Internal Server Error
2026-11-05T01:00:00.200000000Z ERROR:    Exception in ASGI application
2026-11-05T01:00:00.200000001Z Traceback (most recent call last):
2026-11-05T01:00:00.200000002Z   File "/usr/lib/uvicorn/protocols/http/h11_impl.py", line 403, in run_asgi
2026-11-05T01:00:00.200000003Z   File "/app/app/main.py", line 9, in x
2026-11-05T01:00:00.200000004Z KeyError: 'boom'
2026-11-05T03:00:00.000000000Z ERROR:    Exception in ASGI application
2026-11-05T03:00:00.000000001Z Traceback (most recent call last):
2026-11-05T03:00:00.000000002Z RuntimeError: a middleware failed on its own, the handler never saw it
""".splitlines()
    ]
    events = der.parse_python_service("app", lines, der.Stats())
    assert [e.title for e in events] == [
        "Unhandled error GET /x/{id} → KeyError: 'boom'",
        "Exception in ASGI application → RuntimeError: a middleware failed on its own, the handler never saw it",
    ]
