"""Daily error report: analyze one day of production container logs and push a summary to Telegram.

Input is the directory produced by `container_logs.sh collect`:
  logs/<service>__<id12>.log   every line starts with docker's UTC timestamp
  containers.json              `docker inspect` output

What it detects:
  - app:     WARNING / ERROR / CRITICAL log lines and tracebacks (exception type, the line of
             our own code that failed, the request path)
  - nginx:   error log (warn and above) and requests answered with 5xx; also counts requests / 4xx / 5xx
  - db:      PostgreSQL WARNING / ERROR / FATAL / PANIC lines
  - backup:  failed backups, and a day with no completed backup at all
  - containers: not running, unexpected restarts, OOM kills, failed one-shot containers

Output:
  - Telegram messages: a summary a person can read at a glance, then the details of every group
  - A full JSON report (tracebacks, hourly distribution, whether each group was seen in the
    previous 7 days), sent to Telegram as a file attachment

Only the standard library is used, so it runs in a bare `python:3.12-alpine` container.

Usage:
  python daily_error_report.py <collect dir> [--date 2026-11-05] [--project NAME] [--utc-offset 8]
      [--backup-time 22:00] [--services app,nginx,backup,db] [--one-shot migrate]
      [--run-url URL] [--out-dir DIR] [--send]
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path

# Report days are cut in local time. A fixed UTC offset is used instead of an IANA zone
# name so the script needs no tzdata (python:3.12-alpine ships without it).
LOCAL_TZ: timezone = UTC
LEVEL_RANK = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2}
LEVEL_ICON = {"CRITICAL": "🔴", "ERROR": "🟠", "WARNING": "🟡"}
HISTORY_DAYS = 7
TG_LIMIT = 4000
# Services that should always be running, and one-shot services that run to completion and exit.
LONG_RUNNING: tuple[str, ...] = ("app", "nginx", "backup", "db")
ONE_SHOT: tuple[str, ...] = ("migrate",)

TS_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z\s?(.*)$")
LEVEL_RE = re.compile(r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL):\s+(.*)$")
UVICORN_ACCESS_RE = re.compile(r'^INFO:\s+\S+ - "(\S+) (\S+) [^"]*" (\d{3})')
NGINX_ERROR_RE = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[(\w+)\] \d+#\d+: (?:\*\d+ )?(.*)$")
NGINX_ACCESS_RE = re.compile(r'^\S+ - \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) ')
NGINX_LEVEL = {"warn": "WARNING", "error": "ERROR", "crit": "CRITICAL", "alert": "CRITICAL", "emerg": "CRITICAL"}
POSTGRES_RE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)? \S+ \[\d+\] (\w+):\s+(.*)$")
POSTGRES_LEVEL = {"WARNING": "WARNING", "ERROR": "ERROR", "FATAL": "ERROR", "PANIC": "CRITICAL"}
FRAME_RE = re.compile(r'^\s+File "([^"]+)", line (\d+), in (\S+)')
EXC_LINE_RE = re.compile(r"^([A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt|Timeout|Warning|Fault)\w*)(?::\s?(.*))?$")
BACKUP_RE = re.compile(r"^\[backup [^\]]+\] (.*)$")


def set_utc_offset(hours: float) -> None:
    global LOCAL_TZ
    LOCAL_TZ = timezone(timedelta(hours=hours))


def tz_label() -> str:
    hours = LOCAL_TZ.utcoffset(None).total_seconds() / 3600
    return "UTC" if not hours else f"UTC{hours:+g}"


def parse_ts(line: str) -> tuple[datetime, str] | None:
    m = TS_RE.match(line.rstrip("\n"))
    if not m:
        return None
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    ts = datetime.fromisoformat(f"{m.group(1)}.{frac}").replace(tzinfo=UTC)
    return ts, m.group(3)


def normalize(text: str, limit: int = 160) -> str:
    """Replace the parts that differ on every occurrence (ids, uuids, query strings, host
    names) so that the same kind of problem lands in the same group."""
    s = re.sub(r"https?://[^/\s\"']+", "", text)
    s = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "{uuid}", s)
    s = re.sub(r"\b0x[0-9a-fA-F]+\b", "{addr}", s)
    s = re.sub(r"\b[0-9a-fA-F]{16,}\b", "{hex}", s)
    s = re.sub(r"(/[\w.-]*)\?[^\s\"']*", r"\1", s)
    s = re.sub(r"/\d+(?=[/\s\"']|$)", "/{id}", s)
    s = re.sub(r"(?<![\d.])\d{6,}(?![\d.])", "{n}", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


@dataclass
class Event:
    service: str
    level: str
    title: str  # normalized; events with the same service + level + title form one group
    ts: datetime
    raw: str
    exception: str = ""
    location: str = ""  # last frame inside our own code (/app/app/...)
    raised_at: str = ""  # last frame of the traceback
    request: str = ""
    traceback: list[str] = field(default_factory=list)


@dataclass
class Stats:
    requests: int = 0
    status_4xx: int = 0
    status_5xx: int = 0
    backup_done: list[datetime] = field(default_factory=list)
    earliest_log: datetime | None = None


def _frame_text(m: re.Match) -> str:
    path = m.group(1).removeprefix("/app/")
    return f"{path}:{m.group(2)} in {m.group(3)}"


def _finish_traceback(ev: Event) -> None:
    frames = [m for m in (FRAME_RE.match(x) for x in ev.traceback) if m]
    if frames:
        ev.raised_at = _frame_text(frames[-1])
        own = [m for m in frames if m.group(1).startswith("/app/app/")]
        ev.location = _frame_text(own[-1]) if own else ev.raised_at
    for line in reversed(ev.traceback):
        m = EXC_LINE_RE.match(line.strip())
        if m:
            ev.exception = line.strip()[:500]
            break
    if ev.exception:
        exc_type = EXC_LINE_RE.match(ev.exception).group(1)
        exc_msg = EXC_LINE_RE.match(ev.exception).group(2) or ""
        summary = f"{exc_type}: {normalize(exc_msg, 100)}" if exc_msg else exc_type
        ev.title = f"{ev.title} → {summary}" if ev.title else summary


def _is_traceback_line(text: str) -> bool:
    return (
        text.startswith(("Traceback (most recent call last)", " ", "\t", "During handling", "The above exception"))
        or text == ""
        or bool(EXC_LINE_RE.match(text.strip()))
        or text.startswith(("+ Exception Group", "| ", "+-"))
    )


def _duplicate_of_unhandled(ev: Event, events: list[Event]) -> bool:
    """After Starlette calls the app's catch-all handler (`_unhandled` in app/main.py) it
    re-raises, and uvicorn logs "Exception in ASGI application" for the same exception.
    Do not count an exception twice when the handler has just logged it."""
    if not ev.title.startswith("Exception in ASGI application"):
        return False
    for prev in reversed(events[-5:]):
        if prev.title.startswith("Unhandled error") and prev.exception == ev.exception:
            return (ev.ts - prev.ts).total_seconds() <= 5
    return False


def parse_python_service(service: str, lines: list[tuple[datetime, str]], stats: Stats) -> list[Event]:
    """Logs of Python services: level lines, tracebacks, uvicorn access log, backup messages."""
    events: list[Event] = []
    current: Event | None = None  # the event whose traceback is being collected
    in_tb = False

    def close() -> None:
        nonlocal current, in_tb
        if current is not None:
            if current.traceback:
                _finish_traceback(current)
            if not _duplicate_of_unhandled(current, events):
                events.append(current)
        current, in_tb = None, False

    for ts, text in lines:
        # uvicorn's access log is skipped: request counts and 5xx come from nginx, which is
        # what the user actually received. This check comes first because the access line
        # goes to stdout and the traceback to stderr, so docker can interleave one in the
        # middle of the other; it must not cut the traceback short.
        if UVICORN_ACCESS_RE.match(text):
            continue

        if current is not None:
            if text.startswith("Traceback (most recent call last)") or (in_tb and _is_traceback_line(text)):
                in_tb = True
                current.traceback.append(text)
                # The exception line ends this traceback, but a chained one ("During handling
                # of the above exception...") may follow, so the event stays open for now.
                continue
            close()

        if service == "backup" and (m := BACKUP_RE.match(text)):
            msg = m.group(1)
            if msg.startswith("backup completed"):
                stats.backup_done.append(ts)
            elif msg.startswith("backup failed"):
                reason = normalize(msg.split(":", 1)[-1])
                events.append(Event(service, "CRITICAL", f"Database backup failed: {reason}", ts, text))
            elif msg.startswith("warning"):
                events.append(Event(service, "WARNING", normalize(msg), ts, text))
            continue

        if m := LEVEL_RE.match(text):
            level = m.group(1)
            msg = re.sub(r"^\[[\w.]+\]\s*", "", m.group(2))  # drop the app's own "[logger name]" prefix
            if level in LEVEL_RANK:
                um = re.match(r"Unhandled error: (\S+) (\S+)", msg)  # `_unhandled` in app/main.py
                request = f"{um.group(1)} {normalize(um.group(2))}" if um else ""
                title = f"Unhandled error {request}" if um else normalize(msg)
                current = Event(service, level, title, ts, text, request=request)
            continue

        if text.startswith("Traceback (most recent call last)"):
            current = Event(service, "ERROR", "", ts, text, traceback=[text])
            in_tb = True
    close()
    return events


def parse_nginx(lines: list[tuple[datetime, str]], stats: Stats) -> list[Event]:
    events: list[Event] = []
    for ts, text in lines:
        if m := NGINX_ACCESS_RE.match(text):
            method, path, status = m.group(1), m.group(2), int(m.group(3))
            stats.requests += 1
            if 400 <= status < 500:
                stats.status_4xx += 1
            elif status >= 500:
                stats.status_5xx += 1
                req = f"{method} {normalize(path)}"
                events.append(Event("nginx", "ERROR", f"HTTP {status} {req}", ts, text, request=req))
        elif m := NGINX_ERROR_RE.match(text):
            level = NGINX_LEVEL.get(m.group(1))
            if not level:
                continue
            msg = m.group(2)
            head = msg.split(", client:", 1)[0]
            rm = re.search(r'request: "(\S+) (\S+)', msg)
            req = f"{rm.group(1)} {normalize(rm.group(2))}" if rm else ""
            events.append(Event("nginx", level, normalize(head), ts, text, request=req))
    return events


def parse_postgres(service: str, lines: list[tuple[datetime, str]]) -> list[Event]:
    events: list[Event] = []
    for ts, text in lines:
        m = POSTGRES_RE.match(text)
        level = POSTGRES_LEVEL.get(m.group(1)) if m else None
        if level:
            events.append(Event(service, level, f"{m.group(1)}: {normalize(m.group(2))}", ts, text))
    return events


def container_events(containers: list[dict], start: datetime, end: datetime) -> tuple[list[Event], list[dict]]:
    """Derive container-state anomalies from `docker inspect`, plus a status summary per container."""
    events: list[Event] = []
    summary: list[dict] = []
    present = set()
    for c in containers:
        labels = (c.get("Config") or {}).get("Labels") or {}
        svc = labels.get("com.docker.compose.service", c.get("Name", "?").lstrip("/"))
        state = c.get("State") or {}
        started = _docker_time(state.get("StartedAt"))
        created = _docker_time(c.get("Created"))
        info = {
            "service": svc,
            "container": c.get("Name", "").lstrip("/"),
            "image": (c.get("Config") or {}).get("Image"),
            "status": state.get("Status"),
            "health": (state.get("Health") or {}).get("Status"),
            "restart_count": c.get("RestartCount", 0),
            "oom_killed": state.get("OOMKilled", False),
            "exit_code": state.get("ExitCode"),
            "created": _iso_local(created),
            "started": _iso_local(started),
        }
        summary.append(info)
        present.add(svc)
        raw = json.dumps(info)
        when = min(max(started or start, start), end - timedelta(seconds=1))
        if svc in LONG_RUNNING and state.get("Status") != "running":
            msg = f"Container is not running (status={state.get('Status')}, exit code={state.get('ExitCode')})"
            events.append(Event(svc, "CRITICAL", msg, when, raw))
        if info["health"] == "unhealthy":
            events.append(Event(svc, "CRITICAL", "Container health check is failing (unhealthy)", when, raw))
        if state.get("OOMKilled"):
            events.append(Event(svc, "CRITICAL", "Container ran out of memory and was killed (OOMKilled)", when, raw))
        if info["restart_count"] and started and start <= started < end:
            msg = f"Container restarted unexpectedly ({info['restart_count']} restarts, latest on the report day)"
            events.append(Event(svc, "CRITICAL", msg, started, raw))
        if svc in ONE_SHOT and state.get("Status") == "exited" and state.get("ExitCode"):
            msg = f"One-shot container failed (exit code={state.get('ExitCode')})"
            events.append(Event(svc, "ERROR", msg, when, raw))
    for svc in LONG_RUNNING:
        if containers and svc not in present:
            events.append(Event(svc, "CRITICAL", "No container found for this service", end - timedelta(seconds=1), ""))
    return events, summary


def _docker_time(value: str | None) -> datetime | None:
    if not value or value.startswith("0001-"):
        return None
    parsed = parse_ts(value)
    return parsed[0] if parsed else None


def _iso_local(dt: datetime | None) -> str | None:
    return dt.astimezone(LOCAL_TZ).isoformat(timespec="seconds") if dt else None


def read_logs(logs_dir: Path, since: datetime, end: datetime) -> dict[str, list[tuple[datetime, str]]]:
    """Merge the logs of every container of a service (a deploy replaces the container, so one
    service can have several), sorted by time."""
    by_service: dict[str, list[tuple[datetime, str]]] = {}
    for f in sorted(logs_dir.glob("*.log")):
        service = f.name.split("__", 1)[0]
        rows = by_service.setdefault(service, [])
        with f.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parsed = parse_ts(line)
                if parsed and since <= parsed[0] < end:
                    rows.append(parsed)
    for rows in by_service.values():
        rows.sort(key=lambda r: r[0])
    return by_service


def analyze(collect_dir: Path, day: date, backup_time: str = "22:00") -> dict:
    start = datetime.combine(day, datetime.min.time(), LOCAL_TZ).astimezone(UTC)
    end = start + timedelta(days=1)
    history_start = start - timedelta(days=HISTORY_DAYS)

    logs = read_logs(collect_dir / "logs", history_start, end)
    containers_path = collect_dir / "containers.json"
    containers = json.loads(containers_path.read_text()) if containers_path.exists() else []

    day_stats, hist_stats = Stats(), Stats()
    events: list[Event] = []
    history: list[Event] = []
    for service, rows in logs.items():
        if rows:
            first = rows[0][0]
            if hist_stats.earliest_log is None or first < hist_stats.earliest_log:
                hist_stats.earliest_log = first
        for scope_rows, stats, sink in (
            ([r for r in rows if r[0] >= start], day_stats, events),
            ([r for r in rows if r[0] < start], hist_stats, history),
        ):
            if service == "nginx":
                sink.extend(parse_nginx(scope_rows, stats))
            elif service == "db":
                sink.extend(parse_postgres(service, scope_rows))
            else:
                sink.extend(parse_python_service(service, scope_rows, stats))

    c_events, c_summary = container_events(containers, start, end)
    events.extend(c_events)

    has_backup_service = "backup" in logs or any(c["service"] == "backup" for c in c_summary)
    backup_due = datetime.combine(day, datetime.strptime(backup_time, "%H:%M").time(), LOCAL_TZ)
    # Only complain once the scheduled time has actually passed (matters when reporting on today).
    backup_overdue = backup_due.astimezone(UTC) < min(end, datetime.now(UTC))
    if has_backup_service and not day_stats.backup_done and backup_overdue:
        events.append(
            Event(
                "backup",
                "CRITICAL",
                f"No completed database backup on the report day (scheduled {backup_time})",
                min(backup_due.astimezone(UTC), end - timedelta(seconds=1)),
                "",
            )
        )
    if not logs:
        msg = "No container logs were collected (the collect step may have failed)"
        events.append(Event("collector", "CRITICAL", msg, end - timedelta(seconds=1), ""))

    report = build_report(day, start, end, events, history, day_stats, hist_stats, c_summary, has_backup_service)
    report["backup"] |= {"scheduled": backup_time, "overdue": backup_overdue}
    return report


def build_report(day, start, end, events, history, day_stats, hist_stats, c_summary, backup_service=True) -> dict:
    groups: dict[tuple[str, str, str], list[Event]] = {}
    for ev in events:
        groups.setdefault((ev.service, ev.level, ev.title), []).append(ev)

    hist_by_key: dict[tuple[str, str, str], Counter] = {}
    for ev in history:
        day_key = ev.ts.astimezone(LOCAL_TZ).date().isoformat()
        hist_by_key.setdefault((ev.service, ev.level, ev.title), Counter())[day_key] += 1

    out_groups = []
    for key, evs in groups.items():
        evs.sort(key=lambda e: e.ts)
        service, level, title = key
        tb_event = next((e for e in evs if e.traceback), None)
        samples = list(dict.fromkeys(e.raw for e in evs if e.raw))[:3]
        hist = hist_by_key.get(key, Counter())
        out_groups.append(
            {
                "level": level,
                "service": service,
                "title": title,
                "count": len(evs),
                "first_seen": _iso_local(evs[0].ts),
                "last_seen": _iso_local(evs[-1].ts),
                "hourly": dict(sorted(Counter(e.ts.astimezone(LOCAL_TZ).strftime("%H") for e in evs).items())),
                "requests": dict(Counter(e.request for e in evs if e.request).most_common(5)),
                "exception": tb_event.exception if tb_event else "",
                "location": tb_event.location if tb_event else "",
                "raised_at": tb_event.raised_at if tb_event else "",
                "traceback": "\n".join(tb_event.traceback[-40:]) if tb_event else "",
                "samples": [s[:1000] for s in samples],
                "previous_days": dict(sorted(hist.items())),
                "new_in_last_7_days": not hist,
            }
        )
    out_groups.sort(key=lambda g: (LEVEL_RANK[g["level"]], -g["count"], g["first_seen"] or ""))
    for i, g in enumerate(out_groups, 1):
        g["id"] = i

    by_level = Counter()
    for g in out_groups:
        by_level[g["level"]] += g["count"]
    deploys = sorted(
        ({"service": c["service"], "created": c["created"]} for c in c_summary if c["created"]),
        key=lambda d: d["created"],
    )
    return {
        "schema": "devsecops-pipeline.daily-error-report/v1",
        "date": day.isoformat(),
        "window": {"start": _iso_local(start), "end": _iso_local(end), "timezone": tz_label()},
        "generated_at": _iso_local(datetime.now(UTC)),
        "summary": {
            "total": sum(by_level.values()),
            "by_level": {lv: by_level.get(lv, 0) for lv in LEVEL_RANK},
            "group_count": len(out_groups),
        },
        "groups": out_groups,
        "backup": {"service_present": backup_service, "completed_at": [_iso_local(t) for t in day_stats.backup_done]},
        "traffic": {
            "source": "nginx access log",
            "requests": day_stats.requests,
            "status_4xx": day_stats.status_4xx,
            "status_5xx": day_stats.status_5xx,
        },
        "containers": c_summary,
        "recent_deploys": [d for d in deploys if _iso_local(start) <= d["created"] < _iso_local(end)],
        "history_coverage_start": _iso_local(hist_stats.earliest_log),
        "notes": [
            "An nginx HTTP 5xx is what the user actually received. It is usually the same incident as an "
            "app exception at the same time, so do not count the impact twice.",
            "previous_days / new_in_last_7_days only cover logs that still exist after history_coverage_start.",
            "Logs of containers replaced by a deploy come from the pre-deploy archive. Use recent_deploys "
            "to check whether an error started with a deploy.",
        ],
    }


# ── Telegram messages ────────────────────────────────────────────────────────


def _esc(text: str) -> str:
    # Telegram HTML only needs < > & escaped; quotes are left alone to keep messages readable.
    return html.escape(text, quote=False)


def render_messages(report: dict, project: str, run_url: str = "") -> list[str]:
    """Return the HTML messages to send, in order (none longer than TG_LIMIT)."""
    esc = _esc
    s = report["summary"]
    lv = s["by_level"]
    head = [f"📊 <b>[{esc(project)}] Daily error summary</b> ({report['date']}, {report['window']['timezone']})"]
    if not s["total"]:
        head.append("✅ No anomalies detected")
    else:
        head.append(
            f"{s['total']} events in {s['group_count']} groups "
            f"(🔴 CRITICAL {lv['CRITICAL']} | 🟠 ERROR {lv['ERROR']} | 🟡 WARNING {lv['WARNING']})"
        )
        rows = ["Count | Anomaly"]
        for g in report["groups"][:20]:
            rows.append(f"{g['count']:>4}x | [{g['level']}] {g['service']}: {g['title'][:90]}")
        if len(report["groups"]) > 20:
            rows.append(f"…and {len(report['groups']) - 20} more groups, see the full report")
        head.append("<pre>" + esc("\n".join(rows)) + "</pre>")
    head.append(_status_block(report))
    if run_url:
        head.append(f'🔗 <a href="{esc(run_url)}">Workflow run</a> (the full JSON report is attached separately)')

    blocks = ["\n".join(head)]
    for g in report["groups"]:
        blocks.append(_group_block(g))
    return _pack(blocks)


def _status_block(report: dict) -> str:
    esc = _esc
    lines = ["🖥 <b>System status</b>"]
    cs = report["containers"]
    if cs:
        parts = []
        for c in cs:
            ok = c["status"] == "running" or (c["service"] in ONE_SHOT and c["exit_code"] == 0)
            parts.append(f"{c['service']} {'✅' if ok else '❌'} {c['status']} (restarts {c['restart_count']})")
        lines.append("• Containers: " + " | ".join(esc(p) for p in parts))
    done = report["backup"]["completed_at"]
    if done:
        backup = "✅ completed at " + ", ".join(t[11:16] for t in done)
    elif not report["backup"]["service_present"]:
        backup = "⚠️ no backup service detected"
    elif not report["backup"].get("overdue", True):
        backup = f"⏳ not due yet (scheduled {report['backup'].get('scheduled')})"
    else:
        backup = "❌ no completion record"
    lines.append("• Database backup: " + backup)
    if report["recent_deploys"]:
        lines.append(
            "• Deploys / recreated containers: "
            + ", ".join(f"{esc(d['service'])} {d['created'][11:16]}" for d in report["recent_deploys"])
        )
    t = report["traffic"]
    lines.append(f"• Traffic (nginx): {t['requests']:,} requests | 4xx {t['status_4xx']:,} | 5xx {t['status_5xx']:,}")
    return "\n".join(lines)


def _group_block(g: dict) -> str:
    esc = _esc
    first, last = g["first_seen"][11:19], g["last_seen"][11:19]
    novelty = (
        "🆕 First seen in the last 7 days"
        if g["new_in_last_7_days"]
        else "↩️ Also seen in the last 7 days: " + ", ".join(f"{d[5:]}×{n}" for d, n in g["previous_days"].items())
    )
    lines = [
        f"{LEVEL_ICON[g['level']]} <b>#{g['id']} [{g['level']}] {esc(g['service'])}</b> ×{g['count']}"
        f" | {first} ~ {last}",
        esc(g["title"]),
        f"By hour: {', '.join(f'{h}h×{n}' for h, n in g['hourly'].items())}",
        novelty,
    ]
    if g["exception"]:
        lines.append(f"Exception: <code>{esc(g['exception'][:300])}</code>")
    if g["location"]:
        where = g["location"] + (f" (raised at: {g['raised_at']})" if g["raised_at"] != g["location"] else "")
        lines.append(f"Location: <code>{esc(where)}</code>")
    if g["requests"]:
        lines.append("Requests: " + ", ".join(f"<code>{esc(r)}</code>×{n}" for r, n in g["requests"].items()))
    if g["samples"] and not g["exception"]:
        lines.append(f"Sample: <code>{esc(g['samples'][0][:300])}</code>")
    return "\n".join(lines)


def _pack(blocks: list[str]) -> list[str]:
    """Fill messages up to TG_LIMIT block by block; a block is never split, so no HTML tag is cut in half."""
    messages: list[str] = []
    cur = ""
    for b in blocks:
        b = b if len(b) <= TG_LIMIT else b[: TG_LIMIT - 20] + "…"
        if cur and len(cur) + 2 + len(b) > TG_LIMIT:
            messages.append(cur)
            cur = b
        else:
            cur = f"{cur}\n\n{b}" if cur else b
    if cur:
        messages.append(cur)
    return messages


def _strip_html(text: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", text))


def _tg(token: str, method: str, data: bytes, content_type: str) -> dict:
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}", data=data, headers={"Content-Type": content_type}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}") | {"ok": False, "http_status": e.code}


def send_message(token: str, chat_id: str, text: str) -> None:
    def post(body: dict) -> dict:
        return _tg(token, "sendMessage", json.dumps(body).encode(), "application/json")

    body = {"chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    res = post(body)
    # If Telegram cannot parse the formatting, resend as plain text so the message still arrives.
    if not res.get("ok") and "can't parse entities" in str(res.get("description", "")).lower():
        res = post({"chat_id": chat_id, "text": _strip_html(text), "disable_web_page_preview": True})
    if not res.get("ok"):
        raise RuntimeError(f"Telegram sendMessage failed: {res}")


def send_document(token: str, chat_id: str, filename: str, content: bytes, caption: str) -> None:
    boundary = uuid.uuid4().hex
    parts = []
    for name, value in (("chat_id", chat_id), ("caption", caption)):
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{filename}"\r\n'
        "Content-Type: application/json\r\n\r\n".encode()
        + content
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    res = _tg(token, "sendDocument", b"".join(parts), f"multipart/form-data; boundary={boundary}")
    if not res.get("ok"):
        raise RuntimeError(f"Telegram sendDocument failed: {res}")


def _names(text: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in text.split(",") if x.strip())


def main(argv: list[str] | None = None) -> int:
    global LONG_RUNNING, ONE_SHOT
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("collect_dir", type=Path)
    p.add_argument("--date", help="local date to report on (YYYY-MM-DD); default: yesterday")
    p.add_argument("--project", default=os.getenv("REPORT_PROJECT") or "my-app")
    p.add_argument("--utc-offset", type=float, default=float(os.getenv("REPORT_UTC_OFFSET") or 0))
    p.add_argument("--backup-time", default=os.getenv("BACKUP_TIME") or "22:00")
    p.add_argument("--services", default=",".join(LONG_RUNNING), help="services expected to be running")
    p.add_argument("--one-shot", default=",".join(ONE_SHOT), help="services that run once and exit")
    p.add_argument("--run-url", default="")
    p.add_argument("--out-dir", type=Path, help="write report.json and message.txt here")
    p.add_argument("--send", action="store_true", help="send to Telegram (needs TELEGRAM_TOKEN and TELEGRAM_CHAT_ID)")
    args = p.parse_args(argv)

    set_utc_offset(args.utc_offset)
    LONG_RUNNING, ONE_SHOT = _names(args.services), _names(args.one_shot)

    day = date.fromisoformat(args.date) if args.date else datetime.now(LOCAL_TZ).date() - timedelta(days=1)
    report = analyze(args.collect_dir, day, args.backup_time)
    report["project"] = args.project
    report["run_url"] = args.run_url
    messages = render_messages(report, args.project, args.run_url)
    report_json = json.dumps(report, ensure_ascii=False, indent=2)

    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        (args.out_dir / "report.json").write_text(report_json, encoding="utf-8")
        (args.out_dir / "message.txt").write_text("\n\n----\n\n".join(map(_strip_html, messages)), encoding="utf-8")
    print("\n\n----\n\n".join(map(_strip_html, messages)))

    if args.send:
        token, chat_id = os.environ.get("TELEGRAM_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
        if not token or not chat_id:
            print("::error::TELEGRAM_TOKEN or TELEGRAM_CHAT_ID is missing", file=sys.stderr)
            return 1
        for m in messages:
            send_message(token, chat_id, m)
        caption = f"{args.project} {report['date']} error report (full JSON, with tracebacks)"
        send_document(token, chat_id, f"error-report-{report['date']}.json", report_json.encode(), caption)
    return 0


if __name__ == "__main__":
    sys.exit(main())
