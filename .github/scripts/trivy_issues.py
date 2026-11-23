"""Sync the actionable findings of Trivy JSON reports to GitHub issues.

One issue per "thing to fix", matched through a hidden marker in the issue body
(<!-- trivy:key=... -->):
  - package vulnerabilities: every CVE of one package goes into a single issue
    (one upgrade fixes them together)
  - misconfiguration / secret / license: one issue per rule + file
The highest severity decides the priority label (CRITICAL→P0, HIGH→P1, MEDIUM→P2, LOW→P3).

What is included (the CI gate, plus medium and low findings that have a fix):
  - application package vulnerabilities: CRITICAL/HIGH always; MEDIUM/LOW only with a patched release
  - OS package vulnerabilities: only with a patched release (nothing can be done about the rest)
  - misconfigurations and secrets: HIGH/CRITICAL
  - licenses: CRITICAL (forbidden)

On every run: new findings open an issue, existing ones get their content and priority
updated, and open issues whose finding is gone are commented on and closed.

Usage:
  python .github/scripts/trivy_issues.py report1.json report2.json ...
  python .github/scripts/trivy_issues.py --dry-run report.json   # only print what would happen
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

SECURITY_LABEL = "security"
PRIORITY_LABELS = {
    "CRITICAL": "P0: Critical",
    "HIGH": "P1: High",
    "MEDIUM": "P2: Medium",
    "LOW": "P3: Low",
}
LABEL_COLORS = {
    "P0: Critical": "B60205",
    "P1: High": "D93F0B",
    "P2: Medium": "FBCA04",
    "P3: Low": "0E8A16",
    SECURITY_LABEL: "5319E7",
}
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
GATE_SEVERITIES = {"HIGH", "CRITICAL"}
KEY_RE = re.compile(r"<!-- trivy:key=(\S+) -->")
RUN_LINE = "- **Latest scan**"


@dataclass
class Finding:
    key: str
    kind: str  # vuln / misconfig / secret / license
    subject: str  # package name or rule ID
    severity: str
    rows: list[dict] = field(default_factory=list)
    targets: set[str] = field(default_factory=set)
    os_pkg: bool = False

    def bump(self, severity: str) -> None:
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(self.severity, 0):
            self.severity = severity

    @property
    def priority_label(self) -> str:
        return PRIORITY_LABELS[self.severity]


# ── Parse Trivy JSON ─────────────────────────────────────────────────────────


def _want_vuln(v: dict, os_pkg: bool) -> bool:
    sev = v.get("Severity", "UNKNOWN")
    if sev not in PRIORITY_LABELS:
        return False
    fixed = bool(v.get("FixedVersion"))
    if os_pkg:
        return fixed
    return sev in GATE_SEVERITIES or fixed


def collect(reports: list[dict]) -> dict[str, Finding]:
    found: dict[str, Finding] = {}

    def get(key: str, kind: str, subject: str, severity: str, os_pkg: bool = False) -> Finding:
        f = found.get(key)
        if f is None:
            f = found[key] = Finding(key, kind, subject, severity, os_pkg=os_pkg)
        f.bump(severity)
        return f

    for report in reports:
        # The image name carries the commit SHA and a filesystem scan carries the checkout
        # path; both change on every run. Only the kind of source is recorded, so the issue
        # text stays stable between scans.
        is_image = report.get("ArtifactType") == "container_image"
        for res in report.get("Results") or []:
            target = res.get("Target", "")
            where = f"image → {target}" if is_image else target
            cls = res.get("Class", "")
            os_pkg = cls == "os-pkgs"

            for v in res.get("Vulnerabilities") or []:
                if not _want_vuln(v, os_pkg):
                    continue
                pkg = v["PkgName"]
                f = get(f"vuln:{'os' if os_pkg else 'lib'}:{pkg}", "vuln", pkg, v["Severity"], os_pkg)
                f.targets.add("image → OS packages" if is_image and os_pkg else where)
                row = {
                    "id": v["VulnerabilityID"],
                    "severity": v["Severity"],
                    "installed": v.get("InstalledVersion", ""),
                    "fixed": v.get("FixedVersion", ""),
                    "title": (v.get("Title") or "").replace("|", "\\|").replace("\n", " "),
                    "url": v.get("PrimaryURL", ""),
                }
                if row not in f.rows:
                    f.rows.append(row)

            for m in res.get("Misconfigurations") or []:
                if m.get("Status") != "FAIL" or m.get("Severity") not in GATE_SEVERITIES:
                    continue
                f = get(f"misconfig:{m['ID']}:{target}", "misconfig", m["ID"], m["Severity"])
                f.targets.add(target)
                f.rows = [
                    {
                        "title": m.get("Title", ""),
                        "message": m.get("Message", ""),
                        "resolution": m.get("Resolution", ""),
                        "url": m.get("PrimaryURL", ""),
                    }
                ]

            for s in res.get("Secrets") or []:
                if s.get("Severity") not in GATE_SEVERITIES:
                    continue
                # Record the rule and the location only. The secret itself (Match / Code)
                # must never be written into an issue.
                f = get(f"secret:{s['RuleID']}:{target}", "secret", s["RuleID"], s["Severity"])
                f.targets.add(f"{target}:{s.get('StartLine', '?')}")
                f.rows = [{"title": s.get("Title", "")}]

            for lic in res.get("Licenses") or []:
                if lic.get("Severity") != "CRITICAL":
                    continue
                pkg = lic.get("PkgName") or lic.get("FilePath") or target
                f = get(f"license:{pkg}:{lic.get('Name')}", "license", pkg, lic["Severity"])
                f.targets.add(where)
                f.rows = [{"license": lic.get("Name", ""), "category": lic.get("Category", "")}]
    return found


# ── Render issue content ─────────────────────────────────────────────────────


def _sorted_rows(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (-SEVERITY_RANK.get(r.get("severity", ""), 0), r.get("id", "")))


def render_title(f: Finding) -> str:
    if f.kind == "vuln":
        kind = "OS package" if f.os_pkg else "Package"
        noun = "vulnerability" if len(f.rows) == 1 else "vulnerabilities"
        return f"[trivy] {kind} {f.subject}: {len(f.rows)} {noun} to fix (highest {f.severity})"
    if f.kind == "misconfig":
        return f"[trivy] Misconfiguration {f.subject}: {f.rows[0]['title']}"
    if f.kind == "secret":
        return f"[trivy] Possible leaked secret ({f.subject})"
    return f"[trivy] Package {f.subject} uses the forbidden license {f.rows[0]['license']}"


def _vuln_advice(f: Finding) -> str:
    unfixed = [r["id"] for r in f.rows if not r["fixed"]]
    # FixedVersion can list several release lines ("1.2.3, 1.3.1"); take the highest of all.
    fixed = {x.strip() for r in f.rows for x in r["fixed"].split(",") if x.strip()}
    lines = []
    if fixed:
        lines.append(
            f"- Upgrade `{f.subject}` to `{max(fixed, key=_version_key)}` or later "
            "(this fixes every vulnerability above that has a patched release)."
        )
        if f.os_pkg:
            lines.append(
                "  OS packages come from the base image. Rebuilding the image, which applies the "
                "latest security updates, is usually enough."
            )
    if unfixed:
        lines.append(
            f"- {', '.join(unfixed)}: no patched release upstream yet. Consider replacing the package, "
            "or accept the risk in `.trivyignore` with a reason and an `exp:` expiry date."
        )
    return "\n".join(lines)


def _version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def render_body(f: Finding, run_url: str) -> str:
    # The inclusion rules already drop unfixable OS packages, so every remaining
    # HIGH/CRITICAL finding is one that blocks deployment.
    blocking = f.severity in GATE_SEVERITIES
    out = [
        f"<!-- trivy:key={f.key} -->",
        "Created and updated automatically by the Trivy scan in CI. "
        "It closes itself once a later scan no longer finds the problem.",
        "",
        f"- **Priority**: {f.priority_label} (highest severity {f.severity})",
        f"- **Blocks deployment**: {'yes' if blocking else 'no'}",
        f"- **Found in**: {', '.join(f'`{t}`' for t in sorted(f.targets))}",
    ]
    if run_url:
        out.append(f"{RUN_LINE}: {run_url}")
    out.append("")
    if f.kind == "vuln":
        out += [
            "| Vulnerability | Severity | Installed | Fixed in | Description |",
            "|---|---|---|---|---|",
        ]
        for r in _sorted_rows(f.rows):
            vid = f"[{r['id']}]({r['url']})" if r["url"] else r["id"]
            out.append(f"| {vid} | {r['severity']} | `{r['installed']}` | {r['fixed'] or 'none yet'} | {r['title']} |")
        out += ["", "### Suggested fix", _vuln_advice(f)]
    elif f.kind == "misconfig":
        r = f.rows[0]
        out += [f"**{r['title']}**", "", r["message"], "", f"Suggested fix: {r['resolution']}"]
        if r["url"]:
            out += ["", r["url"]]
    elif f.kind == "secret":
        out += [
            f"Rule: {f.rows[0]['title']}",
            "",
            "Check whether this is a real key or password. If it is: rotate the credential immediately, "
            "remove it from the code, and consider purging it from the git history. "
            "If it is a false positive, add it to `.trivyignore`.",
        ]
    else:
        r = f.rows[0]
        out += [
            f"License `{r['license']}` is in the `{r['category']}` category. "
            "Replace the package with one under a different license."
        ]
    return "\n".join(out) + "\n"


# ── Plan the actions (pure function, easy to test) ───────────────────────────


@dataclass
class Action:
    op: str  # create / update / close
    number: int | None = None
    title: str = ""
    body: str = ""
    add_labels: list[str] = field(default_factory=list)
    remove_labels: list[str] = field(default_factory=list)


def plan(found: dict[str, Finding], existing: list[dict], run_url: str = "") -> list[Action]:
    """existing: output of `gh issue list --json number,title,body,labels` (open, security label)."""
    by_key: dict[str, dict] = {}
    for issue in existing:
        m = KEY_RE.search(issue.get("body") or "")
        if m:
            by_key[m.group(1)] = issue

    actions: list[Action] = []
    for key, f in sorted(found.items(), key=lambda kv: (-SEVERITY_RANK[kv[1].severity], kv[0])):
        title, body = render_title(f), render_body(f, run_url)
        issue = by_key.get(key)
        if issue is None:
            actions.append(Action("create", title=title, body=body, add_labels=[SECURITY_LABEL, f.priority_label]))
            continue
        labels = {lbl["name"] for lbl in issue.get("labels", [])}
        stale = sorted(lbl for lbl in labels if lbl in PRIORITY_LABELS.values() and lbl != f.priority_label)
        missing = [lbl for lbl in (SECURITY_LABEL, f.priority_label) if lbl not in labels]
        # The "Latest scan" link differs on every run; ignore that line when comparing so the
        # issue is not edited (and its watchers notified) by every scan.
        changed = _strip_run(issue.get("body") or "") != _strip_run(body) or issue.get("title") != title
        if changed or stale or missing:
            actions.append(
                Action(
                    "update",
                    number=issue["number"],
                    title=title,
                    body=body,
                    add_labels=missing,
                    remove_labels=stale,
                )
            )

    for key, issue in by_key.items():
        if key not in found:
            actions.append(Action("close", number=issue["number"], title=issue.get("title", "")))
    return actions


def _strip_run(body: str) -> str:
    return "\n".join(line for line in body.splitlines() if not line.startswith(RUN_LINE))


# ── Apply (gh CLI) ───────────────────────────────────────────────────────────


def _gh(*args: str, stdin: str | None = None) -> str:
    return subprocess.run(["gh", *args], input=stdin, text=True, capture_output=True, check=True).stdout


def ensure_labels(repo: str) -> None:
    have = {lbl["name"] for lbl in json.loads(_gh("label", "list", "-R", repo, "--limit", "200", "--json", "name"))}
    for name, color in LABEL_COLORS.items():
        if name not in have:
            _gh("label", "create", name, "-R", repo, "--color", color)


def fetch_existing(repo: str) -> list[dict]:
    out = _gh(
        "issue",
        "list",
        "-R",
        repo,
        "--label",
        SECURITY_LABEL,
        "--state",
        "open",
        "--limit",
        "500",
        "--json",
        "number,title,body,labels",
    )
    return json.loads(out)


def apply(repo: str, actions: list[Action], run_url: str) -> None:
    for a in actions:
        if a.op == "create":
            args = ["issue", "create", "-R", repo, "--title", a.title, "--body-file", "-"]
            for lbl in a.add_labels:
                args += ["--label", lbl]
            print(_gh(*args, stdin=a.body).strip())
        elif a.op == "update":
            args = ["issue", "edit", str(a.number), "-R", repo, "--title", a.title, "--body-file", "-"]
            for lbl in a.add_labels:
                args += ["--add-label", lbl]
            for lbl in a.remove_labels:
                args += ["--remove-label", lbl]
            _gh(*args, stdin=a.body)
            print(f"updated #{a.number}")
        else:
            note = f"The latest Trivy scan no longer finds this problem, closing automatically. {run_url}".strip()
            _gh("issue", "close", str(a.number), "-R", repo, "--comment", note)
            print(f"closed #{a.number}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reports", nargs="+", help="output files of trivy --format json")
    ap.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", ""))
    ap.add_argument("--dry-run", action="store_true", help="print the planned actions without calling GitHub")
    args = ap.parse_args(argv)

    reports = []
    for path in args.reports:
        with open(path, encoding="utf-8") as fh:
            reports.append(json.load(fh))
    found = collect(reports)

    run_url = ""
    if os.getenv("GITHUB_RUN_ID"):
        server = os.getenv("GITHUB_SERVER_URL", "https://github.com")
        run_url = f"{server}/{args.repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}"

    if args.dry_run:
        for a in plan(found, [], run_url):
            print(f"[{a.op}] {' '.join(a.add_labels)} :: {a.title}")
        return 0

    if not args.repo:
        print("--repo / GITHUB_REPOSITORY is missing", file=sys.stderr)
        return 2
    ensure_labels(args.repo)
    actions = plan(found, fetch_existing(args.repo), run_url)
    apply(args.repo, actions, run_url)
    print(f"{len(found)} findings, {len(actions)} issue actions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
