"""Turn the Trivy scan results into the Summary page of the Actions run.

Contents: whether each gate check passed, the vulnerability database version, counts per
category and severity, the items to fix (same rules as the automatic issues, see
trivy_issues.py), and download links for the reports.

Usage (inside CI):
  python .github/scripts/trivy_summary.py --version version.json \\
      --check "Source=success" --check "Image libraries=failure" ... \\
      --artifact "SBOM=https://..." fs.json image.json license.json >> "$GITHUB_STEP_SUMMARY"
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime

from trivy_issues import GATE_SEVERITIES, SEVERITY_RANK, collect, render_title

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
OUTCOME_ICON = {"success": "✅ passed", "failure": "❌ failed", "skipped": "⏭️ skipped", "cancelled": "⏹️ cancelled"}


def _utc(ts: str | None) -> str:
    """Trivy reports UTC with nanoseconds; trim it to something readable."""
    if not ts:
        return "?"
    try:
        return datetime.fromisoformat(ts[:19]).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return ts


def count(reports: list[dict]) -> dict[str, Counter]:
    """Findings per category and severity. Every severity is counted, without the gate
    thresholds; a finding present in both the source and the image is counted in each."""
    rows: dict[str, Counter] = {}

    def add(category: str, severity: str) -> None:
        rows.setdefault(category, Counter())[severity] += 1

    for report in reports:
        source = "image" if report.get("ArtifactType") == "container_image" else "source"
        for res in report.get("Results") or []:
            for v in res.get("Vulnerabilities") or []:
                kind = "OS package" if res.get("Class") == "os-pkgs" else "Application package"
                fix = "fix available" if v.get("FixedVersion") else "no fix yet"
                add(f"{kind} vulnerabilities ({source}, {fix})", v.get("Severity", "UNKNOWN"))
            for m in res.get("Misconfigurations") or []:
                if m.get("Status") == "FAIL":
                    add(f"Misconfigurations ({source})", m.get("Severity", "UNKNOWN"))
            for s in res.get("Secrets") or []:
                add(f"Possible secrets ({source})", s.get("Severity", "UNKNOWN"))
            for lic in res.get("Licenses") or []:
                add(f"Licenses ({source}, application packages)", lic.get("Severity", "UNKNOWN"))
    return rows


def render(
    reports: list[dict], version: dict | None, checks: list[tuple[str, str]], artifacts: list[tuple[str, str]]
) -> str:
    out = ["## 🔒 Trivy security scan", ""]

    gate_ok = all(outcome == "success" for _, outcome in checks)
    verdict = "✅ all checks passed, the release may deploy" if gate_ok else "❌ a check failed, the release is blocked"
    out += [f"**Deployment gate: {verdict}**", ""]
    out += ["| Check | Result |", "|---|---|"]
    out += [f"| {name} | {OUTCOME_ICON.get(outcome, outcome)} |" for name, outcome in checks]
    out.append("")

    if version:
        db = version.get("VulnerabilityDB") or {}
        out += [
            "### Vulnerability database",
            "",
            f"- Trivy version: `{version.get('Version', '?')}`",
            f"- Database built (UpdatedAt): {_utc(db.get('UpdatedAt'))}",
            f"- Downloaded for this run (DownloadedAt): {_utc(db.get('DownloadedAt'))}",
            "",
        ]

    found = collect(reports)
    out += ["### Items to fix", ""]
    if found:
        out += ["| Priority | Blocks deploy | Item |", "|---|---|---|"]
        for f in sorted(found.values(), key=lambda f: (-SEVERITY_RANK[f.severity], f.key)):
            blocking = "yes" if f.severity in GATE_SEVERITIES else "no"
            out.append(f"| {f.priority_label} | {blocking} | {render_title(f).removeprefix('[trivy] ')} |")
        out += ["", "Scans of `main` sync these items to GitHub issues (label `security`)."]
    else:
        out.append("None 🎉")
    out.append("")

    stats = count(reports)
    out += ["### All findings (including the ones that do not block)", ""]
    if stats:
        out += ["| Category | " + " | ".join(SEVERITIES) + " |", "|---|" + "---|" * len(SEVERITIES)]
        for category in sorted(stats):
            c = stats[category]
            out.append(f"| {category} | " + " | ".join(str(c[s]) if c[s] else "-" for s in SEVERITIES) + " |")
    else:
        out.append("No findings.")
    out.append("")

    if artifacts:
        out += ["### Downloads", ""]
        out += [f"- [{name}]({url})" for name, url in artifacts if url]
        out.append("")
    return "\n".join(out)


def _pair(text: str) -> tuple[str, str]:
    name, _, value = text.partition("=")
    return name, value


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reports", nargs="*", help="output files of trivy --format json")
    ap.add_argument("--version", help="output file of trivy version --format json")
    ap.add_argument("--check", action="append", default=[], type=_pair, help="name=step outcome")
    ap.add_argument("--artifact", action="append", default=[], type=_pair, help="name=download URL")
    args = ap.parse_args(argv)

    reports = []
    for path in args.reports:
        try:
            with open(path, encoding="utf-8") as fh:
                reports.append(json.load(fh))
        except (OSError, ValueError) as exc:  # the summary must still be written when a report is missing
            print(f"> ⚠️ Could not read report `{path}`: {exc}\n")
    version = None
    if args.version:
        try:
            with open(args.version, encoding="utf-8") as fh:
                version = json.load(fh)
        except (OSError, ValueError):
            pass
    print(render(reports, version, args.check, args.artifact))
    return 0


if __name__ == "__main__":
    sys.exit(main())
