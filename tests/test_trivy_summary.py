"""Tests for .github/scripts/trivy_summary.py."""

import trivy_summary as ts

REPORT = {
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "Python",
            "Class": "lang-pkgs",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "PkgName": "jose", "Severity": "CRITICAL", "FixedVersion": ""},
                {"VulnerabilityID": "CVE-2", "PkgName": "pip", "Severity": "MEDIUM", "FixedVersion": "26.1"},
            ],
        },
        {
            "Target": "debian",
            "Class": "os-pkgs",
            "Vulnerabilities": [{"VulnerabilityID": "CVE-3", "PkgName": "libc", "Severity": "HIGH"}],
        },
    ],
}
VERSION = {"Version": "0.75.0", "VulnerabilityDB": {"UpdatedAt": "2026-10-07T00:53:05.111120428Z"}}


def test_render_failed_gate_lists_items_and_stats():
    md = ts.render([REPORT], VERSION, [("Source", "success"), ("Image", "failure")], [("SBOM", "https://x/1")])
    assert "❌ a check failed, the release is blocked" in md
    assert "| Image | ❌ failed |" in md
    assert "2026-10-07 00:53 UTC" in md
    assert "| P0: Critical | yes | Package jose" in md
    assert "| P2: Medium | no | Package pip" in md
    assert "libc" not in md  # unfixable OS package: counted in the statistics, not listed as an item to fix
    assert "| OS package vulnerabilities (image, no fix yet) | - | 1 |" in md
    assert "[SBOM](https://x/1)" in md


def test_render_all_clear():
    md = ts.render([{"Results": []}], None, [("Source", "success")], [])
    assert "✅ all checks passed, the release may deploy" in md
    assert "None 🎉" in md
    assert "No findings." in md


def test_main_survives_missing_report(tmp_path, capsys):
    assert ts.main([str(tmp_path / "missing.json"), "--check", "Source=failure"]) == 0
    out = capsys.readouterr().out
    assert "Could not read report" in out
    assert "| Source | ❌ failed |" in out
