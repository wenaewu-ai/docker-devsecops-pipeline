"""Tests for .github/scripts/trivy_issues.py."""

import trivy_issues as ti


def _vuln(vid, pkg, sev, fixed="", installed="1.0"):
    return {
        "VulnerabilityID": vid,
        "PkgName": pkg,
        "Severity": sev,
        "FixedVersion": fixed,
        "InstalledVersion": installed,
        "Title": f"{vid} title",
        "PrimaryURL": f"https://avd.example/{vid}",
    }


def _image_report(lib_vulns=(), os_vulns=(), secrets=(), sha="abc123"):
    return {
        "ArtifactName": f"app:{sha}",
        "ArtifactType": "container_image",
        "Results": [
            {"Target": f"app:{sha} (debian 13.7)", "Class": "os-pkgs", "Vulnerabilities": list(os_vulns)},
            {"Target": "Python", "Class": "lang-pkgs", "Vulnerabilities": list(lib_vulns)},
            {"Target": "/app/config.py", "Class": "secret", "Secrets": list(secrets)},
        ],
    }


def test_collect_rules():
    report = _image_report(
        lib_vulns=[
            _vuln("CVE-1", "jose", "CRITICAL"),  # CRITICAL is included even without a fix
            _vuln("CVE-2", "jose", "HIGH", fixed="2.0"),
            _vuln("CVE-3", "pip", "MEDIUM", fixed="26.1"),  # MEDIUM with a fix: included
            _vuln("CVE-4", "foo", "MEDIUM"),  # MEDIUM without a fix: left out
        ],
        os_vulns=[
            _vuln("CVE-5", "libc", "HIGH"),  # OS package without a fix: left out
            _vuln("CVE-6", "openssl", "LOW", fixed="3.0.1"),  # OS package with a fix: included
        ],
    )
    found = ti.collect([report])
    assert set(found) == {"vuln:lib:jose", "vuln:lib:pip", "vuln:os:openssl"}
    jose = found["vuln:lib:jose"]
    assert jose.severity == "CRITICAL"
    assert jose.priority_label == "P0: Critical"
    assert len(jose.rows) == 2
    assert found["vuln:lib:pip"].priority_label == "P2: Medium"
    assert found["vuln:os:openssl"].priority_label == "P3: Low"


def test_same_package_in_source_and_image_merges_into_one_issue():
    fs = {
        "ArtifactName": ".",
        "ArtifactType": "filesystem",
        "Results": [
            {"Target": "requirements.txt", "Class": "lang-pkgs", "Vulnerabilities": [_vuln("CVE-1", "jose", "HIGH")]}
        ],
    }
    image = _image_report(lib_vulns=[_vuln("CVE-1", "jose", "HIGH")])
    found = ti.collect([fs, image])
    jose = found["vuln:lib:jose"]
    assert len(jose.rows) == 1
    assert jose.targets == {"requirements.txt", "image → Python"}


def test_secret_value_never_written_to_issue():
    report = _image_report(
        secrets=[
            {
                "RuleID": "aws-access-key-id",
                "Severity": "CRITICAL",
                "Title": "AWS Access Key ID",
                "StartLine": 3,
                "Match": "AKIAABCDEFGHIJKLMNOP",
                "Code": {"Lines": [{"Content": "AKIAABCDEFGHIJKLMNOP"}]},
            }
        ]
    )
    f = ti.collect([report])["secret:aws-access-key-id:/app/config.py"]
    text = ti.render_title(f) + ti.render_body(f, "")
    assert "AKIA" not in text
    assert "/app/config.py:3" in text


def test_fix_advice_uses_highest_fixed_version():
    report = _image_report(
        lib_vulns=[
            _vuln("CVE-1", "pip", "MEDIUM", fixed="25.3"),
            _vuln("CVE-2", "pip", "MEDIUM", fixed="26.1.2, 25.3.1"),
            _vuln("CVE-3", "pip", "MEDIUM", fixed="26.1"),
        ]
    )
    body = ti.render_body(ti.collect([report])["vuln:lib:pip"], "")
    assert "to `26.1.2` or later" in body


def test_title_singular_and_plural():
    one = ti.collect([_image_report(lib_vulns=[_vuln("CVE-1", "jose", "HIGH")])])["vuln:lib:jose"]
    assert ti.render_title(one) == "[trivy] Package jose: 1 vulnerability to fix (highest HIGH)"
    two = ti.collect(
        [_image_report(os_vulns=[_vuln("CVE-1", "zlib", "HIGH", "2"), _vuln("CVE-2", "zlib", "LOW", "2")])]
    )
    assert ti.render_title(two["vuln:os:zlib"]) == "[trivy] OS package zlib: 2 vulnerabilities to fix (highest HIGH)"


def _existing(found, key, priority_label, run_url="https://run/1", number=7):
    f = found[key]
    return {
        "number": number,
        "title": ti.render_title(f),
        "body": ti.render_body(f, run_url),
        "labels": [{"name": "security"}, {"name": priority_label}],
    }


def test_plan_create_noop_update_close():
    found = ti.collect([_image_report(lib_vulns=[_vuln("CVE-1", "jose", "HIGH")])])

    # First scan: open a new issue with the security and priority labels.
    [a] = ti.plan(found, [])
    assert a.op == "create"
    assert a.add_labels == ["security", "P1: High"]

    # Same content, only the run link differs: nothing to do.
    existing = [_existing(found, "vuln:lib:jose", "P1: High", run_url="https://run/1")]
    assert ti.plan(found, existing, run_url="https://run/2") == []

    # Severity rises to CRITICAL: update the content and swap the priority label.
    worse = ti.collect([_image_report(lib_vulns=[_vuln("CVE-1", "jose", "HIGH"), _vuln("CVE-9", "jose", "CRITICAL")])])
    [a] = ti.plan(worse, existing)
    assert (a.op, a.number) == ("update", 7)
    assert a.add_labels == ["P0: Critical"]
    assert a.remove_labels == ["P1: High"]

    # No longer found: close.
    [a] = ti.plan({}, existing)
    assert (a.op, a.number) == ("close", 7)


def test_issue_is_not_rewritten_when_only_the_image_tag_changes():
    # The image is tagged with the commit SHA, so the OS target name differs on every run.
    first = ti.collect([_image_report(os_vulns=[_vuln("CVE-1", "zlib", "HIGH", fixed="2")], sha="aaa111")])
    existing = [_existing(first, "vuln:os:zlib", "P1: High")]
    second = ti.collect([_image_report(os_vulns=[_vuln("CVE-1", "zlib", "HIGH", fixed="2")], sha="bbb222")])
    assert ti.plan(second, existing) == []


def test_plan_ignores_issues_without_marker():
    manual = {"number": 3, "title": "a security issue opened by hand", "body": "no marker", "labels": []}
    assert ti.plan({}, [manual]) == []
