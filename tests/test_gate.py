"""Tests for the security gate itself - a gate that can't fail is worthless."""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import security_gate as g  # noqa: E402

POLICY = yaml.safe_load((Path(__file__).resolve().parents[1] / "security-policy.yml").read_text())
TODAY = dt.date(2026, 6, 1)


def write_clean(d: Path):
    (d / "gitleaks.json").write_text("[]")
    (d / "bandit.json").write_text(json.dumps({"results": []}))
    (d / "semgrep.json").write_text(json.dumps({"results": []}))
    (d / "pip-audit.json").write_text(json.dumps({"dependencies": []}))
    (d / "trivy-fs.json").write_text(json.dumps({"Results": []}))
    (d / "trivy-image.json").write_text(json.dumps({"Results": []}))


def trivy(sev, fixed=None, vid="CVE-2099-1"):
    return {"Results": [{"Target": "t", "Vulnerabilities": [
        {"VulnerabilityID": vid, "PkgName": "libx", "Severity": sev, "FixedVersion": fixed}]}]}


def run(d, exc=None):
    return g.evaluate(d, POLICY, exc or {"exceptions": []}, TODAY)


def test_clean_reports_pass(tmp_path):
    write_clean(tmp_path)
    b, _, _, p = run(tmp_path)
    assert not b and not p


def test_missing_report_fails_closed(tmp_path):
    write_clean(tmp_path)
    (tmp_path / "trivy-image.json").unlink()
    assert run(tmp_path)[3]


def test_secret_blocks(tmp_path):
    write_clean(tmp_path)
    (tmp_path / "gitleaks.json").write_text(json.dumps([{"RuleID": "aws-access-token", "File": "x", "StartLine": 1, "Commit": "abcdef123"}]))
    assert run(tmp_path)[0]


def test_critical_image_vuln_blocks(tmp_path):
    write_clean(tmp_path)
    (tmp_path / "trivy-image.json").write_text(json.dumps(trivy("CRITICAL")))
    assert run(tmp_path)[0]


def test_high_with_fix_blocks_but_high_without_fix_is_reported(tmp_path):
    write_clean(tmp_path)
    (tmp_path / "trivy-image.json").write_text(json.dumps(trivy("HIGH", fixed="1.2.3")))
    assert run(tmp_path)[0]
    (tmp_path / "trivy-image.json").write_text(json.dumps(trivy("HIGH", fixed=None)))
    b, r, _, _ = run(tmp_path)
    assert not b and r


def test_medium_is_reported_not_blocking(tmp_path):
    write_clean(tmp_path)
    (tmp_path / "trivy-image.json").write_text(json.dumps(trivy("MEDIUM", fixed="9")))
    b, r, _, _ = run(tmp_path)
    assert not b and r


def test_pip_audit_vuln_blocks(tmp_path):
    write_clean(tmp_path)
    (tmp_path / "pip-audit.json").write_text(json.dumps(
        {"dependencies": [{"name": "foo", "version": "1", "vulns": [{"id": "PYSEC-1", "fix_versions": ["2"]}]}]}))
    assert run(tmp_path)[0]


def good_exception(**kw):
    e = dict(id="CVE-2099-1", tool="trivy_image", package="libx", justification="not reachable",
             owner="team-a", review_condition="on fix release", expires="2026-12-31")
    e.update(kw)
    return {"exceptions": [e]}


def test_valid_exception_downgrades_finding(tmp_path):
    write_clean(tmp_path)
    (tmp_path / "trivy-image.json").write_text(json.dumps(trivy("CRITICAL")))
    b, _, used, p = run(tmp_path, good_exception())
    assert not b and not p and used


def test_expired_exception_is_a_failure(tmp_path):
    write_clean(tmp_path)
    (tmp_path / "trivy-image.json").write_text(json.dumps(trivy("CRITICAL")))
    b, _, _, p = run(tmp_path, good_exception(expires="2026-01-01"))
    assert b and p


@pytest.mark.parametrize("field", ["justification", "owner", "review_condition", "expires"])
def test_incomplete_exception_is_rejected(tmp_path, field):
    write_clean(tmp_path)
    (tmp_path / "trivy-image.json").write_text(json.dumps(trivy("CRITICAL")))
    b, _, _, p = run(tmp_path, good_exception(**{field: ""}))
    assert b and p
