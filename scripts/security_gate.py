"""Security gate: reads scanner reports + policy and decides PASS/FAIL.

Design rules
  * A missing/unreadable report is a FAILURE (a scan that did not run proves nothing).
  * Thresholds come from security-policy.yml (reviewable, CODEOWNERS-protected).
  * Exceptions come from security-exceptions.yml and must be complete and unexpired.
  * Every finding is either BLOCKING or REPORTED - nothing is silently dropped.

Usage: python scripts/security_gate.py [--reports reports] [--policy security-policy.yml]
Exit code: 0 = pass, 1 = fail.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import yaml

REQUIRED_EXCEPTION_FIELDS = ("id", "tool", "justification", "owner", "review_condition", "expires")
CONF_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


class GateError(Exception):
    pass


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GateError(f"report missing or unreadable: {path.name} ({exc.__class__.__name__})") from exc


def validate_exceptions(data: dict, today: dt.date) -> tuple[list[dict], list[str]]:
    problems, active = [], []
    for i, exc in enumerate((data or {}).get("exceptions") or []):
        missing = [f for f in REQUIRED_EXCEPTION_FIELDS if not exc.get(f)]
        if missing:
            problems.append(f"exception #{i + 1} ({exc.get('id', '?')}) missing fields: {', '.join(missing)}")
            continue
        expires = exc["expires"] if isinstance(exc["expires"], dt.date) else dt.date.fromisoformat(str(exc["expires"]))
        if expires < today:
            problems.append(f"exception {exc['id']} expired on {expires} - fix the finding or re-justify")
            continue
        active.append(exc)
    return active, problems


def is_excepted(finding_id: str, tool: str, pkg: str | None, exceptions: list[dict]) -> dict | None:
    for e in exceptions:
        if e["id"] == finding_id and e["tool"] == tool and (not e.get("package") or e["package"] == pkg):
            return e
    return None


def trivy_findings(report: dict) -> list[dict]:
    out = []
    for res in report.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            out.append(
                {
                    "id": v["VulnerabilityID"],
                    "pkg": v.get("PkgName"),
                    "severity": v.get("Severity", "UNKNOWN"),
                    "fixed": v.get("FixedVersion"),
                    "target": res.get("Target"),
                }
            )
    return out


def evaluate(reports: Path, policy: dict, exc_data: dict, today: dt.date | None = None):
    """Returns (blocking, reported, exceptions_used, problems)."""
    today = today or dt.date.today()
    exceptions, problems = validate_exceptions(exc_data, today)
    blocking: list[str] = []
    reported: list[str] = []
    used: list[str] = []

    def classify(tool, fid, pkg, is_blocking, text):
        exc = is_excepted(fid, tool, pkg, exceptions)
        if exc:
            used.append(f"[{tool}] {text}  -> EXCEPTION (owner={exc['owner']}, expires={exc['expires']})")
        elif is_blocking:
            blocking.append(f"[{tool}] {text}")
        else:
            reported.append(f"[{tool}] {text}")

    # gitleaks: JSON list of leaks
    try:
        leaks = load_json(reports / "gitleaks.json") or []
        for leak in leaks:
            classify("gitleaks", leak.get("RuleID", "?"), None, True,
                     f"{leak.get('RuleID')} in {leak.get('File')}:{leak.get('StartLine')} (commit {str(leak.get('Commit'))[:8]})")
    except GateError as e:
        problems.append(str(e))

    # bandit
    try:
        p = policy["bandit"]
        for r in load_json(reports / "bandit.json").get("results", []):
            sev, conf = r["issue_severity"], r["issue_confidence"]
            blocks = sev in p["block_severity"] and CONF_RANK[conf] >= CONF_RANK[p["block_min_confidence"]]
            classify("bandit", r["test_id"], None, blocks, f"{r['test_id']} {sev}/{conf} {r['filename']}:{r['line_number']} {r['issue_text']}")
    except GateError as e:
        problems.append(str(e))

    # semgrep
    try:
        p = policy["semgrep"]
        for r in load_json(reports / "semgrep.json").get("results", []):
            sev = r["extra"]["severity"]
            classify("semgrep", r["check_id"], None, sev in p["block_severity"], f"{r['check_id']} {sev} {r['path']}:{r['start']['line']}")
    except GateError as e:
        problems.append(str(e))

    # pip-audit
    try:
        for dep in load_json(reports / "pip-audit.json").get("dependencies", []):
            for v in dep.get("vulns", []):
                classify("pip_audit", v["id"], dep["name"], True,
                         f"{v['id']} {dep['name']}=={dep['version']} (fix: {', '.join(v.get('fix_versions') or []) or 'none'})")
    except GateError as e:
        problems.append(str(e))

    # trivy (fs + image)
    for tool, fname in (("trivy_fs", "trivy-fs.json"), ("trivy_image", "trivy-image.json")):
        try:
            p = policy[tool]
            for f in trivy_findings(load_json(reports / fname)):
                blocks = f["severity"] in p["block_severity"] or (
                    f["severity"] == "HIGH" and p.get("block_high_if_fix_available") and bool(f["fixed"])
                )
                classify(tool, f["id"], f["pkg"], blocks,
                         f"{f['id']} {f['severity']} {f['pkg']} (fixed in: {f['fixed'] or 'no fix yet'})")
        except GateError as e:
            problems.append(str(e))

    return blocking, reported, used, problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--policy", default="security-policy.yml")
    ap.add_argument("--exceptions", default="security-exceptions.yml")
    a = ap.parse_args()

    policy = yaml.safe_load(Path(a.policy).read_text(encoding="utf-8"))
    exc_data = yaml.safe_load(Path(a.exceptions).read_text(encoding="utf-8"))
    blocking, reported, used, problems = evaluate(Path(a.reports), policy, exc_data)

    def section(title, items):
        print(f"\n== {title} ({len(items)}) ==")
        for i in items:
            print("  -", i)

    section("BLOCKING findings", blocking)
    section("REPORTED (non-blocking) findings", reported)
    section("Accepted via documented exception", used)
    section("Gate/process problems (missing reports, bad exceptions)", problems)

    failed = bool(blocking or problems)
    print("\nSECURITY GATE:", "FAIL - deployment blocked" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
