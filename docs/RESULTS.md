# Verified results (local run, Windows 11 + Docker Desktop)

| Stage | Result |
|---|---|
| Unit + security tests (pytest) | **51 passed** |
| Gitleaks (full git history) | No leaks |
| Bandit (app code) | No medium/high issues |
| Semgrep (Python rules + 4 custom rules) | 0 findings |
| pip-audit (runtime deps) | No known vulnerabilities |
| Trivy filesystem | No blocking findings |
| Docker image | `python:3.12-slim-trixie`, multi-stage, UID 10001, ~58 MB, pip removed |
| Trivy image | 0 CRITICAL; 47 HIGH / 74 MEDIUM / 65 LOW / 15 UNKNOWN, all OS packages with **no upstream fix**: reported, not blocking by policy |
| SBOM (Syft) | CycloneDX + SPDX, 641 components (120 libraries, 1 OS) |
| Security gate | **PASS** (0 blocking, 0 exceptions, 0 process problems) |
| Staging verification | **16/16 checks passed** (health, headers, register/login/profile, non-root, read-only FS, no secrets in logs) |
| Teardown | Containers, volume and network removed |

## The remediation story (what the gate actually caught)
1. First image (Debian 12): **2 CRITICAL** CVEs (`zlib1g`, `libsqlite3-0`) -> gate FAIL.
2. Moved to Debian 13: CRITICALs gone, but **2 HIGH `zlib1g` CVEs with a published fix** -> gate FAIL (policy: HIGH + fix available blocks).
3. Added `apt-get upgrade` to the image -> patched -> gate **PASS**, no exception needed.
4. Semgrep false positives (`token_type`, `token_issuer` flagged as secrets) -> rule regex tightened, not suppressed.

See `docs/sample-reports/gate-summary.txt` for the full gate output.
