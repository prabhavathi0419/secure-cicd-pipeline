# Demo transcripts (reproduced locally on Windows)

All demo material is fake and lives outside the real history (temp repos) or in `fixtures/`.

## Demo 1 - Secrets detection (Gitleaks)
Controlled fake GitHub-style token committed in a *throwaway* repo:
```
1. commit config.py containing GITHUB_TOKEN = "ghp_Zx8Q...(fake)"
   gitleaks git .        -> WRN leaks found: 1                 (exit code 1 => pipeline fails)
2. git rm config.py; git commit -m "remove secret"
   gitleaks dir .        -> no leaks found                     (working tree is clean...)
   gitleaks git .        -> WRN leaks found: 1                 (...but HISTORY still leaks)
   git show HEAD~1:config.py  -> prints the token              (this is what an attacker does)
3. Safe cleanup of UNPUSHED history: git reset --hard HEAD~2; git reflog expire --expire=now --all; git gc --prune=now
   gitleaks git .        -> no leaks found
```
**Lesson:** deletion is not removal. If the secret was ever pushed: (1) revoke/rotate it immediately, (2) rewrite history with `git filter-repo`/BFG, force-push, ask collaborators to re-clone, (3) check provider logs for misuse.
**Pipeline behaviour:** the `secrets` job scans full history (`fetch-depth: 0`); any leak -> gate FAIL.

## Demo 2 - SAST (Bandit; Semgrep runs in CI/Docker)
`fixtures/vulnerable/sqli_demo.py` (intentionally bad):
```
B602 HIGH/High   subprocess call with shell=True      CWE-78  (command injection)
B608 MEDIUM/Med  string-built SQL query               CWE-89  (SQL injection)
B105 LOW/Med     hard-coded password string           CWE-259
B404 LOW/High    imports subprocess (informational)
```
After the fix (`fixtures/fixed/sqli_demo.py`: parameterized query, allow-list validation, argument list without a shell, secret from environment):
```
bandit -ll fixtures/fixed/sqli_demo.py   -> no issues at MEDIUM or above
```
Remaining LOW items (B404/B603/B607) are informational: we do call `ping`, with validated input. They are reported, not hidden.
Explanation of each: *B602* - with `shell=True` the string goes through the shell, so `8.8.8.8 & del *` runs a second command. *B608* - `' OR '1'='1` changes the query's logic. Parameters keep data separate from SQL.

## Demo 3 - SCA (pip-audit + Trivy), disposable environment
Disposable `requirements.txt` (outside the project): `requests==2.19.0`, `jinja2==2.10`.
```
pip-audit  -> Found 22 known vulnerabilities in 2 packages (e.g. PYSEC-2018-28 fix 2.20.0, PYSEC-2021-66 fix 2.11.3)   exit 1
trivy fs   -> HIGH: CVE-2019-10906 jinja2 (fixed 2.10.1), CVE-2018-18074 requests (fixed 2.20.0)
upgrade    -> requests==2.34.0, jinja2==3.1.6
pip-audit  -> No known vulnerabilities found                                                                           exit 0
```
Real application dependencies (`requirements.txt`) were never downgraded; `pip-audit` on them reports **no known vulnerabilities**.
Safe-upgrade method: bump one package, run the test-suite, re-scan, commit with the CVE id in the message.

## Demo 4 - The gate fails closed
Running `scripts/security_gate.py` with some reports missing prints `report missing or unreadable ...` and **FAIL**. Unit tests for the gate (`tests/test_gate.py`) cover: missing reports, secrets, CRITICAL image CVE, HIGH with/without fix, MEDIUM report-only, pip-audit hit, valid/expired/incomplete exceptions.
