# Secure CI/CD Pipeline with Automated DevSecOps Controls

A small FastAPI service plus a GitHub Actions pipeline that **blocks insecure code from reaching staging**.
Everything here was built from scratch for learning; nothing is copied from another project.

```
 push / PR ──► tests ─┐
              secrets ─┤  (Gitleaks)
              sast    ─┤  (Bandit + Semgrep)         ┌──────────────┐     ┌─────────────────┐
              sca     ─┼─► reports/*.json ──────────►│ SECURITY GATE│────►│ deploy-staging  │
              container┘  (pip-audit, Trivy fs/image, │ policy + exc.│ ok  │ (main only,     │
                          Syft SBOM)                  └──────────────┘     │  docker compose)│
                                                          │ fail           └─────────────────┘
                                                          └─► pipeline blocked
```

## Repository map
| Path | Purpose |
|---|---|
| `app/` | FastAPI app (health, register, login, protected profile) |
| `tests/` | 50+ pytest tests: functional, negative, security, and tests of the gate itself |
| `.github/workflows/ci.yml` | The pipeline (7 jobs, least-privilege, SHA-pinned actions) |
| `security-policy.yml` | Gate thresholds (what blocks, what is only reported) |
| `security-exceptions.yml` | Accepted risks (owner, justification, review condition, expiry required) |
| `scripts/security_gate.py` | Reads scanner reports and enforces the policy |
| `scripts/verify_staging.py` | Post-deploy checks (health, headers, non-root, logs) |
| `scripts/install-tools.sh` | Checksum-verified, pinned install of Gitleaks/Trivy/Syft in CI |
| `scripts/run-local.ps1` | Run the whole security suite on Windows |
| `fixtures/` | **Intentionally vulnerable** demo code + its fixed twin (never shipped) |
| `Dockerfile`, `docker-compose.yml` | Hardened image + local staging |
| `docs/` | Concepts guide, demo transcripts, GitHub setup, threat notes |

## Quick start (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
.\.venv\Scripts\python -m pytest -q                 # run tests
.\scripts\run-local.ps1                              # tests + all scanners + gate
```
Run the API locally:
```powershell
$env:APP_ENV="development"; $env:APP_SECRET_KEY=[guid]::NewGuid().ToString("N")+[guid]::NewGuid().ToString("N")
.\.venv\Scripts\uvicorn app.main:app --port 8000      # docs at http://127.0.0.1:8000/docs
```
Local staging (needs Docker):
```powershell
docker build -t secure-cicd-demo:local .
$env:APP_SECRET_KEY=[guid]::NewGuid().ToString("N")+[guid]::NewGuid().ToString("N")
docker compose up -d
.\.venv\Scripts\python scripts\verify_staging.py
docker compose down -v
```

## Security gate policy (summary)
| Finding | Result |
|---|---|
| Failing test | **Block** |
| Secret detected by Gitleaks | **Block** |
| Bandit HIGH (confidence ≥ MEDIUM) / Semgrep ERROR | **Block**; lower levels reported |
| Any pip-audit vulnerability | **Block** |
| Trivy CRITICAL (fs or image) | **Block** |
| Trivy HIGH **with a fix available** | **Block**; HIGH with no fix is reported |
| MEDIUM / LOW | Reported in artifacts and job summary |
| Missing/unreadable scan report | **Block** (fail closed) |
| Exception without owner/justification/review/expiry, or expired | **Block** |

Edit thresholds in `security-policy.yml`. Because that file is covered by `CODEOWNERS`, loosening a gate needs the owner's review - it cannot happen silently.

## Docs
* `docs/CONCEPTS.md` - plain-English explanations (Git, Docker, SAST/DAST/SCA, CVE/CVSS, SBOM, gates).
* `docs/DEMOS.md` - recorded output of the secrets, SAST and SCA demos.
* `docs/GITHUB_SETUP.md` - pushing, branch protection, environments (manual steps).
* `docs/SECURITY_NOTES.md` - design decisions, limitations, what is *not* covered.

## Branching strategy
`main` is always deployable and protected. Work happens on `feature/<topic>` branches, merged through pull requests that must pass the pipeline.
