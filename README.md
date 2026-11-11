# Secure CI/CD Pipeline with Automated DevSecOps Controls

![CI](https://github.com/prabhavathi0419/secure-cicd-pipeline/actions/workflows/ci.yml/badge.svg)

A reference **DevSecOps pipeline**: every code change is automatically tested and security-scanned, and a **security gate** decides whether it may reach staging. A small FastAPI service is included as the thing being protected.

> Built from scratch for learning. All demo secrets/vulnerabilities are fake and isolated in `fixtures/`.

## What it is, in one picture
```
 git push / pull request
          │
          ▼
 ┌────────────────────── GitHub Actions ──────────────────────┐
 │ 1 Tests      pytest (51 tests, incl. security negatives)    │
 │ 2 Secrets    Gitleaks  -> any leaked key in history?        │
 │ 3 SAST       Bandit + Semgrep -> insecure code patterns     │
 │ 4 SCA        pip-audit + Trivy -> vulnerable libraries      │
 │ 5 Container  build image -> Trivy scan -> Syft SBOM         │
 └───────────────┬────────────────────────────────────────────┘
                 ▼
        6 SECURITY GATE  (policy in security-policy.yml)
          PASS │ FAIL -> pipeline blocked, nothing deploys
                 ▼
        7 Deploy to staging (main branch only) + 16 automated checks
```

## Why use it (benefits)
| Benefit | How |
|---|---|
| **Catch problems before production** | Secrets, vulnerable libraries, insecure code and image CVEs are found on every push, not months later in a pentest |
| **Nobody can skip security quietly** | Thresholds live in a reviewed file; missing scan reports **fail closed**; exceptions need owner, reason, review condition and an expiry date |
| **Less noise** | Blocks only what matters (secrets, CRITICAL, fixable HIGH); lower findings are reported, not blocking |
| **Supply-chain visibility** | An SBOM (CycloneDX + SPDX) is produced for every build |
| **Safe CI itself** | Least-privilege tokens, actions pinned to commit SHAs, no `pull_request_target`, verified tool downloads |
| **Proof, not promises** | Reports are uploaded as artifacts on every run |
| **A learning template** | Heavily commented code; `docs/CONCEPTS.md` explains each idea in plain English |

## Use it - three ways

### A) Just look at it running (no install)
Open the **Actions** tab. Click the latest run -> see the 6 checks and the gate; download **security-reports-all** (gate summary, Trivy JSON, SBOMs) from *Artifacts*.

### B) Use it as a template for your own project
1. Click **Use this template / Fork**, or copy these into your repo: `.github/workflows/ci.yml`, `security-policy.yml`, `security-exceptions.yml`, `scripts/`, `.gitleaks.toml`, `bandit.yaml`, `.semgrep/`, `Dockerfile`.
2. Replace `app/` and `tests/` with your Python app; adjust `requirements.txt` and the `Dockerfile`.
3. Tune thresholds in `security-policy.yml` (e.g. make Trivy block HIGH too).
4. Push a branch and open a pull request - the pipeline runs automatically.
5. In *Settings > Branches*, require the six checks before merging (see `docs/GITHUB_SETUP.md`).

### C) Run everything locally (Windows PowerShell, Docker Desktop)
```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
.\scripts\run-local.ps1          # tests + all scanners + gate (needs Docker for image/Semgrep/SBOM)
```
Then deploy to local staging and verify it:
```powershell
docker build -t secure-cicd-demo:local .
$env:APP_SECRET_KEY = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
docker compose up -d
.\.venv\Scripts\python scripts\verify_staging.py     # 16 checks: health, headers, non-root, no secrets in logs...
docker compose down -v
```
Run just the API for development:
```powershell
$env:APP_ENV="development"; $env:APP_SECRET_KEY=[guid]::NewGuid().ToString("N")+[guid]::NewGuid().ToString("N")
.\.venv\Scripts\uvicorn app.main:app --port 8000     # docs: http://127.0.0.1:8000/docs
```

## Reading the gate result
| Gate output | Meaning | What you do |
|---|---|---|
| **BLOCKING** | Policy violation (secret, CRITICAL, fixable HIGH, any pip-audit hit...) | Fix it: rotate/remove the secret, upgrade the package, patch the image |
| **REPORTED** | Real but non-blocking (e.g. HIGH with no upstream fix) | Track it; fix on a normal cadence |
| **Accepted via exception** | A documented accepted risk | Revisit before its expiry date |
| **Gate/process problems** | A report is missing or an exception is invalid | Fix the pipeline - a scan that didn't run proves nothing |

Accepting a risk? Add an entry to `security-exceptions.yml` (id, tool, justification, owner, review_condition, expires). Expired or incomplete entries fail the gate.

## The sample app
FastAPI service: `GET /health`, `POST /register`, `POST /login`, `GET /profile` (token-protected). Argon2id password hashing, pinned-algorithm JWT, strict input validation, parameterized SQL, security headers, generic errors, JSON logs without secrets, env-based config.

## Policy summary
| Finding | Result |
|---|---|
| Failing test | **Block** |
| Secret found by Gitleaks | **Block** |
| Bandit HIGH (confidence >= MEDIUM) / Semgrep ERROR | **Block** |
| Any pip-audit vulnerability | **Block** |
| Trivy CRITICAL (fs or image) | **Block** |
| Trivy HIGH with a fix available | **Block** (no fix yet: reported) |
| MEDIUM / LOW | Reported |
| Missing scan report / bad exception | **Block** |

## Verified results
See `docs/RESULTS.md`: 51 tests, 0 blocking findings, gate PASS, staging 16/16 checks (local and in GitHub Actions).

## Repository map
| Path | Purpose |
|---|---|
| `.github/workflows/ci.yml` | The pipeline (7 jobs) |
| `security-policy.yml`, `security-exceptions.yml` | Gate thresholds and accepted risks |
| `scripts/security_gate.py` | Applies the policy to scanner reports |
| `scripts/verify_staging.py`, `scripts/run-local.ps1`, `scripts/install-tools.sh` | Staging checks, local runner, verified tool installer |
| `app/`, `tests/` | The sample API and its tests |
| `Dockerfile`, `docker-compose.yml` | Hardened image (non-root, read-only FS) and local staging |
| `fixtures/` | Intentionally vulnerable demo code and its fixed twin (never shipped) |
| `docs/` | `CONCEPTS.md`, `DEMOS.md`, `RESULTS.md`, `GITHUB_SETUP.md`, `SECURITY_NOTES.md` |

## Limitations (honest list)
No rate limiting; staging is HTTP on localhost/CI runner; OWASP ZAP and Cosign signing are documented optional stages, not wired in; base images are pinned by tag, not digest; remaining image CVEs are OS packages with no upstream fix (reported by policy).

## Branching
`main` is deployable; work on `feature/<topic>` branches and merge via pull request. Enable branch protection yourself (see `docs/GITHUB_SETUP.md`) - it is **not** enabled automatically.
