# Security design notes & known limitations

## App decisions
* **Argon2id** password hashing (salted, memory-hard). Dummy-hash verification on unknown users reduces timing-based user enumeration.
* **JWT (HS256)**: algorithm pinned on decode (blocks `alg=none`), required `exp/iat/sub/iss`, short TTL (30 min), user re-checked in DB each request.
* **Secrets** only from environment (`APP_SECRET_KEY`, min 32 chars, app refuses to start without it).
* **SQLite + parameterized queries**; strict Pydantic validation with `extra="forbid"`.
* **Errors**: generic 500; validation errors name the field, never echo values.
* **Headers**: nosniff, frame deny, CSP `default-src 'none'`, no-store, referrer/permissions policy. HSTS is omitted because TLS terminates at a reverse proxy not included here.
* **CORS** disabled unless explicit origins are configured; `*` is rejected at config load.
* **Logging**: JSON, metadata only (method/path/status), query strings and bodies never logged.

## Not covered / honest limitations
* No rate limiting or account lockout (brute-force protection) - add at gateway or with a library for production.
* No HTTPS in local staging (plain HTTP on localhost only).
* No token revocation/refresh flow. HS256 shared secret; consider asymmetric keys for multi-service setups.
* DAST (OWASP ZAP) is an *optional stage* against staging - see below. Cosign signing is an advanced stage that needs a registry or `cosign sign-blob`; not wired into the gate.
* Base images are pinned by tag, not by digest; pin digests (Dependabot/Renovate can update them) for stronger supply-chain guarantees.
* Semgrep registry rules need network access; custom local rules in `.semgrep/` work offline.

## Optional: OWASP ZAP baseline against staging
```powershell
docker compose up -d
docker run --rm --network host -v ${PWD}/reports:/zap/wrk ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://127.0.0.1:8000 -r zap.html
```
(On Docker Desktop for Windows use `http://host.docker.internal:8000`.) Treat ZAP warnings with the same triage rules as other tools.

## Optional: sign artifacts with Cosign
`cosign generate-key-pair` (store the private key as a CI secret, never in Git), then `cosign sign-blob --key cosign.key reports/sbom.cdx.json`. Keyless (OIDC) signing in GitHub Actions needs `id-token: write` on that one job only.
