# Concepts in plain English

## Git basics
* **Git** records the history of your files so you can go back, compare, and collaborate.
* **Commit** = a saved snapshot with a message and author. Commits are chained; each one points to its parent.
* **Branch** = a movable label on a commit. `main` is the stable line; `feature/x` is where you experiment safely.
* **Pull request (PR)** = "please merge my branch into main". It's where review and the automated pipeline happen *before* code lands.
* **.gitignore** = list of files Git must never track (virtualenvs, `.env`, keys, databases, scan output).
* **Why secrets must never enter history:** Git keeps *every* version forever and copies it to every clone. Deleting a file only adds a new commit; the old commit still contains the secret (see `docs/DEMOS.md`, demo 1). Once pushed, assume the secret is public: **rotate it first**, then clean history.

## Branching strategy used here
`main` (protected, deployable) <- PR <- `feature/<topic>`. No direct pushes to `main`; PR needs green checks.

## Kinds of security testing
| | What it examines | When | Finds | Misses |
|---|---|---|---|---|
| **SAST** (Bandit, Semgrep) | Source code, without running it | On every commit | SQL injection patterns, `shell=True`, hard-coded secrets | Runtime/config issues, business logic |
| **DAST** (OWASP ZAP) | The *running* app from outside, like an attacker | Against staging | Missing headers, XSS/injection reachable over HTTP, misconfigurations | Code paths it never reaches |
| **SCA** (pip-audit, Trivy) | Third-party libraries and their known CVEs | On every commit + nightly (new CVEs appear daily) | Vulnerable dependency versions | Unknown (0-day) flaws; your own bugs |
| **Manual review / pentest** | A human thinking like an attacker | Before big releases | Logic flaws, auth bypass, chained attacks | Doesn't scale; point-in-time |
They overlap but don't replace each other.

## CVE, CVSS, dependencies
* **CVE** = a public ID for a known vulnerability (`CVE-2018-18074`).
* **CVSS** = 0-10 severity score (Low <4, Medium 4-6.9, High 7-8.9, Critical 9+). It measures *potential* severity, not *your* risk - reachability and exposure matter.
* **Direct dependency** = a package you list in `requirements.txt`. **Transitive** = a package your dependency pulls in (FastAPI -> Starlette -> ...). Most vulnerable packages are transitive, so scan the resolved tree.

## Reading scanner findings
* **Confirmed vulnerability** - reproducible and reachable (e.g. injectable query on a public route). Fix now.
* **Potential** - pattern matches but needs a human check (e.g. `subprocess` used safely). Triage.
* **Informational** - best-practice hints (e.g. Bandit B404 "imports subprocess").
* **False positive** - scanner is wrong (e.g. vulnerable function never called, test fixture). Record it as an *exception* with owner, justification, expiry - never just ignore it.

## Docker
* **Image** = read-only template (OS files + your app) built from a Dockerfile.
* **Container** = a running instance of an image; an isolated process.
* **Layers** = each Dockerfile instruction adds a cached layer. Order matters: copy `requirements.txt` before code so dependency layers are reused. Anything written in a layer (even if deleted later) stays in the image -> never `COPY` secrets.
* **Isolation** = Linux *namespaces* (own process/network/filesystem view) + *cgroups* (resource limits) + *capabilities/seccomp* (restricted kernel powers). Containers share the host kernel, so they're weaker than VMs.
* **Why not root?** If an attacker escapes the app, root-in-container is much closer to root-on-host. Our image runs as UID 10001, with a read-only filesystem, all capabilities dropped, `no-new-privileges`.
* **Secrets** belong in runtime environment/secret stores, never in the image (`docker history` and registries expose them).

## Vulnerability severities & policy
* **Critical** - trivially exploitable, severe impact: block always.
* **High** - serious: block when a fix exists (no excuse not to upgrade), otherwise report + track.
* **Medium/Low** - report; fix on normal cadence.
* **Exceptions** need: id, tool, justification, owner, review condition, expiry (`security-exceptions.yml`). Expired = failure.

## SBOM
A **Software Bill of Materials** is an ingredient list of your artifact: every package, version, license, and hash (formats: CycloneDX, SPDX). When a new CVE drops (say Log4Shell) you can *query* your SBOMs and know within minutes which products are affected. Inspect it with `jq '.components[] | {name,version}' reports/sbom.cdx.json`. Attach it to each build so customers/auditors can verify it.

## CI/CD workflow security (what this pipeline does)
| Risk | Control |
|---|---|
| Over-powered token | `permissions: {}` at top; `contents: read` per job |
| Malicious/compromised action | Every `uses:` pinned to a full commit SHA |
| Untrusted PR code gets secrets | Only `pull_request` (no `pull_request_target`); deploy job runs only on `main` pushes |
| Script injection via `${{ }}` | Values passed through `env:`, never spliced into shell |
| Credential left on disk | `persist-credentials: false` |
| Tool supply chain | Tools downloaded at pinned versions + SHA-256 verified |
| Gate bypass | Policy/exceptions/gate script covered by CODEOWNERS; missing reports fail closed |
| Docker socket | Never mounted; image built and loaded on the runner only |
| Stale/racing runs | `concurrency` group |
| Scanned != deployed | Deploy loads the *same image tarball* that was scanned |
