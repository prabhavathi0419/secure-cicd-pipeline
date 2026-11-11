# GitHub setup (manual steps - NOT automated, NOT yet done)

1. Authenticate the CLI: `& "$HOME\devsecops-tools\cli\bin\gh.exe" auth login` (choose GitHub.com, HTTPS, browser).
2. Create a **private** repo and push:
   ```powershell
   gh repo create secure-cicd-pipeline --private --source . --remote origin --push
   ```
   (Use your GitHub **noreply** address for commits if you make it public: Settings > Emails.)
3. `.github/CODEOWNERS` already points to `@prabhavathi0419` - change it if the repo owner differs.
4. **Branch protection for `main`** (Settings > Branches > Add rule, or Rulesets):
   * Require a pull request before merging (+ "Require review from Code Owners")
   * Require status checks: `Unit & security tests`, `Secrets detection (Gitleaks)`, `SAST (Bandit + Semgrep)`, `SCA (pip-audit + Trivy fs)`, `Build, scan image, SBOM`, `Security gate`
   * Require branches to be up to date; block force pushes; block deletions; (optionally) include administrators
   * Private repos on the free plan may not offer protection rules - public repos or a paid plan do.
5. **Environment `staging`** (Settings > Environments): add *Required reviewers* for a manual approval before deploy.
6. Settings > Actions > General: "Workflow permissions" = *Read repository contents*; require approval for outside-collaborator workflows.
7. Enable Dependabot alerts, secret scanning and push protection (Settings > Code security) if available.

Status: none of the above is configured yet. Tick them off yourself and verify by trying a direct push to `main`.
