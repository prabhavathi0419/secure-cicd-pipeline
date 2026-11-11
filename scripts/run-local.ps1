# Run the same checks as CI on a Windows workstation.
# Semgrep has no native Windows build; if Docker is available it is run from its image,
# otherwise it is skipped here (and still runs in CI) - the gate then reports it as missing.
$ErrorActionPreference = "Continue"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$py   = "$root\.venv\Scripts"
$tools = "$HOME\devsecops-tools"
$tag  = "local"
New-Item -ItemType Directory -Force reports | Out-Null

Write-Host "== tests ==" ; & "$py\python.exe" -m pytest -q
Write-Host "== gitleaks (git history + working tree) =="
& "$tools\gitleaks\gitleaks.exe" git . --config .gitleaks.toml --redact --report-format json --report-path reports\gitleaks.json --exit-code 0 --no-banner
Write-Host "== bandit =="
& "$py\bandit.exe" -c bandit.yaml -r . -f json -o reports\bandit.json --exit-zero -q
& "$py\bandit.exe" -c bandit.yaml -r . -f txt -o reports\bandit.txt --exit-zero -q
Write-Host "== pip-audit =="
& "$py\pip-audit.exe" -r requirements.txt -f json -o reports\pip-audit.json 2>$null
Write-Host "== trivy fs =="
& "$tools\trivy\trivy.exe" fs --scanners vuln --format json --output reports\trivy-fs.json . 2>$null

if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "== semgrep (docker) =="
    docker run --rm -v "${root}:/src" -w /src semgrep/semgrep:1.185.0 semgrep scan --config p/python --config .semgrep/custom-rules.yml --metrics=off --json --output reports/semgrep.json app
    Write-Host "== docker build + trivy image + SBOM =="
    docker build -t "secure-cicd-demo:$tag" .
    & "$tools\trivy\trivy.exe" image --format json --output reports\trivy-image.json "secure-cicd-demo:$tag" 2>$null
    & "$tools\syft\syft.exe" "secure-cicd-demo:$tag" -o cyclonedx-json=reports\sbom.cdx.json -o spdx-json=reports\sbom.spdx.json
} else {
    Write-Warning "Docker not found: skipping semgrep/image scan/SBOM (they run in CI)."
}

Write-Host "== security gate =="
& "$py\python.exe" scripts\security_gate.py
exit $LASTEXITCODE
