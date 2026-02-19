# CI/CD Integration Guide

This guide explains how to integrate `vulners-cli` into your CI/CD pipelines to automate security scanning.

## GitHub Actions

Integrating with GitHub Actions allows you to see vulnerability reports directly in the **Security** tab of your repository.

### Using the Reusable Workflow (Recommended)

The simplest way is to use the provided reusable workflow.

```yaml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  vulners:
    uses: kidoz/vulners-cli/.github/workflows/vulners-scan.yml@main
    with:
      fail-on: high
      output-format: sarif
    secrets:
      vulners-api-key: ${{ secrets.VULNERS_API_KEY }}
```

### Manual Setup with Code Scanning

If you need a custom setup, use the SARIF output format and upload it to GitHub.

```yaml
name: Custom Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write # Required for uploading SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install vulners
        run: go install github.com/kidoz/vulners-cli/cmd/vulners@latest

      - name: Run Scan
        env:
          VULNERS_API_KEY: ${{ secrets.VULNERS_API_KEY }}
        run: |
          vulners scan repo . --output sarif --fail-on high > results.sarif

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

## GitLab CI

GitLab CI integration works best with the **CycloneDX** format, which populates the GitLab Security Dashboard.

### Basic Dependency Scanning

Add `VULNERS_API_KEY` to **Settings > CI/CD > Variables**.

```yaml
vulners-scan:
  image: golang:1.25-alpine
  stage: test
  script:
    - go install github.com/kidoz/vulners-cli/cmd/vulners@latest
    - vulners scan repo . --output cyclonedx --output-file gl-dependency-scanning-report.json --fail-on high
  variables:
    VULNERS_API_KEY: $VULNERS_API_KEY
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
    paths:
      - gl-dependency-scanning-report.json
    expire_in: 1 week
```

### Container Image Scanning

You can also scan your Docker images before pushing them to the registry.

```yaml
container-scan:
  image: golang:1.25-alpine
  stage: test
  script:
    - go install github.com/kidoz/vulners-cli/cmd/vulners@latest
    - vulners scan image $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA --output cyclonedx --output-file gl-container-scanning-report.json
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
```

## Generic CI / CLI Usage

### Exit Codes
- `0`: Success (no findings at/above threshold)
- `1`: Findings found (at or above `--fail-on` level)
- `2+`: Tool error

### Common Commands

```bash
# Scan SBOM for critical vulnerabilities
vulners scan sbom sbom.json --fail-on critical

# Use VEX for suppression of known/accepted risks
vulners scan repo . --vex suppressions.vex.json

# Generate HTML report for manual review
vulners scan repo . --output html > report.html
```
