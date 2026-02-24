# GitHub Actions Integration Guide

This guide provides a detailed look at integrating `vulners-cli` with GitHub Actions for automated vulnerability scanning.

## Key Integration Features

`vulners-cli` supports several GitHub-native features:
1.  **SARIF Reporting:** Integrating with the **Security** tab and Code Scanning.
2.  **Reusable Workflow:** Simple, one-liner job definitions.
3.  **PR Annotations:** Visualization of security issues directly on your code changes.

## Reusable Workflow Example

Add this to `.github/workflows/security.yml`:

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
      # Optional configurations
      scan-path: '.'
      fail-on: high
      output-format: sarif
      vulners-version: 'latest'
    secrets:
      vulners-api-key: ${{ secrets.VULNERS_API_KEY }}
```

## Manual Setup Example

For advanced control, use the `vulners` binary directly:

```yaml
name: Custom Vulnerability Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # Required for upload-sarif
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install Vulners CLI
        run: go install github.com/kidoz/vulners-cli/cmd/vulners@latest

      - name: Scan Repository
        env:
          VULNERS_API_KEY: ${{ secrets.VULNERS_API_KEY }}
        run: |
          # Use SARIF for GitHub Security tab integration
          vulners scan repo . \
            --output sarif \
            --fail-on high \
            --output-file results.sarif

      - name: Upload results to GitHub
        uses: github/codeql-action/upload-sarif@v3
        if: always() # Upload even if scan found issues and exited with 1
        with:
          sarif_file: results.sarif
          category: vulners-scan
```

## Security Alerts & Pull Request Integration

By using the SARIF output and the `upload-sarif` action, you gain:

- **Security Alerts:** New vulnerabilities will appear in the **Security > Code scanning alerts** tab.
- **PR Check Failure:** If `--fail-on` is used and vulnerabilities are found, the job will fail, and the PR check will show as failed.
- **Code Annotations:** If the scan identifies a vulnerability in a specific file and line (e.g., in a dependency file), GitHub will annotate that file in the PR view.

## Integration Best Practices

- **Scan SBOMs:** For faster scans, generate an SBOM first (e.g., using `syft`) and then run `vulners scan sbom sbom.json`.
- **Caching:** Cache the `vulners` database to speed up repeated runs in your pipeline.
- **Suppress False Positives:** Use OpenVEX documents (`--vex`) to suppress vulnerabilities that aren't reachable or have been accepted as risks.
