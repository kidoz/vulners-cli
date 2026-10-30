# Scan a repository with GitHub Actions

This guide shows how to run `vulners-cli` in GitHub Actions and publish findings to the Security tab.

## What you get

`vulners-cli` supports several GitHub-native features:
1.  **SARIF reporting:** Integrates with the **Security** tab and Code Scanning.
2.  **Reusable workflow:** Simple, one-line job definitions.
3.  **PR annotations:** Shows security issues directly on changed files.

## Reusable workflow example

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

## Manual setup example

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
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version-file: go.mod

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

## Security alerts and pull request integration

By using the SARIF output and the `upload-sarif` action, you gain:

- **Security Alerts:** New vulnerabilities will appear in the **Security > Code scanning alerts** tab.
- **PR Check Failure:** If `--fail-on` is used and vulnerabilities are found, the job will fail, and the PR check will show as failed.
- **Code Annotations:** If the scan identifies a vulnerability in a specific file and line (e.g., in a dependency file), GitHub will annotate that file in the PR view.

## Integration best practices

- **Scan SBOMs:** For faster scans, generate an SBOM first (e.g., using `syft`) and then run `vulners scan sbom sbom.json`.
- **Caching:** Cache the `vulners` database to speed up repeated runs in your pipeline.
- **Suppress false positives:** Use OpenVEX documents (`--vex`) to suppress vulnerabilities that aren't reachable or have been accepted as risks.

`scan repo` runs Go reachability analysis in-process, so the Go toolchain installed by `setup-go` must match the project's `go.mod`.

## Related

- [Scan a repository with GitLab CI](gitlab-ci.md)
- [CLI reference](../reference/cli.md)
- [How vulners-cli scans](../explanation/scanning-model.md)
