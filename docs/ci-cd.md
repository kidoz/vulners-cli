# CI/CD Integration

## GitHub Actions

### Using the Reusable Workflow

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  vulners:
    uses: kidoz/vulners-cli/.github/workflows/vulners-scan.yml@main
    with:
      fail-on: high
      output-format: sarif
    secrets:
      vulners-api-key: ${{ secrets.VULNERS_API_KEY }}
```

### Manual Setup

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Install vulners
        run: go install github.com/kidoz/vulners-cli/cmd/vulners@latest

      - name: Scan
        env:
          VULNERS_API_KEY: ${{ secrets.VULNERS_API_KEY }}
        run: vulners scan repo . --output sarif --fail-on high > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

## GitLab CI

```yaml
vulners-scan:
  image: golang:1.24
  stage: test
  script:
    - go install github.com/kidoz/vulners-cli/cmd/vulners@latest
    - vulners scan repo . --output json --fail-on high
  variables:
    VULNERS_API_KEY: $VULNERS_API_KEY
```

## Generic CI

```bash
# Install
go install github.com/kidoz/vulners-cli/cmd/vulners@latest

# Scan with exit code on high+ findings
export VULNERS_API_KEY="your-key"
vulners scan repo . --fail-on high

# Scan SBOM
vulners scan sbom sbom.json --fail-on critical

# Scan with VEX suppression
vulners scan repo . --fail-on high --vex accepted-risks.vex.json

# Generate SARIF for upload
vulners scan repo . --output sarif > results.sarif
```
