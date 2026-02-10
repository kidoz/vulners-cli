# vulners-cli

Go-based CLI vulnerability scanner powered by [Vulners](https://vulners.com), using [go-vulners](https://github.com/kidoz/go-vulners) as the intelligence backend.

Designed for Security Engineers, CI/CD pipelines, and AI agents needing deterministic JSON output.

## Install

### From source

```bash
go install github.com/kidoz/vulners-cli/cmd/vulners@latest
```

### From releases

Download binaries from [GitHub Releases](https://github.com/kidoz/vulners-cli/releases).

### Docker

```bash
docker build -t vulners .
docker run --rm -e VULNERS_API_KEY vulners scan repo /src

# Or mount a local project:
docker run --rm -e VULNERS_API_KEY -v "$(pwd):/src" vulners scan repo /src
```

## Authentication

Set your Vulners API key as an environment variable:

```bash
export VULNERS_API_KEY=your-api-key-here
```

See [`.env.example`](.env.example) for a template. Get an API key at [vulners.com](https://vulners.com).

## Commands

### Intel commands

```bash
# Search the Vulners database
vulners search "apache log4j"
vulners search "type:exploit AND apache" --limit 20
vulners search "log4j" --exploits           # search exploits only

# Look up a specific CVE
vulners cve CVE-2021-44228
vulners cve CVE-2021-44228 --references     # include external references
vulners cve CVE-2021-44228 --history        # include change history

# Search by CPE
vulners cpe chrome --vendor google
vulners cpe nginx --limit 20               # vendor defaults to product name

# Export STIX bundle
vulners stix CVE-2021-44228                # auto-detects CVE prefix
vulners stix RHSA-2021:5137                # by bulletin ID
vulners stix CVE-2021-44228 --by-cve       # explicit CVE lookup
```

### Audit commands

```bash
# Audit Linux packages
vulners audit linux --distro ubuntu --version 22.04 --pkg openssl=3.0.2 --pkg curl=7.81.0

# Audit Windows KB updates
vulners audit windows --kb KB5034441 --kb KB5034439

# Host audit (v4 API -- packages in "name version" format)
vulners audit host --os ubuntu --version 22.04 --packages "openssl 3.0.2" --packages "curl 7.81.0"

# Full Windows audit (KBs + software)
vulners audit winaudit --os "Windows 10" --version "19045" --kb KB5034441 --software "Firefox 121.0"
```

### Scan commands

```bash
# Scan a Go repository (reachability-aware via govulncheck)
vulners scan repo .
vulners scan repo /path/to/project

# Scan a directory for package manifests
vulners scan dir .

# Scan a CycloneDX SBOM
vulners scan sbom sbom.json --format cyclonedx

# Scan an SPDX SBOM
vulners scan sbom sbom.spdx.json --format spdx

# Scan a container image (requires syft)
vulners scan image alpine:3.18
```

### Offline mode

```bash
# Sync vulnerability data for offline use
vulners offline sync --collections cve,exploit

# Check offline database status
vulners offline status

# Purge offline database
vulners offline purge

# Use offline data with any supported command
vulners scan repo . --offline
vulners scan dir . --offline
vulners cve CVE-2021-44228 --offline
vulners search "log4j" --offline
```

## Output formats

```bash
# JSON (default)
vulners scan repo . --output json

# Human-readable table
vulners scan repo . --output table

# SARIF (for GitHub Code Scanning, IDE integration)
vulners scan repo . --output sarif

# HTML report
vulners scan repo . --output html

# CycloneDX VEX
vulners scan repo . --output cyclonedx
```

> **Note:** `sarif`, `html`, and `cyclonedx` formats are only available for scan commands. Intel, audit, STIX, and offline commands support `json` and `table`.

## Policy & exit codes

```bash
# Fail if findings at or above severity
vulners scan repo . --fail-on high
vulners scan repo . --fail-on critical

# Ignore specific CVEs
vulners scan repo . --ignore CVE-2021-44228 --ignore CVE-2023-0001

# Suppress findings using an OpenVEX document
vulners scan repo . --vex vex.json
```

| Exit code | Meaning |
|---|---|
| 0 | No findings above threshold |
| 1 | Findings above threshold |
| 2 | Usage or configuration error |
| 3 | Runtime error |

## Global flags

| Flag | Description |
|---|---|
| `--output` | Output format: `json`, `table`, `sarif`, `html`, `cyclonedx` (default: `json`) |
| `--quiet` / `-q` | Suppress non-error output |
| `--verbose` / `-v` | Enable debug output |
| `--offline` | Use offline database only |
| `--fail-on` | Fail with exit code 1 at severity: `low`, `medium`, `high`, `critical` |
| `--ignore` | CVE IDs to ignore (repeatable) |
| `--vex` | Path to an OpenVEX document for finding suppression |

## Configuration

`vulners-cli` can be configured via a YAML file at `~/.vulners/config.yaml`:

```yaml
api_key: your-api-key-here
verbose: false
quiet: false
offline: false
```

Configuration precedence (highest wins): CLI flags > environment variables > config file > defaults.

Environment variables use the `VULNERS_` prefix (e.g. `VULNERS_API_KEY`, `VULNERS_VERBOSE`).

## Development

```bash
# Build
just build

# Run tests (with race detector)
just test

# Run integration tests (requires VULNERS_API_KEY)
just test-integration

# Run linter
just lint

# Format code
just fmt

# Remove build artifacts
just clean
```

### Requirements

- Go >= 1.24
- [just](https://github.com/casey/just) task runner
- golangci-lint v2
- gofumpt

## Architecture

```
cmd/vulners/main.go        Fx wiring, Kong parse, logger init
internal/cmd/              Kong command structs
internal/config/           Koanf v2 config loader
internal/intel/            go-vulners wrapper + govulncheck
internal/cache/            SQLite offline cache (modernc.org/sqlite)
internal/inventory/        go.mod + CycloneDX/SPDX parsers
internal/matcher/          Component normalization + vuln matching
internal/policy/           --fail-on / --ignore / VEX filtering + exit codes
internal/report/           JSON, table, SARIF, HTML, CycloneDX output
internal/model/            Component, Finding, ExitCode, SeverityLevel
```

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## License

MIT -- see [LICENSE](LICENSE) for details.
