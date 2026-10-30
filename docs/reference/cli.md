# CLI reference

Information-oriented reference for `vulners-cli` commands, global flags, output formats, exit codes, and configuration.

For the exact, machine-readable command tree, run:

```bash
vulners spec
vulners <command> --help
```

For the scan output schema:

```bash
vulners spec --schema scan
vulners spec --schema list
```

## Command groups

| Group | Commands | Purpose |
|---|---|---|
| Intel | `search`, `cve`, `cpe`, `stix`, `autocomplete`, `suggest` | Query the Vulners database and export intelligence |
| Audit | `audit linux`, `audit library`, `audit windows`, `audit host`, `audit smart`, `audit winaudit` | Audit explicit package, library, KB, or software inventories |
| Scan | `scan host`, `scan repo`, `scan dir`, `scan sbom`, `scan image`, `scan web` | Discover components from a target and report findings |
| Offline | `offline sync`, `offline status`, `offline purge` | Manage the local SQLite vulnerability cache |
| VScanner | `vscan license`, `vscan project`, `vscan task`, `vscan result` | Manage remote VScanner projects, tasks, and results |
| Notifications | `webhook`, `subscription` | Manage alert webhooks and subscriptions |
| Reports | `report summary`, `report vulns`, `report hosts`, `report scans`, `report ips` | Retrieve account-level reports |
| Integration | `mcp`, `spec`, `schema` | Run the MCP server and emit machine-readable specifications |
| Diagnostics | `version`, `doctor` | Print build metadata and check the environment |

## Global flags

| Flag | Description |
|---|---|
| `--output` | Output format: `json`, `table`, `sarif`, `html`, `cyclonedx`, `markdown` (default: `json`) |
| `--output-file` | Write output to a file instead of stdout |
| `--quiet`, `-q` | Suppress non-error output |
| `--verbose`, `-v` | Enable debug output |
| `--offline` | Use the offline database only |
| `--agent` | Machine-friendly mode: JSON output, quiet logging, deterministic sorting, no color |
| `--no-color` | Disable colored log output |
| `--fail-on` | Exit with code 1 at or above severity: `low`, `medium`, `high`, `critical` |
| `--ignore` | CVE IDs to ignore (repeatable) |
| `--vex` | Path to an OpenVEX document for finding suppression |
| `--fields` | Select JSON fields to include in output (repeatable, JSON only) |
| `--summary-only` | Output the summary and top findings only |
| `--max-findings` | Maximum findings in output; `0` means unlimited (default: `0`) |
| `--plan` | Show what a scan would do without executing it |
| `--help`, `-h` | Show command help |

## Scan output

Host and web scans now use the common scan JSON structure: `schemaVersion`, `target`, `components`, `findings`, and `summary`. This replaces their earlier direct API envelopes (`command`/`data`, including web `results`); consumers must read the normalized findings. `spec --schema scan-host` and `spec --schema scan-web` describe the current structure. All scan commands apply `--fail-on`, `--ignore`, and `--vex` before reporting and deciding the exit code.

For web scans, component references are `software@version` when software is supplied, otherwise `path@`; matching paths appear in finding references. Host findings use package/software references from the audit result; an advisory without a package reference uses the host target.

## Output formats

| Format | Availability | Notes |
|---|---|---|
| `json` | All commands | Default; deterministic object per command |
| `table` | All commands | Human-readable summary |
| `markdown` | All commands | Portable report for issues, pull requests, or documentation |
| `sarif` | Scan commands only | GitHub Code Scanning and IDE integration |
| `html` | Scan commands only | Standalone HTML report |
| `cyclonedx` | Scan commands only | CycloneDX VEX output |

`--output-file` writes the report to a path and leaves stdout empty.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above the configured threshold |
| `1` | Findings at or above the threshold |
| `2` | Usage or configuration error |
| `3` | Runtime error (API, filesystem, network, cancellation) |

## Findings

Scan findings include a `reachability` field when the source supports it:

| Value | Meaning |
|---|---|
| `reachable` | The vulnerable symbol is reachable from the scanned code |
| `imported` | The vulnerable module is in the build graph, but the vulnerable symbol is not reached |
| absent | The finding came from package matching, an audit, or offline data |

`--fail-on` only counts findings that are `reachable` or have no reachability data. Imported-only findings are reported but do not fail the command. A reachable finding with `severity: unknown` (or no severity) fails closed at any threshold.

## Configuration

The default configuration file is `~/.vulners/config.yaml`. On Unix systems it must use mode `0600`; group- or world-readable files are rejected because they may contain an API key.

```yaml
api_key: your-api-key-here
verbose: false
quiet: false
offline: false
# max_response_size: 536870912  # bytes
```

Precedence, highest first: CLI flags > environment variables > config file > defaults.

| Environment variable | Type | Notes |
|---|---|---|
| `VULNERS_API_KEY` | string | Required for most commands |
| `VULNERS_DB_PATH` | string | Offline cache database path |
| `VULNERS_VERBOSE`, `VULNERS_QUIET` | bool (`true`/`false`/`1`/`0`) | Log verbosity |
| `VULNERS_OFFLINE` | bool | Force offline mode |
| `VULNERS_ENABLE_AI_SCORE` | bool | Fetch AI enrichment scores |
| `VULNERS_MAX_RESPONSE_SIZE` | integer bytes | Raise the HTTP response-body limit (default 50 MiB) for large offline collections |
| `VULNERS_CONFIG` | string | Override the config file path |

## Input limits

Go manifests, Python requirements, SBOM files, npm lockfiles, and OpenVEX documents are limited to 64 MiB per file. Larger inputs are rejected before parsing.

Go, Python, and npm collectors accept at most 10,000 components. Directory scans enforce that count across manifests. Component-based online matching permits at most 1,000 search requests across all components and result pages. Exceeding either budget returns a scan error without emitting a partial report.

`scan host --plan` reports pending inventory and the planned steps without creating an executor, prompting for credentials, or contacting the audit API. `scan web --plan` reports the requested inputs without calling the API. Both plan modes work without an API key.
