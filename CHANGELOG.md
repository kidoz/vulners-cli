# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Reachability-aware online scanning for `vulners scan repo` via `govulncheck`, enriched with Vulners data.
- Structured offline matching by component name, version, and CPE.
- Full offline syncs replace stored collections, removing bulletins deleted upstream.
- Support for passing a `go.mod` file path directly to the Go inventory collector.

### Changed

- Usage and configuration errors now exit with code 2; runtime errors remain code 3.
- Missing API keys, unsupported output formats, and invalid `--fail-on` values are usage errors on every command.
- `--fail-on` ignores govulncheck findings that are imported but not reachable.
- Scanner and inventory failures now abort scans instead of being skipped: component search errors, malformed manifests, image `LinuxAudit` failures, and non-zero `govulncheck` exits.
- Output close errors are propagated.
- Update Go to 1.26.10, refresh dependencies, and pin goreleaser to v2.12.7.

### Fixed

- Populate govulncheck fixed versions from the `fixed_version` field.
- Attach CVE aliases from govulncheck OSV metadata so reachability findings are enriched with severity.
- Merge duplicate govulncheck findings for the same advisory and module.
- Prefer populated CVSS data when the API returns an empty `cvss3` object alongside `cvss`.
- Offline scans fail on lookup errors instead of returning empty results.
- Markdown tables escape backslashes, newlines, and control characters.

### Security

- Require `0600` permissions for Unix config files that may contain an API key.
- Reject passwords embedded in host URIs and write password prompts to stderr.
- Sanitize terminal control characters in table and Markdown reports.
- Limit SBOM, npm lockfile, and VEX inputs to 64 MiB.
- Require products in OpenVEX statements and scope suppression to matching PURL, CPE, or `name@version`.
- Address 13 standard-library vulnerabilities by updating to Go 1.26.10.

## [1.5.2] - 2026-07-21

### Added

- Full Windows audit for `scan host`, covering installed KBs and software via the WinAudit API.
- Windows software inventory through `Get-Package`, with Uninstall registry fallback on Server Core and hosts without PackageManagement.

### Changed

- Improve Windows OS detection: Caption, Version, and Build parsing; Windows 10/11 disambiguation by build; Server R2 preservation; and legacy SKU support.
- Pass the full OS version to the WinAudit API.
- Update go-vulners to v1.3.4.

## [1.5.1] - 2026-07-21

### Added

- `VULNERS_MAX_RESPONSE_SIZE` to raise the HTTP response-body limit for large offline collections.

### Changed

- Validate boolean and integer `VULNERS_*` environment variables.
- Match vulnerability IDs case-insensitively for `--ignore` and VEX statements.
- Fail offline sync when every bulletin in a collection fails to persist.
- Report pip versions only for exact specifiers.
- Close the SSH agent socket after use.
- Update go-vulners to v1.3.4 and document configuration environment variables.

## [1.5.0] - 2026-07-20

### Added

- `vulners audit smart --software` with official and extended catalogs.
- MCP tools for CPE search, SBOM audit, and smart audit.

### Changed

- Update go-vulners to v1.3.2, Go to 1.26.5, and dependencies; refresh usage examples and gosec exclusions.

## [1.4.0] - 2026-07-12

### Added

- `cve --affected` reverse lookup and `cve --related` grouped bulletins.
- `audit library` for PURL-based library audits.
- `audit linux --modern`.
- `scan web` for web path checks.

### Changed

- Migrate VScanner to go-vulners v1.3.1; add `vscan project stats` and remove redundant subcommands.
- Update go-vulners to v1.3.1 and dependencies.

## [1.3.0] - 2026-02-25

### Added

- `scan host` for local, SSH, and WinRM targets.
- OS fingerprinting and package inventory for Debian/Ubuntu, the RHEL family, Alpine, SUSE, and Windows.
- Authentication options, context cancellation, and CI/CD documentation for GitHub Actions and GitLab CI.

### Changed

- Remove dependabot configuration.

## [1.2.5] - 2026-02-17

### Added

- Markdown report output for scan commands.
- macOS installation instructions.

### Fixed

- CPE search returning empty results with the v4 API.
- `audit host` handling of the v4 `SoftwareAuditResult` response.

### Changed

- Update golangci-lint to v2.9.0 and go-vulners to v1.2.0.

## [1.2.4] - 2026-02-14

### Changed

- Update Go to 1.26.0 and refresh direct and transitive dependencies.

## [1.2.3] - 2026-02-14

### Added

- `--arch` override for Linux audits.

### Fixed

- Linux audit for Debian-based distributions by sending `name version arch` and detecting the architecture.

### Changed

- Update go-vulners to v1.1.5.

## [1.2.2] - 2026-02-12

### Fixed

- AI score extraction from `enchantments.score`, with fallback to `aiScore`.

### Changed

- Update go-vulners to v1.1.4.

## [1.2.1] - 2026-02-12

### Changed

- Embed syft as a library; image scanning no longer requires an external binary.
- Remove syft checks from doctor and MCP and update the README.

## [1.2.0] - 2026-02-11

### Added

- Hybrid image scanning with distro auto-detection and image metadata.
- MCP server, VScanner integration, webhooks, subscriptions, and report commands.
- `doctor`, `autocomplete`, `suggest`, `spec`, and `schema` commands.
- Agent output controls: `--agent`, `--fields`, `--summary-only`, `--max-findings`, `--plan`, CycloneDX VEX, and HTML.

### Fixed

- Fail closed when all component lookups fail.
- Give the primary VEX ID priority over aliases.
- Correct query escaping, CVSS3 zero-score handling, pagination validation, search limits, config errors, component normalization, top-findings sorting, log-level precedence, and CycloneDX parsing deduplication.

## [1.0.1] - 2026-02-11

### Added

- Richer bulletin fields and a shared `BulletinToFinding` conversion.

### Fixed

- Offline deduplication, CycloneDX UUID error propagation, and SARIF parse errors.

### Changed

- Pin GitHub Actions, golangci-lint, govulncheck, and gofumpt; read the Go version from `go.mod`; update Go to 1.25.7 and dependencies; add README badges.

## [1.0.0] - 2026-02-11

### Added

- Initial release with Intel, audit, scan, offline, output, and policy command families, including search/CVE/CPE/STIX, Linux/Windows/host audits, repo/dir/SBOM/image scans, offline sync, JSON/table/SARIF/HTML/CycloneDX VEX output, and `--fail-on`/`--ignore`/`--vex` policy controls.

[Unreleased]: https://github.com/kidoz/vulners-cli/compare/v1.5.2...HEAD
[1.5.2]: https://github.com/kidoz/vulners-cli/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/kidoz/vulners-cli/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/kidoz/vulners-cli/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/kidoz/vulners-cli/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/kidoz/vulners-cli/compare/v1.2.5...v1.3.0
[1.2.5]: https://github.com/kidoz/vulners-cli/compare/v1.2.4...v1.2.5
[1.2.4]: https://github.com/kidoz/vulners-cli/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/kidoz/vulners-cli/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/kidoz/vulners-cli/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/kidoz/vulners-cli/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/kidoz/vulners-cli/compare/v1.0.1...v1.2.0
[1.0.1]: https://github.com/kidoz/vulners-cli/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/kidoz/vulners-cli/releases/tag/v1.0.0
