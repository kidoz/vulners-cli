# How vulners-cli scans

This page explains the model behind `vulners-cli` scans: how a target becomes components, how components become findings, how policy changes the result, and where the trust boundaries are.

## Pipeline

Every scan follows the same four stages:

1. **Inventory** — collect components from a target. The source depends on the command: `go.mod`, npm lockfiles, Python requirements, CycloneDX/SPDX SBOMs, container images, or a remote host.
2. **Matching** — look up vulnerabilities for those components. Matching is either package-based (search by name and version), audit-based (send an inventory to a Vulners audit API), or reachability-based (`govulncheck` for Go repositories).
3. **Policy** — apply `--fail-on`, `--ignore`, and `--vex`, then decide the process exit code.
4. **Reporting** — render the same result as JSON, table, SARIF, HTML, CycloneDX, or Markdown.

Keeping these stages separate is why `--fail-on` and `--ignore` work the same way across commands.

## Matching strategies

### Directory and manifest scans

`scan dir` collects components from local manifests and asks the Vulners search API about each component. This is broad package matching: it answers "does this version have known vulnerabilities?", not "can this code reach the vulnerable function?".

`scan sbom` sends the SBOM to the `SBOMAudit` API, which returns findings with CVSS, EPSS, AI score, and exploit metadata.

### Go repository scans

Online `scan repo` uses `govulncheck` in-process to perform reachability analysis:

- A finding is **reachable** when a vulnerable symbol is called from the scanned code.
- A finding is **imported** when the vulnerable module is in the build graph but the vulnerable symbol is not reached.

The Go vulnerability database supplies advisory IDs and the fixed version. `vulners-cli` also reads the advisory aliases (for example, CVE IDs) and enriches findings through Vulners. Duplicate findings for the same advisory and module are merged.

`--fail-on` only considers reachable findings, so imported-only advisories stay visible without failing a build. Findings without reachability data, such as package-matching results, still count.

Offline `scan repo` cannot run reachability analysis; it uses the structured offline cache instead (see below).

### Image scans

`scan image` extracts an SBOM with the embedded `syft` library and routes packages by type:

- OS packages (apk/deb/rpm) go through the distro-aware `LinuxAudit` API.
- Application packages go through `SBOMAudit` for richer enrichment.
- When a distro is detected, the two result sets are merged and OS-package duplicates are removed; the output records the audit mode in `imageMeta`.

If `LinuxAudit` fails for OS packages, the scan aborts instead of silently falling back to a less accurate path.

### Offline matching

`offline sync` stores bulletins in a local SQLite database. A delta sync fetches only changes since the last sync; a full sync replaces the stored collection so bulletins removed upstream do not linger. Offline scans match components by normalized name, version, and CPE against the cached data.

Offline mode fails closed: if the cache is missing, unavailable, or a lookup fails, the command returns an error instead of an empty result.

## Policy

`--ignore` matches vulnerability IDs case-insensitively, including aliases. `--vex` loads OpenVEX statements; each statement must list `products`, and suppression only applies when a product matches the scanned component's PURL, CPE, or `name@version`. `not_affected` and `fixed` statements suppress findings.

`--fail-on` sets the severity threshold for exit code `1`. It does not change what is reported: filtered findings remain in the output, while the exit code reflects the policy decision. A reachable finding with unknown severity fails closed, because there is not enough data to prove it is below the threshold.

## Reporting

JSON is the default and is deterministic. `--agent` forces JSON, quiet logging, no color, and stable ordering for machine consumers. `--fields`, `--summary-only`, and `--max-findings` shape the payload without changing the underlying result.

## Trust boundaries

- API keys can come from the environment or a config file. On Unix, config files must not be group- or world-readable.
- Host target URIs reject embedded passwords; use `--password-env` or `--ask-pass`. Password prompts are written to stderr, never stdout.
- SBOM, npm lockfile, and OpenVEX inputs are limited to 64 MiB.
- Report writers sanitize terminal control characters so hostile bulletin data cannot inject escape sequences.
- Offline reads fail closed, and write failures are reported rather than treated as success.

## Trade-offs

Reachability analysis reduces noise but depends on symbol-level analysis and on Vulners knowing the advisory ID. Go advisories with no CVE alias may remain `severity: unknown`; because reachable findings fail closed, such an advisory still trips `--fail-on` instead of being silently ignored.

Package matching is broader and catches vulnerabilities that reachability analysis misses, at the cost of reporting issues that may not be exploitable in a given application. The right command depends on whether you want maximum coverage or a low-noise gate.
