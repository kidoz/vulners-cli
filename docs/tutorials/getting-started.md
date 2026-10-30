# Get started with vulners-cli

In this tutorial you will install `vulners-cli`, scan a small npm project with a known vulnerable dependency, and read the results.

## Prerequisites

- Go 1.26 or newer, or Homebrew on macOS
- A Vulners API key
- Network access to the Vulners API

## 1. Install the CLI

From source:

```bash
go install github.com/kidoz/vulners-cli/cmd/vulners@latest
```

On macOS with Homebrew:

```bash
brew install kidoz/vulners/vulners-cli
```

Check that the binary is available:

```bash
vulners version
```

## 2. Provide your API key

```bash
export VULNERS_API_KEY="your-api-key-here"
```

You can also keep the key in an uncommitted `.env` file and load it in your shell. For a persistent configuration file, see the [CLI reference](../reference/cli.md#configuration); on Unix the file must use mode `0600`.

## 3. Create a sample project

```bash
mkdir vulners-tutorial
cd vulners-tutorial
```

Create a `package-lock.json` that pins `lodash` 4.17.20:

```json
{
  "name": "vulners-tutorial",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "vulners-tutorial",
      "version": "1.0.0"
    },
    "node_modules/lodash": {
      "version": "4.17.20"
    }
  }
}
```

This version of `lodash` is known to be vulnerable, so the scan returns a non-empty result.

## 4. Run the scan

```bash
vulners scan dir . --output table
```

You should see a summary with one component and several findings for `lodash@4.17.20`. The exact count can change as the Vulners database is updated.

The default output is JSON. Add `--output table` for a human-readable view, or keep JSON for scripts and agents.

## 5. Make the scan gate your build

```bash
vulners scan dir . --fail-on high
echo $?
```

The exit code tells you what happened:

- `0` — no findings at or above the threshold
- `1` — findings at or above the threshold
- `2` — usage or configuration error
- `3` — runtime error

With the sample project this command exits `1`, because `lodash@4.17.20` has high-severity findings.

## 6. Inspect the JSON output

```bash
vulners scan dir . --output json --max-findings 3
```

Useful flags for scripts and agents:

- `--agent` — JSON output, quiet logging, deterministic ordering, no color
- `--fields findings.vulnID,findings.severity,summary` — select JSON fields
- `--summary-only` — keep the summary and top five findings only
- `--max-findings N` — limit findings while preserving the total count

## 7. Clean up

```bash
cd ..
rm -rf vulners-tutorial
```

## Next steps

- Scan a Go repository with reachability analysis: `vulners scan repo .`
- Add scanning to a pipeline: [GitHub Actions](../how-to/github-actions.md) or [GitLab CI](../how-to/gitlab-ci.md)
- Look up commands and flags: [CLI reference](../reference/cli.md)
- Understand matching, policy, and offline mode: [Scanning model](../explanation/scanning-model.md)
