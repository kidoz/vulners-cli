# Scan a repository with GitLab CI

This guide shows how to run `vulners-cli` in GitLab CI/CD and publish findings to the Security Dashboard and merge requests.

## What you get

`vulners-cli` supports several GitLab-native features:
1.  **Dependency scanning:** Using CycloneDX output.
2.  **Container scanning:** Using CycloneDX output for images.
3.  **Merge request reports:** Visualizing scan results directly in merge requests.

## Full workflow example

Create a `.gitlab-ci.yml` in your project root:

```yaml
stages:
  - test
  - scan

variables:
  # Ensure VULNERS_API_KEY is set in Settings > CI/CD > Variables
  SCAN_THRESHOLD: "high"

vulners-dependency-scan:
  stage: scan
  image: golang:1.26-alpine
  before_script:
    - apk add --no-cache git
    - go install github.com/kidoz/vulners-cli/cmd/vulners@latest
  script:
    - vulners scan repo . \
        --output cyclonedx \
        --output-file gl-dependency-scanning-report.json \
        --fail-on $SCAN_THRESHOLD
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
    paths:
      - gl-dependency-scanning-report.json
    expire_in: 1 week

vulners-container-scan:
  stage: scan
  image: golang:1.26-alpine
  services:
    - docker:dind
  variables:
    DOCKER_HOST: tcp://docker:2375
    DOCKER_TLS_CERTDIR: ""
  before_script:
    - go install github.com/kidoz/vulners-cli/cmd/vulners@latest
  script:
    - vulners scan image $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA \
        --output cyclonedx \
        --output-file gl-container-scanning-report.json
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
```

## Security dashboard integration

By using the `artifacts:reports:dependency_scanning` and `artifacts:reports:container_scanning` keys, GitLab will automatically parse the CycloneDX report and populate:

- **Security Dashboard** (at the Group and Project level).
- **Vulnerability Report** tab.
- **Merge Request widget** (showing newly introduced vulnerabilities).

## Tips

- **Fail-on severity:** Use `--fail-on` to stop the pipeline if high-severity vulnerabilities are found.
- **VEX (Vulnerability Exploitability eXchange):** If you have false positives or accepted risks, use the `--vex` flag with an OpenVEX file to suppress them in the output.
- **Offline scanning:** If your runner is air-gapped, use `vulners offline sync` (if the runner has a persistent cache) or provide the database manually.

`scan repo` runs Go reachability analysis in-process, so the Go image must provide a toolchain compatible with the project's `go.mod`.

## Related

- [Scan a repository with GitHub Actions](github-actions.md)
- [CLI reference](../reference/cli.md)
- [How vulners-cli scans](../explanation/scanning-model.md)
