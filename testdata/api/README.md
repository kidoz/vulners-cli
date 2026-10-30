# API regression fixtures

These are minimized, synthetic fixtures reproducing the payload shapes reported
in live testing, not verbatim API captures. IDs and scores are test values.

- `sbom_audit.json`: the v4 envelope with object records in `metrics.epss`.
- `web_vulnerabilities.json`: decoded web results with CVSS under
  `metrics.<provider>.cvss31.baseScore`.
