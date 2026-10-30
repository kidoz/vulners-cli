package intel

import (
	"io"
	"log/slog"
	"testing"
)

func discardGovulncheckLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestParseGovulncheckOutput(t *testing.T) {
	// OSV metadata intentionally appears after its finding to prove parsing
	// does not depend on message ordering. The duplicate GO-2024-0002 finding
	// must merge into the reachable one.
	const stream = `
{"config":{"protocol_version":"v1.0.0"}}
{"finding":{"osv":"GO-2024-0001","fixed_version":"v1.2.4","trace":[{"module":"example.com/mod","version":"v1.2.3"}]}}
{"osv":{"id":"GO-2024-0001","aliases":["CVE-2024-1111","GHSA-aaaa-bbbb-cccc"]}}
{"finding":{"osv":"GO-2024-0001","fixed_version":"v1.2.4","trace":[{"module":"example.com/mod","version":"v1.2.3"}]}}
{"finding":{"osv":"GO-2024-0002","trace":[{"module":"example.com/mod","version":"v1.2.3"}]}}
{"finding":{"osv":"GO-2024-0002","fixed_version":"v1.2.5","trace":[{"module":"example.com/mod","version":"v1.2.3","function":"Vulnerable"}]}}
{"progress":{"message":"done"}}
`

	findings, err := parseGovulncheckOutput([]byte(stream), discardGovulncheckLogger())
	if err != nil {
		t.Fatalf("parseGovulncheckOutput() error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 deduplicated findings, got %d: %+v", len(findings), findings)
	}

	imported := findings[0]
	if imported.VulnID != "GO-2024-0001" {
		t.Errorf("VulnID = %q, want GO-2024-0001", imported.VulnID)
	}
	if imported.ComponentRef != "example.com/mod@v1.2.3" {
		t.Errorf("ComponentRef = %q, want example.com/mod@v1.2.3", imported.ComponentRef)
	}
	if imported.Fix != "v1.2.4" {
		t.Errorf("Fix = %q, want v1.2.4", imported.Fix)
	}
	if imported.Reachability != "imported" {
		t.Errorf("Reachability = %q, want imported", imported.Reachability)
	}
	if len(imported.Aliases) != 2 || imported.Aliases[0] != "CVE-2024-1111" || imported.Aliases[1] != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("Aliases = %v, want [CVE-2024-1111 GHSA-aaaa-bbbb-cccc]", imported.Aliases)
	}

	reachable := findings[1]
	if reachable.VulnID != "GO-2024-0002" || reachable.Reachability != "reachable" {
		t.Errorf("unexpected merged finding: %+v", reachable)
	}
	if reachable.Fix != "v1.2.5" {
		t.Errorf("merged Fix = %q, want v1.2.5", reachable.Fix)
	}
}

func TestParseGovulncheckOutputTruncated(t *testing.T) {
	if _, err := parseGovulncheckOutput(
		[]byte(`{"finding":{"osv":"GO-2024-0001"`), discardGovulncheckLogger()); err == nil {
		t.Fatal("expected truncated output to fail")
	}
}
