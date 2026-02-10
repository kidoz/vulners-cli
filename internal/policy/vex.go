package policy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
)

// vexDocument represents a minimal OpenVEX document.
type vexDocument struct {
	Statements []vexStatement `json:"statements"`
}

type vexStatement struct {
	Vulnerability vexVulnerability `json:"vulnerability"`
	Status        string           `json:"status"`
}

type vexVulnerability struct {
	Name string `json:"name"`
}

// LoadVEX parses an OpenVEX JSON document and returns a map of vuln ID → status.
// NOTE: The OpenVEX "products" field is intentionally ignored; filtering is by
// vulnerability ID only. Product-scoped suppression is a known limitation.
func LoadVEX(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading VEX document: %w", err)
	}

	var doc vexDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing VEX document: %w", err)
	}

	statuses := make(map[string]string, len(doc.Statements))
	for _, s := range doc.Statements {
		if s.Vulnerability.Name != "" {
			if prev, exists := statuses[s.Vulnerability.Name]; exists {
				slog.Warn("duplicate VEX statement, overwriting",
					"vulnerability", s.Vulnerability.Name,
					"previous_status", prev,
					"new_status", s.Status)
			}
			statuses[s.Vulnerability.Name] = s.Status
		}
	}

	return statuses, nil
}
