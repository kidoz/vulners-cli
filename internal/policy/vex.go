package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const maxVEXDocumentSize = 64 << 20

type vexDocument struct {
	Statements []struct {
		Vulnerability vexVulnerability `json:"vulnerability"`
		Status        string           `json:"status"`
		Products      []string         `json:"products"`
	} `json:"statements"`
}

type vexVulnerability struct {
	Name string `json:"name"`
}

// VEXStatement describes one product-scoped vulnerability status.
type VEXStatement struct {
	Status   string
	Products []string
}

// LoadVEX parses an OpenVEX JSON document and groups statements by vulnerability ID.
func LoadVEX(path string) (map[string][]VEXStatement, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading VEX document: %w", err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxVEXDocumentSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading VEX document: %w", err)
	}
	if len(data) > maxVEXDocumentSize {
		return nil, fmt.Errorf("VEX document exceeds %d bytes", maxVEXDocumentSize)
	}

	var doc vexDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing VEX document: %w", err)
	}

	statements := make(map[string][]VEXStatement, len(doc.Statements))
	for _, s := range doc.Statements {
		if s.Vulnerability.Name == "" {
			return nil, fmt.Errorf("VEX statement has no vulnerability name")
		}
		if len(s.Products) == 0 {
			return nil, fmt.Errorf("VEX statement for %s has no products", s.Vulnerability.Name)
		}
		if s.Status == "" {
			return nil, fmt.Errorf("VEX statement for %s has no status", s.Vulnerability.Name)
		}
		id := normID(s.Vulnerability.Name)
		statements[id] = append(statements[id], VEXStatement{Status: s.Status, Products: s.Products})
	}

	return statements, nil
}
