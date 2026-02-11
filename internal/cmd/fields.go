package cmd

import (
	"encoding/json"
	"fmt"
)

// projectFields keeps only the specified top-level keys from data.
// It marshals to map[string]any, filters, and returns the filtered map.
func projectFields(data any, fields []string) (any, error) {
	if len(fields) == 0 {
		return data, nil
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshalling for field projection: %w", err)
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		// Not an object (e.g., an array) — return as-is.
		return data, nil
	}

	keep := make(map[string]bool, len(fields))
	for _, f := range fields {
		keep[f] = true
	}

	filtered := make(map[string]any, len(fields))
	for k, v := range m {
		if keep[k] {
			filtered[k] = v
		}
	}

	return filtered, nil
}
