package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// JSONReporter writes output as indented JSON.
type JSONReporter struct{}

func (r *JSONReporter) Write(w io.Writer, data any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}
