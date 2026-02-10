package cmd

import (
	"fmt"

	"github.com/kidoz/vulners-cli/internal/model"
)

// scanOnlyFormats lists output formats that require scan-structured data.
var scanOnlyFormats = map[model.OutputFormat]bool{
	model.OutputSARIF:     true,
	model.OutputHTML:      true,
	model.OutputCycloneDX: true,
}

// validateNonScanFormat returns an error if the chosen format is scan-only.
func validateNonScanFormat(format string) error {
	if scanOnlyFormats[model.OutputFormat(format)] {
		return fmt.Errorf("output format %q is only supported for scan commands; use json or table", format)
	}
	return nil
}
