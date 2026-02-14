package cmd

import (
	"fmt"
	"io"
	"os"

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
		return fmt.Errorf("output format %q is only supported for scan commands; use json, table, or markdown", format)
	}
	return nil
}

// outputWriter returns the writer for command output. When --output-file is
// set, it opens the file and returns a closer that must be called. Otherwise
// it returns os.Stdout with a no-op closer.
func outputWriter(globals *CLI) (io.Writer, func() error, error) {
	if globals.OutputFile == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	f, err := os.Create(globals.OutputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("opening output file: %w", err)
	}
	return f, f.Close, nil
}
