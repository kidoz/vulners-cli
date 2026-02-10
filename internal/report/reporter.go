package report

import (
	"io"

	"github.com/kidoz/vulners-cli/internal/model"
)

// Version is set by the main package to inject the build version into reporters
// (SARIF, CycloneDX) that include tool metadata.
var Version = "dev"

// Reporter formats and writes command output.
type Reporter interface {
	Write(w io.Writer, data any) error
}

// New returns a reporter for the given format.
func New(format model.OutputFormat) Reporter {
	switch format {
	case model.OutputTable:
		return &TableReporter{}
	case model.OutputSARIF:
		return &SARIFReporter{}
	case model.OutputHTML:
		return &HTMLReporter{}
	case model.OutputCycloneDX:
		return &CycloneDXReporter{}
	default:
		return &JSONReporter{}
	}
}
