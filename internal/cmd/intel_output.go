package cmd

import (
	"io"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/report"
)

// IntelOutput is the standard JSON envelope for intel/audit commands.
type IntelOutput struct {
	SchemaVersion string `json:"schemaVersion"`
	Command       string `json:"command"`
	Data          any    `json:"data"`
	Meta          any    `json:"meta,omitempty"`
}

// writeIntelOutput writes data to w, wrapping it in an IntelOutput envelope
// when the output format is JSON. Table and other formats receive raw data.
func writeIntelOutput(w io.Writer, globals *CLI, command string, data any, meta any) error {
	reporter := report.New(model.OutputFormat(globals.Output))
	if model.OutputFormat(globals.Output) == model.OutputJSON {
		envelope := IntelOutput{
			SchemaVersion: "1.0.0",
			Command:       command,
			Data:          data,
			Meta:          meta,
		}
		return reporter.Write(w, envelope)
	}
	return reporter.Write(w, data)
}
