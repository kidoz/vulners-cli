package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/kidoz/vulners-cli/internal/model"
	"github.com/kidoz/vulners-cli/internal/report"
)

// Set via ldflags at build time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// VersionInfo holds version metadata.
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"goVersion"`
}

// VersionCmd prints version information.
type VersionCmd struct{}

// Run executes the version command.
func (c *VersionCmd) Run(globals *CLI) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	info := VersionInfo{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
	}

	if globals.Output == "table" {
		fmt.Printf("vulners %s (commit: %s, built: %s, %s)\n",
			info.Version, info.Commit, info.Date, info.GoVersion)
		return nil
	}

	reporter := report.New(model.OutputFormat(globals.Output))
	return reporter.Write(os.Stdout, info)
}
