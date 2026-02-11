package cmd

import (
	"fmt"
	"runtime"
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

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	if globals.Output == "table" {
		_, err := fmt.Fprintf(w, "vulners %s (commit: %s, built: %s, %s)\n",
			info.Version, info.Commit, info.Date, info.GoVersion)
		return err
	}

	return writeIntelOutput(w, globals, "version", info, nil)
}
