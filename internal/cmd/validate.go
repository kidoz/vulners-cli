package cmd

import "github.com/kidoz/vulners-cli/internal/model"

// validateFailOn rejects unknown --fail-on values instead of silently treating
// them as "no severity threshold".
func validateFailOn(value string) error {
	if value != "" && model.ParseSeverity(value) == model.SeverityNone {
		return usageErrorf("invalid --fail-on value %q: use low, medium, high, or critical", value)
	}
	return nil
}

// ValidateGlobals validates flags that apply to every command before dispatch.
func ValidateGlobals(cli *CLI) error {
	return validateFailOn(cli.FailOn)
}
