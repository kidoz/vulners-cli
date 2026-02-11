package cmd

import (
	"context"
	"fmt"
)

// SuggestCmd returns valid field values for structured Vulners search queries.
type SuggestCmd struct {
	Field string `arg:"" help:"Field name to get suggestions for (e.g. type, bulletinFamily)"`
}

func (c *SuggestCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("suggest does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for suggest")
	}

	suggestions, err := deps.Intel.GetSuggestion(ctx, c.Field)
	if err != nil {
		return fmt.Errorf("suggest failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "suggest", suggestions, nil)
}
