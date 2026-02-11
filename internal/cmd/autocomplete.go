package cmd

import (
	"context"
	"fmt"
)

// AutocompleteCmd returns query suggestions for a partial Vulners search query.
type AutocompleteCmd struct {
	Query string `arg:"" help:"Partial query to autocomplete"`
}

func (c *AutocompleteCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if globals.Offline {
		return fmt.Errorf("autocomplete does not support offline mode")
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for autocomplete")
	}

	suggestions, err := deps.Intel.QueryAutocomplete(ctx, c.Query)
	if err != nil {
		return fmt.Errorf("autocomplete failed: %w", err)
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "autocomplete", suggestions, nil)
}
