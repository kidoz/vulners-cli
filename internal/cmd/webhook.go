package cmd

import (
	"context"
	"fmt"
)

// WebhookCmd is the parent command for webhook management.
type WebhookCmd struct {
	List    WebhookListCmd    `cmd:"" help:"List all webhooks"`
	Add     WebhookAddCmd     `cmd:"" help:"Create a webhook for a search query"`
	Get     WebhookGetCmd     `cmd:"" help:"Get a webhook by ID"`
	Read    WebhookReadCmd    `cmd:"" help:"Read new data from a webhook"`
	Enable  WebhookEnableCmd  `cmd:"" help:"Enable a webhook"`
	Disable WebhookDisableCmd `cmd:"" help:"Disable a webhook"`
	Delete  WebhookDeleteCmd  `cmd:"" help:"Delete a webhook"`
}

type WebhookListCmd struct{}

func (c *WebhookListCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for webhook commands")
	}
	result, err := deps.Intel.ListWebhooks(ctx)
	if err != nil {
		return fmt.Errorf("listing webhooks: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "webhook list", result, nil)
}

type WebhookAddCmd struct {
	Query string `arg:"" help:"Search query for the webhook"`
}

func (c *WebhookAddCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for webhook commands")
	}
	result, err := deps.Intel.AddWebhook(ctx, c.Query)
	if err != nil {
		return fmt.Errorf("adding webhook: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "webhook add", result, nil)
}

type WebhookGetCmd struct {
	ID string `arg:"" help:"Webhook ID"`
}

func (c *WebhookGetCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for webhook commands")
	}
	result, err := deps.Intel.GetWebhook(ctx, c.ID)
	if err != nil {
		return fmt.Errorf("getting webhook: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "webhook get", result, nil)
}

type WebhookReadCmd struct {
	ID         string `arg:"" help:"Webhook ID"`
	NewestOnly bool   `help:"Only return data since last read" default:"true" name:"newest-only"`
}

func (c *WebhookReadCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for webhook commands")
	}
	result, err := deps.Intel.ReadWebhook(ctx, c.ID, c.NewestOnly)
	if err != nil {
		return fmt.Errorf("reading webhook: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "webhook read", result, nil)
}

type WebhookEnableCmd struct {
	ID string `arg:"" help:"Webhook ID"`
}

func (c *WebhookEnableCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for webhook commands")
	}
	if err := deps.Intel.EnableWebhook(ctx, c.ID, true); err != nil {
		return fmt.Errorf("enabling webhook: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "webhook enable", map[string]any{"id": c.ID, "active": true}, nil)
}

type WebhookDisableCmd struct {
	ID string `arg:"" help:"Webhook ID"`
}

func (c *WebhookDisableCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for webhook commands")
	}
	if err := deps.Intel.EnableWebhook(ctx, c.ID, false); err != nil {
		return fmt.Errorf("disabling webhook: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "webhook disable", map[string]any{"id": c.ID, "active": false}, nil)
}

type WebhookDeleteCmd struct {
	ID string `arg:"" help:"Webhook ID"`
}

func (c *WebhookDeleteCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for webhook commands")
	}
	if err := deps.Intel.DeleteWebhook(ctx, c.ID); err != nil {
		return fmt.Errorf("deleting webhook: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "webhook delete", map[string]any{"id": c.ID, "deleted": true}, nil)
}
