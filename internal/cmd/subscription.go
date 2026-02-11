package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	vulners "github.com/kidoz/go-vulners"
)

// SubscriptionCmd is the parent command for subscription management.
type SubscriptionCmd struct {
	List    SubscriptionListCmd    `cmd:"" help:"List all subscriptions"`
	Get     SubscriptionGetCmd     `cmd:"" help:"Get a subscription by ID"`
	Create  SubscriptionCreateCmd  `cmd:"" help:"Create a new subscription"`
	Update  SubscriptionUpdateCmd  `cmd:"" help:"Update an existing subscription"`
	Delete  SubscriptionDeleteCmd  `cmd:"" help:"Delete a subscription"`
	Enable  SubscriptionEnableCmd  `cmd:"" help:"Enable a subscription"`
	Disable SubscriptionDisableCmd `cmd:"" help:"Disable a subscription"`
}

type SubscriptionListCmd struct{}

func (c *SubscriptionListCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for subscription commands")
	}
	result, err := deps.Intel.ListSubscriptions(ctx)
	if err != nil {
		return fmt.Errorf("listing subscriptions: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "subscription list", result, nil)
}

type SubscriptionGetCmd struct {
	ID string `arg:"" help:"Subscription ID"`
}

func (c *SubscriptionGetCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for subscription commands")
	}
	result, err := deps.Intel.GetSubscription(ctx, c.ID)
	if err != nil {
		return fmt.Errorf("getting subscription: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "subscription get", result, nil)
}

type SubscriptionCreateCmd struct {
	Name   string `help:"Subscription name" required:""`
	Type   string `help:"Subscription type" required:""`
	Query  string `help:"Search query" required:""`
	Config string `help:"JSON config string" default:""`
}

func (c *SubscriptionCreateCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for subscription commands")
	}
	req := &vulners.SubscriptionRequest{
		Name:   c.Name,
		Type:   c.Type,
		Query:  c.Query,
		Active: true,
	}
	if c.Config != "" {
		req.Config = json.RawMessage(c.Config)
	}
	result, err := deps.Intel.CreateSubscription(ctx, req)
	if err != nil {
		return fmt.Errorf("creating subscription: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "subscription create", result, nil)
}

type SubscriptionUpdateCmd struct {
	ID     string `arg:"" help:"Subscription ID"`
	Name   string `help:"Subscription name"`
	Type   string `help:"Subscription type"`
	Query  string `help:"Search query"`
	Config string `help:"JSON config string"`
}

func (c *SubscriptionUpdateCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for subscription commands")
	}
	req := &vulners.SubscriptionRequest{
		Name:  c.Name,
		Type:  c.Type,
		Query: c.Query,
	}
	if c.Config != "" {
		req.Config = json.RawMessage(c.Config)
	}
	result, err := deps.Intel.UpdateSubscription(ctx, c.ID, req)
	if err != nil {
		return fmt.Errorf("updating subscription: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "subscription update", result, nil)
}

type SubscriptionDeleteCmd struct {
	ID string `arg:"" help:"Subscription ID"`
}

func (c *SubscriptionDeleteCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for subscription commands")
	}
	if err := deps.Intel.DeleteSubscription(ctx, c.ID); err != nil {
		return fmt.Errorf("deleting subscription: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "subscription delete", map[string]any{"id": c.ID, "deleted": true}, nil)
}

type SubscriptionEnableCmd struct {
	ID string `arg:"" help:"Subscription ID"`
}

func (c *SubscriptionEnableCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for subscription commands")
	}
	if err := deps.Intel.EnableSubscription(ctx, c.ID, true); err != nil {
		return fmt.Errorf("enabling subscription: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "subscription enable", map[string]any{"id": c.ID, "active": true}, nil)
}

type SubscriptionDisableCmd struct {
	ID string `arg:"" help:"Subscription ID"`
}

func (c *SubscriptionDisableCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if deps.Intel == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for subscription commands")
	}
	if err := deps.Intel.EnableSubscription(ctx, c.ID, false); err != nil {
		return fmt.Errorf("disabling subscription: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "subscription disable", map[string]any{"id": c.ID, "active": false}, nil)
}
