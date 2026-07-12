package cmd

import (
	"context"
	"fmt"

	"github.com/kidoz/go-vulners/vscanner"
)

// VScanCmd is the parent command for VScanner operations.
type VScanCmd struct {
	Project VScanProjectCmd `cmd:"" help:"Manage VScanner projects"`
	Task    VScanTaskCmd    `cmd:"" help:"Manage VScanner scan tasks"`
	Result  VScanResultCmd  `cmd:"" help:"Access VScanner scan results"`
	License VScanLicenseCmd `cmd:"" help:"Show VScanner license information"`
}

func requireVScanner(deps *Deps) error {
	if deps.VScanner == nil {
		return fmt.Errorf("VULNERS_API_KEY is required for vscan commands")
	}
	return nil
}

// --- Project subcommands ---

type VScanProjectCmd struct {
	List   VScanProjectListCmd   `cmd:"" help:"List all projects"`
	Create VScanProjectCreateCmd `cmd:"" help:"Create a new project"`
	Update VScanProjectUpdateCmd `cmd:"" help:"Update a project"`
	Delete VScanProjectDeleteCmd `cmd:"" help:"Delete a project"`
	Stats  VScanProjectStatsCmd  `cmd:"" help:"Get project statistics"`
}

type VScanProjectListCmd struct {
	Limit  int `help:"Maximum items to return" default:"100"`
	Offset int `help:"Pagination offset" default:"0"`
}

func (c *VScanProjectListCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.ListProjects(ctx, c.Limit, c.Offset)
	if err != nil {
		return fmt.Errorf("listing projects: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan project list", result, nil)
}

type VScanProjectCreateCmd struct {
	Name           string   `help:"Project name" required:""`
	License        string   `help:"License ID to use" required:""`
	Notify         string   `help:"Notification period" enum:"disabled,asap,hourly,daily" default:"disabled"`
	Email          []string `help:"Notification email address"`
	Slack          []string `help:"Notification Slack webhook"`
	ResultExpireIn int      `help:"Result retention in days (0 = never)" default:"0" name:"result-expire-in"`
}

func (c *VScanProjectCreateCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	req := newVScannerProjectRequest(c.Name, c.License, c.Notify, c.Email, c.Slack, c.ResultExpireIn)
	result, err := deps.VScanner.CreateProject(ctx, req)
	if err != nil {
		return fmt.Errorf("creating project: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan project create", result, nil)
}

type VScanProjectUpdateCmd struct {
	ID             string   `arg:"" help:"Project ID"`
	Name           string   `help:"Project name" required:""`
	License        string   `help:"License ID to use" required:""`
	Notify         string   `help:"Notification period" enum:"disabled,asap,hourly,daily" default:"disabled"`
	Email          []string `help:"Notification email address"`
	Slack          []string `help:"Notification Slack webhook"`
	ResultExpireIn int      `help:"Result retention in days (0 = never)" default:"0" name:"result-expire-in"`
}

func (c *VScanProjectUpdateCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	req := newVScannerProjectRequest(c.Name, c.License, c.Notify, c.Email, c.Slack, c.ResultExpireIn)
	result, err := deps.VScanner.UpdateProject(ctx, c.ID, req)
	if err != nil {
		return fmt.Errorf("updating project: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan project update", result, nil)
}

type VScanProjectDeleteCmd struct {
	ID string `arg:"" help:"Project ID"`
}

func (c *VScanProjectDeleteCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	if err := deps.VScanner.DeleteProject(ctx, c.ID); err != nil {
		return fmt.Errorf("deleting project: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan project delete", map[string]any{"id": c.ID, "deleted": true}, nil)
}

type VScanProjectStatsCmd struct {
	ProjectID string   `arg:"" help:"Project ID"`
	Stat      []string `help:"Statistic aggregation" enum:"total_hosts,vulnerable_hosts,unique_cve,min_max_cvss,vulnerabilities_rank,vulnerable_hosts_rank" required:""`
}

func (c *VScanProjectStatsCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.GetProjectStatistics(ctx, c.ProjectID, c.Stat)
	if err != nil {
		return fmt.Errorf("getting project statistics: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan project stats", result, nil)
}

func newVScannerProjectRequest(name, license, notify string, email, slack []string, resultExpireIn int) *vscanner.ProjectRequest {
	req := &vscanner.ProjectRequest{
		Name:         name,
		LicenseID:    license,
		Notification: vscanner.NewNotification(notify, email, slack),
	}
	if resultExpireIn > 0 {
		req.ResultExpireIn = &resultExpireIn
	}
	return req
}

// --- Task subcommands ---

type VScanTaskCmd struct {
	List   VScanTaskListCmd   `cmd:"" help:"List tasks in a project"`
	Create VScanTaskCreateCmd `cmd:"" help:"Create a scan task"`
	Update VScanTaskUpdateCmd `cmd:"" help:"Update a scan task"`
	Start  VScanTaskStartCmd  `cmd:"" help:"Start a scan task"`
	Delete VScanTaskDeleteCmd `cmd:"" help:"Delete a scan task"`
}

type VScanTaskListCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	Limit     int    `help:"Maximum items to return" default:"100"`
	Offset    int    `help:"Pagination offset" default:"0"`
}

func (c *VScanTaskListCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.ListTasks(ctx, c.ProjectID, c.Limit, c.Offset)
	if err != nil {
		return fmt.Errorf("listing tasks: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan task list", result, nil)
}

type VScanTaskCreateCmd struct {
	ProjectID string   `arg:"" help:"Project ID"`
	Name      string   `help:"Task name" required:""`
	Networks  []string `help:"Networks to scan (IP, hostname, or CIDR)" required:""`
	Ports     []string `help:"Port or port range (e.g. 22 or 1-1000)" required:""`
	Schedule  string   `help:"Crontab schedule"`
	Timing    string   `help:"Scanner timing profile" default:"normal"`
	Enabled   bool     `help:"Enable the scheduled task" default:"true"`
}

func (c *VScanTaskCreateCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	req := &vscanner.TaskRequest{
		Name:     c.Name,
		Networks: c.Networks,
		Ports:    c.Ports,
		Schedule: c.Schedule,
		Timing:   c.Timing,
		Enabled:  c.Enabled,
	}
	result, err := deps.VScanner.CreateTask(ctx, c.ProjectID, req)
	if err != nil {
		return fmt.Errorf("creating task: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan task create", result, nil)
}

type VScanTaskUpdateCmd struct {
	ProjectID string   `arg:"" help:"Project ID"`
	TaskID    string   `arg:"" help:"Task ID"`
	Name      string   `help:"Task name" required:""`
	Networks  []string `help:"Networks to scan (IP, hostname, or CIDR)" required:""`
	Ports     []string `help:"Port or port range (e.g. 22 or 1-1000)" required:""`
	Schedule  string   `help:"Crontab schedule"`
	Timing    string   `help:"Scanner timing profile" default:"normal"`
	Enabled   bool     `help:"Enable the scheduled task" default:"true"`
}

func (c *VScanTaskUpdateCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	req := &vscanner.TaskRequest{
		Name:     c.Name,
		Networks: c.Networks,
		Ports:    c.Ports,
		Schedule: c.Schedule,
		Timing:   c.Timing,
		Enabled:  c.Enabled,
	}
	result, err := deps.VScanner.UpdateTask(ctx, c.ProjectID, c.TaskID, req)
	if err != nil {
		return fmt.Errorf("updating task: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan task update", result, nil)
}

type VScanTaskStartCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	TaskID    string `arg:"" help:"Task ID"`
}

func (c *VScanTaskStartCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.StartTask(ctx, c.ProjectID, c.TaskID)
	if err != nil {
		return fmt.Errorf("starting task: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan task start", result, nil)
}

type VScanTaskDeleteCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	TaskID    string `arg:"" help:"Task ID"`
}

func (c *VScanTaskDeleteCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	if err := deps.VScanner.DeleteTask(ctx, c.ProjectID, c.TaskID); err != nil {
		return fmt.Errorf("deleting task: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan task delete", map[string]any{
		"projectId": c.ProjectID, "taskId": c.TaskID, "deleted": true,
	}, nil)
}

// --- Result subcommands ---

type VScanResultCmd struct {
	List   VScanResultListCmd   `cmd:"" help:"List scan results for a project"`
	Delete VScanResultDeleteCmd `cmd:"" help:"Delete a scan result"`
}

type VScanResultListCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	Limit     int    `help:"Maximum items to return" default:"100"`
	Offset    int    `help:"Pagination offset" default:"0"`
}

func (c *VScanResultListCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.ListResults(ctx, c.ProjectID, c.Limit, c.Offset)
	if err != nil {
		return fmt.Errorf("listing results: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan result list", result, nil)
}

type VScanResultDeleteCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	ResultID  string `arg:"" help:"Result ID"`
}

func (c *VScanResultDeleteCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	if err := deps.VScanner.DeleteResult(ctx, c.ProjectID, c.ResultID); err != nil {
		return fmt.Errorf("deleting result: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan result delete", map[string]any{
		"projectId": c.ProjectID, "resultId": c.ResultID, "deleted": true,
	}, nil)
}

// --- License subcommand ---

type VScanLicenseCmd struct{}

func (c *VScanLicenseCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.GetLicenses(ctx)
	if err != nil {
		return fmt.Errorf("getting licenses: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan license", result, nil)
}
