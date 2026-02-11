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
	Get    VScanProjectGetCmd    `cmd:"" help:"Get a project by ID"`
	Create VScanProjectCreateCmd `cmd:"" help:"Create a new project"`
	Update VScanProjectUpdateCmd `cmd:"" help:"Update a project"`
	Delete VScanProjectDeleteCmd `cmd:"" help:"Delete a project"`
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

type VScanProjectGetCmd struct {
	ID string `arg:"" help:"Project ID"`
}

func (c *VScanProjectGetCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.GetProject(ctx, c.ID)
	if err != nil {
		return fmt.Errorf("getting project: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan project get", result, nil)
}

type VScanProjectCreateCmd struct {
	Name        string `help:"Project name" required:""`
	Description string `help:"Project description" default:""`
	License     string `help:"License ID to use" default:""`
}

func (c *VScanProjectCreateCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	req := &vscanner.ProjectRequest{
		Name:        c.Name,
		Description: c.Description,
		License:     c.License,
	}
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
	ID          string `arg:"" help:"Project ID"`
	Name        string `help:"Project name" required:""`
	Description string `help:"Project description" default:""`
}

func (c *VScanProjectUpdateCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	req := &vscanner.ProjectRequest{
		Name:        c.Name,
		Description: c.Description,
	}
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

// --- Task subcommands ---

type VScanTaskCmd struct {
	List   VScanTaskListCmd   `cmd:"" help:"List tasks in a project"`
	Get    VScanTaskGetCmd    `cmd:"" help:"Get a task by ID"`
	Create VScanTaskCreateCmd `cmd:"" help:"Create a scan task"`
	Update VScanTaskUpdateCmd `cmd:"" help:"Update a scan task"`
	Start  VScanTaskStartCmd  `cmd:"" help:"Start a scan task"`
	Stop   VScanTaskStopCmd   `cmd:"" help:"Stop a running scan task"`
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

type VScanTaskGetCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	TaskID    string `arg:"" help:"Task ID"`
}

func (c *VScanTaskGetCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.GetTask(ctx, c.ProjectID, c.TaskID)
	if err != nil {
		return fmt.Errorf("getting task: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan task get", result, nil)
}

type VScanTaskCreateCmd struct {
	ProjectID      string   `arg:"" help:"Project ID"`
	Name           string   `help:"Task name" required:""`
	Description    string   `help:"Task description" default:""`
	Targets        []string `help:"Scan targets (IPs, hostnames, CIDR ranges)" required:""`
	ScanType       string   `help:"Scan type" enum:"fast,normal,full" default:"normal" name:"scan-type"`
	Ports          string   `help:"Port range or list (e.g. 1-1000, 22,80,443)" default:""`
	MaxConcurrency int      `help:"Maximum concurrent scan threads" default:"0" name:"max-concurrency"`
}

func (c *VScanTaskCreateCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	req := &vscanner.TaskRequest{
		Name:        c.Name,
		Description: c.Description,
		Targets:     c.Targets,
		Config: &vscanner.TaskConfig{
			ScanType:       c.ScanType,
			Ports:          c.Ports,
			MaxConcurrency: c.MaxConcurrency,
		},
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
	ProjectID   string   `arg:"" help:"Project ID"`
	TaskID      string   `arg:"" help:"Task ID"`
	Name        string   `help:"Task name" required:""`
	Description string   `help:"Task description" default:""`
	Targets     []string `help:"Scan targets (IPs, hostnames, CIDR ranges)"`
}

func (c *VScanTaskUpdateCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	req := &vscanner.TaskRequest{
		Name:        c.Name,
		Description: c.Description,
		Targets:     c.Targets,
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
	if err := deps.VScanner.StartTask(ctx, c.ProjectID, c.TaskID); err != nil {
		return fmt.Errorf("starting task: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan task start", map[string]any{
		"projectId": c.ProjectID, "taskId": c.TaskID, "started": true,
	}, nil)
}

type VScanTaskStopCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	TaskID    string `arg:"" help:"Task ID"`
}

func (c *VScanTaskStopCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	if err := deps.VScanner.StopTask(ctx, c.ProjectID, c.TaskID); err != nil {
		return fmt.Errorf("stopping task: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan task stop", map[string]any{
		"projectId": c.ProjectID, "taskId": c.TaskID, "stopped": true,
	}, nil)
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
	Get    VScanResultGetCmd    `cmd:"" help:"Get a scan result"`
	Stats  VScanResultStatsCmd  `cmd:"" help:"Get statistics for a scan result"`
	Hosts  VScanResultHostsCmd  `cmd:"" help:"List hosts from a scan result"`
	Host   VScanResultHostCmd   `cmd:"" help:"Get detailed host information"`
	Vulns  VScanResultVulnsCmd  `cmd:"" help:"List vulnerabilities from a scan result"`
	Delete VScanResultDeleteCmd `cmd:"" help:"Delete a scan result"`
	Export VScanResultExportCmd `cmd:"" help:"Export a scan result"`
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

type VScanResultGetCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	ResultID  string `arg:"" help:"Result ID"`
}

func (c *VScanResultGetCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.GetResult(ctx, c.ProjectID, c.ResultID)
	if err != nil {
		return fmt.Errorf("getting result: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan result get", result, nil)
}

type VScanResultStatsCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	ResultID  string `arg:"" help:"Result ID"`
}

func (c *VScanResultStatsCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.GetResultStatistics(ctx, c.ProjectID, c.ResultID)
	if err != nil {
		return fmt.Errorf("getting statistics: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan result stats", result, nil)
}

type VScanResultHostsCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	ResultID  string `arg:"" help:"Result ID"`
	Limit     int    `help:"Maximum items to return" default:"100"`
	Offset    int    `help:"Pagination offset" default:"0"`
}

func (c *VScanResultHostsCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.GetResultHosts(ctx, c.ProjectID, c.ResultID, c.Limit, c.Offset)
	if err != nil {
		return fmt.Errorf("getting hosts: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan result hosts", result, nil)
}

type VScanResultHostCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	ResultID  string `arg:"" help:"Result ID"`
	Host      string `arg:"" help:"Host identifier or IP"`
}

func (c *VScanResultHostCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.GetHostDetail(ctx, c.ProjectID, c.ResultID, c.Host)
	if err != nil {
		return fmt.Errorf("getting host detail: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan result host", result, nil)
}

type VScanResultVulnsCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	ResultID  string `arg:"" help:"Result ID"`
	Limit     int    `help:"Maximum items to return" default:"100"`
	Offset    int    `help:"Pagination offset" default:"0"`
}

func (c *VScanResultVulnsCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}
	if err := requireVScanner(deps); err != nil {
		return err
	}
	result, err := deps.VScanner.GetResultVulnerabilities(ctx, c.ProjectID, c.ResultID, c.Limit, c.Offset)
	if err != nil {
		return fmt.Errorf("getting vulnerabilities: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	return writeIntelOutput(w, globals, "vscan result vulns", result, nil)
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

type VScanResultExportCmd struct {
	ProjectID string `arg:"" help:"Project ID"`
	ResultID  string `arg:"" help:"Result ID"`
	Format    string `help:"Export format" enum:"pdf,csv,json,xml" default:"json" name:"format"`
}

func (c *VScanResultExportCmd) Run(ctx context.Context, globals *CLI, deps *Deps) error {
	if err := requireVScanner(deps); err != nil {
		return err
	}
	data, err := deps.VScanner.ExportResult(ctx, c.ProjectID, c.ResultID, c.Format)
	if err != nil {
		return fmt.Errorf("exporting result: %w", err)
	}
	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()
	_, err = w.Write(data)
	return err
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
