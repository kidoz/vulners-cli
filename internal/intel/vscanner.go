package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/kidoz/go-vulners/vscanner"
)

// VScannerClient is the interface for VScanner operations.
type VScannerClient interface {
	// Project management
	ListProjects(ctx context.Context, limit, offset int) ([]vscanner.Project, error)
	CreateProject(ctx context.Context, req *vscanner.ProjectRequest) (*vscanner.Project, error)
	UpdateProject(ctx context.Context, id string, req *vscanner.ProjectRequest) (*vscanner.Project, error)
	DeleteProject(ctx context.Context, id string) error
	GetProjectStatistics(ctx context.Context, projectID string, stats []string) (map[string]json.RawMessage, error)

	// Task management
	ListTasks(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Task, error)
	CreateTask(ctx context.Context, projectID string, req *vscanner.TaskRequest) (*vscanner.Task, error)
	UpdateTask(ctx context.Context, projectID, taskID string, req *vscanner.TaskRequest) (*vscanner.Task, error)
	StartTask(ctx context.Context, projectID, taskID string) (*vscanner.Task, error)
	DeleteTask(ctx context.Context, projectID, taskID string) error

	// Result access
	ListResults(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Result, error)
	DeleteResult(ctx context.Context, projectID, resultID string) error

	// License
	GetLicenses(ctx context.Context) ([]vscanner.License, error)
}

// VulnersVScannerClient implements VScannerClient using go-vulners/vscanner.
type VulnersVScannerClient struct {
	client *vscanner.Client
	logger *slog.Logger
}

// NewVScannerClient creates a new VScanner API client.
func NewVScannerClient(apiKey string, logger *slog.Logger) (*VulnersVScannerClient, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("VULNERS_API_KEY is required")
	}

	c, err := vscanner.NewClient(
		apiKey,
		vscanner.WithTimeout(defaultTimeout),
		vscanner.WithUserAgent("vulners-cli/"+Version),
	)
	if err != nil {
		return nil, fmt.Errorf("creating vscanner client: %w", err)
	}

	return &VulnersVScannerClient{client: c, logger: logger}, nil
}

func (v *VulnersVScannerClient) ListProjects(ctx context.Context, limit, offset int) ([]vscanner.Project, error) {
	v.logger.Debug("list projects", "limit", limit, "offset", offset)
	return v.client.Project().List(ctx, vscanner.WithListLimit(limit), vscanner.WithListOffset(offset))
}

func (v *VulnersVScannerClient) CreateProject(ctx context.Context, req *vscanner.ProjectRequest) (*vscanner.Project, error) {
	v.logger.Debug("create project", "name", req.Name)
	return v.client.Project().Create(ctx, req)
}

func (v *VulnersVScannerClient) UpdateProject(ctx context.Context, id string, req *vscanner.ProjectRequest) (*vscanner.Project, error) {
	v.logger.Debug("update project", "id", id)
	return v.client.Project().Update(ctx, id, req)
}

func (v *VulnersVScannerClient) DeleteProject(ctx context.Context, id string) error {
	v.logger.Debug("delete project", "id", id)
	return v.client.Project().Delete(ctx, id)
}

func (v *VulnersVScannerClient) GetProjectStatistics(ctx context.Context, projectID string, stats []string) (map[string]json.RawMessage, error) {
	v.logger.Debug("get project statistics", "projectID", projectID, "stats", stats)
	return v.client.Project().GetStatistics(ctx, projectID, stats...)
}

func (v *VulnersVScannerClient) ListTasks(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Task, error) {
	v.logger.Debug("list tasks", "projectID", projectID, "limit", limit, "offset", offset)
	return v.client.Task().List(ctx, projectID, vscanner.WithListLimit(limit), vscanner.WithListOffset(offset))
}

func (v *VulnersVScannerClient) CreateTask(ctx context.Context, projectID string, req *vscanner.TaskRequest) (*vscanner.Task, error) {
	v.logger.Debug("create task", "projectID", projectID, "name", req.Name)
	return v.client.Task().Create(ctx, projectID, req)
}

func (v *VulnersVScannerClient) UpdateTask(ctx context.Context, projectID, taskID string, req *vscanner.TaskRequest) (*vscanner.Task, error) {
	v.logger.Debug("update task", "projectID", projectID, "taskID", taskID)
	return v.client.Task().Update(ctx, projectID, taskID, req)
}

func (v *VulnersVScannerClient) StartTask(ctx context.Context, projectID, taskID string) (*vscanner.Task, error) {
	v.logger.Debug("start task", "projectID", projectID, "taskID", taskID)
	return v.client.Task().Start(ctx, projectID, taskID)
}

func (v *VulnersVScannerClient) DeleteTask(ctx context.Context, projectID, taskID string) error {
	v.logger.Debug("delete task", "projectID", projectID, "taskID", taskID)
	return v.client.Task().Delete(ctx, projectID, taskID)
}

func (v *VulnersVScannerClient) ListResults(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Result, error) {
	v.logger.Debug("list results", "projectID", projectID, "limit", limit, "offset", offset)
	return v.client.Result().List(ctx, projectID, vscanner.WithResultLimit(limit), vscanner.WithResultOffset(offset))
}

func (v *VulnersVScannerClient) DeleteResult(ctx context.Context, projectID, resultID string) error {
	v.logger.Debug("delete result", "projectID", projectID, "resultID", resultID)
	return v.client.Result().Delete(ctx, projectID, resultID)
}

func (v *VulnersVScannerClient) GetLicenses(ctx context.Context) ([]vscanner.License, error) {
	v.logger.Debug("get licenses")
	return v.client.GetLicenses(ctx)
}
