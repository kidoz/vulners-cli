package intel

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/kidoz/go-vulners/vscanner"
)

// VScannerClient is the interface for VScanner operations.
type VScannerClient interface {
	// Project management
	ListProjects(ctx context.Context, limit, offset int) ([]vscanner.Project, error)
	GetProject(ctx context.Context, id string) (*vscanner.Project, error)
	CreateProject(ctx context.Context, req *vscanner.ProjectRequest) (*vscanner.Project, error)
	UpdateProject(ctx context.Context, id string, req *vscanner.ProjectRequest) (*vscanner.Project, error)
	DeleteProject(ctx context.Context, id string) error

	// Task management
	ListTasks(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Task, error)
	GetTask(ctx context.Context, projectID, taskID string) (*vscanner.Task, error)
	CreateTask(ctx context.Context, projectID string, req *vscanner.TaskRequest) (*vscanner.Task, error)
	UpdateTask(ctx context.Context, projectID, taskID string, req *vscanner.TaskRequest) (*vscanner.Task, error)
	StartTask(ctx context.Context, projectID, taskID string) error
	StopTask(ctx context.Context, projectID, taskID string) error
	DeleteTask(ctx context.Context, projectID, taskID string) error

	// Result access
	ListResults(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Result, error)
	GetResult(ctx context.Context, projectID, resultID string) (*vscanner.Result, error)
	GetResultStatistics(ctx context.Context, projectID, resultID string) (*vscanner.Statistics, error)
	GetResultHosts(ctx context.Context, projectID, resultID string, limit, offset int) ([]vscanner.HostSummary, error)
	GetHostDetail(ctx context.Context, projectID, resultID, host string) (*vscanner.HostDetail, error)
	GetResultVulnerabilities(ctx context.Context, projectID, resultID string, limit, offset int) ([]vscanner.VulnSummary, error)
	DeleteResult(ctx context.Context, projectID, resultID string) error
	ExportResult(ctx context.Context, projectID, resultID, format string) ([]byte, error)

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

	c, err := vscanner.NewClient(apiKey,
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

func (v *VulnersVScannerClient) GetProject(ctx context.Context, id string) (*vscanner.Project, error) {
	v.logger.Debug("get project", "id", id)
	return v.client.Project().Get(ctx, id)
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

func (v *VulnersVScannerClient) ListTasks(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Task, error) {
	v.logger.Debug("list tasks", "projectID", projectID, "limit", limit, "offset", offset)
	return v.client.Task().List(ctx, projectID, vscanner.WithListLimit(limit), vscanner.WithListOffset(offset))
}

func (v *VulnersVScannerClient) GetTask(ctx context.Context, projectID, taskID string) (*vscanner.Task, error) {
	v.logger.Debug("get task", "projectID", projectID, "taskID", taskID)
	return v.client.Task().Get(ctx, projectID, taskID)
}

func (v *VulnersVScannerClient) CreateTask(ctx context.Context, projectID string, req *vscanner.TaskRequest) (*vscanner.Task, error) {
	v.logger.Debug("create task", "projectID", projectID, "name", req.Name)
	return v.client.Task().Create(ctx, projectID, req)
}

func (v *VulnersVScannerClient) UpdateTask(ctx context.Context, projectID, taskID string, req *vscanner.TaskRequest) (*vscanner.Task, error) {
	v.logger.Debug("update task", "projectID", projectID, "taskID", taskID)
	return v.client.Task().Update(ctx, projectID, taskID, req)
}

func (v *VulnersVScannerClient) StartTask(ctx context.Context, projectID, taskID string) error {
	v.logger.Debug("start task", "projectID", projectID, "taskID", taskID)
	return v.client.Task().Start(ctx, projectID, taskID)
}

func (v *VulnersVScannerClient) StopTask(ctx context.Context, projectID, taskID string) error {
	v.logger.Debug("stop task", "projectID", projectID, "taskID", taskID)
	return v.client.Task().Stop(ctx, projectID, taskID)
}

func (v *VulnersVScannerClient) DeleteTask(ctx context.Context, projectID, taskID string) error {
	v.logger.Debug("delete task", "projectID", projectID, "taskID", taskID)
	return v.client.Task().Delete(ctx, projectID, taskID)
}

func (v *VulnersVScannerClient) ListResults(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Result, error) {
	v.logger.Debug("list results", "projectID", projectID, "limit", limit, "offset", offset)
	return v.client.Result().List(ctx, projectID, vscanner.WithListLimit(limit), vscanner.WithListOffset(offset))
}

func (v *VulnersVScannerClient) GetResult(ctx context.Context, projectID, resultID string) (*vscanner.Result, error) {
	v.logger.Debug("get result", "projectID", projectID, "resultID", resultID)
	return v.client.Result().Get(ctx, projectID, resultID)
}

func (v *VulnersVScannerClient) GetResultStatistics(ctx context.Context, projectID, resultID string) (*vscanner.Statistics, error) {
	v.logger.Debug("get result statistics", "projectID", projectID, "resultID", resultID)
	return v.client.Result().GetStatistics(ctx, projectID, resultID)
}

func (v *VulnersVScannerClient) GetResultHosts(ctx context.Context, projectID, resultID string, limit, offset int) ([]vscanner.HostSummary, error) {
	v.logger.Debug("get result hosts", "projectID", projectID, "resultID", resultID)
	return v.client.Result().GetHosts(ctx, projectID, resultID, vscanner.WithListLimit(limit), vscanner.WithListOffset(offset))
}

func (v *VulnersVScannerClient) GetHostDetail(ctx context.Context, projectID, resultID, host string) (*vscanner.HostDetail, error) {
	v.logger.Debug("get host detail", "projectID", projectID, "resultID", resultID, "host", host)
	return v.client.Result().GetHostDetail(ctx, projectID, resultID, host)
}

func (v *VulnersVScannerClient) GetResultVulnerabilities(ctx context.Context, projectID, resultID string, limit, offset int) ([]vscanner.VulnSummary, error) {
	v.logger.Debug("get result vulnerabilities", "projectID", projectID, "resultID", resultID)
	return v.client.Result().GetVulnerabilities(ctx, projectID, resultID, vscanner.WithListLimit(limit), vscanner.WithListOffset(offset))
}

func (v *VulnersVScannerClient) DeleteResult(ctx context.Context, projectID, resultID string) error {
	v.logger.Debug("delete result", "projectID", projectID, "resultID", resultID)
	return v.client.Result().Delete(ctx, projectID, resultID)
}

func (v *VulnersVScannerClient) ExportResult(ctx context.Context, projectID, resultID, format string) ([]byte, error) {
	v.logger.Debug("export result", "projectID", projectID, "resultID", resultID, "format", format)
	return v.client.Result().Export(ctx, projectID, resultID, format)
}

func (v *VulnersVScannerClient) GetLicenses(ctx context.Context) ([]vscanner.License, error) {
	v.logger.Debug("get licenses")
	return v.client.GetLicenses(ctx)
}
