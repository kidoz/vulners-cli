package cmd

import (
	"context"

	"github.com/kidoz/go-vulners/vscanner"
)

// mockVScannerClient implements intel.VScannerClient for testing.
type mockVScannerClient struct {
	listProjectsFn   func(ctx context.Context, limit, offset int) ([]vscanner.Project, error)
	getProjectFn     func(ctx context.Context, id string) (*vscanner.Project, error)
	createProjectFn  func(ctx context.Context, req *vscanner.ProjectRequest) (*vscanner.Project, error)
	updateProjectFn  func(ctx context.Context, id string, req *vscanner.ProjectRequest) (*vscanner.Project, error)
	deleteProjectFn  func(ctx context.Context, id string) error
	listTasksFn      func(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Task, error)
	getTaskFn        func(ctx context.Context, projectID, taskID string) (*vscanner.Task, error)
	createTaskFn     func(ctx context.Context, projectID string, req *vscanner.TaskRequest) (*vscanner.Task, error)
	updateTaskFn     func(ctx context.Context, projectID, taskID string, req *vscanner.TaskRequest) (*vscanner.Task, error)
	startTaskFn      func(ctx context.Context, projectID, taskID string) error
	stopTaskFn       func(ctx context.Context, projectID, taskID string) error
	deleteTaskFn     func(ctx context.Context, projectID, taskID string) error
	listResultsFn    func(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Result, error)
	getResultFn      func(ctx context.Context, projectID, resultID string) (*vscanner.Result, error)
	getStatisticsFn  func(ctx context.Context, projectID, resultID string) (*vscanner.Statistics, error)
	getResultHostsFn func(ctx context.Context, projectID, resultID string, limit, offset int) ([]vscanner.HostSummary, error)
	getHostDetailFn  func(ctx context.Context, projectID, resultID, host string) (*vscanner.HostDetail, error)
	getResultVulnsFn func(ctx context.Context, projectID, resultID string, limit, offset int) ([]vscanner.VulnSummary, error)
	deleteResultFn   func(ctx context.Context, projectID, resultID string) error
	exportResultFn   func(ctx context.Context, projectID, resultID, format string) ([]byte, error)
	getLicensesFn    func(ctx context.Context) ([]vscanner.License, error)
}

func (m *mockVScannerClient) ListProjects(ctx context.Context, limit, offset int) ([]vscanner.Project, error) {
	if m.listProjectsFn != nil {
		return m.listProjectsFn(ctx, limit, offset)
	}
	return nil, nil
}

func (m *mockVScannerClient) GetProject(ctx context.Context, id string) (*vscanner.Project, error) {
	if m.getProjectFn != nil {
		return m.getProjectFn(ctx, id)
	}
	return &vscanner.Project{}, nil
}

func (m *mockVScannerClient) CreateProject(ctx context.Context, req *vscanner.ProjectRequest) (*vscanner.Project, error) {
	if m.createProjectFn != nil {
		return m.createProjectFn(ctx, req)
	}
	return &vscanner.Project{}, nil
}

func (m *mockVScannerClient) UpdateProject(ctx context.Context, id string, req *vscanner.ProjectRequest) (*vscanner.Project, error) {
	if m.updateProjectFn != nil {
		return m.updateProjectFn(ctx, id, req)
	}
	return &vscanner.Project{}, nil
}

func (m *mockVScannerClient) DeleteProject(ctx context.Context, id string) error {
	if m.deleteProjectFn != nil {
		return m.deleteProjectFn(ctx, id)
	}
	return nil
}

func (m *mockVScannerClient) ListTasks(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Task, error) {
	if m.listTasksFn != nil {
		return m.listTasksFn(ctx, projectID, limit, offset)
	}
	return nil, nil
}

func (m *mockVScannerClient) GetTask(ctx context.Context, projectID, taskID string) (*vscanner.Task, error) {
	if m.getTaskFn != nil {
		return m.getTaskFn(ctx, projectID, taskID)
	}
	return &vscanner.Task{}, nil
}

func (m *mockVScannerClient) CreateTask(ctx context.Context, projectID string, req *vscanner.TaskRequest) (*vscanner.Task, error) {
	if m.createTaskFn != nil {
		return m.createTaskFn(ctx, projectID, req)
	}
	return &vscanner.Task{}, nil
}

func (m *mockVScannerClient) UpdateTask(ctx context.Context, projectID, taskID string, req *vscanner.TaskRequest) (*vscanner.Task, error) {
	if m.updateTaskFn != nil {
		return m.updateTaskFn(ctx, projectID, taskID, req)
	}
	return &vscanner.Task{}, nil
}

func (m *mockVScannerClient) StartTask(ctx context.Context, projectID, taskID string) error {
	if m.startTaskFn != nil {
		return m.startTaskFn(ctx, projectID, taskID)
	}
	return nil
}

func (m *mockVScannerClient) StopTask(ctx context.Context, projectID, taskID string) error {
	if m.stopTaskFn != nil {
		return m.stopTaskFn(ctx, projectID, taskID)
	}
	return nil
}

func (m *mockVScannerClient) DeleteTask(ctx context.Context, projectID, taskID string) error {
	if m.deleteTaskFn != nil {
		return m.deleteTaskFn(ctx, projectID, taskID)
	}
	return nil
}

func (m *mockVScannerClient) ListResults(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Result, error) {
	if m.listResultsFn != nil {
		return m.listResultsFn(ctx, projectID, limit, offset)
	}
	return nil, nil
}

func (m *mockVScannerClient) GetResult(ctx context.Context, projectID, resultID string) (*vscanner.Result, error) {
	if m.getResultFn != nil {
		return m.getResultFn(ctx, projectID, resultID)
	}
	return &vscanner.Result{}, nil
}

func (m *mockVScannerClient) GetResultStatistics(ctx context.Context, projectID, resultID string) (*vscanner.Statistics, error) {
	if m.getStatisticsFn != nil {
		return m.getStatisticsFn(ctx, projectID, resultID)
	}
	return &vscanner.Statistics{}, nil
}

func (m *mockVScannerClient) GetResultHosts(ctx context.Context, projectID, resultID string, limit, offset int) ([]vscanner.HostSummary, error) {
	if m.getResultHostsFn != nil {
		return m.getResultHostsFn(ctx, projectID, resultID, limit, offset)
	}
	return nil, nil
}

func (m *mockVScannerClient) GetHostDetail(ctx context.Context, projectID, resultID, host string) (*vscanner.HostDetail, error) {
	if m.getHostDetailFn != nil {
		return m.getHostDetailFn(ctx, projectID, resultID, host)
	}
	return &vscanner.HostDetail{}, nil
}

func (m *mockVScannerClient) GetResultVulnerabilities(ctx context.Context, projectID, resultID string, limit, offset int) ([]vscanner.VulnSummary, error) {
	if m.getResultVulnsFn != nil {
		return m.getResultVulnsFn(ctx, projectID, resultID, limit, offset)
	}
	return nil, nil
}

func (m *mockVScannerClient) DeleteResult(ctx context.Context, projectID, resultID string) error {
	if m.deleteResultFn != nil {
		return m.deleteResultFn(ctx, projectID, resultID)
	}
	return nil
}

func (m *mockVScannerClient) ExportResult(ctx context.Context, projectID, resultID, format string) ([]byte, error) {
	if m.exportResultFn != nil {
		return m.exportResultFn(ctx, projectID, resultID, format)
	}
	return []byte("{}"), nil
}

func (m *mockVScannerClient) GetLicenses(ctx context.Context) ([]vscanner.License, error) {
	if m.getLicensesFn != nil {
		return m.getLicensesFn(ctx)
	}
	return nil, nil
}
