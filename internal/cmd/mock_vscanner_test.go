package cmd

import (
	"context"
	"encoding/json"

	"github.com/kidoz/go-vulners/vscanner"
)

// mockVScannerClient implements intel.VScannerClient for testing.
type mockVScannerClient struct {
	listProjectsFn      func(ctx context.Context, limit, offset int) ([]vscanner.Project, error)
	createProjectFn     func(ctx context.Context, req *vscanner.ProjectRequest) (*vscanner.Project, error)
	updateProjectFn     func(ctx context.Context, id string, req *vscanner.ProjectRequest) (*vscanner.Project, error)
	deleteProjectFn     func(ctx context.Context, id string) error
	projectStatisticsFn func(ctx context.Context, projectID string, stats []string) (map[string]json.RawMessage, error)
	listTasksFn         func(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Task, error)
	createTaskFn        func(ctx context.Context, projectID string, req *vscanner.TaskRequest) (*vscanner.Task, error)
	updateTaskFn        func(ctx context.Context, projectID, taskID string, req *vscanner.TaskRequest) (*vscanner.Task, error)
	startTaskFn         func(ctx context.Context, projectID, taskID string) (*vscanner.Task, error)
	deleteTaskFn        func(ctx context.Context, projectID, taskID string) error
	listResultsFn       func(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Result, error)
	deleteResultFn      func(ctx context.Context, projectID, resultID string) error
	getLicensesFn       func(ctx context.Context) ([]vscanner.License, error)
}

func (m *mockVScannerClient) ListProjects(ctx context.Context, limit, offset int) ([]vscanner.Project, error) {
	if m.listProjectsFn != nil {
		return m.listProjectsFn(ctx, limit, offset)
	}
	return nil, nil
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

func (m *mockVScannerClient) GetProjectStatistics(ctx context.Context, projectID string, stats []string) (map[string]json.RawMessage, error) {
	if m.projectStatisticsFn != nil {
		return m.projectStatisticsFn(ctx, projectID, stats)
	}
	return nil, nil
}

func (m *mockVScannerClient) ListTasks(ctx context.Context, projectID string, limit, offset int) ([]vscanner.Task, error) {
	if m.listTasksFn != nil {
		return m.listTasksFn(ctx, projectID, limit, offset)
	}
	return nil, nil
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

func (m *mockVScannerClient) StartTask(ctx context.Context, projectID, taskID string) (*vscanner.Task, error) {
	if m.startTaskFn != nil {
		return m.startTaskFn(ctx, projectID, taskID)
	}
	return &vscanner.Task{ID: taskID, ProjectID: projectID}, nil
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

func (m *mockVScannerClient) DeleteResult(ctx context.Context, projectID, resultID string) error {
	if m.deleteResultFn != nil {
		return m.deleteResultFn(ctx, projectID, resultID)
	}
	return nil
}

func (m *mockVScannerClient) GetLicenses(ctx context.Context) ([]vscanner.License, error) {
	if m.getLicensesFn != nil {
		return m.getLicensesFn(ctx)
	}
	return nil, nil
}
