package inventory

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/kidoz/vulners-cli/internal/model"
)

// Collector collects software components from a target.
type Collector interface {
	Collect(ctx context.Context, target string) ([]model.Component, error)
}

const maxInputFileSize = 64 << 20

func readFileLimited(path string) ([]byte, error) {
	return readFileAtMost(path, maxInputFileSize)
}

func readFileAtMost(path string, maxSize int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("file exceeds %d bytes", maxSize)
	}
	return data, nil
}
