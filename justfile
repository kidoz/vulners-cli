binary := "vulners"
module := "github.com/kidoz/vulners-cli"
version := env("VERSION", "dev")
commit := `git rev-parse --short HEAD 2>/dev/null || echo "none"`
date := `date -u +"%Y-%m-%dT%H:%M:%SZ"`
ldflags := "-s -w -X '" + module + "/internal/cmd.Version=" + version + "' -X '" + module + "/internal/cmd.Commit=" + commit + "' -X '" + module + "/internal/cmd.Date=" + date + "'"

# Build the binary
build:
    CGO_ENABLED=0 go build -ldflags "{{ldflags}}" -o {{binary}} ./cmd/vulners/

# Run unit tests
test:
    go test -race ./...

# Run integration tests (requires VULNERS_API_KEY)
test-integration:
    go test -tags=integration ./...

# Run linter
lint:
    golangci-lint run

# Format code
fmt:
    gofumpt -w .

# Remove build artifacts
clean:
    rm -f {{binary}}
    rm -rf dist/
