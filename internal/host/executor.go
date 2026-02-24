package host

import "context"

// Executor defines an interface for running commands on a target host.
type Executor interface {
	// Execute runs a command and returns its standard output as a string.
	// It should return an error if the command fails to execute or exits with a non-zero status.
	Execute(ctx context.Context, cmd string) (string, error)

	// Close cleans up any resources associated with the executor.
	Close() error
}
