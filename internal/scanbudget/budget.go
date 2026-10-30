// Package scanbudget bounds inventory growth and per-component API work.
package scanbudget

import (
	"errors"
	"fmt"
)

const (
	MaxComponents     = 10000
	MaxSearchRequests = 1000
)

var ErrExceeded = errors.New("scan budget exceeded")

func CheckComponents(count int) error {
	if count > MaxComponents {
		return fmt.Errorf("%w: maximum %d components", ErrExceeded, MaxComponents)
	}
	return nil
}
