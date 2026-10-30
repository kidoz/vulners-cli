// Package boundedio bounds captured command output and cancels producers on overflow.
package boundedio

import (
	"bytes"
	"context"
	"errors"
)

const (
	StdoutLimit = 64 << 20
	StderrLimit = 1 << 20
)

var ErrOutputLimit = errors.New("command output exceeds size limit")

// Buffer must be read only after its writer has finished, like bytes.Buffer.
type Buffer struct {
	buf    bytes.Buffer
	limit  int
	cancel context.CancelFunc
	err    error
}

func NewBuffer(limit int, cancel context.CancelFunc) *Buffer {
	return &Buffer{limit: limit, cancel: cancel}
}

func (b *Buffer) Write(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	remaining := b.limit - b.Len()
	if len(p) <= remaining {
		return b.buf.Write(p)
	}
	n, _ := b.buf.Write(p[:remaining])
	b.err = ErrOutputLimit
	b.cancel()
	return n, b.err
}

func (b *Buffer) Err() error { return b.err }

func (b *Buffer) Len() int       { return b.buf.Len() }
func (b *Buffer) String() string { return b.buf.String() }
func (b *Buffer) Bytes() []byte  { return b.buf.Bytes() }
