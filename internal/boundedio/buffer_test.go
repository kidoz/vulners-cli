package boundedio

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestBufferOverflowCancelsProducer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := NewBuffer(4, cancel)
	if n, err := b.Write([]byte("abcd")); n != 4 || err != nil {
		t.Fatalf("boundary write: %d, %v", n, err)
	}
	if ctx.Err() != nil {
		t.Fatal("cancelled at exact limit")
	}
	if n, err := b.Write([]byte("efgh")); n != 0 || !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("overflow: %d, %v", n, err)
	}
	if ctx.Err() == nil || b.String() != "abcd" {
		t.Fatal("overflow did not cancel or changed buffer")
	}
}

func TestBufferLargeWrite(t *testing.T) {
	b := NewBuffer(3, func() {})
	n, err := b.Write([]byte("abcdef"))
	if n != 3 || !errors.Is(err, ErrOutputLimit) || b.String() != "abc" {
		t.Fatalf("write: %d, %v, %q", n, err, b.String())
	}
}

func TestBufferCopyCannotBypassLimit(t *testing.T) {
	b := NewBuffer(3, func() {})
	// Hide WriterTo to exercise io.Copy's destination path.
	src := struct{ io.Reader }{strings.NewReader("abcdef")}
	_, err := io.Copy(b, src)
	if !errors.Is(err, ErrOutputLimit) || b.String() != "abc" {
		t.Fatalf("copy: %v, %q", err, b.String())
	}
}
