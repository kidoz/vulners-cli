package report

import (
	"io"
	"unicode"
)

type terminalWriter struct {
	writer io.Writer
}

func (w *terminalWriter) Write(p []byte) (int, error) {
	sanitized := []rune(string(p))
	for i, r := range sanitized {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			sanitized[i] = ' '
		}
	}
	output := []byte(string(sanitized))
	n, err := w.writer.Write(output)
	if err != nil {
		return 0, err
	}
	if n != len(output) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}
