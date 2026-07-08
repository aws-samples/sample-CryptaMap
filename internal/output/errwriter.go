package output

import "io"

// errWriter wraps an io.Writer and remembers the first write error, letting
// sequential fmt.Fprintf-style writers skip per-call error checks while still
// propagating a mid-stream failure (e.g. a full disk truncating report.md).
// After the first error, subsequent writes are no-ops.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) Write(p []byte) (int, error) {
	if ew.err != nil {
		return 0, ew.err
	}
	n, err := ew.w.Write(p)
	if err != nil {
		ew.err = err
	}
	return n, err
}
