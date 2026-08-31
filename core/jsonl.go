package core

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"sync"
)

// FileAuditSink persists audit records to a JSONL file (one record per line).
// It satisfies the AuditSink interface and is the P2 deliverable: append-only,
// grep-friendly, and trivially shippable to a log pipeline later.
type FileAuditSink struct {
	mu   sync.Mutex
	path string
	f    *os.File
	w    *bufio.Writer
}

// NewFileAudit opens (or creates) the JSONL audit file at path.
func NewFileAudit(path string) (*FileAuditSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &FileAuditSink{path: path, f: f, w: bufio.NewWriter(f)}, nil
}

// Record appends one record as a single JSON line.
func (s *FileAuditSink) Record(_ context.Context, r AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		return err
	}
	return s.w.Flush()
}

// Close flushes and closes the underlying file.
func (s *FileAuditSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.w.Flush(); err != nil {
		return err
	}
	return s.f.Close()
}

// Query reads the JSONL file back and returns matching records (newest last).
func (s *FileAuditSink) Query(_ context.Context, f AuditFilter) ([]AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	in, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	var out []AuditRecord
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var r AuditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue // skip malformed lines
		}
		if f.Tool != "" && r.Tool != f.Tool {
			continue
		}
		if f.Actor != "" && r.Actor != f.Actor {
			continue
		}
		if f.Decision != "" && r.Decision != f.Decision {
			continue
		}
		if f.Since != nil && r.Time.Before(*f.Since) {
			continue
		}
		out = append(out, r)
	}
	return out, sc.Err()
}
