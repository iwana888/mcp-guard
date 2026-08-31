package core

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// AuditRecord is a single immutable log entry for one tool-call decision.
type AuditRecord struct {
	ID          string          `json:"id"`
	Time        time.Time       `json:"time"`
	Tool        string          `json:"tool"`
	Arguments   json.RawMessage `json:"arguments"`
	Actor       string          `json:"actor"`
	Channel     string          `json:"channel"`
	PolicyID    string          `json:"policy_id,omitempty"`
	Decision    string          `json:"decision"`
	Reason      string          `json:"reason"`
	ApprovedBy  string          `json:"approved_by,omitempty"`
	// Mode is the guard mode at decision time (enforce | observe).
	Mode string `json:"mode,omitempty"`
	// WouldBe is the verdict the policy would have produced under enforce
	// mode. In enforce mode it equals Decision; in observe mode it records
	// what *would* have happened, while Decision stays ALLOW.
	WouldBe string `json:"would_be,omitempty"`
	// ReceiptID is a stable id returned to the caller (for correlation).
	ReceiptID string `json:"receipt_id,omitempty"`
	// RequestHash is SHA-256 of the canonical request (tool + args + meta).
	RequestHash string `json:"request_hash,omitempty"`
	// TargetServer is the upstream the call would be (or was) sent to.
	TargetServer string `json:"target_server,omitempty"`
}

// AuditSink persists audit records. Implement this to ship logs to your
// favourite store (file, Postgres, Splunk, ...).
type AuditSink interface {
	Record(ctx context.Context, r AuditRecord) error
	// Query returns all records (optionally filtered) for forensics.
	Query(ctx context.Context, filter AuditFilter) ([]AuditRecord, error)
}

// AuditFilter narrows an audit query.
type AuditFilter struct {
	Tool     string
	Actor    string
	Decision string
	Since    *time.Time
}

// MemoryAudit is an in-process audit sink, good for tests and small servers.
type MemoryAudit struct {
	mu   sync.Mutex
	logs []AuditRecord
}

// Record appends a record.
func (m *MemoryAudit) Record(_ context.Context, r AuditRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, r)
	return nil
}

// Query returns matching records in chronological order.
func (m *MemoryAudit) Query(_ context.Context, f AuditFilter) ([]AuditRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AuditRecord, 0, len(m.logs))
	for _, r := range m.logs {
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
	return out, nil
}
