package core

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	ar "github.com/agent-reliability/agent-reliability"
	"github.com/agent-reliability/mcp-guard/hotel"
	"github.com/agent-reliability/mcp-guard/policy"
)

// buildGuard wires hotel + default YAML baseline policies into a guard with
// the supplied approver/mode.
func buildGuard(t *testing.T, approver Approver, mode string) *Guard {
	t.Helper()
	kernel := &ar.Guard{}
	kernel.AddPolicy(hotel.IssueCardPolicy())
	kernel.AddPolicy(hotel.GetGuestProfilePolicy())
	def, err := policy.DefaultPolicies()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range def {
		kernel.AddPolicy(p)
	}
	return New(kernel, WithApprover(approver), WithMode(mode))
}

func args(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}

func TestIntegrationALLOW(t *testing.T) {
	g := buildGuard(t, DenyAll{}, "enforce")
	dec, err := g.Check(context.Background(), ToolCall{
		Tool: hotel.ToolIssueCard, Arguments: args(map[string]any{"role": "front_desk", "room": "203"}), Meta: Meta{User: "alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != ar.Allow {
		t.Fatalf("want ALLOW, got %s", dec.Type)
	}
	if dec.ReceiptID == "" || dec.RequestHash == "" {
		t.Fatalf("receipt/hash missing")
	}
}

func TestIntegrationDENY(t *testing.T) {
	g := buildGuard(t, DenyAll{}, "enforce")
	dec, err := g.Check(context.Background(), ToolCall{
		Tool: "shell", Arguments: args(map[string]any{"command": "rm -rf /"}), Meta: Meta{User: "bob"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != ar.Deny {
		t.Fatalf("want DENY, got %s", dec.Type)
	}
}

func TestIntegrationASKPending(t *testing.T) {
	// ASK under enforce with DenyAll approver => blocked (pending denied).
	g := buildGuard(t, DenyAll{}, "enforce")
	dec, err := g.Check(context.Background(), ToolCall{
		Tool: hotel.ToolIssueCard, Arguments: args(map[string]any{"role": "guest", "room": "203"}), Meta: Meta{User: "carol"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != ar.Deny {
		t.Fatalf("ASK+DenyAll must end DENY, got %s", dec.Type)
	}
	// With AllowAll approver it is approved => ALLOW (the "approved" path).
	g2 := buildGuard(t, AllowAll{}, "enforce")
	dec2, err := g2.Check(context.Background(), ToolCall{
		Tool: hotel.ToolIssueCard, Arguments: args(map[string]any{"role": "guest", "room": "203"}), Meta: Meta{User: "carol"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec2.Type != ar.Allow || dec2.ApprovedBy == "" {
		t.Fatalf("ASK+AllowAll must be ALLOW+approved, got %s/%q", dec2.Type, dec2.ApprovedBy)
	}
}

func TestIntegrationMODIFY(t *testing.T) {
	g := buildGuard(t, DenyAll{}, "enforce")
	dec, err := g.Check(context.Background(), ToolCall{
		Tool: hotel.ToolIssueCard, Arguments: args(map[string]any{"role": "front_desk", "room": "203", "privileged": true}), Meta: Meta{User: "alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != ar.Modify {
		t.Fatalf("want MODIFY, got %s", dec.Type)
	}
	var got map[string]any
	_ = json.Unmarshal(dec.Arguments, &got)
	if _, ok := got["privileged"]; ok {
		t.Fatalf("privileged should be stripped by MODIFY: %v", got)
	}
}

func TestCheckPathShellDeny(t *testing.T) {
	// Mirrors cmd/guard `check` with no --config: empty engine + default YAML
	// baseline only. A destructive shell command must be DENIED by
	// block-dangerous-shell (not merely ASKed by require-approval-shell).
	kernel := &ar.Guard{}
	def, err := policy.DefaultPolicies()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range def {
		kernel.AddPolicy(p)
	}
	g := New(kernel, WithApprover(DenyAll{}))
	dec, err := g.Check(context.Background(), ToolCall{
		Tool:      "shell",
		Arguments: args(map[string]any{"command": "rm -rf /"}),
		Meta:      Meta{User: "bob"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != ar.Deny {
		t.Fatalf("want DENY, got %s", dec.Type)
	}
	if dec.PolicyID != "block-dangerous-shell" {
		t.Fatalf("want policy block-dangerous-shell, got %q", dec.PolicyID)
	}
}

func TestIntegrationObserve(t *testing.T) {
	// Under observe mode a destructive shell call must NOT be blocked: it is
	// reported ALLOW, but the audit records the would-be DENY.
	g := buildGuard(t, DenyAll{}, "observe")
	dec, err := g.Check(context.Background(), ToolCall{
		Tool: "shell", Arguments: args(map[string]any{"command": "rm -rf /"}), Meta: Meta{User: "bob"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != ar.Allow {
		t.Fatalf("observe must report ALLOW, got %s", dec.Type)
	}
	recs, _ := g.Audit().Query(context.Background(), AuditFilter{Tool: "shell"})
	if len(recs) != 1 {
		t.Fatalf("want 1 audit record, got %d", len(recs))
	}
	if recs[0].WouldBe != string(ar.Deny) {
		t.Fatalf("observe audit must record would-be DENY, got %q", recs[0].WouldBe)
	}
	if recs[0].Mode != "observe" {
		t.Fatalf("audit mode should be observe, got %q", recs[0].Mode)
	}
}

func TestJSONLAuditAndRedaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	sink, err := NewFileAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	kernel := ar.NewGuard()
	kernel.AddPolicy(hotel.IssueCardPolicy())
	guard := New(kernel, WithAudit(sink))

	_, err = guard.Check(context.Background(), ToolCall{
		Tool:      hotel.ToolIssueCard,
		Arguments: args(map[string]any{"role": "front_desk", "room": "203", "token": "super-secret"}),
		Meta:      Meta{User: "alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = sink.Close()

	// Read back via a fresh sink.
	sink2, _ := NewFileAudit(path)
	defer sink2.Close()
	recs, err := sink2.Query(context.Background(), AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 record on disk, got %d", len(recs))
	}
	raw := string(recs[0].Arguments)
	if raw == "" {
		t.Fatal("audit arguments empty")
	}
	var got map[string]any
	_ = json.Unmarshal(recs[0].Arguments, &got)
	if got["token"] != "***" {
		t.Fatalf("sensitive token not redacted: %v", got)
	}
	if recs[0].ReceiptID == "" || recs[0].RequestHash == "" {
		t.Fatalf("receipt/hash missing in jsonl audit")
	}
}
