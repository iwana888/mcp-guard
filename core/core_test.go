package core

import (
	"context"
	"encoding/json"
	"testing"

	ar "github.com/agent-reliability/agent-reliability"
	"github.com/agent-reliability/mcp-guard/hotel"
)

func newTestGuard(t *testing.T, approver Approver) *Guard {
	t.Helper()
	kernel := ar.NewGuard()
	kernel.AddPolicy(hotel.IssueCardPolicy())
	kernel.AddPolicy(hotel.GetGuestProfilePolicy())
	return New(kernel, WithApprover(approver))
}

func mustArgs(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}

func TestIssueCardDecisions(t *testing.T) {
	g := newTestGuard(t, AllowAll{})
	ctx := context.Background()

	cases := []struct {
		name     string
		args     map[string]any
		wantType ar.DecisionType
	}{
		{"front_desk allow", map[string]any{"actor": "a", "role": "front_desk", "room": "203"}, ar.Allow},
		{"housekeeping assigned", map[string]any{"actor": "b", "role": "housekeeping", "room": "410", "assigned_room": "410"}, ar.Allow},
		{"housekeeping other room", map[string]any{"actor": "b", "role": "housekeeping", "room": "999", "assigned_room": "410"}, ar.Deny},
		{"guest with booking", map[string]any{"actor": "c", "role": "guest", "room": "203", "booking_id": "BK-1"}, ar.Allow},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			call := ToolCall{Tool: hotel.ToolIssueCard, Arguments: mustArgs(c.args), Meta: Meta{User: "u"}}
			dec, err := g.Check(ctx, call)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Type != c.wantType {
				t.Fatalf("want %s, got %s (%s)", c.wantType, dec.Type, dec.Reason)
			}
		})
	}
}

func TestAskResolvedByApprover(t *testing.T) {
	// ASK with DenyAll approver => DENY.
	g := newTestGuard(t, DenyAll{})
	call := ToolCall{
		Tool:      hotel.ToolIssueCard,
		Arguments: mustArgs(map[string]any{"actor": "c", "role": "guest", "room": "203"}),
		Meta:      Meta{User: "u"},
	}
	dec, err := g.Check(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type != ar.Deny {
		t.Fatalf("want DENY after approver denies, got %s", dec.Type)
	}

	// ASK with AllowAll approver => ALLOW with ApprovedBy set.
	g2 := newTestGuard(t, AllowAll{})
	dec2, err := g2.Check(context.Background(), call)
	if err != nil {
		t.Fatal(err)
	}
	if dec2.Type != ar.Allow || dec2.ApprovedBy == "" {
		t.Fatalf("want ALLOW with approver, got %s / by=%q", dec2.Type, dec2.ApprovedBy)
	}
}

func TestAuditTrail(t *testing.T) {
	g := newTestGuard(t, AllowAll{})
	ctx := context.Background()
	call := ToolCall{
		Tool:      hotel.ToolIssueCard,
		Arguments: mustArgs(map[string]any{"actor": "a", "role": "front_desk", "room": "203"}),
		Meta:      Meta{User: "alice"},
	}
	if _, err := g.Check(ctx, call); err != nil {
		t.Fatal(err)
	}
	recs, err := g.Audit().Query(ctx, AuditFilter{Actor: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 audit record, got %d", len(recs))
	}
	if recs[0].Decision != string(ar.Allow) {
		t.Fatalf("want ALLOW in audit, got %s", recs[0].Decision)
	}
}
