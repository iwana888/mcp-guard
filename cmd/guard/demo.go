package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	ar "github.com/agent-reliability/agent-reliability"
	mguard "github.com/agent-reliability/mcp-guard/core"
	"github.com/agent-reliability/mcp-guard/hotel"
	"github.com/agent-reliability/mcp-guard/policy"
)

// runDemo exercises the four decision types against the hotel key-card
// policies, with no external dependencies. It shows ALLOW / DENY / ASK /
// MODIFY end to end plus the audit trail.
func runDemo() {
	kernel := &ar.Guard{}
	hotelPolicies(kernel)
	if def, err := policy.DefaultPolicies(); err == nil {
		for _, p := range def {
			kernel.AddPolicy(p)
		}
	}

	// In demo we auto-approve ASK so the full flow is visible.
	guard := mguard.New(kernel, mguard.WithApprover(mguard.AllowAll{}))
	ctx := context.Background()

	scenarios := []struct {
		label string
		call  mguard.ToolCall
	}{
		{
			label: "front-desk issues a card",
			call:  call(hotel.ToolIssueCard, map[string]any{"role": "front_desk", "room": "203"}),
		},
		{
			label: "housekeeping → other room",
			call:  call(hotel.ToolIssueCard, map[string]any{"role": "housekeeping", "room": "999", "assigned_room": "410"}),
		},
		{
			label: "guest without booking (ASK)",
			call:  call(hotel.ToolIssueCard, map[string]any{"role": "guest", "room": "203"}),
		},
		{
			label: "privileged flag (MODIFY)",
			call:  call(hotel.ToolIssueCard, map[string]any{"role": "front_desk", "room": "203", "privileged": true}),
		},
		{
			label: "destructive shell (DENY via YAML baseline)",
			call:  call("shell", map[string]any{"command": "rm -rf /"}),
		},
	}

	for _, s := range scenarios {
		dec, err := guard.Check(ctx, s.call)
		if err != nil {
			fmt.Printf("[%s] ERROR: %v\n", s.label, err)
			continue
		}
		fmt.Printf("[%s]\n  => %-6s (policy=%s)\n  reason: %s\n  receipt: %s\n  hash:   %s\n",
			s.label, dec.Type, dec.PolicyID, dec.Reason, dec.ReceiptID, dec.RequestHash)
		if dec.ApprovedBy != "" {
			fmt.Printf("  approved_by: %s\n", dec.ApprovedBy)
		}
	}

	recs, _ := guard.Audit().Query(ctx, mguard.AuditFilter{})
	fmt.Printf("\naudit trail (%d entries):\n", len(recs))
	for _, r := range recs {
		fmt.Printf("  %s %-12s %-6s would=%s by %s\n", r.Time.Format(time.TimeOnly), r.Tool, r.Decision, r.WouldBe, r.Actor)
	}
}

func hotelPolicies(kernel *ar.Guard) {
	kernel.AddPolicy(hotel.IssueCardPolicy())
	kernel.AddPolicy(hotel.GetGuestProfilePolicy())
}

func call(tool string, args map[string]any) mguard.ToolCall {
	b, _ := json.Marshal(args)
	return mguard.ToolCall{Tool: tool, Arguments: b, Meta: mguard.Meta{User: "demo"}}
}
