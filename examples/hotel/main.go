// Command hotel-demo runs the MCP-Guard gateway end-to-end against the
// hotel key-card policies, exercising ALLOW / DENY / ASK decisions and audit.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	ar "github.com/agent-reliability/agent-reliability"
	mguard "github.com/agent-reliability/mcp-guard/core"
	"github.com/agent-reliability/mcp-guard/hotel"
)

func main() {
	kernel := ar.NewGuard()
	kernel.AddPolicy(hotel.IssueCardPolicy())
	kernel.AddPolicy(hotel.GetGuestProfilePolicy())

	// In a demo we auto-approve ASK so the full flow is visible; swap in
	// mguard.ConsoleApprover{} for a real human-in-the-loop prompt.
	guard := mguard.New(kernel, mguard.WithApprover(mguard.AllowAll{}))
	ctx := context.Background()

	scenarios := []struct {
		name string
		call mguard.ToolCall
	}{
		{
			name: "front-desk issues a card",
			call: call(hotel.ToolIssueCard, map[string]any{
				"actor": "alice", "role": "front_desk", "room": "203",
			}),
		},
		{
			name: "housekeeping → assigned room",
			call: call(hotel.ToolIssueCard, map[string]any{
				"actor": "bob", "role": "housekeeping", "room": "410", "assigned_room": "410",
			}),
		},
		{
			name: "housekeeping → other room",
			call: call(hotel.ToolIssueCard, map[string]any{
				"actor": "bob", "role": "housekeeping", "room": "999", "assigned_room": "410",
			}),
		},
		{
			name: "guest with booking",
			call: call(hotel.ToolIssueCard, map[string]any{
				"actor": "carol", "role": "guest", "room": "203", "booking_id": "BK-7781",
			}),
		},
		{
			name: "guest without booking (ASK→approve)",
			call: call(hotel.ToolIssueCard, map[string]any{
				"actor": "carol", "role": "guest", "room": "203",
			}),
		},
		{
			name: "guest reads other profile (DENY)",
			call: call(hotel.ToolGetGuestProfile, map[string]any{
				"actor": "carol", "role": "guest", "room": "203",
			}),
		},
	}

	for _, s := range scenarios {
		dec, err := guard.Check(ctx, s.call)
		if err != nil {
			fmt.Printf("[%s] ERROR: %v\n", s.name, err)
			continue
		}
		fmt.Printf("[%s] => %-6s %s\n", s.name, dec.Type, dec.Reason)
	}

	// Show the audit trail.
	recs, _ := guard.Audit().Query(ctx, mguard.AuditFilter{})
	fmt.Printf("\naudit trail (%d entries):\n", len(recs))
	for _, r := range recs {
		fmt.Printf("  %s %-18s %-6s by %s\n", r.Time.Format(time.TimeOnly), r.Tool, r.Decision, r.Actor)
	}
}

func call(tool string, args map[string]any) mguard.ToolCall {
	b, _ := json.Marshal(args)
	return mguard.ToolCall{Tool: tool, Arguments: b, Meta: mguard.Meta{User: "demo"}}
}
