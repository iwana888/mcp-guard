// Package hotel provides the MCP-Guard action policies for a hotel front-desk
// agent that can issue physical key cards and query guest data.
//
// It implements the two canonical scenarios from mcp-guard.txt:
//
//   - Housekeeping staff (role=housekeeping) may only ask for a card to a
//     room they are assigned to. Issuing a card to any OTHER room is DENIED.
//
//   - A guest requesting a card must present a booking confirmation. With a
//     confirmation the call is ALLOWED; without it the call is ASK and must
//     be approved by a human (front-desk).
//
// These rules are expressed as agent-reliability Policies so they share the
// kernel's decision pipeline with any other policy you add.
package hotel

import (
	"fmt"

	"github.com/agent-reliability/agent-reliability"
)

// Action types used by this domain.
const (
	ToolIssueCard       = "issue_card"
	ToolGetGuestProfile = "get_guest_profile"
)

// argStr reads a string argument from a kernel Action. Identity fields set by
// the MCP-Guard gateway are prefixed with "__".
func argStr(a agentreliability.Action, key string) string {
	if v, ok := a.Args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// argBool reads a bool argument from a kernel Action.
func argBool(a agentreliability.Action, key string) bool {
	if v, ok := a.Args[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// IssueCardPolicy enforces the key-card issuance rules. It covers the five
// end-to-end scenarios from the project spec:
//
//	ordinary issue      → ALLOW
//	unauthorized room   → DENY
//	Master Card         → ASK   (high-risk, needs approval)
//	bulk issue          → ASK   (batch, needs approval)
//	dangerous argument  → MODIFY (strip the privilege escalation)
func IssueCardPolicy() agentreliability.Policy {
	return agentreliability.Policy{
		ID:          "hotel.issue_card",
		Name:        "Restrict key-card issuance",
		Description: "Restrict key-card issuance by staff role and booking status.",
		Severity:    "high",
		Enabled:     true,
		Eval: func(a agentreliability.Action) (agentreliability.Decision, bool) {
			if a.Tool != ToolIssueCard {
				return agentreliability.Decision{}, false
			}

			// Master Card: a skeleton/emergency card that opens every door.
			if argStr(a, "card_type") == "master" {
				return ask("Master Card opens all doors; front-desk manager approval required"), true
			}
			// Bulk issue: an array of rooms is a batch operation.
			if _, ok := a.Args["rooms"]; ok {
				return ask("bulk card issuance; front-desk manager approval required"), true
			}
			// Dangerous argument: privilege escalation must be stripped, not run.
			if argBool(a, "privileged") {
				safe := stripKey(a.Args, "privileged")
				return agentreliability.Decision{
					Type:      agentreliability.Modify,
					PolicyID:  "hotel.issue_card",
					Reason:    "privileged flag stripped; issue non-privileged card instead",
					Suggested: &agentreliability.Action{Tool: ToolIssueCard, Args: safe},
				}, true
			}

			role := argStr(a, "role")
			room := argStr(a, "room")
			assigned := argStr(a, "assigned_room")
			booking := argStr(a, "booking_id")

			switch role {
			case "housekeeping":
				if room == "" {
					return deny("housekeeping must specify a room"), true
				}
				if assigned != "" && room != assigned {
					return deny(fmt.Sprintf("housekeeping not assigned to room %s", room)), true
				}
				return allow("housekeeping → assigned room"), true

			case "guest":
				if booking != "" {
					return allow("guest with booking confirmation"), true
				}
				return ask("guest has no booking confirmation; front-desk approval required"), true

			case "front_desk":
				return allow("front-desk staff"), true

			default:
				return ask(fmt.Sprintf("unknown role %q; manual approval required", role)), true
			}
		},
	}
}

// stripKey returns a copy of m with key removed (used for MODIFY suggestions).
func stripKey(m map[string]any, key string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k == key {
			continue
		}
		out[k] = v
	}
	return out
}

// GetGuestProfilePolicy guards PII reads.
func GetGuestProfilePolicy() agentreliability.Policy {
	return agentreliability.Policy{
		ID:          "hotel.get_guest_profile",
		Name:        "Guard guest-profile reads",
		Description: "Allow guest-profile reads only for staff with a legitimate role.",
		Severity:    "medium",
		Enabled:     true,
		Eval: func(a agentreliability.Action) (agentreliability.Decision, bool) {
			if a.Tool != ToolGetGuestProfile {
				return agentreliability.Decision{}, false
			}
			switch argStr(a, "role") {
			case "front_desk", "housekeeping":
				return allow("staff role may read guest profile"), true
			case "guest":
				return deny("guests may not read other guest profiles"), true
			default:
				return ask("unknown role; manual approval required"), true
			}
		},
	}
}

func allow(reason string) agentreliability.Decision {
	return agentreliability.Decision{Type: agentreliability.Allow, Reason: reason}
}
func deny(reason string) agentreliability.Decision {
	return agentreliability.Decision{Type: agentreliability.Deny, Reason: reason}
}
func ask(reason string) agentreliability.Decision {
	return agentreliability.Decision{Type: agentreliability.Ask, Reason: reason}
}
