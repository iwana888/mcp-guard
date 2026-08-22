package core

import (
	"context"
	"fmt"

	"github.com/agent-reliability/agent-reliability"
)

// Approver resolves an ASK decision through a human (or automated) approver.
type Approver interface {
	// Request returns whether the tool call is approved, who approved/denied
	// it, and a short reason.
	Request(ctx context.Context, call ToolCall, policyID, reason string) (approved bool, by, why string)
}

// DenyAll is the safe default: every ASK is denied. Use it when no approver
// is wired up (e.g. a batch/offline context) so risky calls fail closed.
type DenyAll struct{}

// Request always denies.
func (DenyAll) Request(_ context.Context, _ ToolCall, _ , _ string) (bool, string, string) {
	return false, "system", "no approver configured"
}

// AllowAll auto-approves every ASK. Convenient for demos and trusted
// automation, but never use it in production without a real approver.
type AllowAll struct{}

// Request always approves.
func (AllowAll) Request(_ context.Context, _ ToolCall, _ , _ string) (bool, string, string) {
	return true, "auto", "auto-approve (demo mode)"
}

// ConsoleApprover asks a human on stdin/stdout. Suitable for local runs and
// CLI demos.
type ConsoleApprover struct {
	// DecisionFallback is used when no TTY is available; defaults to deny.
	DecisionFallback func(policyID, reason string) (bool, string, string)
}

// Request prompts on stdout and reads a single y/N line from stdin.
func (c ConsoleApprover) Request(ctx context.Context, call ToolCall, policyID, reason string) (bool, string, string) {
	fmt.Printf("\n[approve] policy=%q actor=%q reason=%s\n", policyID, call.Meta.User, reason)
	fmt.Printf("  arguments: %s\n", string(call.Arguments))
	fmt.Print("  allow this call? [y/N] ")

	var ans string
	if _, err := fmt.Scanln(&ans); err != nil {
		if c.DecisionFallback != nil {
			return c.DecisionFallback(policyID, reason)
		}
		return false, "console", "no input, denying"
	}
	if ans == "y" || ans == "Y" || ans == "yes" {
		return true, "console-operator", "operator confirmed"
	}
	return false, "console-operator", "operator rejected"
}

// DecisionType alias keeps callers insulated from the kernel type name.
type DecisionType = agentreliability.DecisionType
