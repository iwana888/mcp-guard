// Package core defines the MCP-Guard gateway: a thin enforcement layer that
// sits in front of an MCP server's tool dispatch and routes every tool call
// through the agent-reliability kernel for a policy decision.
//
// It covers the four things MCP-Guard must deliver on top of the kernel
// (per README.md / mcp-guard.txt):
//   1. Action Policy  - rules expressed as kernel Policies
//   2. Decision       - ALLOW / DENY / ASK / MODIFY from the kernel
//   3. Approval       - interactive (or scripted) human-in-the-loop
//   4. Audit          - every decision persisted for forensics
package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/agent-reliability/agent-reliability"
)

// Meta carries the identity / session context of the agent making the call.
type Meta struct {
	User          string `json:"user"`
	SessionID     string `json:"session_id"`
	Channel       string `json:"channel"`
	SourceIP      string `json:"source_ip"`
	AgentID       string `json:"agent_id"`
	Impersonating string `json:"impersonating,omitempty"`
}

// ToolCall describes a single invocation of an MCP tool, exactly as it arrives
// at the server's tool dispatch.
type ToolCall struct {
	// Tool is the MCP tool name, e.g. "issue_card", "get_guest_profile".
	Tool string `json:"tool"`
	// Arguments are the raw JSON arguments forwarded to the tool.
	Arguments json.RawMessage `json:"arguments"`
	// Meta is the identity / session context of the caller.
	Meta Meta `json:"meta"`
}

// Decision is the verdict returned to the MCP server after a Check.
type Decision struct {
	// Type is one of ALLOW, DENY, ASK, MODIFY (mirrors the kernel).
	Type agentreliability.DecisionType `json:"type"`
	// Reason is a human-readable explanation.
	Reason string `json:"reason"`
	// PolicyID is the kernel policy that produced the verdict.
	PolicyID string `json:"policy_id,omitempty"`
	// Tool is the (possibly modified) tool that should be executed.
	Tool string `json:"tool"`
	// Arguments are the (possibly modified) arguments to execute.
	Arguments json.RawMessage `json:"arguments,omitempty"`
	// ApprovedBy is populated when an ASK was granted by a human.
	ApprovedBy string `json:"approved_by,omitempty"`
	// DecisionID links this verdict to its audit record.
	DecisionID string `json:"decision_id"`
	// ReceiptID is a stable correlation id returned to the caller.
	ReceiptID string `json:"receipt_id,omitempty"`
	// RequestHash is SHA-256 of the canonical request (tool+args+meta).
	RequestHash string `json:"request_hash,omitempty"`
}

// Guard is the MCP-Guard enforcement point. It wraps a kernel guard and adds
// audit + approval handling on top of the raw policy decision.
type Guard struct {
	kernel       *agentreliability.Guard
	audit        AuditSink
	approve      Approver
	now          func() time.Time
	mode         string // "enforce" | "observe"
	targetServer string
}

// Option configures a Guard.
type Option func(*Guard)

// WithAudit sets the audit sink (default: in-memory sink).
func WithAudit(sink AuditSink) Option { return func(g *Guard) { g.audit = sink } }

// WithApprover sets the human-in-the-loop approver (default: deny-all).
func WithApprover(a Approver) Option { return func(g *Guard) { g.approve = a } }

// WithClock overrides the clock used for timestamps (mainly for tests).
func WithClock(now func() time.Time) Option { return func(g *Guard) { g.now = now } }

// WithMode sets the guard mode. "observe" records what the policy would have
// decided but never blocks (downstream runs as if ALLOW). "enforce" is default.
func WithMode(mode string) Option { return func(g *Guard) { g.mode = mode } }

// WithTargetServer records the upstream target for audit correlation.
func WithTargetServer(target string) Option { return func(g *Guard) { g.targetServer = target } }

// New builds a Guard from the supplied kernel guard.
func New(kernel *agentreliability.Guard, opts ...Option) *Guard {
	g := &Guard{
		kernel:  kernel,
		audit:   &MemoryAudit{},
		approve: DenyAll{},
		now:     time.Now,
		mode:    "enforce",
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

// toAction converts a ToolCall into a kernel Action. Arguments are merged with
// the caller's identity (Meta) so policies can reason about who acts and on
// whose behalf, without the agent being able to hide those fields.
func toAction(call ToolCall) agentreliability.Action {
	args := map[string]any{}
	if len(call.Arguments) > 0 {
		_ = json.Unmarshal(call.Arguments, &args)
	}
	// Inject identity context the policy layer can trust.
	args["__actor"] = call.Meta.User
	args["__session"] = call.Meta.SessionID
	args["__channel"] = call.Meta.Channel
	args["__source_ip"] = call.Meta.SourceIP
	args["__agent_id"] = call.Meta.AgentID
	args["__impersonating"] = call.Meta.Impersonating
	return agentreliability.Action{
		Tool: call.Tool,
		Args: args,
	}
}

// Check evaluates a tool call and returns the decision the MCP server must
// enforce. It converts the ToolCall into a kernel Action, runs the kernel,
// and then resolves ASK via the configured Approver.
//
// Under "observe" mode the real verdict is recorded as WouldBe but the call is
// always reported as ALLOW, so the downstream tool still runs (shadow mode).
func (g *Guard) Check(ctx context.Context, call ToolCall) (Decision, error) {
	id := newID()
	receipt := newID()
	hash := requestHash(call)

	kdec := g.kernel.Check(ctx, toAction(call))

	dec := Decision{
		Type:        kdec.Type,
		Reason:      kdec.Reason,
		PolicyID:    kdec.PolicyID,
		Tool:        call.Tool,
		Arguments:   call.Arguments,
		DecisionID:  id,
		ReceiptID:   receipt,
		RequestHash: hash,
	}
	// MODIFY: the kernel suggests a replacement action. Surface it without
	// silently rewriting the agent's intent (matches kernel semantics).
	if kdec.Type == agentreliability.Modify && kdec.Suggested != nil {
		mod, err := json.Marshal(kdec.Suggested.Args)
		if err == nil {
			dec.Tool = kdec.Suggested.Tool
			dec.Arguments = mod
		}
	}

	// Human-in-the-loop: an ASK decision must be resolved by an approver
	// before the tool may run. In observe mode we skip approval and let the
	// call proceed, recording the would-be verdict.
	if kdec.Type == agentreliability.Ask && g.mode != "observe" {
		approved, by, why := g.approve.Request(ctx, call, kdec.PolicyID, kdec.Reason)
		if approved {
			dec.Type = agentreliability.Allow
			dec.ApprovedBy = by
			dec.Reason = fmt.Sprintf("approved by %s: %s", by, why)
		} else {
			dec.Type = agentreliability.Deny
			dec.Reason = fmt.Sprintf("denied by approver %s: %s", by, why)
		}
	}

	// Shadow mode: never block. The downstream tool runs as if ALLOW, but we
	// keep the real verdict for the audit trail.
	wouldBe := string(kdec.Type)
	if g.mode == "observe" {
		dec.Type = agentreliability.Allow
		dec.Reason = fmt.Sprintf("[observe] would be %s: %s", wouldBe, kdec.Reason)
	}

	rec := AuditRecord{
		ID:          id,
		Time:        g.now(),
		Tool:        call.Tool,
		Arguments:   redactArgs(call.Arguments),
		Actor:       call.Meta.User,
		Channel:     call.Meta.Channel,
		PolicyID:    kdec.PolicyID,
		Decision:    string(dec.Type),
		Reason:      dec.Reason,
		ApprovedBy:  dec.ApprovedBy,
		Mode:        g.mode,
		WouldBe:     wouldBe,
		ReceiptID:   receipt,
		RequestHash: hash,
		TargetServer: g.targetServer,
	}
	if err := g.audit.Record(ctx, rec); err != nil {
		// Auditing failing must not silently let a call through; surface it.
		return Decision{}, fmt.Errorf("audit failed: %w", err)
	}

	return dec, nil
}

// requestHash returns a stable SHA-256 of the canonical request, so the same
// call produces the same hash regardless of encoding whitespace.
func requestHash(call ToolCall) string {
	h := sha256.New()
	h.Write([]byte(call.Tool))
	h.Write([]byte{0})
	h.Write(call.Arguments)
	h.Write([]byte{0})
	h.Write([]byte(call.Meta.User))
	h.Write([]byte{0})
	h.Write([]byte(call.Meta.SessionID))
	return hex.EncodeToString(h.Sum(nil))
}

// Audit exposes the configured audit sink for querying the trail.
func (g *Guard) Audit() AuditSink { return g.audit }

// TranslateError explains a kernel error as an MCP-facing message.
func TranslateError(err error) string {
	if err == nil {
		return ""
	}
	return "mcp-guard: " + err.Error()
}

// newID returns a short random identifier for an audit record.
func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// sensitiveKeys are argument names whose values are masked in audit logs.
var sensitiveKeys = []string{"token", "password", "secret", "api_key", "apikey", "authorization", "access_token", "private_key", "credential"}

// redactArgs returns a copy of the arguments with sensitive values masked so
// the audit trail never stores plaintext secrets.
func redactArgs(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	for _, k := range sensitiveKeys {
		if _, ok := m[k]; ok {
			m[k] = "***"
			continue
		}
		// case-insensitive match
		for mk := range m {
			if strings.EqualFold(mk, k) && mk != k {
				m[mk] = "***"
			}
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return b
}
