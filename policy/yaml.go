// Package policy turns declarative YAML rules into agent-reliability Policies
// so non-Go developers can configure MCP-Guard without editing code.
//
// It is intentionally decoupled from the core gate: a parsed YAML file yields
// []agentreliability.Policy, which is fed into the kernel exactly like the
// built-in hotel policies. No core interface changes.
package policy

import (
	"fmt"
	"strings"

	"github.com/agent-reliability/agent-reliability"
	"gopkg.in/yaml.v3"
)

// File is the top-level YAML document.
type File struct {
	DefaultAction string `yaml:"default_action"` // allow | deny (informational; kernel no-match == allow)
	Mode          string `yaml:"mode"`            // enforce | observe
	Rules         []Rule `yaml:"rules"`
}

// Rule is one declarative policy.
type Rule struct {
	ID           string            `yaml:"id"`
	Tool         string            `yaml:"tool"`          // single tool name (alias for tools[0])
	Tools        []string          `yaml:"tools"`         // match any of these tools
	CommandContains []string       `yaml:"command_contains"` // target/command substring match
	ArgContains  []string          `yaml:"arg_contains"`  // any argument value substring match
	Params       map[string]string `yaml:"params"`        // exact argument match
	Action       string            `yaml:"action"`        // allow | deny | ask | modify
	ModifyTo     map[string]any    `yaml:"modify_to"`     // modify: suggested args (optional)
	Reason       string            `yaml:"reason"`
	Severity     string            `yaml:"severity"`
	Disabled     bool              `yaml:"disabled"`
}

// Parse loads a YAML policy file into a structured File.
func Parse(data []byte) (*File, error) {
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("policy: parse yaml: %w", err)
	}
	return &f, nil
}

// ToPolicies converts every enabled rule into a kernel Policy. The order of
// the slice preserves the document order (first match wins in the kernel).
func (f *File) ToPolicies() []agentreliability.Policy {
	out := make([]agentreliability.Policy, 0, len(f.Rules))
	for _, r := range f.Rules {
		if r.Disabled {
			continue
		}
		out = append(out, r.toPolicy())
	}
	return out
}

func (r Rule) toPolicy() agentreliability.Policy {
	tools := r.Tools
	if len(tools) == 0 && r.Tool != "" {
		tools = []string{r.Tool}
	}
	severity := r.Severity
	if severity == "" {
		severity = "medium"
	}
	reason := r.Reason
	if reason == "" {
		reason = fmt.Sprintf("matched rule %q", r.ID)
	}
	return agentreliability.Policy{
		ID:          r.ID,
		Name:        r.ID,
		Description: reason,
		Severity:    severity,
		Enabled:     true,
		Eval: func(a agentreliability.Action) (agentreliability.Decision, bool) {
			if !ruleMatches(a, tools, r.CommandContains, r.ArgContains, r.Params) {
				return agentreliability.Decision{}, false
			}
			return ruleDecision(r, a), true
		},
	}
}

// ruleMatches returns true only when EVERY specified dimension matches (AND
// semantics). An unspecified dimension is ignored.
func ruleMatches(a agentreliability.Action, tools, cmdContains, argContains []string, params map[string]string) bool {
	// tool filter
	if len(tools) > 0 {
		hit := false
		for _, t := range tools {
			if t == "*" || t == a.Tool {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	// command/target substring: must match at least one (if dimension specified).
	// We check a.Target and the common MCP argument names (command/query) so
	// shell/sql tools whose payload lives in Arguments are still matched.
	if len(cmdContains) > 0 {
		haystacks := []string{a.Target}
		for _, key := range []string{"command", "query", "sql"} {
			if v, ok := a.Args[key]; ok {
				haystacks = append(haystacks, valueToString(v))
			}
		}
		matched := false
		for _, h := range haystacks {
			low := strings.ToLower(h)
			for _, sub := range cmdContains {
				if strings.Contains(low, strings.ToLower(sub)) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	// any argument value substring: must match at least one (if specified)
	if len(argContains) > 0 {
		matched := false
		for _, sub := range argContains {
			low := strings.ToLower(sub)
			for _, v := range a.Args {
				if strings.Contains(strings.ToLower(valueToString(v)), low) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}
	// exact argument match: every key must equal (if dimension specified)
	for k, want := range params {
		got, ok := a.Args[k]
		if !ok || valueToString(got) != want {
			return false
		}
	}
	// If no dimension was specified, the rule can never match (avoid wildcard).
	if len(tools) == 0 && len(cmdContains) == 0 && len(argContains) == 0 && len(params) == 0 {
		return false
	}
	return true
}

func ruleDecision(r Rule, a agentreliability.Action) agentreliability.Decision {
	switch strings.ToLower(r.Action) {
	case "allow":
		return agentreliability.Decision{Type: agentreliability.Allow, PolicyID: r.ID, Reason: r.Reason}
	case "ask":
		return agentreliability.Decision{Type: agentreliability.Ask, PolicyID: r.ID, Reason: r.Reason}
	case "modify":
		sugg := &agentreliability.Action{Tool: a.Tool, Target: a.Target, Args: cloneArgs(a.Args)}
		for k, v := range r.ModifyTo {
			sugg.Args[k] = v
		}
		return agentreliability.Decision{
			Type: agentreliability.Modify, PolicyID: r.ID, Reason: r.Reason, Suggested: sugg,
		}
	case "deny", "":
		return agentreliability.Decision{Type: agentreliability.Deny, PolicyID: r.ID, Reason: r.Reason}
	default:
		// Unknown action defaults to deny (fail closed).
		return agentreliability.Decision{
			Type: agentreliability.Deny, PolicyID: r.ID,
			Reason: fmt.Sprintf("unknown action %q; denied (fail-closed)", r.Action),
		}
	}
}

func valueToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}

func cloneArgs(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
