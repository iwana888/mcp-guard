package policy

import (
	"context"
	"testing"

	"github.com/agent-reliability/agent-reliability"
)

func buildAction(tool, target string, args map[string]any) agentreliability.Action {
	return agentreliability.Action{Tool: tool, Target: target, Args: args}
}

func TestYAMLRules(t *testing.T) {
	src := `
rules:
  - id: block-dangerous-shell
    tool: shell
    command_contains: ["rm -rf", "mkfs"]
    action: deny
  - id: require-approval-production
    tool: deploy
    params:
      environment: "production"
    action: ask
  - id: strip-privileged
    tool: issue_card
    params:
      privileged: "true"
    action: modify
    modify_to:
      privileged: "false"
`
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	policies := f.ToPolicies()
	// Empty engine (no kernel defaults) so the YAML rule itself is evaluated.
	kernel := &agentreliability.Guard{}
	for _, p := range policies {
		kernel.AddPolicy(p)
	}

	cases := []struct {
		name   string
		act    agentreliability.Action
		want   agentreliability.DecisionType
		policy string
	}{
		{"shell rm", buildAction("shell", "rm -rf /", nil), agentreliability.Deny, "block-dangerous-shell"},
		{"shell mkfs", buildAction("shell", "mkfs.ext4", nil), agentreliability.Deny, "block-dangerous-shell"},
		{"shell ls allowed", buildAction("shell", "ls -l", nil), agentreliability.Allow, ""},
		{"deploy prod", buildAction("deploy", "", map[string]any{"environment": "production"}), agentreliability.Ask, "require-approval-production"},
		{"deploy dev", buildAction("deploy", "", map[string]any{"environment": "dev"}), agentreliability.Allow, ""},
		{"issue privileged", buildAction("issue_card", "", map[string]any{"privileged": "true"}), agentreliability.Modify, "strip-privileged"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := kernel.Check(context.Background(), c.act)
			if d.Type != c.want {
				t.Fatalf("want %s, got %s (%s)", c.want, d.Type, d.Reason)
			}
			if c.policy != "" && d.PolicyID != c.policy {
				t.Fatalf("want policy %s, got %s", c.policy, d.PolicyID)
			}
			if d.Type == agentreliability.Modify && d.Suggested == nil {
				t.Fatalf("modify decision missing Suggested")
			}
			if d.Type == agentreliability.Modify {
				if v, _ := d.Suggested.Args["privileged"].(string); v != "false" {
					t.Fatalf("modify did not rewrite privileged: %v", d.Suggested.Args)
				}
			}
		})
	}
}

func TestDefaultPoliciesParse(t *testing.T) {
	ps, err := DefaultPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) == 0 {
		t.Fatal("expected default policies")
	}
	kernel := &agentreliability.Guard{}
	for _, p := range ps {
		kernel.AddPolicy(p)
	}
	// dangerous shell should be denied by the baseline.
	d := kernel.Check(context.Background(), buildAction("shell", "rm -rf /", nil))
	if d.Type != agentreliability.Deny {
		t.Fatalf("default baseline should deny rm -rf, got %s", d.Type)
	}
}

func TestDefaultShellDenyViaArgs(t *testing.T) {
	def, err := DefaultPolicies()
	if err != nil {
		t.Fatal(err)
	}
	kernel := &agentreliability.Guard{}
	for _, p := range def {
		kernel.AddPolicy(p)
	}
	// MCP shell tools carry the command in Arguments, not Target.
	d := kernel.Check(context.Background(), agentreliability.Action{
		Tool: "shell",
		Args: map[string]any{"command": "rm -rf /"},
	})
	if d.Type != agentreliability.Deny {
		t.Fatalf("want DENY, got %s (%s)", d.Type, d.PolicyID)
	}
	if d.PolicyID != "block-dangerous-shell" {
		t.Fatalf("want block-dangerous-shell, got %s", d.PolicyID)
	}
}
