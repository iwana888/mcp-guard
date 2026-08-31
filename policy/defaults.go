package policy

import "github.com/agent-reliability/agent-reliability"

// DefaultPoliciesYAML is the built-in, language-agnostic safety baseline. It
// mirrors the rules a security team would hand an operator on day one: block
// destructive shell commands and dangerous SQL, require approval for shell
// access and production deploys. Operators can extend or override it with
// their own YAML files.
const DefaultPoliciesYAML = `
# Built-in safety baseline for MCP-Guard.
# See policy.File / Rule for the schema.
mode: enforce
rules:
  - id: block-dangerous-shell
    tool: shell
    command_contains:
      - "rm -rf"
      - "rm -r /"
      - "mkfs"
      - "shutdown"
      - "reboot"
      - ">: /dev/sda"
      - "dd if="
    action: deny
    severity: high
    reason: "destructive shell command blocked"

  - id: block-dangerous-sql
    tool: sql
    arg_contains:
      - "drop table"
      - "truncate table"
      - "delete from"
      - "drop database"
    action: deny
    severity: high
    reason: "destructive SQL blocked"

  - id: require-approval-shell
    tool: shell
    action: ask
    severity: medium
    reason: "shell execution requires approval"

  - id: require-approval-production-deploy
    tool: deploy
    params:
      environment: "production"
    action: ask
    severity: high
    reason: "production deploy requires approval"
`

// DefaultPolicies parses and returns the built-in safety baseline as kernel
// Policies.
func DefaultPolicies() ([]agentreliability.Policy, error) {
	f, err := Parse([]byte(DefaultPoliciesYAML))
	if err != nil {
		return nil, err
	}
	return f.ToPolicies(), nil
}
