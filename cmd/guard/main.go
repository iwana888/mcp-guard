// Command guard is the MCP-Guard CLI.
//
//	guard serve   # HTTP reverse proxy in front of an MCP Server
//	guard check   # evaluate a single tool call against the policy, locally
//	guard demo    # run the built-in four-scenario demo (no dependencies)
//
// Product name: AgentWorld Guard (formerly MCP Guard).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	ar "github.com/agent-reliability/agent-reliability"
	mguard "github.com/agent-reliability/mcp-guard/core"
	"github.com/agent-reliability/mcp-guard/httpgw"
	"github.com/agent-reliability/mcp-guard/policy"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: guard <serve|check|demo> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	case "demo":
		cmdDemo(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

// buildKernel assembles the policy set on an EMPTY engine so MCP-Guard's own
// rules take priority (the kernel's built-in 10 defaults are not loaded here;
// MCP-Guard ships its own YAML baseline instead). Order: user config first,
// then the built-in safety baseline, then hotel domain policies.
func buildKernel(configPath string, extraHotel bool) (*ar.Guard, error) {
	kernel := &ar.Guard{}
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("read policy: %w", err)
		}
		f, err := policy.Parse(data)
		if err != nil {
			return nil, err
		}
		for _, p := range f.ToPolicies() {
			kernel.AddPolicy(p)
		}
	} else {
		// No --config: use the built-in safety baseline.
		def, err := policy.DefaultPolicies()
		if err != nil {
			return nil, err
		}
		for _, p := range def {
			kernel.AddPolicy(p)
		}
	}
	if extraHotel {
		// hotel domain policies are registered by the caller via package import
		// to avoid an import cycle here; kept separate on purpose.
	}
	return kernel, nil
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	upstream := fs.String("upstream", envOr("UPSTREAM", ""), "Upstream MCP Server base URL.")
	listen := fs.String("listen", envOr("LISTEN_ADDR", ":8080"), "Address MCP-Guard listens on.")
	config := fs.String("config", envOr("GUARD_CONFIG", ""), "Path to YAML policy file (default: built-in baseline).")
	auditPath := fs.String("audit", envOr("AUDIT_FILE", "audit.jsonl"), "JSONL audit file path.")
	mode := fs.String("mode", envOr("GUARD_MODE", "enforce"), "enforce | observe (shadow mode).")
	approve := fs.String("approve", envOr("APPROVE", "deny"), "ASK handling: deny (fail-closed) | auto.")
	mcpPath := fs.String("mcp-path", envOr("MCP_PATH", "/mcp"), "MCP endpoint path.")
	fs.Parse(args)

	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "error: -upstream (or UPSTREAM) is required")
		os.Exit(2)
	}
	u, err := parseURL(*upstream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid upstream: %v\n", err)
		os.Exit(2)
	}

	kernel, err := buildKernel(*config, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	audit, err := mguard.NewFileAudit(*auditPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open audit file: %v\n", err)
		os.Exit(1)
	}
	defer audit.Close()

	var approver mguard.Approver = mguard.DenyAll{}
	if *approve == "auto" {
		approver = mguard.AllowAll{}
	}

	guard := mguard.New(kernel,
		mguard.WithApprover(approver),
		mguard.WithAudit(audit),
		mguard.WithMode(*mode),
		mguard.WithTargetServer(*upstream),
	)
	gw := httpgw.New(u, guard, *mcpPath)

	fmt.Printf("AgentWorld Guard listening on %s, proxying %s%s (mode=%s, audit=%s)\n",
		*listen, *upstream, *mcpPath, *mode, *auditPath)
	if err := listenAndServe(*listen, gw.Handler()); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	config := fs.String("config", envOr("GUARD_CONFIG", ""), "Path to YAML policy file (default: built-in baseline).")
	tool := fs.String("tool", "", "Tool name.")
	argsJSON := fs.String("args", "", "JSON arguments.")
	actor := fs.String("actor", "cli", "Caller identity.")
	fs.Parse(args)

	if *tool == "" {
		fmt.Fprintln(os.Stderr, "error: -tool is required")
		os.Exit(2)
	}
	var raw json.RawMessage
	if *argsJSON != "" {
		raw = json.RawMessage(*argsJSON)
	} else {
		raw = json.RawMessage("{}")
	}

	kernel, err := buildKernel(*config, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	guard := mguard.New(kernel, mguard.WithApprover(mguard.DenyAll{}))
	dec, err := guard.Check(context.Background(), mguard.ToolCall{
		Tool:      *tool,
		Arguments: raw,
		Meta:      mguard.Meta{User: *actor},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"type":         dec.Type,
		"policy_id":    dec.PolicyID,
		"reason":       dec.Reason,
		"approved_by":  dec.ApprovedBy,
		"receipt_id":   dec.ReceiptID,
		"request_hash": dec.RequestHash,
	}, "", "  ")
	fmt.Println(string(out))
	if dec.Type == ar.Deny {
		os.Exit(3)
	}
}

func cmdDemo(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	fs.Parse(args)
	runDemo()
}
