// Command mcp-guard runs MCP-Guard as an HTTP MCP reverse proxy.
//
// The MCP Client points at MCP-Guard; MCP-Guard forwards to UPSTREAM after
// evaluating each tools/call through the agent-reliability kernel.
//
//	# terminal 1: real MCP server (e.g. the bundled hotel server)
//	go run ./server/hotel
//
//	# terminal 2: MCP-Guard in front of it
//	UPSTREAM=http://127.0.0.1:18080 mcp-guard
//
//	# client now talks to MCP-Guard instead of the server
//	curl -X POST http://127.0.0.1:8080/mcp \
//	  -H 'Authorization: Bearer <token>' \
//	  -H 'Content-Type: application/json' \
//	  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_card","arguments":{"role":"guest","room":"203"}}}'
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	ar "github.com/agent-reliability/agent-reliability"
	mguard "github.com/agent-reliability/mcp-guard/core"
	"github.com/agent-reliability/mcp-guard/httpgw"
	"github.com/agent-reliability/mcp-guard/hotel"
)

func main() {
	upstream := flag.String("upstream", os.Getenv("UPSTREAM"),
		"Upstream MCP Server base URL (env UPSTREAM).")
	listen := flag.String("listen", envOr("LISTEN_ADDR", ":8080"),
		"Address MCP-Guard listens on.")
	mcpPath := flag.String("mcp-path", envOr("MCP_PATH", "/mcp"),
		"Path that serves MCP on both proxy and upstream.")
	approve := flag.String("approve", envOr("APPROVE", "deny"),
		"ASK handling: 'deny' (fail closed) or 'auto' (auto-approve for demos).")
	flag.Parse()

	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "error: -upstream (or UPSTREAM env) is required")
		os.Exit(2)
	}
	u, err := url.Parse(*upstream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid upstream URL: %v\n", err)
		os.Exit(2)
	}

	kernel := ar.NewGuard()
	kernel.AddPolicy(hotel.IssueCardPolicy())
	kernel.AddPolicy(hotel.GetGuestProfilePolicy())

	var approver mguard.Approver = mguard.DenyAll{}
	if *approve == "auto" {
		approver = mguard.AllowAll{}
	}

	guard := mguard.New(kernel, mguard.WithApprover(approver))
	gw := httpgw.New(u, guard, *mcpPath)

	fmt.Printf("mcp-guard listening on %s, proxying %s%s (approve=%s)\n",
		*listen, *upstream, *mcpPath, *approve)
	if err := http.ListenAndServe(*listen, gw.Handler()); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
