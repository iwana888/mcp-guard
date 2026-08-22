// Command hotel-server is a minimal but real HTTP MCP Server used to
// demonstrate MCP-Guard end-to-end. It implements the MCP JSON-RPC surface
// (initialize, tools/list, tools/call) for a hotel front-desk agent and calls
// a (stubbed) TCService to issue key cards and read guest profiles.
//
// It plays the role of the "real MCP Server" behind MCP-Guard:
//
//	MCP Client → MCP-Guard → (this server) → TCService → door lock
//
// In production the TCService call would hit a real door-lock backend; here it
// is an in-memory stub so the demo runs without external dependencies.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

// --- MCP JSON-RPC plumbing (minimal, enough for tools/call demo) ---

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any           `json:"result,omitempty"`
	Error   *rpcError     `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func rpcOK(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}
func rpcErr(id json.RawMessage, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// --- tool definitions ---

var toolsList = map[string]any{
	"tools": []map[string]any{
		{
			"name":        "issue_card",
			"description": "Issue a physical key card for a room.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"role":         map[string]any{"type": "string", "enum": []string{"front_desk", "housekeeping", "guest"}},
					"room":         map[string]any{"type": "string"},
					"assigned_room": map[string]any{"type": "string"},
					"booking_id":   map[string]any{"type": "string"},
				},
				"required": []string{"role", "room"},
			},
		},
		{
			"name":        "get_guest_profile",
			"description": "Read a guest's profile (PII).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"role": map[string]any{"type": "string"},
					"room": map[string]any{"type": "string"},
				},
				"required": []string{"role"},
			},
		},
	},
}

// TCServiceStub simulates the door-lock / PMS backend.
func tcServiceIssueCard(args map[string]any) (any, error) {
	room, _ := args["room"].(string)
	// A real backend would open the lock; we just echo success.
	return map[string]any{
		"ok":      true,
		"room":    room,
		"card_id": fmt.Sprintf("CARD-%s-%d", room, len(room)*7+13),
		"issued_by": "TCService",
	}, nil
}

func tcServiceGuestProfile(args map[string]any) (any, error) {
	room, _ := args["room"].(string)
	return map[string]any{
		"room":     room,
		"name":     "REDACTED",
		"checkin":  "2026-08-21",
		"vip":      false,
		"source":   "TCService",
	}, nil
}

func callTool(name string, args map[string]any) (any, error) {
	switch name {
	case "issue_card":
		return tcServiceIssueCard(args)
	case "get_guest_profile":
		return tcServiceGuestProfile(args)
	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

func handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST supported", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeRPC(w, rpcErr(nil, -32700, "read error"))
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPC(w, rpcErr(nil, -32700, "invalid JSON-RPC"))
		return
	}

	switch req.Method {
	case "initialize":
		writeRPC(w, rpcOK(req.ID, map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"serverInfo":      map[string]any{"name": "hotel-mcp", "version": "0.1.0"},
		}))
	case "tools/list":
		writeRPC(w, rpcOK(req.ID, toolsList))
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			writeRPC(w, rpcErr(req.ID, -32602, "invalid params"))
			return
		}
		// The upstream server owns auth: it would validate the Bearer token
		// here. For the demo we just note it was received.
		auth := r.Header.Get("Authorization")
		res, err := callTool(p.Name, p.Arguments)
		if err != nil {
			writeRPC(w, rpcOK(req.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": "error: " + err.Error()}},
				"isError": true,
			}))
			return
		}
		_ = auth
		writeRPC(w, rpcOK(req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": mustJSON(res)}},
		}))
	default:
		// notifications/* and anything else: echo an empty result so the
		// protocol handshake is never broken.
		writeRPC(w, rpcOK(req.ID, map[string]any{}))
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(resp)
	_, _ = w.Write(b)
}

func main() {
	addr := flag.String("listen", envOr("HOTEL_LISTEN", ":18080"), "listen address")
	flag.Parse()
	http.HandleFunc("/mcp", handleMCP)
	fmt.Printf("hotel-mcp server listening on %s/mcp\n", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
