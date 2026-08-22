// Package httpgw implements MCP-Guard as an HTTP MCP reverse proxy.
//
// The MCP Client talks to MCP-Guard instead of the real MCP Server. MCP-Guard
// forwards every request to the configured UPSTREAM, except it inspects
// "tools/call" JSON-RPC requests: it asks the agent-reliability kernel for a
// decision and only then forwards (or blocks / rewrites) the call.
//
// Design boundaries (per project spec):
//   - Token is NOT re-validated by MCP-Guard. The Authorization header is
//     passed through verbatim to the upstream MCP Server, which owns authn/z.
//   - MCP-Guard only judges action risk from the request's identity context.
//   - Only "tools/call" is intercepted. initialize, notifications/*,
//     tools/list, resources/*, prompts/* are transparently proxied.
//
// Supported transport: single JSON-RPC request bodies with
// Content-Type: application/json on POST /mcp. This covers the common
// request/response MCP flow without breaking the handshake.
package httpgw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/agent-reliability/agent-reliability"
	"github.com/agent-reliability/mcp-guard/core"
)

// jsonRPCRequest is the subset of JSON-RPC 2.0 we care about.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// toolsCallParams are the params of an MCP tools/call request.
type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Meta      json.RawMessage `json:"_meta,omitempty"`
}

// jsonRPCError is the error object of a JSON-RPC response.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// jsonRPCResponse is what we return when we block a call locally.
type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
}

// Gateway is the HTTP MCP reverse proxy.
type Gateway struct {
	guard    *core.Guard
	upstream *url.URL
	proxy    *httputil.ReverseProxy
	mcpPath  string
}

// New builds a Gateway. upstream is the real MCP Server base URL
// (e.g. http://mcp-server:8080); mcpPath is the path that serves MCP
// (default "/mcp"). The guard supplies the policy decision.
func New(upstream *url.URL, guard *core.Guard, mcpPath string) *Gateway {
	if mcpPath == "" {
		mcpPath = "/mcp"
	}
	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, fmt.Sprintf("mcp-guard: upstream unreachable: %v", err), http.StatusBadGateway)
	}
	return &Gateway{guard: guard, upstream: upstream, proxy: rp, mcpPath: mcpPath}
}

// Handler returns the http.Handler for the gateway.
func (g *Gateway) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only intercept JSON-RPC POSTs to the MCP endpoint; otherwise proxy.
		if r.Method == http.MethodPost && r.URL.Path == g.mcpPath &&
			contentTypeIsJSON(r.Header.Get("Content-Type")) {
			g.handleMCP(w, r)
			return
		}
		g.proxy.ServeHTTP(w, r)
	})
}

func (g *Gateway) handleMCP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONRPCError(w, nil, -32700, "failed to read request body")
		return
	}

	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONRPCError(w, nil, -32700, "invalid JSON-RPC: "+err.Error())
		return
	}
	// Preserve the original id for any error we return.
	id := req.ID

	// Anything that is not a tools/call is forwarded verbatim.
	if req.Method != "tools/call" {
		g.forwardWithBody(w, r, body)
		return
	}

	// Parse tools/call params.
	var params toolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSONRPCError(w, id, -32602, "invalid tools/call params: "+err.Error())
		return
	}
	if params.Name == "" {
		writeJSONRPCError(w, id, -32602, "tools/call missing tool name")
		return
	}
	args := params.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}

	// Build the identity context. The Authorization token is NOT consumed for
	// auth — we just record it as context and pass it through to upstream.
	meta := extractMeta(r, params.Meta)

	// Evaluate the policy.
	dec, err := g.guard.Check(r.Context(), core.ToolCall{
		Tool:      params.Name,
		Arguments: args,
		Meta:      meta,
	})
	if err != nil {
		writeJSONRPCError(w, id, -32603, "mcp-guard evaluation error: "+err.Error())
		return
	}

	switch dec.Type {
	case agentreliability.Allow:
		// Forward with (possibly) modified arguments.
		forwardBody := body
		if dec.Arguments != nil && string(dec.Arguments) != string(args) {
			forwardBody = rewriteCallArgs(body, params, dec.Arguments)
		}
		g.forwardWithBody(w, r, forwardBody)

	case agentreliability.Deny:
		// Block: do NOT forward. Return a JSON-RPC error to the client.
		writeJSONRPCError(w, id, -32000, "mcp-guard denied: "+dec.Reason)

	case agentreliability.Ask:
		// Approver already resolved ASK inside guard.Check. If it ended up
		// allowed, forward; if denied, block. (Approval happened upstream of
		// this switch in core.Guard.)
		if dec.ApprovedBy != "" {
			g.forwardWithBody(w, r, body)
		} else {
			writeJSONRPCError(w, id, -32000, "mcp-guard denied: "+dec.Reason)
		}

	case agentreliability.Modify:
		// Forward the kernel's suggested arguments.
		modArgs := dec.Arguments
		if modArgs == nil {
			modArgs = args
		}
		g.forwardWithBody(w, r, rewriteCallArgs(body, params, modArgs))
	}
}

// forwardWithBody forwards the (possibly rewritten) request body to upstream,
// preserving the Authorization header and all other headers.
func (g *Gateway) forwardWithBody(w http.ResponseWriter, r *http.Request, body []byte) {
	out, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.upstream.String()+g.mcpPath, bytes.NewReader(body))
	if err != nil {
		writeJSONRPCError(w, nil, -32603, "mcp-guard: failed to build upstream request")
		return
	}
	// Copy headers (Authorization passes through verbatim).
	for k, vals := range r.Header {
		for _, v := range vals {
			out.Header.Add(k, v)
		}
	}
	out.Header.Set("Content-Type", "application/json")
	out.ContentLength = int64(len(body))

	resp, err := http.DefaultClient.Do(out)
	if err != nil {
		http.Error(w, fmt.Sprintf("mcp-guard: upstream unreachable: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	// Copy status + headers + body back to the client.
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// extractMeta builds the caller identity context from request headers and the
// optional params._meta. The Bearer token is recorded as context (token_id)
// but never validated here.
func extractMeta(r *http.Request, paramsMeta json.RawMessage) core.Meta {
	meta := core.Meta{
		SourceIP: clientIP(r),
	}
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		meta.User = auth[7:] // token used as identity context; upstream validates it
	}
	if s := r.Header.Get("X-Session-Id"); s != "" {
		meta.SessionID = s
	}
	if s := r.Header.Get("X-Channel"); s != "" {
		meta.Channel = s
	}
	if s := r.Header.Get("X-Agent-Id"); s != "" {
		meta.AgentID = s
	}
	// Merge any structured identity from params._meta.
	if len(paramsMeta) > 0 {
		var m map[string]any
		if json.Unmarshal(paramsMeta, &m) == nil {
			if v, ok := m["user"].(string); ok && v != "" {
				meta.User = v
			}
			if v, ok := m["session_id"].(string); ok {
				meta.SessionID = v
			}
			if v, ok := m["channel"].(string); ok {
				meta.Channel = v
			}
			if v, ok := m["impersonating"].(string); ok {
				meta.Impersonating = v
			}
		}
	}
	return meta
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

// rewriteCallArgs returns a new JSON-RPC request body where the tools/call
// arguments are replaced with newArgs, keeping method/id intact.
func rewriteCallArgs(original []byte, params toolsCallParams, newArgs json.RawMessage) []byte {
	var req jsonRPCRequest
	if err := json.Unmarshal(original, &req); err != nil {
		return original
	}
	params.Arguments = newArgs
	req.Params = mustJSON(params)
	b, err := json.Marshal(req)
	if err != nil {
		return original
	}
	return b
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}

func writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors ride a 200 with an error object
	resp := jsonRPCResponse{JSONRPC: "2.0", ID: id, Error: &jsonRPCError{Code: code, Message: msg}}
	b, _ := json.Marshal(resp)
	_, _ = w.Write(b)
}

func contentTypeIsJSON(ct string) bool {
	for _, part := range []string{"application/json"} {
		if len(ct) >= len(part) && ct[:len(part)] == part {
			return true
		}
	}
	return false
}

// ---- decision-type helpers (kept local to avoid importing kernel constants) ----

